mod keystore;

use bleep_crypto::sign_tx_payload_for_address;
use bleep_governance::live_governance::{
    governance_vote_signing_payload, GovernableParam, GovernanceConfig, LiveGovernanceEngine,
    VerifiedVoter, Vote,
};
use rpassword::prompt_password;
use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::path::Path;

fn print_help() {
    println!("Governance Demo REPL commands:");
    println!("  snapshot <address> <stake> [<address> <stake> ...]");
    println!("  propose <proposer> <title> <description> [param=value]");
    println!("  vote <proposal_id> <address> <yes|no|abstain|veto> <public_key_hex>");
    println!("  list");
    println!("  status <proposal_id>");
    println!("  tally <proposal_id>");
    println!("  execute <proposal_id>");
    println!("  advance <blocks>");
    println!("  events");
    println!("  help");
    println!("  exit");
}

fn parse_param(s: &str) -> Option<GovernableParam> {
    let parts: Vec<&str> = s.splitn(2, '=').collect();
    if parts.len() != 2 {
        return None;
    }
    let name = parts[0];
    let val = parts[1];
    match name {
        "block_interval_ms" => val.parse().ok().map(GovernableParam::BlockIntervalMs),
        "max_txs_per_block" => val.parse().ok().map(GovernableParam::MaxTxsPerBlock),
        "max_inflation_bps" => val.parse().ok().map(GovernableParam::MaxInflationBps),
        "fee_burn_bps" => val.parse().ok().map(GovernableParam::FeeBurnBps),
        "downtime_penalty_per_block" => val
            .parse()
            .ok()
            .map(GovernableParam::DowntimePenaltyPerBlock),
        "equivocation_penalty_bps" => val
            .parse()
            .ok()
            .map(GovernableParam::EquivocationPenaltyBps),
        "min_validator_stake" => val.parse().ok().map(GovernableParam::MinValidatorStake),
        "oracle_quorum" => val.parse().ok().map(GovernableParam::OracleQuorum),
        "faucet_drip_amount" => val.parse().ok().map(GovernableParam::FaucetDripAmount),
        "prometheus_scrape_secs" => val.parse().ok().map(GovernableParam::PrometheusScrapeSecs),
        _ => None,
    }
}

// Small helper to avoid adding new enum variants for parsing float as downtime
mod helper {
    use bleep_governance::live_governance::GovernableParam;
    pub fn parse_param(name: &str, val: &str) -> Option<GovernableParam> {
        match name {
            "downtime_penalty_per_block" => val
                .parse()
                .ok()
                .map(GovernableParam::DowntimePenaltyPerBlock),
            _ => None,
        }
    }
}

fn main() {
    let mut engine = LiveGovernanceEngine::new(GovernanceConfig::default(), 1_000);
    println!(
        "BLEEP Governance Demo (in-memory). Record the current stake snapshot before proposing."
    );
    println!("Type 'help' for commands.");
    let mut unlocked: Option<(String, String)> = None; // (name, privhex)

    // Attempt to load persisted state if present
    let default_state = Path::new("state.json");
    if default_state.exists() {
        match fs::read_to_string(default_state) {
            Ok(s) => match engine.import_state(&s) {
                Ok(()) => println!("loaded state.json"),
                Err(e) => println!("failed to import state.json: {}", e),
            },
            Err(e) => println!("failed to read state.json: {}", e),
        }
    }

    loop {
        print!("> ");
        io::stdout().flush().ok();
        let mut line = String::new();
        if io::stdin().read_line(&mut line).is_err() {
            println!("failed to read input");
            continue;
        }
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = shell_words::split(line)
            .unwrap_or_else(|_| line.split_whitespace().map(|s| s.to_string()).collect());
        if parts.is_empty() {
            continue;
        }
        let cmd = parts.remove(0);
        match cmd.as_str() {
            "help" => print_help(),
            "keystore" => {
                if parts.is_empty() {
                    println!("usage: keystore <create|import|list|unlock> ...");
                    continue;
                }
                let sub = parts.remove(0);
                match sub.as_str() {
                    "create" | "import" => {
                        if parts.len() < 2 {
                            println!("usage: keystore {} <name> <privhex>", sub);
                            continue;
                        }
                        let name = parts.remove(0);
                        let privhex = parts.remove(0);
                        let pass = prompt_password("passphrase: ").unwrap_or_default();
                        match keystore::create_key(&name, &privhex, &pass) {
                            Ok(_) => println!("key {} stored (encrypted)", name),
                            Err(e) => println!("keystore error: {}", e),
                        }
                    }
                    "list" => match keystore::list_keys() {
                        Ok(list) => {
                            if list.is_empty() {
                                println!("no keys");
                            }
                            for (n, f) in list {
                                println!("{}  fingerprint={}", n, f);
                            }
                        }
                        Err(e) => println!("keystore error: {}", e),
                    },
                    "unlock" => {
                        if parts.is_empty() {
                            println!("usage: keystore unlock <name>");
                            continue;
                        }
                        let name = parts.remove(0);
                        let pass = prompt_password("passphrase: ").unwrap_or_default();
                        match keystore::unlock_key(&name, &pass) {
                            Ok(privhex) => {
                                println!("unlocked key {}", name);
                                unlocked = Some((name, privhex));
                            }
                            Err(e) => println!("unlock error: {}", e),
                        }
                    }
                    _ => println!("unknown keystore command"),
                }
                continue;
            }
            "exit" | "quit" => break,
            "snapshot" => {
                if parts.is_empty() || parts.len() % 2 != 0 {
                    println!("usage: snapshot <address> <stake> [<address> <stake> ...]");
                    continue;
                }
                let mut stakes = HashMap::new();
                let mut valid = true;
                for pair in parts.chunks_exact(2) {
                    let stake = match pair[1].parse::<u128>() {
                        Ok(stake) => stake,
                        Err(_) => {
                            println!("invalid stake amount for {}", pair[0]);
                            valid = false;
                            break;
                        }
                    };
                    if stakes.insert(pair[0].clone(), stake).is_some() {
                        println!("duplicate address in stake snapshot: {}", pair[0]);
                        valid = false;
                        break;
                    }
                }
                if !valid {
                    continue;
                }
                match engine.record_stake_snapshot(engine.current_block(), stakes) {
                    Ok(()) => {
                        println!(
                            "stake snapshot recorded at block {}",
                            engine.current_block()
                        );
                        if let Ok(json) = engine.export_state() {
                            if let Err(error) = fs::write("state.json", json) {
                                println!("failed to save state.json: {}", error);
                            }
                        }
                    }
                    Err(error) => println!("snapshot error: {:?}", error),
                }
            }
            "propose" => {
                if parts.len() < 3 {
                    println!("usage: propose <proposer> <title> <description> [param=value]");
                    continue;
                }
                let proposer = parts.remove(0);
                let title = parts.remove(0);
                let description = parts.remove(0);
                let mut param: Option<GovernableParam> = None;
                let mut invalid_param = false;
                for p in parts.iter() {
                    if let Some(pp) = parse_param(p) {
                        param = Some(pp);
                    } else {
                        let kv: Vec<&str> = p.splitn(2, '=').collect();
                        if kv.len() == 2 {
                            if let Some(pp) = helper::parse_param(kv[0], kv[1]) {
                                param = Some(pp);
                            } else {
                                println!("unknown proposal parameter: {}", p);
                                invalid_param = true;
                                break;
                            }
                        } else {
                            println!("invalid proposal parameter: {}", p);
                            invalid_param = true;
                            break;
                        }
                    }
                }
                if invalid_param {
                    continue;
                }
                let proposer = if proposer == "use:key" {
                    if let Some((name, _)) = &unlocked {
                        format!("bleep:demo:{}", name)
                    } else {
                        println!("no unlocked key; use keystore unlock <name>");
                        continue;
                    }
                } else {
                    proposer
                };
                match engine.submit(&proposer, &title, &description, param) {
                    Ok(id) => println!("proposal submitted id={}", id),
                    Err(e) => println!("submit error: {:?}", e),
                }
                // auto-save
                if let Ok(j) = engine.export_state() {
                    let _ = fs::write("state.json", j);
                }
            }
            "vote" => {
                if parts.len() != 4 {
                    println!(
                        "usage: vote <proposal_id> <address> <yes|no|abstain|veto> <public_key_hex>"
                    );
                    continue;
                }
                let pid: u64 = match parts.remove(0).parse() {
                    Ok(v) => v,
                    Err(_) => {
                        println!("invalid proposal id");
                        continue;
                    }
                };
                let address = parts.remove(0);
                let vt = parts.remove(0).to_lowercase();
                let public_key = match hex::decode(parts.remove(0)) {
                    Ok(key) => key,
                    Err(error) => {
                        println!("invalid public key hex: {}", error);
                        continue;
                    }
                };
                let vote = match vt.as_str() {
                    "yes" => Vote::Yes,
                    "no" => Vote::No,
                    "abstain" => Vote::Abstain,
                    "veto" => Vote::Veto,
                    _ => {
                        println!("unknown vote type");
                        continue;
                    }
                };
                let Some((_, secret_key_hex)) = &unlocked else {
                    println!("unlock the voter's private key with keystore unlock <name>");
                    continue;
                };
                let secret_key = match hex::decode(secret_key_hex) {
                    Ok(key) => key,
                    Err(error) => {
                        println!("invalid unlocked private key: {}", error);
                        continue;
                    }
                };
                let payload = governance_vote_signing_payload(pid, &address, &vote);
                let signature = match sign_tx_payload_for_address(&payload, &secret_key, &address) {
                    Ok(signature) => signature,
                    Err(error) => {
                        println!("vote signing failed: {}", error);
                        continue;
                    }
                };
                match VerifiedVoter::verify_vote(
                    pid,
                    &address,
                    vote.clone(),
                    &public_key,
                    &signature,
                ) {
                    Ok(verified_voter) => match engine.vote(pid, &verified_voter, vote) {
                        Ok(()) => println!("vote recorded"),
                        Err(error) => println!("vote error: {:?}", error),
                    },
                    Err(error) => println!("voter verification failed: {:?}", error),
                }
            }
            "list" => {
                let active = engine.active_proposals();
                if active.is_empty() {
                    println!("no active proposals");
                } else {
                    for p in active {
                        println!(
                            "id={} title='{}' proposer={} state={:?}",
                            p.id, p.title, p.proposer, p.state
                        );
                    }
                }
            }
            "status" => {
                if parts.is_empty() {
                    println!("usage: status <proposal_id>");
                    continue;
                }
                let pid: u64 = match parts.remove(0).parse() {
                    Ok(v) => v,
                    Err(_) => {
                        println!("invalid id");
                        continue;
                    }
                };
                if let Some(p) = engine.proposal(pid) {
                    println!("Proposal {}: {}", p.id, p.title);
                    println!("  proposer: {}", p.proposer);
                    println!("  state: {:?}", p.state);
                    println!(
                        "  yes: {} no: {} abstain: {} veto: {}",
                        p.yes_votes, p.no_votes, p.abstain_votes, p.veto_votes
                    );
                    println!(
                        "  created at block: {} voting end block: {}",
                        p.created_at_block, p.voting_end_block
                    );
                } else {
                    println!("proposal not found");
                }
            }
            "tally" => {
                if parts.is_empty() {
                    println!("usage: tally <proposal_id>");
                    continue;
                }
                let pid: u64 = match parts.remove(0).parse() {
                    Ok(v) => v,
                    Err(_) => {
                        println!("invalid id");
                        continue;
                    }
                };
                match engine.tally(pid) {
                    Ok(state) => println!("tally result: {:?}", state),
                    Err(e) => println!("tally error: {:?}", e),
                }
                if let Ok(j) = engine.export_state() {
                    let _ = fs::write("state.json", j);
                }
            }
            "execute" => {
                if parts.is_empty() {
                    println!("usage: execute <proposal_id>");
                    continue;
                }
                let pid: u64 = match parts.remove(0).parse() {
                    Ok(v) => v,
                    Err(_) => {
                        println!("invalid id");
                        continue;
                    }
                };
                match engine.execute(pid) {
                    Ok(res) => println!(
                        "executed proposal {} tx={} param={:?}",
                        res.proposal_id, res.tx_hash, res.param_applied
                    ),
                    Err(e) => println!("execute error: {:?}", e),
                }
                if let Ok(j) = engine.export_state() {
                    let _ = fs::write("state.json", j);
                }
            }
            "advance" => {
                if parts.is_empty() {
                    println!("usage: advance <blocks>");
                    continue;
                }
                let blocks: u64 = match parts.remove(0).parse() {
                    Ok(v) => v,
                    Err(_) => {
                        println!("invalid number");
                        continue;
                    }
                };
                match engine.advance_block(blocks) {
                    Ok(()) => println!(
                        "advanced {} blocks, current_block={}",
                        blocks,
                        engine.current_block()
                    ),
                    Err(error) => println!("advance error: {:?}", error),
                }
            }
            "events" => {
                for e in engine.event_log() {
                    println!(
                        "[block {}] {} proposal={} actor={} detail={}",
                        e.block, e.kind, e.proposal, e.actor, e.detail
                    );
                }
            }
            "save" => {
                let path = parts.first().map(|s| s.as_str()).unwrap_or("state.json");
                match engine.export_state() {
                    Ok(j) => match fs::write(path, j) {
                        Ok(_) => println!("saved {}", path),
                        Err(e) => println!("save error: {}", e),
                    },
                    Err(e) => println!("export error: {}", e),
                }
            }
            "load" => {
                let path = parts.first().map(|s| s.as_str()).unwrap_or("state.json");
                match fs::read_to_string(path) {
                    Ok(s) => match engine.import_state(&s) {
                        Ok(_) => println!("loaded {}", path),
                        Err(e) => println!("import error: {}", e),
                    },
                    Err(e) => println!("read error: {}", e),
                }
            }
            _ => println!("unknown command: {} (type 'help')", cmd),
        }
    }
    println!("goodbye");
}
