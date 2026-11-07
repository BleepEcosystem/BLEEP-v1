use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use bleep_crypto::tx_signer::{sign_tx_payload, tx_payload_v2};
use futures::{stream, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha3::Digest;
use std::{
    collections::{HashMap, HashSet},
    fs,
    io::Write,
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::time::{sleep, sleep_until, Instant};

#[derive(Deserialize)]
struct SenderKey {
    public_key_hex: String,
    secret_key_hex: String,
}

struct Sender {
    address: String,
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
}

#[derive(Clone, Serialize)]
struct TxResult {
    offered_tps: u64,
    index: usize,
    sender: String,
    submission_id: Option<String>,
    inclusion_hash: String,
    send_time_unix_ms: u128,
    scheduled_offset_ms: u128,
    send_offset_ms: u128,
    dispatch_lag_ms: u128,
    height_at_send: u64,
    response_time_ms: u128,
    http_status: Option<u16>,
    response: String,
    accepted: bool,
    inclusion_height: Option<u64>,
    inclusion_time_unix_ms: Option<u128>,
    inclusion_latency_ms: Option<u128>,
}

struct Summary {
    offered_tps: u64,
    attempted: usize,
    accepted: usize,
    rejected: usize,
    transport_errors: usize,
    included: usize,
    not_included: usize,
    p50_ms: Option<u128>,
    p99_ms: Option<u128>,
    p99_dispatch_lag_ms: Option<u128>,
    observed_tps: f64,
}

fn env(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

fn required_env(name: &str) -> Result<String> {
    std::env::var(name).with_context(|| format!("{name} must be set"))
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn parse_positive<T>(name: &str, value: &str) -> Result<T>
where
    T: std::str::FromStr,
    T: PartialOrd + Default,
    T::Err: std::fmt::Display,
{
    let parsed = value
        .parse::<T>()
        .map_err(|error| anyhow!("{name} must be a positive integer: {error}"))?;
    if parsed <= T::default() {
        bail!("{name} must be a positive integer");
    }
    Ok(parsed)
}

fn percentile(values: &mut [u128], percentile: usize) -> Option<u128> {
    if values.is_empty() {
        return None;
    }
    values.sort_unstable();
    let index = values
        .len()
        .saturating_mul(percentile)
        .div_ceil(100)
        .saturating_sub(1)
        .min(values.len() - 1);
    Some(values[index])
}

async fn response_json(response: reqwest::Response, context: &str) -> Result<Value> {
    let status = response.status();
    let body = response
        .text()
        .await
        .with_context(|| format!("{context}: failed reading response"))?;
    if !status.is_success() {
        bail!("{context} returned HTTP {status}: {body}");
    }
    serde_json::from_str(&body).with_context(|| format!("{context} returned invalid JSON"))
}

async fn admin_dapp_token(client: &reqwest::Client, rpc: &str) -> Result<String> {
    let public_key_hex = required_env("BLEEP_ADMIN_PUBLIC_KEY_HEX")?;
    let secret_path = PathBuf::from(required_env("BLEEP_ADMIN_SECRET_KEY_FILE")?);
    let secret_key = fs::read(&secret_path)
        .with_context(|| format!("failed reading admin secret key {}", secret_path.display()))?;
    if secret_key.len() != 128 {
        bail!(
            "admin secret key must be a raw 128-byte SPHINCS+ key file; got {} bytes",
            secret_key.len()
        );
    }
    let public_key = hex::decode(&public_key_hex).context("invalid admin public-key hex")?;
    if public_key.len() != 64 {
        bail!(
            "admin public key must be 64 bytes; got {} bytes",
            public_key.len()
        );
    }

    let challenge_response = client
        .post(format!("{rpc}/rpc/auth/admin/challenge"))
        .json(&json!({ "public_key_hex": public_key_hex }))
        .send()
        .await
        .context("admin challenge request failed")?;
    let challenge: Value = response_json(challenge_response, "admin challenge").await?;
    let challenge_text = challenge["challenge"]
        .as_str()
        .context("admin challenge response is missing challenge")?;
    let signing_payload = hex::decode(
        challenge["signing_payload_hex"]
            .as_str()
            .context("admin challenge response is missing signing_payload_hex")?,
    )
    .context("admin signing payload is not valid hex")?;
    let signature = sign_tx_payload(&signing_payload, &secret_key)
        .map_err(|error| anyhow!("failed signing admin login challenge: {error}"))?;

    let login_response = client
        .post(format!("{rpc}/rpc/auth/login"))
        .json(&json!({
            "public_key_hex": public_key_hex,
            "challenge": challenge_text,
            "signature_hex": hex::encode(signature),
        }))
        .send()
        .await
        .context("admin login request failed")?;
    let admin_token = response_json(login_response, "admin login").await?["token"]
        .as_str()
        .context("admin login response is missing a session token")?
        .to_string();

    let mut random = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut random);
    let registration_response = client
        .post(format!("{rpc}/rpc/auth/register/dapp"))
        .bearer_auth(&admin_token)
        .json(&json!({
            "developer_handle": format!("bleep-tps-{}", hex::encode(random)),
            "display_name": "BLEEP capacity benchmark",
            "password": hex::encode(random),
        }))
        .send()
        .await
        .context("benchmark DApp registration request failed")?;
    let dapp_token = response_json(registration_response, "benchmark DApp registration").await?
        ["token"]
        .as_str()
        .context("DApp registration response is missing a session token")?
        .to_string();
    Ok(dapp_token)
}

fn load_senders(path: &PathBuf, requested: usize) -> Result<Vec<Sender>> {
    let bytes = fs::read(path)
        .with_context(|| format!("failed reading funded sender key file {}", path.display()))?;
    let keys: Vec<SenderKey> = serde_json::from_slice(&bytes).with_context(|| {
        format!(
            "{} must contain a JSON array of sender keys",
            path.display()
        )
    })?;
    if keys.len() < requested {
        bail!(
            "sender key file has {} entries; offered load requires at least {requested} funded senders",
            keys.len()
        );
    }
    let mut seen_addresses = HashSet::with_capacity(requested);
    keys.into_iter()
        .take(requested)
        .enumerate()
        .map(|(index, key)| {
            let public_key = hex::decode(&key.public_key_hex)
                .with_context(|| format!("sender {index} public key is not valid hex"))?;
            let secret_key = hex::decode(&key.secret_key_hex)
                .with_context(|| format!("sender {index} secret key is not valid hex"))?;
            let address = bleep_crypto::derive_account_address(&public_key);
            if !seen_addresses.insert(address.clone()) {
                bail!("sender key file contains duplicate account {address}");
            }
            Ok(Sender {
                address,
                public_key,
                secret_key,
            })
        })
        .collect()
}

async fn sender_nonces(
    client: &reqwest::Client,
    rpc: &str,
    senders: &[Sender],
) -> Result<Vec<u64>> {
    let responses = stream::iter(senders.iter().enumerate())
        .map(|(index, sender)| async move {
            let response = client
                .get(format!("{rpc}/rpc/tx/nonce/{}", sender.address))
                .send()
                .await
                .with_context(|| format!("nonce query failed for sender {index}"))?;
            let value: Value =
                response_json(response, &format!("nonce query for sender {index}")).await?;
            let nonce = value["nonce"]
                .as_u64()
                .with_context(|| format!("nonce response missing nonce for sender {index}"))?;
            Ok::<_, anyhow::Error>((index, nonce))
        })
        .buffer_unordered(128)
        .collect::<Vec<Result<(usize, u64)>>>()
        .await;
    let mut nonces = vec![None; senders.len()];
    for result in responses {
        let (index, nonce) = result?;
        nonces[index] = Some(nonce);
    }
    nonces
        .into_iter()
        .enumerate()
        .map(|(index, nonce)| nonce.with_context(|| format!("missing nonce for sender {index}")))
        .collect()
}

fn presign(
    offered_tps: u64,
    duration_secs: u64,
    amount: u64,
    chain_id: &str,
    senders: &[Sender],
    mut nonces: Vec<u64>,
) -> Result<Vec<(Vec<u8>, String, String, String)>> {
    let count = usize::try_from(offered_tps.saturating_mul(duration_secs))
        .context("transaction count exceeds platform limits")?;
    if count == 0 {
        bail!("each offered-load test must contain at least one transaction");
    }
    if count.div_ceil(senders.len()) > 64 {
        bail!(
            "this test would offer more than 64 pending transactions per sender; increase sender count or shorten duration"
        );
    }
    let timestamp = now_ms() as u64 / 1000;
    let mut prepared = Vec::with_capacity(count);
    for index in 0..count {
        let sender_index = index % senders.len();
        let sender = &senders[sender_index];
        let nonce = nonces[sender_index];
        nonces[sender_index] = nonces[sender_index]
            .checked_add(1)
            .context("sender nonce overflow")?;
        let receiver = format!("BLEEP1TPS{:032x}", index as u128 + now_ms());
        let fee = bleep_core::transaction::MIN_TRANSACTION_FEE;
        let payload = tx_payload_v2(
            chain_id,
            &sender.address,
            &receiver,
            amount,
            fee,
            timestamp,
            nonce,
        );
        let signature = sign_tx_payload(&payload, &sender.secret_key)
            .map_err(|error| anyhow!("failed to sign transaction {index}: {error}"))?;
        let mut wire_signature = Vec::with_capacity(sender.public_key.len() + signature.len());
        wire_signature.extend_from_slice(&sender.public_key);
        wire_signature.extend_from_slice(&signature);
        let signing_hash = hex::encode(payload);
        let submission_id = hex::encode(sha3::Sha3_256::digest(&wire_signature));
        let request_body = serde_json::to_vec(&json!({
            "version": 2,
            "chain_id": chain_id,
            "sender": sender.address,
            "receiver": receiver,
            "amount": amount,
            "fee": fee,
            "timestamp": timestamp,
            "nonce": nonce,
            "signature": STANDARD.encode(wire_signature),
        }))
        .with_context(|| format!("failed serializing transaction {index}"))?;
        prepared.push((
            request_body,
            sender.address.clone(),
            submission_id,
            signing_hash,
        ));
    }
    Ok(prepared)
}

async fn health_height(client: &reqwest::Client, rpc: &str) -> Result<u64> {
    let response = client
        .get(format!("{rpc}/rpc/health"))
        .send()
        .await
        .context("RPC health request failed")?;
    let health: Value = response_json(response, "RPC health").await?;
    health["height"]
        .as_u64()
        .context("RPC health response is missing numeric height")
}

async fn run_load(
    client: &reqwest::Client,
    rpc: &str,
    token: &str,
    offered_tps: u64,
    duration_secs: u64,
    amount: u64,
    chain_id: &str,
    senders: &[Sender],
    settle_timeout: u64,
) -> Result<(Vec<TxResult>, Summary)> {
    let nonces = sender_nonces(client, rpc, senders).await?;
    let presign_started = Instant::now();
    let prepared = presign(
        offered_tps,
        duration_secs,
        amount,
        chain_id,
        senders,
        nonces,
    )?;
    let replay_window = env("BLEEP_TPS_REPLAY_WINDOW_SECS", "30")
        .parse::<u64>()
        .context("BLEEP_TPS_REPLAY_WINDOW_SECS must be a positive integer")?;
    let height_at_start = health_height(client, rpc).await?;
    let presign_duration = presign_started.elapsed();
    if presign_duration + Duration::from_secs(duration_secs) + Duration::from_millis(100)
        > Duration::from_secs(replay_window)
    {
        let total_secs = presign_duration.as_secs_f64() + duration_secs as f64 + 0.1;
        bail!(
            "pre-signing and load schedule take up to {total_secs:.1}s, exceeding the configured replay window of {replay_window}s; increase BLEEP_TX_REPLAY_WINDOW_SECS on every node and BLEEP_TPS_REPLAY_WINDOW_SECS here"
        );
    }

    let latest_height = Arc::new(AtomicU64::new(height_at_start));
    let monitor_height = Arc::clone(&latest_height);
    let monitor_client = client.clone();
    let monitor_rpc = rpc.to_string();
    let (stop_monitor, mut stop_receiver) = tokio::sync::oneshot::channel::<()>();
    let monitor = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut stop_receiver => break,
                _ = sleep(Duration::from_millis(200)) => {
                    if let Ok(height) = health_height(&monitor_client, &monitor_rpc).await {
                        monitor_height.store(height, Ordering::Relaxed);
                    }
                }
            }
        }
    });

    let start = Instant::now() + Duration::from_millis(100);
    let max_in_flight = prepared.len().max(1);
    let results = stream::iter(prepared.into_iter().enumerate())
        .map(
            |(index, (transaction, sender, submission_id, inclusion_hash))| {
                let client = client.clone();
                let endpoint = format!("{rpc}/rpc/tx");
                let token = token.to_string();
                let height = Arc::clone(&latest_height);
                async move {
                    let offset_ns =
                        (index as u128 * 1_000_000_000u128 / offered_tps as u128) as u64;
                    sleep_until(start + Duration::from_nanos(offset_ns)).await;
                    let sent_at = now_ms();
                    let send_offset_ms =
                        Instant::now().saturating_duration_since(start).as_millis();
                    let scheduled_offset_ms = offset_ns as u128 / 1_000_000;
                    let send_instant = Instant::now();
                    let height_at_send = height.load(Ordering::Relaxed);
                    let result = client
                        .post(endpoint)
                        .bearer_auth(token)
                        .header(reqwest::header::CONTENT_TYPE, "application/json")
                        .body(transaction)
                        .send()
                        .await;
                    let response_time_ms = send_instant.elapsed().as_millis();
                    let (http_status, body, accepted, response_id) = match result {
                        Ok(response) => {
                            let status = response.status().as_u16();
                            match response.text().await {
                                Ok(body) => {
                                    let parsed = serde_json::from_str::<Value>(&body).ok();
                                    let accepted = status == 202
                                        && parsed.as_ref().and_then(|v| v["status"].as_str())
                                            == Some("accepted_durable");
                                    let response_id = parsed
                                        .as_ref()
                                        .and_then(|v| v["tx_id"].as_str())
                                        .map(str::to_owned);
                                    (Some(status), body, accepted, response_id)
                                }
                                Err(error) => (Some(status), error.to_string(), false, None),
                            }
                        }
                        Err(error) => (None, error.to_string(), false, None),
                    };
                    TxResult {
                        offered_tps,
                        index,
                        sender,
                        submission_id: response_id.or(Some(submission_id)),
                        inclusion_hash,
                        send_time_unix_ms: sent_at,
                        scheduled_offset_ms,
                        send_offset_ms,
                        dispatch_lag_ms: send_offset_ms.saturating_sub(scheduled_offset_ms),
                        height_at_send,
                        response_time_ms,
                        http_status,
                        response: body,
                        accepted,
                        inclusion_height: None,
                        inclusion_time_unix_ms: None,
                        inclusion_latency_ms: None,
                    }
                }
            },
        )
        .buffer_unordered(max_in_flight)
        .collect::<Vec<_>>()
        .await;
    let mut results = results;
    results.sort_by_key(|result| result.index);

    let pending_count = results.iter().filter(|result| result.accepted).count();
    let deadline = Instant::now() + Duration::from_secs(settle_timeout);
    let mut last_scanned_height = height_at_start;
    while Instant::now() < deadline
        && results
            .iter()
            .filter(|result| result.inclusion_height.is_some())
            .count()
            < pending_count
    {
        let tip = latest_height.load(Ordering::Relaxed);
        while last_scanned_height < tip {
            last_scanned_height += 1;
            let response = client
                .get(format!("{rpc}/rpc/explorer/block/{last_scanned_height}"))
                .send()
                .await;
            let Ok(response) = response else {
                last_scanned_height -= 1;
                break;
            };
            let Ok(block) = response_json(response, "block inclusion lookup").await else {
                last_scanned_height -= 1;
                break;
            };
            let Some(txs) = block["transactions"].as_array() else {
                last_scanned_height -= 1;
                break;
            };
            let hashes: HashMap<&str, u64> = txs
                .iter()
                .filter_map(|transaction| {
                    Some((
                        transaction["hash"].as_str()?,
                        transaction["block_height"].as_u64()?,
                    ))
                })
                .collect();
            let included_at = now_ms();
            for result in results
                .iter_mut()
                .filter(|result| result.accepted && result.inclusion_height.is_none())
            {
                if let Some(height) = hashes.get(result.inclusion_hash.as_str()) {
                    result.inclusion_height = Some(*height);
                    result.inclusion_time_unix_ms = Some(included_at);
                    result.inclusion_latency_ms =
                        Some(included_at.saturating_sub(result.send_time_unix_ms));
                }
            }
        }
        if results
            .iter()
            .filter(|result| result.inclusion_height.is_some())
            .count()
            < pending_count
        {
            sleep(Duration::from_millis(200)).await;
        }
    }
    let _ = stop_monitor.send(());
    let _ = monitor.await;

    let attempted = results.len();
    let accepted = results.iter().filter(|result| result.accepted).count();
    let rejected = results
        .iter()
        .filter(|result| result.http_status.is_some() && !result.accepted)
        .count();
    let transport_errors = results
        .iter()
        .filter(|result| result.http_status.is_none())
        .count();
    let latencies: Vec<u128> = results
        .iter()
        .filter_map(|result| result.inclusion_latency_ms)
        .collect();
    let mut p50_values = latencies.clone();
    let mut p99_values = latencies;
    let mut dispatch_lag_values = results
        .iter()
        .map(|result| result.dispatch_lag_ms)
        .collect::<Vec<_>>();
    let included = results
        .iter()
        .filter(|result| result.inclusion_height.is_some())
        .count();
    let summary = Summary {
        offered_tps,
        attempted,
        accepted,
        rejected,
        transport_errors,
        included,
        not_included: accepted - included,
        p50_ms: percentile(&mut p50_values, 50),
        p99_ms: percentile(&mut p99_values, 99),
        p99_dispatch_lag_ms: percentile(&mut dispatch_lag_values, 99),
        observed_tps: included as f64 / duration_secs as f64,
    };
    Ok((results, summary))
}

fn output_paths() -> (PathBuf, PathBuf) {
    let stamp = now_ms();
    (
        PathBuf::from(env(
            "BLEEP_TPS_RESULTS",
            &format!("tps-results-{stamp}.jsonl"),
        )),
        PathBuf::from(env(
            "BLEEP_TPS_SUMMARY",
            &format!("tps-summary-{stamp}.csv"),
        )),
    )
}

fn summary_csv(summaries: &[Summary]) -> String {
    let knee = summaries.iter().find(|summary| {
        summary.observed_tps < summary.offered_tps as f64 * 0.9
            || summary.rejected as f64 / summary.attempted as f64 > 0.01
            || summary.transport_errors as f64 / summary.attempted as f64 > 0.01
    });
    let mut csv = String::from(
        "offered_tps,attempted,accepted,rejected,rejection_rate_percent,transport_errors,included,not_included,observed_tps,p50_inclusion_ms,p99_inclusion_ms,p99_dispatch_lag_ms,knee_candidate\n",
    );
    for summary in summaries {
        let rejection_rate = summary.rejected as f64 * 100.0 / summary.attempted as f64;
        let is_knee = knee.is_some_and(|candidate| candidate.offered_tps == summary.offered_tps);
        csv.push_str(&format!(
            "{},{},{},{},{:.2},{},{},{},{:.2},{},{},{},{}\n",
            summary.offered_tps,
            summary.attempted,
            summary.accepted,
            summary.rejected,
            rejection_rate,
            summary.transport_errors,
            summary.included,
            summary.not_included,
            summary.observed_tps,
            summary
                .p50_ms
                .map_or_else(|| "n/a".into(), |v| v.to_string()),
            summary
                .p99_ms
                .map_or_else(|| "n/a".into(), |v| v.to_string()),
            summary
                .p99_dispatch_lag_ms
                .map_or_else(|| "n/a".into(), |v| v.to_string()),
            is_knee
        ));
    }
    csv
}

#[tokio::main]
async fn main() -> Result<()> {
    let rpc = env("BLEEP_RPC", "http://127.0.0.1:8545")
        .trim_end_matches('/')
        .to_string();
    let sender_file = PathBuf::from(required_env("BLEEP_TPS_SENDERS")?);
    let sender_count = parse_positive::<usize>(
        "BLEEP_TPS_SENDER_COUNT",
        &env("BLEEP_TPS_SENDER_COUNT", "500"),
    )?;
    let duration_secs = parse_positive::<u64>(
        "BLEEP_TPS_DURATION_SECS",
        &env("BLEEP_TPS_DURATION_SECS", "5"),
    )?;
    let amount = parse_positive::<u64>("BLEEP_TPS_AMOUNT", &env("BLEEP_TPS_AMOUNT", "1"))?;
    let settle_timeout = parse_positive::<u64>(
        "BLEEP_TPS_SETTLE_TIMEOUT",
        &env("BLEEP_TPS_SETTLE_TIMEOUT", "120"),
    )?;
    let offered_loads = env("BLEEP_TPS_SWEEP", "10,50,100,300,1000")
        .split(',')
        .map(|rate| parse_positive::<u64>("BLEEP_TPS_SWEEP entry", rate.trim()))
        .collect::<Result<Vec<_>>>()?;
    let chain_id = env("BLEEP_CHAIN_ID", bleep_crypto::DEFAULT_CHAIN_ID);
    let senders = load_senders(&sender_file, sender_count)?;

    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(20))
        .pool_max_idle_per_host(2_048)
        .build()
        .context("failed creating HTTP client")?;
    let token = admin_dapp_token(&client, &rpc).await?;
    let (results_path, summary_path) = output_paths();
    fs::write(&results_path, "")
        .with_context(|| format!("failed initializing {}", results_path.display()))?;
    let mut summaries = Vec::new();
    for offered_tps in offered_loads {
        println!(
            "Preparing {} transactions at {} offered TPS ({}s run; pre-signing offline)...",
            offered_tps.saturating_mul(duration_secs),
            offered_tps,
            duration_secs
        );
        let (results, summary) = run_load(
            &client,
            &rpc,
            &token,
            offered_tps,
            duration_secs,
            amount,
            &chain_id,
            &senders,
            settle_timeout,
        )
        .await
        .with_context(|| format!("{} TPS run failed", offered_tps))?;
        println!(
            "{:>5} TPS offered | accepted={} rejected={} transport_errors={} included={} missing={} | observed={:.1} TPS | p50={}ms p99={}ms dispatch_p99={}ms",
            summary.offered_tps,
            summary.accepted,
            summary.rejected,
            summary.transport_errors,
            summary.included,
            summary.not_included,
            summary.observed_tps,
            summary.p50_ms.map_or_else(|| "n/a".into(), |v| v.to_string()),
            summary.p99_ms.map_or_else(|| "n/a".into(), |v| v.to_string()),
            summary
                .p99_dispatch_lag_ms
                .map_or_else(|| "n/a".into(), |v| v.to_string())
        );
        let mut results_file = fs::OpenOptions::new()
            .append(true)
            .open(&results_path)
            .with_context(|| format!("failed opening {}", results_path.display()))?;
        for result in &results {
            serde_json::to_writer(&mut results_file, result)
                .context("failed serializing per-transaction result")?;
            results_file
                .write_all(b"\n")
                .context("failed writing per-transaction result")?;
        }
        summaries.push(summary);
        fs::write(&summary_path, summary_csv(&summaries))
            .with_context(|| format!("failed writing {}", summary_path.display()))?;
    }

    let knee = summaries.iter().find(|summary| {
        summary.observed_tps < summary.offered_tps as f64 * 0.9
            || summary.rejected as f64 / summary.attempted as f64 > 0.01
            || summary.transport_errors as f64 / summary.attempted as f64 > 0.01
    });
    println!("Per-transaction data: {}", results_path.display());
    println!("Sweep summary: {}", summary_path.display());
    if let Some(knee) = knee {
        println!(
            "Knee candidate: {} offered TPS (first load below 90% observed throughput, above 1% rejection, or above 1% transport errors).",
            knee.offered_tps
        );
        println!("Profile the node during this run to identify the limiting subsystem.");
    } else {
        println!("No knee detected through the highest offered load.");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bleep_crypto::tx_signer::generate_tx_keypair;

    #[test]
    fn presigns_valid_transactions_across_distinct_senders() {
        let senders = (0..2)
            .map(|_| {
                let (public_key, secret_key) = generate_tx_keypair();
                Sender {
                    address: bleep_crypto::derive_account_address(&public_key),
                    public_key,
                    secret_key,
                }
            })
            .collect::<Vec<_>>();
        let prepared = presign(
            2,
            1,
            1,
            bleep_crypto::DEFAULT_CHAIN_ID,
            &senders,
            vec![0, 0],
        )
        .expect("pre-sign transactions");
        assert_eq!(prepared.len(), 2);
        assert_ne!(prepared[0].1, prepared[1].1);
        assert_ne!(prepared[0].2, prepared[1].2);
        for (request, sender, _, inclusion_hash) in prepared {
            let transaction: Value = serde_json::from_slice(&request).expect("request JSON");
            let signature = STANDARD
                .decode(
                    transaction["signature"]
                        .as_str()
                        .expect("compact signature"),
                )
                .expect("decode signature");
            let signature_public_key = &signature[..64];
            assert_eq!(
                bleep_crypto::derive_account_address(signature_public_key),
                sender
            );
            let payload = tx_payload_v2(
                transaction["chain_id"].as_str().unwrap(),
                &sender,
                transaction["receiver"].as_str().unwrap(),
                transaction["amount"].as_u64().unwrap(),
                transaction["fee"].as_u64().unwrap(),
                transaction["timestamp"].as_u64().unwrap(),
                transaction["nonce"].as_u64().unwrap(),
            );
            assert_eq!(hex::encode(payload), inclusion_hash);
            assert!(bleep_crypto::tx_signer::verify_tx_signature(
                &payload,
                &signature[64..],
                signature_public_key
            ));
        }
    }

    #[test]
    fn percentile_uses_nearest_rank() {
        let mut values = vec![40, 10, 30, 20];
        assert_eq!(percentile(&mut values, 50), Some(20));
        assert_eq!(percentile(&mut values, 99), Some(40));
    }
}
