//! # bleep-cli — Sprint 6
//!
//! Command-line interface library for the BLEEP node.
//! Sprint 6 additions:
//!   - `validator stake`   — register as a validator by locking stake
//!   - `validator unstake` — initiate graceful exit and stake withdrawal
//!   - `validator list`    — list all active validators and their stakes
//!   - `validator status`  — show own validator status and slashing history

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "bleep-cli")]
#[command(about = "BLEEP Blockchain CLI — Sprint 6", long_about = None)]
#[command(version = "1.1.0")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Start a full BLEEP node
    StartNode,

    /// Wallet operations
    Wallet {
        #[command(subcommand)]
        action: WalletCommand,
    },

    /// Send and manage transactions
    Tx {
        #[command(subcommand)]
        action: TxCommand,
    },

    /// Validator staking operations (Sprint 6)
    Validator {
        #[command(subcommand)]
        action: ValidatorCommand,
    },

    /// AI advisory utilities
    Ai {
        #[command(subcommand)]
        task: AiCommand,
    },

    /// Governance proposals and voting
    Governance {
        #[command(subcommand)]
        task: GovernanceCommand,
    },

    /// Verify ZKPs
    Zkp { proof: String },

    /// State management
    State {
        #[command(subcommand)]
        task: StateCommand,
    },

    /// Print telemetry metrics
    Telemetry,

    /// PAT (Programmable Asset Token) tasks
    Pat {
        #[command(subcommand)]
        task: PatCommand,
    },

    /// Display node information
    Info,

    /// Blockchain operations
    Block {
        #[command(subcommand)]
        task: BlockCommand,
    },

    /// Oracle price feed operations (Sprint 7)
    Oracle {
        #[command(subcommand)]
        task: OracleCommand,
    },

    /// Tokenomics and economics queries (Sprint 7)
    Economics {
        #[command(subcommand)]
        task: EconomicsCommand,
    },

    /// Request testnet faucet funds
    Faucet {
        #[command(subcommand)]
        action: FaucetCommand,
    },
}

// ── Wallet ────────────────────────────────────────────────────────────────────

#[derive(Subcommand)]
pub enum WalletCommand {
    /// Generate a new SPHINCS+ + Kyber-1024 keypair and encrypted wallet
    Create,
    /// Query balance from /rpc/state (offline fallback to local RocksDB)
    Balance,
    /// Import from BIP-39 mnemonic (PBKDF2-HMAC-SHA512, 2048 rounds)
    Import { phrase: String },
    /// Export wallet addresses
    Export,
    /// Delete a wallet by address
    Delete { address: String },
}

// ── Transactions ──────────────────────────────────────────────────────────────

#[derive(Subcommand)]
pub enum TxCommand {
    /// Sign and broadcast a transfer transaction
    Send {
        /// Recipient BLEEP1 address
        to: String,
        /// Amount in BLEEP base units
        amount: u64,
    },
    /// Retrieve transaction history
    History,
}

// ── Validator (Sprint 6) ──────────────────────────────────────────────────────

#[derive(Subcommand)]
pub enum ValidatorCommand {
    /// Register as a validator by locking stake on-chain.
    ///
    /// Builds and broadcasts a `StakeTx` that locks `amount` BLEEP from your wallet
    /// into the validator bond contract. The node must be running and reachable at
    /// BLEEP_RPC. Your SPHINCS+ signing key is loaded from the wallet and used to
    /// authenticate the transaction.
    Stake {
        /// Amount to stake in BLEEP (minimum: 1,000 BLEEP)
        #[arg(long)]
        amount: u64,
        /// Human-readable label for this validator identity
        #[arg(long, default_value = "my-validator")]
        label: String,
    },

    /// Initiate a graceful validator exit and begin the stake unbonding period.
    ///
    /// After submitting the unstake transaction the validator enters `PendingExit`
    /// state. Stake becomes withdrawable after the unbonding period (1 epoch).
    /// The validator continues to sign blocks and earn rewards during this period.
    Unstake {
        /// Validator ID (hex prefix of public key) to unstake
        #[arg(long)]
        validator_id: String,
    },

    /// List all active validators, their stakes, and liveness scores.
    List,

    /// Show the status of your own validator (stake, slashing history, state).
    Status {
        /// Validator ID to query (defaults to the wallet's derived validator ID)
        #[arg(long)]
        validator_id: Option<String>,
    },

    /// Submit slashing evidence for a misbehaving validator.
    ///
    /// Evidence format: JSON-encoded `SlashingEvidence` (DoubleSigning | Equivocation).
    /// SPHINCS+ proofs are checked against the registered validator key. Downtime
    /// counters are rejected because they have no independently verifiable proof.
    SubmitEvidence {
        /// Path to JSON file containing SlashingEvidence
        #[arg(long)]
        evidence_file: String,
    },
}

// ── AI ────────────────────────────────────────────────────────────────────────

#[derive(Subcommand)]
pub enum AiCommand {
    Ask { prompt: String },
    Status,
}

// ── Governance ────────────────────────────────────────────────────────────────

#[derive(Subcommand)]
pub enum GovernanceCommand {
    Propose { proposal: String },
    Vote { proposal_id: u32, yes: bool },
    List,
}

// ── State ─────────────────────────────────────────────────────────────────────

#[derive(Subcommand)]
pub enum StateCommand {
    Snapshot,
    Restore { snapshot_path: String },
}

// ── PAT ───────────────────────────────────────────────────────────────────────

#[derive(Subcommand)]
pub enum PatCommand {
    Status,
    List,
    /// Create a new PAT (owner only; sets supply cap and burn rate)
    Create {
        /// Token symbol (e.g. USDB, WETH-PAT)
        #[arg(long)]
        symbol: String,
        /// Human-readable name
        #[arg(long)]
        name: String,
        /// Decimal places (default 8)
        #[arg(long, default_value = "8")]
        decimals: u8,
        /// Owner address (sole minter)
        #[arg(long)]
        owner: String,
        /// Maximum supply cap (0 = unlimited)
        #[arg(long, default_value = "0")]
        supply_cap: u128,
        /// Deflationary burn rate on transfers (basis points, max 1000)
        #[arg(long, default_value = "50")]
        burn_rate_bps: u16,
        /// Allow token transfers to be frozen by the owner
        #[arg(long, default_value = "false")]
        freezable: bool,
    },
    /// Mint new PAT tokens (owner only)
    Mint {
        /// Token symbol
        #[arg(long)]
        symbol: String,
        /// Caller / owner address (hex)
        #[arg(long)]
        from: String,
        /// Recipient address (hex)
        #[arg(long)]
        to: String,
        /// Amount to mint (base units, 8 decimal places)
        #[arg(long)]
        amount: u64,
    },
    /// Burn PAT tokens (holder burns their own tokens)
    Burn {
        /// Token symbol
        #[arg(long)]
        symbol: String,
        /// Address burning tokens (hex)
        #[arg(long)]
        from: String,
        /// Amount to burn (base units)
        #[arg(long)]
        amount: u64,
    },
    /// Transfer PAT tokens (burn_rate_bps applied automatically)
    Transfer {
        /// Token symbol
        #[arg(long)]
        symbol: String,
        /// Sender address (hex)
        #[arg(long)]
        from: String,
        /// Recipient address (hex)
        #[arg(long)]
        to: String,
        /// Amount to transfer (base units)
        #[arg(long)]
        amount: u64,
    },
    /// Approve a spender to transfer up to `amount` from caller's balance
    Approve {
        /// Token symbol
        #[arg(long)]
        symbol: String,
        /// Owner / caller address (hex)
        #[arg(long)]
        owner: String,
        /// Spender address (hex)
        #[arg(long)]
        spender: String,
        /// Approved amount (base units)
        #[arg(long)]
        amount: u64,
    },
    /// Freeze or unfreeze all transfers for a token (owner only, token must be freezable)
    Freeze {
        /// Token symbol
        #[arg(long)]
        symbol: String,
        /// Owner address (hex)
        #[arg(long)]
        owner: String,
        /// true = freeze, false = unfreeze
        #[arg(long)]
        frozen: bool,
    },
    /// Update the deflationary burn rate (owner only)
    SetBurnRate {
        /// Token symbol
        #[arg(long)]
        symbol: String,
        /// Owner address (hex)
        #[arg(long)]
        owner: String,
        /// New burn rate in basis points (0–1000)
        #[arg(long)]
        rate_bps: u16,
    },
    /// Transfer token ownership to a new address (owner only)
    SetOwner {
        /// Token symbol
        #[arg(long)]
        symbol: String,
        /// Current owner address (hex)
        #[arg(long)]
        owner: String,
        /// New owner address (hex)
        #[arg(long)]
        new_owner: String,
    },
    /// Query PAT balance for an address
    Balance {
        /// Token symbol
        #[arg(long)]
        symbol: String,
        /// Address to query (hex)
        address: String,
    },
    /// Show PAT token info (supply, burn rate, owner, frozen state)
    Info {
        /// Token symbol
        symbol: String,
    },
}

// ── Oracle ────────────────────────────────────────────────────────────────────

#[derive(Subcommand)]
pub enum OracleCommand {
    /// Query the aggregated oracle price for an asset (e.g. "BLEEP/USD")
    Price {
        /// Asset pair, e.g. BLEEP/USD
        asset: String,
    },
    /// Submit a price update as an oracle operator
    Submit {
        /// Asset pair
        #[arg(long)]
        asset: String,
        /// Price in micro-units (6 decimals for USD)
        #[arg(long)]
        price: u128,
        /// Confidence in basis points (e.g. 100 = 1%)
        #[arg(long, default_value = "100")]
        confidence_bps: u16,
        /// Operator ID (hex-encoded public key)
        #[arg(long)]
        operator_id: String,
    },
}

// ── Economics ─────────────────────────────────────────────────────────────────

#[derive(Subcommand)]
pub enum EconomicsCommand {
    /// Show current token supply (circulating, minted, burned)
    Supply,
    /// Show current base fee
    Fee,
    /// Show epoch economics output
    Epoch {
        /// Epoch number to query
        epoch: u64,
    },
}

// ── Faucet ────────────────────────────────────────────────────────────────────

#[derive(Subcommand)]
pub enum FaucetCommand {
    /// Request faucet funds for an address
    Request {
        /// Address to fund
        address: String,
    },
    /// Check faucet status
    Status,
}

// ── Block ─────────────────────────────────────────────────────────────────────

#[derive(Subcommand)]
pub enum BlockCommand {
    /// Print the latest block
    Latest,
    /// Get a block by hash or height
    Get { identifier: String },
    /// Validate a block by hash
    Validate { hash: String },
}
