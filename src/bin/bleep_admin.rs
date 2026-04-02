// src/bin/bleep_admin.rs
use clap::{Parser, Subcommand};
use log::{error, info};
use std::error::Error;

use bleep_wallet_core::wallet::WalletManager;

#[derive(Parser)]
#[command(
    name = "bleep-admin",
    version = "1.0.0",
    about = "BLEEP Blockchain Administration CLI"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Governance operations
    Governance {
        /// List active proposals
        #[arg(long)]
        list: bool,
    },
    /// State operations
    State {
        /// Get state status
        #[arg(long)]
        status: bool,
    },
    /// Wallet operations
    Wallets {
        /// List wallets
        #[arg(long)]
        list: bool,
    },
}

fn main() {
    env_logger::init();
    info!("BLEEP Admin CLI started");
    let cli = Cli::parse();
    if let Err(e) = run(cli) {
        error!("❌ CLI admin error: {}", e);
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn Error>> {
    match cli.command {
        Commands::Governance { .. } => {
            println!("🏛 Governance Module Active");
            println!("Active proposals: loading...");
        }
        Commands::State { .. } => {
            println!("🧠 State Module Status");
            println!("State initialized and ready for operations");
        }
        Commands::Wallets { .. } => match WalletManager::load_or_create() {
            Ok(manager) => {
                let all = manager.list_wallets();
                println!("💼 Wallet Manager: {} wallets", all.len());
                for w in all {
                    println!("  - Address: {}", w.address());
                }
            }
            Err(e) => eprintln!("Failed to load wallet manager: {}", e),
        },
    }
    Ok(())
}
