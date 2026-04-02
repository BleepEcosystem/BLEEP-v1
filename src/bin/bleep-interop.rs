// src/bin/bleep_interop.rs

use bleep_interop::interoperability::BLEEPInteroperabilityModule;
use log::info;

fn main() {
    env_logger::init();
    info!("🌉 BLEEP Interop Engine Starting...");

    // Example: Initialize the interoperability module and register adapters
    let mut module = BLEEPInteroperabilityModule::new();
    module.register_adapter(
        "ethereum".into(),
        Box::new(bleep_interop::interoperability::EthereumAdapter::new(
            bleep_interop::ChainId::Ethereum,
        )),
    );
    module.register_adapter(
        "binance".into(),
        Box::new(bleep_interop::interoperability::BinanceAdapter),
    );
    module.register_adapter(
        "cosmos".into(),
        Box::new(bleep_interop::interoperability::CosmosAdapter::default_cosmos()),
    );
    module.register_adapter(
        "polkadot".into(),
        Box::new(bleep_interop::interoperability::PolkadotAdapter),
    );
    module.register_adapter(
        "solana".into(),
        Box::new(bleep_interop::interoperability::SolanaAdapter),
    );

    info!("✅ Interop module initialized with adapters.");
    // Further logic would go here, e.g., cross-chain sync, etc.
}
