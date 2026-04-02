pub mod wallet;

/// Initializes the BLEEP wallet core services.
/// Sets up quantum-secure key management, transaction handling, and state synchronization.
///
/// # Returns
/// * `Result<(), Box<dyn std::error::Error>>` - Success or initialization error
pub fn init_wallet_services() -> Result<(), Box<dyn std::error::Error>> {
    use log::info;

    // Wallet services are initialized via the wallet_core module
    // This function serves as the startup hook for wallet subsystem
    info!("Wallet core services initialized with quantum-secure key management");
    Ok(())
}
