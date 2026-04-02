//! # Layer 6 — Gas Model
//!
//! **All engines emit gas in their native units.**
//! The `GasModel` normalises everything to BLEEP gas units before
//! charging the caller and enforcing limits.
//!
//! Without normalisation, attackers could exploit cheaper VMs:
//! a WASM instruction costing 1 WASM-gas might do the same work
//! as an EVM opcode costing 3 EVM-gas — enabling DoS.
//!
//! ## Conversion table (approximate)
//! | VM        | 1 BLEEP gas = N native gas |
//! |-----------|---------------------------|
//! | EVM       | 1.0× (EVM is the baseline)|
//! | WASM      | 2.5× (WASM ops are cheaper)|
//! | SBF       | 3.0× (Solana ops very cheap)|
//! | Move      | 2.0× (Move gas is different)|
//! | ZK        | 0.1× (ZK gas is expensive)|

use crate::intent::TargetVm;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// GAS PARAMETERS
// ─────────────────────────────────────────────────────────────────────────────

/// Per-VM normalisation factor.
/// `bleep_gas = native_gas / factor`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmGasParams {
    /// Name of the VM (for debugging).
    pub name: &'static str,
    /// Native gas per BLEEP gas unit.
    /// A factor of 2.5 means 1 BLEEP gas = 2.5 WASM gas.
    pub native_per_bleep: f64,
    /// Minimum gas charge for any execution (prevents DoS via tiny calls).
    pub minimum_charge: u64,
    /// Maximum gas refund fraction (e.g. 0.2 = up to 20% refund).
    pub max_refund_pct: f64,
}

impl VmGasParams {
    pub fn bleep_from_native(&self, native: u64) -> u64 {
        let converted = (native as f64 / self.native_per_bleep).ceil() as u64;
        converted.max(self.minimum_charge)
    }

    pub fn native_from_bleep(&self, bleep: u64) -> u64 {
        (bleep as f64 * self.native_per_bleep).ceil() as u64
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GAS MODEL
// ─────────────────────────────────────────────────────────────────────────────

/// Unified gas model for all BLEEP VM engines.
#[derive(Debug, Clone)]
pub struct GasModel {
    /// Per-VM conversion parameters.
    params: HashMap<String, VmGasParams>,
    /// Global gas price in wei (used for fee calculation).
    #[allow(dead_code)]
    base_gas_price: u64,
}

impl Default for GasModel {
    fn default() -> Self {
        let mut params = HashMap::new();

        // EVM is the baseline: 1 EVM gas = 1 BLEEP gas
        params.insert(
            "evm".into(),
            VmGasParams {
                name: "EVM (revm)",
                native_per_bleep: 1.0,
                minimum_charge: 21_000,
                max_refund_pct: 0.20,
            },
        );

        // WASM is ~2.5× cheaper per instruction than EVM
        params.insert(
            "wasm".into(),
            VmGasParams {
                name: "WASM",
                native_per_bleep: 2.5,
                minimum_charge: 5_000,
                max_refund_pct: 0.10,
            },
        );

        // Solana SBF is very cheap per instruction
        params.insert(
            "sbf".into(),
            VmGasParams {
                name: "Solana SBF",
                native_per_bleep: 3.0,
                minimum_charge: 5_000,
                max_refund_pct: 0.05,
            },
        );

        // Move gas schedule is different but comparable to EVM
        params.insert(
            "move".into(),
            VmGasParams {
                name: "Move VM",
                native_per_bleep: 2.0,
                minimum_charge: 5_000,
                max_refund_pct: 0.10,
            },
        );

        // ZK proofs are extremely expensive
        params.insert(
            "zk".into(),
            VmGasParams {
                name: "ZK Engine",
                native_per_bleep: 0.1,
                minimum_charge: 100_000,
                max_refund_pct: 0.0,
            },
        );

        // CosmWasm (treated same as WASM)
        params.insert(
            "cosmwasm".into(),
            VmGasParams {
                name: "CosmWasm",
                native_per_bleep: 2.5,
                minimum_charge: 5_000,
                max_refund_pct: 0.10,
            },
        );

        GasModel {
            params,
            base_gas_price: 1_000_000_000, // 1 Gwei
        }
    }
}

impl GasModel {
    /// Normalise `native_gas` from engine `vm` to BLEEP gas units.
    pub fn normalise(&self, native_gas: u64, vm: &TargetVm) -> u64 {
        let key = vm_to_key(vm);
        if let Some(p) = self.params.get(key) {
            p.bleep_from_native(native_gas)
        } else {
            // Unknown VM: 1:1 conversion with minimum
            native_gas.max(5_000)
        }
    }

    /// Convert BLEEP gas limit to native gas limit for a given engine.
    pub fn to_native(&self, bleep_gas: u64, vm: &TargetVm) -> u64 {
        let key = vm_to_key(vm);
        if let Some(p) = self.params.get(key) {
            p.native_from_bleep(bleep_gas)
        } else {
            bleep_gas
        }
    }

    /// Calculate fee in wei for a given BLEEP gas amount.
    pub fn fee_wei(&self, bleep_gas: u64, gas_price: u64) -> u128 {
        (bleep_gas as u128) * (gas_price as u128)
    }

    /// Apply gas refund (Berlin-compatible: capped at 20% of used gas).
    pub fn apply_refund(&self, used: u64, refund: u64, vm: &TargetVm) -> u64 {
        let key = vm_to_key(vm);
        let max_pct = self.params.get(key).map_or(0.20, |p| p.max_refund_pct);
        let max_refund = (used as f64 * max_pct) as u64;
        used.saturating_sub(refund.min(max_refund))
    }

    /// Gas schedule for storage operations (EVM-aligned).
    pub fn storage_write_gas(&self) -> u64 {
        20_000
    }
    pub fn storage_read_gas(&self) -> u64 {
        2_100
    } // EIP-2929 cold read
    pub fn event_base_gas(&self) -> u64 {
        375
    }
    pub fn event_per_topic(&self) -> u64 {
        375
    }
    pub fn event_per_byte(&self) -> u64 {
        8
    }
    pub fn keccak256_base(&self) -> u64 {
        30
    }
    pub fn keccak256_per_word(&self) -> u64 {
        6
    }
    pub fn sha256_base(&self) -> u64 {
        60
    }
    pub fn sha256_per_word(&self) -> u64 {
        12
    }
    pub fn cross_call_base(&self) -> u64 {
        2_000
    }
    pub fn cross_chain_base(&self) -> u64 {
        50_000
    }
    pub fn zk_verify_base(&self) -> u64 {
        100_000
    }
}

fn vm_to_key(vm: &TargetVm) -> &'static str {
    match vm {
        TargetVm::Evm => "evm",
        TargetVm::Wasm => "wasm",
        TargetVm::SolanaSbf => "sbf",
        TargetVm::Move => "move",
        TargetVm::Zk => "zk",
        TargetVm::Auto => "wasm",
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GAS ESTIMATION
// ─────────────────────────────────────────────────────────────────────────────

/// Static gas estimator — estimates BLEEP gas cost without executing.
pub struct GasEstimator<'a> {
    model: &'a GasModel,
}

impl<'a> GasEstimator<'a> {
    pub fn new(model: &'a GasModel) -> Self {
        Self { model }
    }

    /// Estimate gas for a contract call based on calldata size.
    /// This is a conservative upper bound; actual usage may be lower.
    pub fn estimate_call(&self, calldata: &[u8], vm: &TargetVm) -> u64 {
        let base = match vm {
            TargetVm::Evm => 21_000,
            TargetVm::Wasm | TargetVm::Auto => 5_000,
            TargetVm::SolanaSbf => 5_000,
            TargetVm::Move => 5_000,
            TargetVm::Zk => 100_000,
        };
        // 4 gas per zero byte, 16 gas per non-zero byte (EIP-2028)
        let calldata_cost: u64 = calldata.iter().map(|&b| if b == 0 { 4 } else { 16 }).sum();
        self.model.normalise(base + calldata_cost, vm)
    }

    /// Estimate gas for deploying `bytecode`.
    pub fn estimate_deploy(&self, bytecode: &[u8], vm: &TargetVm) -> u64 {
        let base = 32_000u64; // CREATE base cost
        let code_cost = bytecode.len() as u64 * 200; // 200 gas/byte for code deposit
        self.model.normalise(base + code_cost, vm)
    }

    /// Estimate gas for a value transfer.
    pub fn estimate_transfer(&self) -> u64 {
        21_000
    }

    /// Estimate gas for ZK proof verification.
    pub fn estimate_zk_verify(&self, proof_len: usize) -> u64 {
        let base = 100_000u64;
        let len_cost = proof_len as u64 * 10;
        self.model.normalise(base + len_cost, &TargetVm::Zk)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TESTS
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evm_gas_is_one_to_one() {
        let model = GasModel::default();
        assert_eq!(model.normalise(21_000, &TargetVm::Evm), 21_000);
        assert_eq!(model.normalise(100_000, &TargetVm::Evm), 100_000);
    }

    #[test]
    fn test_wasm_gas_cheaper_than_evm() {
        let model = GasModel::default();
        // 250_000 WASM gas / 2.5 = 100_000 BLEEP gas
        let bleep = model.normalise(250_000, &TargetVm::Wasm);
        assert_eq!(bleep, 100_000);
    }

    #[test]
    fn test_sbf_gas_cheapest() {
        let model = GasModel::default();
        // 300_000 SBF gas / 3.0 = 100_000 BLEEP gas
        let bleep = model.normalise(300_000, &TargetVm::SolanaSbf);
        assert_eq!(bleep, 100_000);
    }

    #[test]
    fn test_zk_gas_expensive() {
        let model = GasModel::default();
        // 100_000 ZK native / 0.1 = 1_000_000 BLEEP gas
        let bleep = model.normalise(100_000, &TargetVm::Zk);
        assert_eq!(bleep, 1_000_000);
    }

    #[test]
    fn test_minimum_charge_enforced() {
        let model = GasModel::default();
        // Even 0 EVM gas gets charged the minimum
        assert_eq!(model.normalise(0, &TargetVm::Evm), 21_000);
        assert_eq!(model.normalise(0, &TargetVm::Wasm), 5_000);
    }

    #[test]
    fn test_fee_calculation() {
        let model = GasModel::default();
        let fee = model.fee_wei(21_000, 1_000_000_000); // 21k gas at 1 Gwei
        assert_eq!(fee, 21_000_000_000_000u128); // 0.000021 ETH
    }

    #[test]
    fn test_refund_capped_at_20_pct_evm() {
        let model = GasModel::default();
        let used = 100_000u64;
        let refund = 30_000u64; // 30% refund requested
                                // Max refund is 20% of used = 20_000
        let after_refund = model.apply_refund(used, refund, &TargetVm::Evm);
        assert_eq!(after_refund, 80_000); // 100_000 - 20_000
    }

    #[test]
    fn test_to_native_conversion() {
        let model = GasModel::default();
        // 100_000 BLEEP gas → 250_000 WASM gas
        let native = model.to_native(100_000, &TargetVm::Wasm);
        assert_eq!(native, 250_000);
    }

    #[test]
    fn test_estimator_call() {
        let model = GasModel::default();
        let estimator = GasEstimator::new(&model);
        let calldata = vec![0x00u8, 0xFF, 0xAB, 0x00];
        let gas = estimator.estimate_call(&calldata, &TargetVm::Evm);
        // base 21_000 + (2*4 + 2*16) = 21_040, normalised 1:1 for EVM
        assert_eq!(gas, 21_040);
    }

    #[test]
    fn test_estimator_deploy() {
        let model = GasModel::default();
        let estimator = GasEstimator::new(&model);
        let bytecode = vec![0u8; 100]; // 100 bytes
        let gas = estimator.estimate_deploy(&bytecode, &TargetVm::Evm);
        // 32_000 + 100*200 = 52_000 EVM gas = 52_000 BLEEP gas
        assert_eq!(gas, 52_000);
    }

    #[test]
    fn test_storage_gas_constants() {
        let model = GasModel::default();
        assert_eq!(model.storage_write_gas(), 20_000);
        assert_eq!(model.storage_read_gas(), 2_100);
        assert_eq!(model.cross_chain_base(), 50_000);
    }
}
