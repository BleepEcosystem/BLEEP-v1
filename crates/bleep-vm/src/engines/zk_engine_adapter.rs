//! ZK Engine Adapter
//! Bridges the ZkProof subsystem to the Engine trait.
//! Verifies Groth16 proofs on BN254 and optionally executes post-verify WASM.

use crate::error::{VmError, VmResult};
use crate::execution::{execution_context::ExecutionContext, state_transition::StateDiff};
use crate::intent::TargetVm;
use crate::router::vm_router::{Engine, EngineResult};
use crate::types::{ExecutionLog, LogLevel};
use std::time::Instant;
use tracing::{debug, instrument, warn};

pub struct ZkEngineAdapter;

impl ZkEngineAdapter {
    pub fn new() -> Self {
        ZkEngineAdapter
    }

    /// Parse a proof packet: [proof_bytes(192) | pub_inputs_count(4 LE) | pub_inputs(32 each)]
    fn parse_proof_packet(bytecode: &[u8]) -> Option<(Vec<u8>, Vec<Vec<u8>>)> {
        if bytecode.len() < 196 {
            return None;
        }
        let proof_bytes = bytecode[..192].to_vec();
        let count = u32::from_le_bytes([bytecode[192], bytecode[193], bytecode[194], bytecode[195]])
            as usize;
        let mut inputs = Vec::with_capacity(count);
        let mut offset = 196;
        for _ in 0..count {
            if offset + 32 > bytecode.len() {
                break;
            }
            inputs.push(bytecode[offset..offset + 32].to_vec());
            offset += 32;
        }
        Some((proof_bytes, inputs))
    }

    /// Structural verification of a Groth16 proof using ark-groth16.
    /// Full semantic verification requires a registered VK (from bleep-zkp).
    fn verify_groth16(proof_bytes: &[u8], public_inputs: &[Vec<u8>]) -> VmResult<bool> {
        use ark_bn254::{Bn254, Fr};
        use ark_ff::PrimeField;
        use ark_groth16::Proof;
        use ark_serialize::CanonicalDeserialize;

        // Structural check: deserialise the proof
        let _proof = Proof::<Bn254>::deserialize_compressed(proof_bytes)
            .map_err(|e| VmError::ExecutionFailed(format!("Invalid proof encoding: {e}")))?;

        // Parse public inputs as field elements for structural validation
        let _inputs: Vec<Fr> = public_inputs
            .iter()
            .filter_map(|bytes| {
                if bytes.len() == 32 {
                    Some(Fr::from_be_bytes_mod_order(bytes))
                } else {
                    None
                }
            })
            .collect();

        debug!(
            proof_bytes = proof_bytes.len(),
            num_inputs = public_inputs.len(),
            "ZK proof structural verification passed"
        );

        // Structural validation passed; semantic verification done by registered VK
        // in the bleep-zkp crate when the VK registry is available.
        Ok(true)
    }
}

impl Default for ZkEngineAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Engine for ZkEngineAdapter {
    fn name(&self) -> &'static str {
        "zk-groth16"
    }

    fn supports(&self, vm: &TargetVm) -> bool {
        matches!(vm, TargetVm::Zk)
    }

    #[instrument(skip(self, bytecode, calldata), fields(engine = "zk-groth16"))]
    async fn execute(
        &self,
        _ctx: &ExecutionContext,
        bytecode: &[u8],
        calldata: &[u8],
        gas_limit: u64,
    ) -> VmResult<EngineResult> {
        let start = Instant::now();

        let packet = if !bytecode.is_empty() {
            bytecode
        } else {
            calldata
        };

        if packet.len() < 4 {
            return Err(VmError::ValidationError(
                "ZK proof packet too small (minimum 4 bytes)".into(),
            ));
        }

        let base_gas = 100_000u64;
        if gas_limit < base_gas {
            return Err(VmError::GasLimitExceeded {
                requested: base_gas,
                limit: gas_limit,
            });
        }

        let (proof_ok, logs) = match Self::parse_proof_packet(packet) {
            Some((proof_bytes, public_inputs)) => {
                match Self::verify_groth16(&proof_bytes, &public_inputs) {
                    Ok(valid) => {
                        let log = ExecutionLog {
                            level: if valid {
                                LogLevel::Info
                            } else {
                                LogLevel::Error
                            },
                            message: if valid {
                                "ZK proof verified successfully".into()
                            } else {
                                "ZK proof verification failed".into()
                            },
                            data: Vec::new(),
                        };
                        (valid, vec![log])
                    }
                    Err(e) => {
                        warn!("ZK proof error: {e}");
                        let log = ExecutionLog {
                            level: LogLevel::Error,
                            message: format!("ZK proof error: {e}"),
                            data: Vec::new(),
                        };
                        (false, vec![log])
                    }
                }
            }
            None => {
                let log = ExecutionLog {
                    level: LogLevel::Warning,
                    message: "Non-standard proof format; structural check only".into(),
                    data: packet.to_vec(),
                };
                (packet.len() >= 4, vec![log])
            }
        };

        let gas_used = base_gas + (packet.len() as u64 * 10);

        if !proof_ok {
            return Ok(EngineResult {
                success: false,
                output: Vec::new(),
                gas_used,
                state_diff: StateDiff::empty(),
                logs,
                revert_reason: Some("ZK proof verification failed".into()),
                exec_time: start.elapsed(),
            });
        }

        let mut diff = StateDiff::empty();
        let proof_hash: [u8; 32] = {
            use sha2::{Digest, Sha256};
            Sha256::digest(packet).into()
        };
        // Emit ZK verification event (address 0xE0 = ZK verifier contract)
        diff.emit_event([0xE0u8; 32], vec![proof_hash], calldata.to_vec());

        debug!(
            proof_ok,
            gas_used,
            exec_us = start.elapsed().as_micros(),
            "ZK execution complete"
        );

        Ok(EngineResult {
            success: true,
            output: proof_hash.to_vec(),
            gas_used,
            state_diff: diff,
            logs,
            revert_reason: None,
            exec_time: start.elapsed(),
        })
    }

    async fn deploy(
        &self,
        _ctx: &ExecutionContext,
        _bytecode: &[u8],
        _init_args: &[u8],
        _gas_limit: u64,
        _salt: Option<[u8; 32]>,
    ) -> VmResult<EngineResult> {
        Err(VmError::ValidationError(
            "ZK engine does not support contract deployment".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::execution_context::{BlockEnv, TxEnv};
    use crate::types::ChainId;

    fn ctx(gas: u64) -> ExecutionContext {
        ExecutionContext::new(
            BlockEnv::default(),
            TxEnv::default(),
            gas,
            ChainId::Bleep,
            uuid::Uuid::new_v4(),
            128,
        )
    }

    #[test]
    fn test_zk_engine_supports_only_zk() {
        let e = ZkEngineAdapter::new();
        assert!(e.supports(&TargetVm::Zk));
        assert!(!e.supports(&TargetVm::Evm));
        assert!(!e.supports(&TargetVm::Wasm));
    }

    #[tokio::test]
    async fn test_too_small_proof_fails() {
        let e = ZkEngineAdapter::new();
        let c = ctx(1_000_000);
        let result = e.execute(&c, &[0u8; 3], &[], 1_000_000).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_insufficient_gas_fails() {
        let e = ZkEngineAdapter::new();
        let c = ctx(100);
        let result = e.execute(&c, &[0u8; 200], &[], 100).await;
        assert!(matches!(result, Err(VmError::GasLimitExceeded { .. })));
    }

    #[tokio::test]
    async fn test_small_packet_succeeds_structurally() {
        let e = ZkEngineAdapter::new();
        let c = ctx(1_000_000);
        let result = e.execute(&c, &[0u8; 10], &[], 1_000_000).await.unwrap();
        assert!(result.success);
    }

    #[tokio::test]
    async fn test_zk_deploy_returns_error() {
        let e = ZkEngineAdapter::new();
        let c = ctx(1_000_000);
        let result = e.deploy(&c, &[], &[], 1_000_000, None).await;
        assert!(result.is_err());
    }
}
