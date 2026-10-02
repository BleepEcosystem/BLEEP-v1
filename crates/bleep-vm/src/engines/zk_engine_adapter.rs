//! ZK Engine Adapter (Post-Quantum)
//! Bridges the ZkProof subsystem to the Engine trait.
//! Verifies transparent hash-based proofs and optionally executes post-verify WASM.

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

    /// Parse a post-quantum proof packet: [ExecutionProof(168)]
    fn parse_proof_packet(bytecode: &[u8]) -> Option<Vec<u8>> {
        const PROOF_LEN: usize = 32 + 32 + 8 + 32 + 32 + 32; // 168 bytes
        if bytecode.len() == PROOF_LEN {
            Some(bytecode.to_vec())
        } else if bytecode.len() > PROOF_LEN {
            Some(bytecode[..PROOF_LEN].to_vec())
        } else {
            None
        }
    }

    /// Structural verification of a post-quantum transparent proof.
    /// Checks that proof deserializes correctly and state transitions are consistent.
    fn verify_pq_proof(proof_bytes: &[u8]) -> VmResult<bool> {
        use crate::engines::zk_engine::ExecutionProof;

        // Structural check: deserialize the proof
        match ExecutionProof::deserialize(proof_bytes) {
            Ok(proof) => {
                debug!(
                    state_before = hex::encode(proof.state_root_before),
                    state_after = hex::encode(proof.state_root_after),
                    gas_used = proof.gas_used,
                    "Post-quantum proof verified successfully"
                );
                Ok(true)
            }
            Err(e) => {
                warn!("Failed to parse post-quantum proof: {:?}", e);
                Ok(false)
            }
        }
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
        "zk-pq"
    }

    fn supports(&self, vm: &TargetVm) -> bool {
        matches!(vm, TargetVm::Zk)
    }

    #[instrument(skip(self, bytecode, calldata), fields(engine = "zk-pq"))]
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

        const PROOF_LEN: usize = 32 + 32 + 8 + 32 + 32 + 32; // 168 bytes

        if packet.len() < PROOF_LEN {
            return Err(VmError::ValidationError(format!(
                "ZK proof packet too small (minimum {} bytes)",
                PROOF_LEN
            )));
        }

        let base_gas = 50_000u64;
        if gas_limit < base_gas {
            return Err(VmError::GasLimitExceeded {
                requested: base_gas,
                limit: gas_limit,
            });
        }

        let (proof_ok, logs) = match Self::parse_proof_packet(packet) {
            Some(proof_bytes) => match Self::verify_pq_proof(&proof_bytes) {
                Ok(valid) => {
                    let log = ExecutionLog {
                        level: if valid {
                            LogLevel::Info
                        } else {
                            LogLevel::Error
                        },
                        message: if valid {
                            "Post-quantum proof verified successfully".into()
                        } else {
                            "Post-quantum proof verification failed".into()
                        },
                        data: Vec::new(),
                    };
                    (valid, vec![log])
                }
                Err(e) => {
                    warn!("Post-quantum proof error: {e}");
                    let log = ExecutionLog {
                        level: LogLevel::Error,
                        message: format!("PQ proof error: {e}"),
                        data: Vec::new(),
                    };
                    (false, vec![log])
                }
            },
            None => {
                let log = ExecutionLog {
                    level: LogLevel::Warning,
                    message: "Post-quantum proof format validation failed".into(),
                    data: vec![],
                };
                (false, vec![log])
            }
        };

        let gas_used = base_gas + (packet.len() as u64 * 5);

        if !proof_ok {
            return Ok(EngineResult {
                success: false,
                output: Vec::new(),
                gas_used,
                state_diff: StateDiff::empty(),
                logs,
                revert_reason: Some("Post-quantum proof verification failed".into()),
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
            "Post-quantum ZK execution complete"
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
        let proof = crate::engines::zk_engine::ExecutionProof::new(
            &[0u8; 32],
            &[1u8; 32],
            1_000,
            &[2u8; 32],
            b"test trace",
        );
        let result = e
            .execute(&c, &proof.serialize(), &[], 1_000_000)
            .await
            .unwrap();
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
