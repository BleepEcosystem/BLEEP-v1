//! # Execution Context
//!
//! `ExecutionContext` is created by the router for each intent and
//! threaded through the entire engine execution path.
//! It carries block metadata, caller identity, gas accounting state,
//! and the mutable call stack — everything an engine needs that is
//! *not* part of persistent state.

use crate::intent::{Intent, IntentKind};
use crate::types::ChainId;
use serde::{Deserialize, Serialize};
use std::time::Instant;

// ─────────────────────────────────────────────────────────────────────────────
// BLOCK ENVIRONMENT
// ─────────────────────────────────────────────────────────────────────────────

/// Block-level metadata injected by the node for each block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockEnv {
    pub number: u64,
    pub timestamp: u64,
    pub gas_limit: u64,
    pub coinbase: [u8; 32],
    pub difficulty: [u8; 32],
    pub base_fee: u64,
    pub chain_id: u64,
}

impl Default for BlockEnv {
    fn default() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        BlockEnv {
            number: 1,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            gas_limit: 30_000_000,
            coinbase: [0u8; 32],
            difficulty: [0u8; 32],
            base_fee: 1_000_000_000, // 1 Gwei
            chain_id: 0xB1EE,        // 0xB1EE = BLEEP
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TRANSACTION ENVIRONMENT
// ─────────────────────────────────────────────────────────────────────────────

/// Transaction-level metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxEnv {
    /// Caller's address (32 bytes).
    pub caller: [u8; 32],
    /// Value sent with the call (in base units).
    pub value: u128,
    /// Gas price this transaction is paying.
    pub gas_price: u64,
    /// Nonce of the caller.
    pub nonce: u64,
    /// Raw calldata.
    pub calldata: Vec<u8>,
}

impl Default for TxEnv {
    fn default() -> Self {
        TxEnv {
            caller: [0u8; 32],
            value: 0,
            gas_price: 1_000_000_000,
            nonce: 0,
            calldata: Vec::new(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GAS ACCOUNTING STATE
// ─────────────────────────────────────────────────────────────────────────────

/// Live gas accounting — mutated as each opcode executes.
#[derive(Debug, Clone)]
pub struct GasState {
    pub limit: u64,
    pub used: u64,
    pub refund: u64,
}

impl GasState {
    pub fn new(limit: u64) -> Self {
        GasState {
            limit,
            used: 0,
            refund: 0,
        }
    }

    /// Attempt to consume `cost` gas. Returns `false` if out of gas.
    #[inline]
    pub fn consume(&mut self, cost: u64) -> bool {
        if self.used.saturating_add(cost) > self.limit {
            return false;
        }
        self.used += cost;
        true
    }

    pub fn remaining(&self) -> u64 {
        self.limit.saturating_sub(self.used)
    }

    pub fn is_exhausted(&self) -> bool {
        self.used >= self.limit
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EXECUTION CONTEXT
// ─────────────────────────────────────────────────────────────────────────────

/// Full context threaded through an execution.
/// Created once by the router; cloned for nested calls.
#[derive(Debug)]
pub struct ExecutionContext {
    pub block: BlockEnv,
    pub tx: TxEnv,
    pub gas: GasState,
    pub call_depth: usize,
    pub max_call_depth: usize,
    pub chain_id: ChainId,
    pub intent_id: uuid::Uuid,
    /// Wall-clock start time (not serialisable — reset on clone).
    #[allow(dead_code)]
    start_time: Instant,
}

impl ExecutionContext {
    pub fn new(
        block: BlockEnv,
        tx: TxEnv,
        gas_limit: u64,
        chain_id: ChainId,
        intent_id: uuid::Uuid,
        max_call_depth: usize,
    ) -> Self {
        ExecutionContext {
            block,
            tx,
            gas: GasState::new(gas_limit),
            call_depth: 0,
            max_call_depth,
            chain_id,
            intent_id,
            start_time: Instant::now(),
        }
    }

    /// Derive a context from an intent (uses default block/tx envs for unit tests).
    pub fn from_intent(intent: &Intent, max_call_depth: usize) -> Self {
        let gas_limit = intent.gas_limit();
        let (caller, value, calldata) = match &intent.kind {
            IntentKind::ContractCall(c) => (intent.signer, c.value, c.calldata.clone()),
            IntentKind::Deploy(d) => (intent.signer, 0, d.init_args.clone()),
            IntentKind::Transfer(t) => (t.from, t.amount, Vec::new()),
            _ => (intent.signer, 0, Vec::new()),
        };
        let tx = TxEnv {
            caller,
            value,
            calldata,
            nonce: intent.nonce,
            ..Default::default()
        };
        ExecutionContext::new(
            BlockEnv::default(),
            tx,
            gas_limit,
            intent.source_chain.clone(),
            intent.id,
            max_call_depth,
        )
    }

    /// Create a child context for a nested call (increments depth).
    pub fn child_call(
        &self,
        caller: [u8; 32],
        value: u128,
        calldata: Vec<u8>,
        gas: u64,
    ) -> Option<ExecutionContext> {
        if self.call_depth >= self.max_call_depth {
            return None;
        }
        Some(ExecutionContext {
            block: self.block.clone(),
            tx: TxEnv {
                caller,
                value,
                calldata,
                nonce: 0,
                gas_price: self.tx.gas_price,
            },
            gas: GasState::new(gas),
            call_depth: self.call_depth + 1,
            max_call_depth: self.max_call_depth,
            chain_id: self.chain_id.clone(),
            intent_id: self.intent_id,
            start_time: Instant::now(),
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TESTS
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gas_state_consume() {
        let mut gas = GasState::new(1000);
        assert!(gas.consume(400));
        assert_eq!(gas.used, 400);
        assert_eq!(gas.remaining(), 600);
        assert!(!gas.consume(700)); // over limit
        assert_eq!(gas.used, 400); // not mutated on failure
    }

    #[test]
    fn test_gas_state_exact_limit() {
        let mut gas = GasState::new(100);
        assert!(gas.consume(100));
        assert!(gas.is_exhausted());
    }

    #[test]
    fn test_child_call_depth() {
        let ctx = ExecutionContext::new(
            BlockEnv::default(),
            TxEnv::default(),
            100_000,
            ChainId::Bleep,
            uuid::Uuid::new_v4(),
            3,
        );
        let child = ctx.child_call([1u8; 32], 0, vec![], 50_000).unwrap();
        assert_eq!(child.call_depth, 1);
    }

    #[test]
    fn test_call_depth_limit() {
        let mut ctx = ExecutionContext::new(
            BlockEnv::default(),
            TxEnv::default(),
            100_000,
            ChainId::Bleep,
            uuid::Uuid::new_v4(),
            2,
        );
        let c1 = ctx.child_call([1u8; 32], 0, vec![], 10_000).unwrap();
        ctx.call_depth = c1.call_depth;
        let c2 = ctx.child_call([1u8; 32], 0, vec![], 10_000).unwrap();
        ctx.call_depth = c2.call_depth;
        let c3 = ctx.child_call([1u8; 32], 0, vec![], 10_000);
        assert!(c3.is_none()); // depth 2 is the limit
    }
}
