//! # Call Stack
//!
//! Tracks nested contract-to-contract calls during execution.
//! Enforces depth limits and provides stack-frame introspection.

use serde::{Deserialize, Serialize};

/// One frame in the call stack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallFrame {
    /// Caller address.
    pub caller: [u8; 32],
    /// Contract being called.
    pub callee: [u8; 32],
    /// Value sent.
    pub value: u128,
    /// Gas budget for this frame.
    pub gas_limit: u64,
    /// Gas consumed so far in this frame.
    pub gas_used: u64,
    /// Depth of this frame (0 = top-level).
    pub depth: usize,
    /// Whether this is a STATIC call (no state changes allowed).
    pub is_static: bool,
    /// Whether this is a DELEGATE call (caller's storage context).
    pub is_delegate: bool,
}

/// LIFO call stack with configurable depth limit.
#[derive(Debug, Default)]
pub struct CallStack {
    frames: Vec<CallFrame>,
    max_depth: usize,
}

impl CallStack {
    pub fn new(max_depth: usize) -> Self {
        CallStack {
            frames: Vec::with_capacity(16),
            max_depth,
        }
    }

    /// Push a new frame. Returns `Err` if depth limit exceeded.
    pub fn push(&mut self, frame: CallFrame) -> Result<(), &'static str> {
        if self.frames.len() >= self.max_depth {
            return Err("Call stack depth exceeded");
        }
        self.frames.push(frame);
        Ok(())
    }

    /// Pop the topmost frame. Returns `None` if stack is empty.
    pub fn pop(&mut self) -> Option<CallFrame> {
        self.frames.pop()
    }

    /// Current depth (number of active frames).
    pub fn depth(&self) -> usize {
        self.frames.len()
    }

    /// Whether the current execution context is inside a static call.
    pub fn is_in_static_call(&self) -> bool {
        self.frames.iter().any(|f| f.is_static)
    }

    /// Peek at the topmost frame without removing it.
    pub fn peek(&self) -> Option<&CallFrame> {
        self.frames.last()
    }

    /// Accesses the current gas used in the topmost frame.
    pub fn top_gas_used(&self) -> u64 {
        self.frames.last().map_or(0, |f| f.gas_used)
    }

    /// Charge gas to the topmost frame. Returns false if out of gas.
    pub fn charge_gas(&mut self, cost: u64) -> bool {
        if let Some(frame) = self.frames.last_mut() {
            if frame.gas_used.saturating_add(cost) > frame.gas_limit {
                return false;
            }
            frame.gas_used += cost;
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(depth: usize) -> CallFrame {
        CallFrame {
            caller: [0u8; 32],
            callee: [1u8; 32],
            value: 0,
            gas_limit: 100_000,
            gas_used: 0,
            depth,
            is_static: false,
            is_delegate: false,
        }
    }

    #[test]
    fn test_push_pop() {
        let mut stack = CallStack::new(3);
        stack.push(frame(0)).unwrap();
        stack.push(frame(1)).unwrap();
        assert_eq!(stack.depth(), 2);
        let f = stack.pop().unwrap();
        assert_eq!(f.depth, 1);
        assert_eq!(stack.depth(), 1);
    }

    #[test]
    fn test_depth_limit() {
        let mut stack = CallStack::new(2);
        stack.push(frame(0)).unwrap();
        stack.push(frame(1)).unwrap();
        let err = stack.push(frame(2));
        assert!(err.is_err());
    }

    #[test]
    fn test_static_call_propagation() {
        let mut stack = CallStack::new(10);
        stack.push(frame(0)).unwrap();
        let mut static_frame = frame(1);
        static_frame.is_static = true;
        stack.push(static_frame).unwrap();
        stack.push(frame(2)).unwrap(); // nested under static
        assert!(stack.is_in_static_call());
    }

    #[test]
    fn test_gas_charging() {
        let mut stack = CallStack::new(5);
        stack.push(frame(0)).unwrap();
        assert!(stack.charge_gas(50_000));
        assert!(!stack.charge_gas(60_000)); // would exceed 100_000
        assert_eq!(stack.top_gas_used(), 50_000);
    }
}
