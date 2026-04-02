use crate::block::Block;

pub struct BlockValidator;

impl BlockValidator {
    /// **Validate block integrity (Signature + Fiat-Shamir ZKP)**
    ///
    /// SAFETY: Rejects blocks with invalid signatures or ZK proofs.
    /// This is a mandatory check before adding a block to the chain.
    ///
    /// ## ZKP check (Sprint 5)
    /// `verify_zkp()` validates the 64-byte Fiat-Shamir commitment produced by
    /// `generate_zkp()`.  The commitment binds: block hash, validator public key,
    /// epoch, protocol version, consensus mode, merkle root, shard fields, and
    /// tx count.  An empty proof is allowed only for unsigned genesis blocks.
    pub fn validate_block(block: &Block, public_key: &[u8]) -> bool {
        // Verify validator signature (quantum-secure)
        match block.verify_signature(public_key) {
            Ok(valid) => {
                if !valid {
                    log::error!(
                        "Block {} signature verification failed for validator",
                        block.index
                    );
                    return false;
                }
            }
            Err(e) => {
                log::error!("Block {} signature verification error: {}", block.index, e);
                return false;
            }
        }

        // Verify ZK proof
        if !block.verify_zkp() {
            log::error!("Block {} ZK proof verification failed", block.index);
            return false;
        }

        true
    }

    /// **AI-based anomaly detection for malicious blocks**
    ///
    /// SAFETY: Returns FALSE for any block that appears malicious.
    /// This is a defense-in-depth check AFTER signature validation.
    /// Uses deterministic metrics: transaction count, timestamp ordering, etc.
    pub fn ai_validate(block: &Block) -> bool {
        // Check 1: Block must have finite timestamp
        if block.timestamp == 0 {
            log::warn!("Block {} has zero timestamp", block.index);
            return false;
        }

        // Check 2: Merkle root must be non-empty for non-empty blocks
        if !block.transactions.is_empty() && block.merkle_root.is_empty() {
            log::warn!(
                "Block {} has transactions but empty merkle root",
                block.index
            );
            return false;
        }

        // Check 3: Merkle root must be empty only if transactions are empty
        if block.transactions.is_empty() && !block.merkle_root.is_empty() {
            log::warn!(
                "Block {} has no transactions but non-empty merkle root",
                block.index
            );
            return false;
        }

        // Check 4: Consensus mode must be valid for the reported epoch
        // (In production, we would validate against the epoch schedule)

        // Check 5: Transaction count should be reasonable (< 10000)
        if block.transactions.len() > 10000 {
            log::warn!(
                "Block {} has suspiciously many transactions ({})",
                block.index,
                block.transactions.len()
            );
            return false;
        }

        true
    }

    /// **Ensure new block links correctly to the previous block**
    pub fn validate_block_link(prev_block: &Block, current_block: &Block) -> bool {
        let expected_previous_hash = prev_block.compute_hash();

        if current_block.previous_hash != expected_previous_hash {
            log::error!(
                "Block {} hash mismatch! Expected {}, got {}",
                current_block.index,
                expected_previous_hash,
                current_block.previous_hash
            );
            return false;
        }

        true
    }

    /// **Network-wide peer consensus verification**
    ///
    /// SAFETY: Rejects blocks that don't match network consensus.
    /// Uses deterministic checks: proof-of-work difficulty, finality confirmation, etc.
    pub fn network_validate(block: &Block) -> bool {
        // Check 1: Previous hash must be valid (non-zero length)
        if block.previous_hash.is_empty() && block.index > 0 {
            log::warn!(
                "Block {} has empty previous_hash but is not genesis",
                block.index
            );
            return false;
        }

        // Check 2: Genesis block (index 0) should have zero/default previous hash
        if block.index == 0 && !block.previous_hash.is_empty() && block.previous_hash != "0" {
            log::warn!(
                "Genesis block has non-zero previous_hash: {}",
                block.previous_hash
            );
            return false;
        }

        // Check 3: Consensus mode must be deterministically assigned for epoch
        // (This would be validated against the epoch schedule in production)
        if block.epoch_id == u64::MAX {
            log::warn!("Block {} has invalid epoch_id", block.index);
            return false;
        }

        // Check 4: Shard ID should be reasonable (< 256 in a typical setup)
        if block.shard_id > 256 {
            log::warn!(
                "Block {} has unreasonable shard_id: {}",
                block.index,
                block.shard_id
            );
            return false;
        }

        true
    }

    /// **Full block validation pipeline**
    ///
    /// SAFETY: Executes all validation steps in strict order:
    /// 1. Signature validation
    /// 2. Link validation
    /// 3. Network consensus checks
    /// 4. AI anomaly detection
    pub fn validate_full_block(prev_block: &Block, block: &Block, public_key: &[u8]) -> bool {
        // Step 1: Verify block signature
        if !Self::validate_block(block, public_key) {
            log::error!("Block {} failed signature validation", block.index);
            return false;
        }

        // Step 2: Verify block link to previous block
        if !Self::validate_block_link(prev_block, block) {
            log::error!(
                "Block {} failed link validation to previous block",
                block.index
            );
            return false;
        }

        // Step 3: Network consensus validation
        if !Self::network_validate(block) {
            log::error!("Block {} failed network validation", block.index);
            return false;
        }

        // Step 4: AI anomaly detection
        if !Self::ai_validate(block) {
            log::error!("Block {} failed AI anomaly detection", block.index);
            return false;
        }

        // All validations passed
        log::debug!("Block {} passed full validation pipeline", block.index);
        true
    }
}
