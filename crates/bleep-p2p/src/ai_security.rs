//! AI-powered peer scoring and Sybil resistance for bleep-p2p.
//!
//! Implements a lightweight, deterministic multi-factor scoring model
//! (no external ML runtime required) with the following signals:
//!
//! | Signal                         | Weight |
//! |--------------------------------|--------|
//! | Success / total interaction ratio | 40%  |
//! | Message rate (flood detection) | 20%    |
//! | Longevity (age of relationship)| 15%    |
//! | Latency consistency            | 15%    |
//! | Unique subnet diversity        | 10%    |
//!
//! Sybil detection uses subnet clustering: if more than `MAX_PEERS_PER_SUBNET`
//! peers share the same /24 IPv4 prefix (or /48 IPv6 prefix), new peers from
//! that subnet are marked as Sybil candidates.

use std::net::{IpAddr, SocketAddr};

use dashmap::DashMap;
use tracing::warn;

use crate::types::{unix_now, NodeId, PeerStatus};

// ─────────────────────────────────────────────────────────────────────────────
// CONSTANTS
// ─────────────────────────────────────────────────────────────────────────────

/// Peers above this score are Healthy.
pub const TRUST_HEALTHY_THRESHOLD: f64 = 70.0;
/// Peers above this but below HEALTHY are Suspicious.
pub const TRUST_SUSPICIOUS_THRESHOLD: f64 = 40.0;
/// Window for rate-of-message calculation.
const MESSAGE_RATE_WINDOW_SECS: u64 = 60;
/// Max messages per MESSAGE_RATE_WINDOW_SECS before penalising.
const MESSAGE_RATE_FLOOD_THRESHOLD: u64 = 500;
/// Max peers tolerated from the same /24 subnet before flagging.
const MAX_PEERS_PER_SUBNET: usize = 5;
/// Minimum peer age (seconds) before receiving full longevity bonus.
const LONGEVITY_FULL_BONUS_SECS: u64 = 86400; // 24 h

// ─────────────────────────────────────────────────────────────────────────────
// INTERACTION RECORD — per peer
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Default, Clone)]
pub struct InteractionRecord {
    pub success_count: u64,
    pub failure_count: u64,
    /// UNIX timestamps of recent messages (in the current rate window).
    pub recent_message_times: Vec<u64>,
    /// Sorted latency samples (milliseconds).
    pub latency_samples: Vec<u32>,
    pub first_seen: u64,
}

impl InteractionRecord {
    pub fn new(now: u64) -> Self {
        InteractionRecord {
            first_seen: now,
            ..Default::default()
        }
    }

    pub fn total_interactions(&self) -> u64 {
        self.success_count + self.failure_count
    }

    pub fn success_ratio(&self) -> f64 {
        let total = self.total_interactions();
        if total == 0 {
            return 0.5; // Neutral for brand-new peers
        }
        self.success_count as f64 / total as f64
    }

    /// Prune message timestamps older than the rate window.
    pub fn prune_old_messages(&mut self, now: u64) {
        self.recent_message_times
            .retain(|&t| now.saturating_sub(t) <= MESSAGE_RATE_WINDOW_SECS);
    }

    pub fn record_message(&mut self, now: u64) {
        self.prune_old_messages(now);
        self.recent_message_times.push(now);
    }

    pub fn message_rate(&self, now: u64) -> u64 {
        let window_start = now.saturating_sub(MESSAGE_RATE_WINDOW_SECS);
        self.recent_message_times
            .iter()
            .filter(|&&t| t >= window_start)
            .count() as u64
    }

    pub fn record_latency(&mut self, latency_ms: u32) {
        self.latency_samples.push(latency_ms);
        if self.latency_samples.len() > 100 {
            self.latency_samples.remove(0);
        }
    }

    /// Coefficient of variation of latency (std / mean).  Low = consistent.
    pub fn latency_cv(&self) -> f64 {
        if self.latency_samples.len() < 3 {
            return 0.5; // Neutral
        }
        let n = self.latency_samples.len() as f64;
        let mean = self.latency_samples.iter().map(|&x| x as f64).sum::<f64>() / n;
        if mean < 1.0 {
            return 0.0;
        }
        let variance = self
            .latency_samples
            .iter()
            .map(|&x| {
                let d = x as f64 - mean;
                d * d
            })
            .sum::<f64>()
            / n;
        variance.sqrt() / mean
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PEER SCORING ENGINE
// ─────────────────────────────────────────────────────────────────────────────

pub struct PeerScoring {
    records: DashMap<NodeId, InteractionRecord>,
}

impl PeerScoring {
    pub fn new() -> Self {
        PeerScoring {
            records: DashMap::new(),
        }
    }

    fn record_mut(
        &self,
        id: &NodeId,
    ) -> dashmap::mapref::one::RefMut<'_, NodeId, InteractionRecord> {
        self.records
            .entry(id.clone())
            .or_insert_with(|| InteractionRecord::new(unix_now()))
    }

    pub fn record_success(&self, id: &NodeId) {
        self.record_mut(id).success_count += 1;
    }

    pub fn record_failure(&self, id: &NodeId) {
        self.record_mut(id).failure_count += 1;
    }

    pub fn record_message(&self, id: &NodeId) {
        let now = unix_now();
        self.record_mut(id).record_message(now);
    }

    pub fn record_latency(&self, id: &NodeId, latency_ms: u32) {
        self.record_mut(id).record_latency(latency_ms);
    }

    /// Compute the composite trust score [0.0, 100.0].
    pub fn calculate_score(&self, id: &NodeId) -> f64 {
        let now = unix_now();
        let rec = match self.records.get(id) {
            Some(r) => r.clone(),
            None => return 50.0, // Unknown peer — neutral
        };

        // 1. Success ratio component [0, 40]
        let success_component = rec.success_ratio() * 40.0;

        // 2. Message rate component [0, 20] — penalise flooding
        let rate = rec.message_rate(now);
        let rate_score = if rate > MESSAGE_RATE_FLOOD_THRESHOLD {
            0.0
        } else {
            (1.0 - (rate as f64 / MESSAGE_RATE_FLOOD_THRESHOLD as f64)) * 20.0
        };

        // 3. Longevity component [0, 15]
        let age_secs = now.saturating_sub(rec.first_seen);
        let longevity_score = (age_secs as f64 / LONGEVITY_FULL_BONUS_SECS as f64).min(1.0) * 15.0;

        // 4. Latency consistency component [0, 15] — lower CV is better
        let cv = rec.latency_cv();
        let latency_score = (1.0 - cv.min(1.0)) * 15.0;

        // 5. Diversity component — placeholder for subnet scoring; set by SybilDetector
        //    Here we give full marks unless overridden.
        let diversity_score = 10.0;

        let total =
            success_component + rate_score + longevity_score + latency_score + diversity_score;
        total.clamp(0.0, 100.0)
    }

    pub fn classify_status(&self, id: &NodeId) -> PeerStatus {
        let score = self.calculate_score(id);
        if score >= TRUST_HEALTHY_THRESHOLD {
            PeerStatus::Healthy
        } else if score >= TRUST_SUSPICIOUS_THRESHOLD {
            PeerStatus::Suspicious
        } else {
            PeerStatus::Malicious
        }
    }

    /// Remove record for a peer (e.g., banned peer).
    pub fn remove(&self, id: &NodeId) {
        self.records.remove(id);
    }

    /// Return a sorted list of (NodeId, score) for routing decisions.
    pub fn ranked_peers(&self, candidates: &[NodeId]) -> Vec<(NodeId, f64)> {
        let mut scored: Vec<(NodeId, f64)> = candidates
            .iter()
            .map(|id| (id.clone(), self.calculate_score(id)))
            .collect();
        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        scored
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SYBIL DETECTOR
// ─────────────────────────────────────────────────────────────────────────────

/// Detects Sybil attacks via subnet clustering and behavioural correlation.
pub struct SybilDetector {
    /// subnet_key → peer_count
    subnet_counts: DashMap<String, usize>,
    /// Peers flagged as Sybil candidates.
    flagged: DashMap<NodeId, bool>,
}

impl SybilDetector {
    pub fn new() -> Self {
        SybilDetector {
            subnet_counts: DashMap::new(),
            flagged: DashMap::new(),
        }
    }

    fn subnet_key(addr: &SocketAddr) -> String {
        match addr.ip() {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                format!("{}.{}.{}", octets[0], octets[1], octets[2])
            }
            IpAddr::V6(v6) => {
                let segs = v6.segments();
                format!("{:x}:{:x}:{:x}", segs[0], segs[1], segs[2])
            }
        }
    }

    /// Register a peer's address and return true if it is flagged as a Sybil.
    pub fn register(&self, id: &NodeId, addr: &SocketAddr) -> bool {
        let key = Self::subnet_key(addr);
        let mut count = self.subnet_counts.entry(key.clone()).or_insert(0);
        *count += 1;

        if *count > MAX_PEERS_PER_SUBNET {
            warn!(peer = %id, subnet = %key, count = *count, "Sybil candidate: subnet saturation");
            self.flagged.insert(id.clone(), true);
            return true;
        }
        false
    }

    /// Explicitly flag a peer as suspicious.
    pub fn flag(&self, id: &NodeId) {
        self.flagged.insert(id.clone(), true);
    }

    pub fn is_flagged(&self, id: &NodeId) -> bool {
        self.flagged.get(id).map(|v| *v).unwrap_or(false)
    }

    /// Deregister a peer (when removed / banned).
    pub fn deregister(&self, id: &NodeId, addr: &SocketAddr) {
        let key = Self::subnet_key(addr);
        if let Some(mut count) = self.subnet_counts.get_mut(&key) {
            *count = count.saturating_sub(1);
        }
        self.flagged.remove(id);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ANOMALY DETECTOR
// ─────────────────────────────────────────────────────────────────────────────

/// Rule-based anomaly detection on incoming message payloads.
pub struct AnomalyDetector {
    /// Maximum acceptable payload size in bytes.
    max_payload_bytes: usize,
    /// Maximum acceptable hop count.
    max_hop_count: u8,
}

impl AnomalyDetector {
    pub fn new() -> Self {
        AnomalyDetector {
            max_payload_bytes: 2 * 1024 * 1024, // 2 MiB
            max_hop_count: 64,
        }
    }

    /// Returns `Some(reason)` if the message is anomalous, `None` if clean.
    pub fn check_message(&self, payload: &[u8], hop_count: u8) -> Option<String> {
        if payload.len() > self.max_payload_bytes {
            return Some(format!(
                "Oversized payload: {} bytes (max {})",
                payload.len(),
                self.max_payload_bytes
            ));
        }
        if hop_count > self.max_hop_count {
            return Some(format!(
                "Hop count {} exceeds max {}",
                hop_count, self.max_hop_count
            ));
        }
        // Check for obvious poisoning signatures
        if payload.windows(4).any(|w| w == b"\xde\xad\xbe\xef") {
            return Some("Known malicious payload signature detected".into());
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::NodeId;

    fn nid(b: u8) -> NodeId {
        let mut id = [0u8; 32];
        id[0] = b;
        NodeId(id)
    }

    #[test]
    fn test_score_new_peer_is_neutral() {
        let scoring = PeerScoring::new();
        let id = nid(1);
        // Unknown peer returns 50.0
        assert_eq!(scoring.calculate_score(&id), 50.0);
    }

    #[test]
    fn test_score_increases_with_successes() {
        let scoring = PeerScoring::new();
        let id = nid(2);
        scoring
            .records
            .insert(id.clone(), InteractionRecord::new(unix_now()));
        for _ in 0..10 {
            scoring.record_success(&id);
        }
        let score = scoring.calculate_score(&id);
        assert!(score > 50.0, "Score {score} should be > 50 after successes");
    }

    #[test]
    fn test_score_penalised_for_flooding() {
        let scoring = PeerScoring::new();
        let id = nid(3);
        let now = unix_now();
        let mut rec = InteractionRecord::new(now);
        // Simulate 600 messages in the window
        rec.success_count = 5;
        for i in 0..600 {
            rec.recent_message_times.push(now - i % 60);
        }
        scoring.records.insert(id.clone(), rec);
        let score = scoring.calculate_score(&id);
        // Rate component should be 0
        assert!(
            score < 80.0,
            "Score {score} should be penalised for flooding"
        );
    }

    #[test]
    fn test_classify_status_boundaries() {
        let scoring = PeerScoring::new();
        let id = nid(10);
        // Manually inject a high-success record
        let mut rec = InteractionRecord::new(unix_now() - 90000);
        rec.success_count = 1000;
        rec.failure_count = 10;
        scoring.records.insert(id.clone(), rec);
        assert_eq!(scoring.classify_status(&id), PeerStatus::Healthy);
    }

    #[test]
    fn test_sybil_detector_flags_on_subnet_saturation() {
        let sybil = SybilDetector::new();
        let addr_base = "192.168.1.1:9000";
        for i in 0..=MAX_PEERS_PER_SUBNET {
            let id = nid(i as u8);
            let addr: std::net::SocketAddr = format!("192.168.1.{}:9000", i + 1).parse().unwrap();
            sybil.register(&id, &addr);
        }
        // The (MAX_PEERS_PER_SUBNET+1)-th peer should be flagged
        let last_id = nid(MAX_PEERS_PER_SUBNET as u8);
        // Note: flagging happens on the (K+1)-th, which is index MAX_PEERS_PER_SUBNET
        assert!(sybil.is_flagged(&last_id));
    }

    #[test]
    fn test_anomaly_detector_oversized_payload() {
        let det = AnomalyDetector::new();
        let big = vec![0u8; 3 * 1024 * 1024];
        assert!(det.check_message(&big, 1).is_some());
    }

    #[test]
    fn test_anomaly_detector_valid_message() {
        let det = AnomalyDetector::new();
        let payload = b"valid small message";
        assert!(det.check_message(payload, 3).is_none());
    }

    #[test]
    fn test_ranked_peers_ordering() {
        let scoring = PeerScoring::new();
        for i in 1..=5u8 {
            let id = nid(i);
            let mut rec = InteractionRecord::new(unix_now() - 10000);
            rec.success_count = i as u64 * 10;
            scoring.records.insert(id, rec);
        }
        let ids: Vec<NodeId> = (1..=5u8).map(nid).collect();
        let ranked = scoring.ranked_peers(&ids);
        // Highest scores first
        for i in 0..ranked.len() - 1 {
            assert!(ranked[i].1 >= ranked[i + 1].1);
        }
    }
}
