# bleep-p2p

**Post-Quantum P2P Networking — BLEEP Quantum Trust Network**

`bleep-p2p` implements the peer-to-peer networking stack for BLEEP nodes. All inter-node messages are authenticated with SPHINCS+ signatures and dropped before payload processing if unauthenticated. Session keys are established via Kyber-1024 KEM. An onion router provides multi-hop anonymised delivery for privacy-sensitive operations.

---

## License

Licensed under **Apache 2.0**.
Copyright © 2026 Muhammad Attahir.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                         P2PNode                              │
│                                                              │
│  ┌─────────────────┐  ┌──────────────┐  ┌───────────────┐   │
│  │  PeerManager    │  │    Gossip    │  │  OnionRouter  │   │
│  │  + AI scoring   │  │   Protocol   │  │  Kyber-1024   │   │
│  │  + Sybil detect │  │  Plumtree    │  │  AES-256-GCM  │   │
│  └─────────────────┘  └──────────────┘  └───────────────┘   │
│  ┌──────────────────────────────────────────────────────┐    │
│  │               MessageProtocol                        │    │
│  │  TCP framing · AES-256-GCM · SPHINCS+ signatures    │    │
│  │  Kyber-1024 KEM · Anti-replay nonce cache (64k LRU) │    │
│  └──────────────────────────────────────────────────────┘    │
│  ┌──────────────────────────────────────────────────────┐    │
│  │                  KademliaDHT                         │    │
│  │  256 K-buckets · XOR metric · k=20 contacts/bucket  │    │
│  └──────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────┘
```

---

## Post-Quantum Network Security

Every message on the BLEEP P2P network is post-quantum authenticated:

| Operation | Algorithm | Standard |
|---|---|---|
| Node identity (long-term) | SPHINCS+-SHAKE-256f-simple | FIPS 205, SL5 |
| Session key establishment | Kyber-1024 / ML-KEM-1024 | FIPS 203, SL5 |
| Session encryption | AES-256-GCM | NIST SP 800-38D |
| Onion routing per-hop | Kyber-1024 + AES-256-GCM | — |
| Peer ID derivation | Deterministic hash of SPHINCS+ public key | SHA3-256 |

Unauthenticated messages are dropped at the receive boundary before any deserialization. A 2 MiB size gate is enforced at the receive boundary before any deserialization — preventing memory exhaustion from oversized gossip messages.

---

## Key Components

### `KademliaDHT`

Structured peer discovery using 256 K-buckets with XOR metric and k=20 contacts per bucket. Supports `find_node`, `store`, and `find_value` operations. Peer IDs are deterministic hashes of SPHINCS+ public keys — a node cannot claim an arbitrary peer ID.

### `PeerManager`

Maintains the active peer set with AI-derived peer quality scores based on latency, uptime, and message validity rate. Sybil detection flags peers exhibiting correlated behaviour patterns (same network prefix, coordinated join/leave, identical timing signatures).

### `GossipProtocol` — Plumtree

Epidemic broadcast protocol for propagating blocks, transactions, and governance messages with O(log n) bandwidth overhead and fanout of 8. Lazy-push fallback prevents message loss during network stress. All gossiped messages are SPHINCS+-signed; unsigned messages are dropped.

### `OnionRouter`

Encrypts messages in layered Kyber-1024 + AES-256-GCM envelopes to route traffic through up to 6 relay hops, obscuring the originating IP address. Each hop decrypts one layer, forwards to the next hop, and has no knowledge of the full path.

### `MessageProtocol`

Transport-layer framing and authentication:
- TCP with length-prefixed frames
- AES-256-GCM authenticated encryption per connection
- SPHINCS+ message signatures for integrity on all protocol messages
- Kyber-1024 KEM for forward-secret session establishment
- Anti-replay nonce cache: 64k slots, LRU eviction

---

## Configuration

`P2PNodeConfig` fields:

| Field | Default | Description |
|---|---|---|
| `listen_addr` | `0.0.0.0:7700` | TCP listen address |
| `bootstrap_peers` | `[]` | Initial peers for DHT seeding |
| `max_peers` | `50` | Maximum connected peers |
| `gossip_fanout` | `8` | Plumtree eager-push fanout |
| `max_gossip_msg_bytes` | `2,097,152` (2 MiB) | Receive-boundary size gate |
| `enable_onion` | `false` | Enable onion routing (opt-in) |
| `quantum_mode` | `true` | Use PQC for all sessions (always enabled in production) |
| `anti_replay_cache_slots` | `65,536` | LRU nonce cache size |

The node binary also reads these environment variables:

| Variable | Default | Description |
|---|---|---|
| `BLEEP_P2P_LISTEN_ADDR` | `0.0.0.0:7700` | TCP listen address |
| `BLEEP_P2P_SEEDS` | empty | Comma-separated `host:port` addresses for authenticated outbound bootstrap dialing |

For example, start a node that listens publicly and dials two known peers:

```sh
BLEEP_P2P_LISTEN_ADDR=0.0.0.0:7700 \
BLEEP_P2P_SEEDS=198.51.100.10:7700,198.51.100.11:7700 \
cargo run --bin bleep
```

Each successful seed connection performs the SPHINCS+ identity admission and
Kyber session exchange before adding the peer to the local Kademlia routing
table. Seed addresses must be reachable from the node; public keys are learned
and verified during the authenticated handshake.

---

## Quick Start

```rust
use bleep_p2p::p2p_node::{P2PNode, P2PNodeConfig};

#[tokio::main]
async fn main() {
    let config = P2PNodeConfig {
        listen_addr: "0.0.0.0:7700".parse().unwrap(),
        quantum_mode: true,
        gossip_fanout: 8,
        ..Default::default()
    };

    let (node, handle) = P2PNode::start(config).await.unwrap();
    println!("P2P node started: peer_id={}", node.peer_id);
    handle.await.unwrap();
}
```

---

## Integration with Consensus

`bleep-p2p` connects to `bleep-consensus` via `GossipBridge` — an async channel that forwards incoming block proposals and votes to the consensus engine, and outgoing signed blocks and votes back to the gossip network. The bridge enforces the 2 MiB size gate and SPHINCS+ authentication before any message reaches the consensus layer.

---

## Testing

```bash
cargo test -p bleep-p2p
```

---

*Part of the [BLEEP Quantum Trust Network](https://github.com/BleepEcosystem/BLEEP-v1) · Protocol Version 5*
*© 2026 Muhammad Attahir — Apache 2.0 Licence*
