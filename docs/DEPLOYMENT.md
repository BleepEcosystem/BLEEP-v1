# BLEEP Deployment Guide

## Overview

This guide covers deploying BLEEP blockchain nodes in various environments:
- **Local Development** - Single validator on local machine
- **Testnet** - Multi-node testnet for testing (Docker Compose)
- **Production** - Kubernetes deployment with monitoring

---

## Prerequisites

### Required Software

```bash
# Core requirements
- Rust 1.70+ (stable channel)
- Cargo package manager
- Git

# Optional but recommended
- Docker 20.10+ (for containerized deployment)
- Docker Compose 2.0+ (for multi-node testnet)
- Kubernetes 1.24+ (for cloud deployment)
- kubectl (for K8s management)
- Helm 3.0+ (for K8s package management)
```

### Hardware Requirements

#### Minimal (Testnet/Development)
- CPU: 2+ cores
- RAM: 4 GB
- Storage: 50 GB SSD
- Bandwidth: 1 Mbps

#### Recommended (Production Validator)
- CPU: 8+ cores
- RAM: 32 GB
- Storage: 500 GB+ SSD
- Bandwidth: 100 Mbps
- Deployment: Dedicated server or cloud VM

#### Archive Node (Full History)
- CPU: 16+ cores
- RAM: 64 GB
- Storage: 2 TB+ SSD
- Bandwidth: 1 Gbps

---

## Local Development Setup

### 1. Build from Source

```bash
# Clone repository
git clone https://github.com/BleepEcosystem/BLEEP-V1.git
cd BLEEP-V1

# Install development tools
./scripts/setup-cicd.sh

# Build release binary
cargo build --release

# Binary location
./target/release/bleep-block
```

### 2. Run Single Node

```bash
# Testnet configuration
./target/release/bleep-block --config config/testnet_config.json

# Mainnet configuration (when available)
./target/release/bleep-block --config config/mainnet_config.json

# Custom configuration
./target/release/bleep-block --config config/custom.json
```

### 3. Verify Operation

```bash
# Check node status (in another terminal)
curl http://localhost:8080/health

# View metrics
curl http://localhost:8080/metrics

# View RPC endpoint
curl -X POST http://localhost:8080 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"net_version","params":[],"id":1}'
```

---

## Docker Deployment

### Single Node (Development)

```bash
# Build Docker image
docker build -t bleep:latest .

# Run container
docker run -d \
  --name bleep-node \
  -p 8080:8080 \
  -p 9000:9000 \
  -v bleep-data:/app/data \
  bleep:latest

# Monitor logs
docker logs -f bleep-node

# Stop container
docker stop bleep-node
docker rm bleep-node
```

### Multi-Node Testnet (Docker Compose)

```bash
# Start 4-validator + 1-full-node network
make docker-compose-up

# Check status
make docker-compose-status

# View logs
make docker-compose-logs

# View specific service
docker-compose logs -f validator-1

# Stop network
make docker-compose-down
```

### Configuration

Edit `docker-compose.yml` to:
- Adjust number of validators
- Modify ports
- Add custom environment variables
- Configure volume mounts

Example environment variables:
```yaml
environment:
  - RUST_LOG=debug        # Log level
  - VALIDATOR_KEY=key123  # Validator key
  - NODE_ID=validator-1   # Node identifier
```

### Genesis Administrator

To enable system administration, add the genesis administrator's 64-byte
SPHINCS+-SHAKE-256f-simple public key as a 128-character hex string in the
genesis config file:

```json
{
  "BLEEP_GENESIS_ADMIN_PUBKEY": "<128-character-public-key-hex>"
}
```

The node reads this value only from the file selected by `BLEEP_GENESIS_CONFIG`
(or the embedded network config); it never accepts an administrator key from an
RPC request or directly from an environment variable. Keep the corresponding
private key offline. To authenticate, request a one-time challenge from
`POST /rpc/auth/admin/challenge`, sign the returned `signing_payload_hex` bytes
with the genesis private key, then submit the public key, challenge, and
signature to the existing `POST /rpc/auth/login` endpoint. The login endpoint
issues the normal session token after verifying the signature. A node started
without this config value has no system administrator and protected
administrative operations remain unavailable. Set this value before the first
node startup: the selected key (or the absence of one) is pinned in persistent
state, and changing it on restart is rejected as a governance-level change.

---

## Kubernetes Deployment

### Prerequisites

```bash
# Install kubectl and helm
kubectl version --client
helm version

# Configure cluster access
kubectl cluster-info
kubectl config current-context
```

### Deploy with Helm

```bash
# Create namespace
kubectl create namespace bleep

# Add BLEEP Helm repository (when available)
helm repo add bleep https://charts.bleep.io
helm repo update

# Install BLEEP release
helm install bleep bleep/bleep-node \
  --namespace bleep \
  --values helm-values.yaml
```

### Manual Kubernetes Deployment

Create `kubernetes/bleep-deployment.yaml`:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: bleep-validator
  namespace: bleep
spec:
  replicas: 1
  selector:
    matchLabels:
      app: bleep
      role: validator
  template:
    metadata:
      labels:
        app: bleep
        role: validator
    spec:
      containers:
      - name: bleep-node
        image: ghcr.io/bleepecosystem/bleep-v1:latest
        ports:
        - containerPort: 8080
          name: rpc
        - containerPort: 9000
          name: p2p
        resources:
          requests:
            memory: "16Gi"
            cpu: "4"
          limits:
            memory: "32Gi"
            cpu: "8"
        volumeMounts:
        - name: data
          mountPath: /app/data
        - name: config
          mountPath: /app/config
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 10
          periodSeconds: 5
      volumes:
      - name: data
        persistentVolumeClaim:
          claimName: bleep-data
      - name: config
        configMap:
          name: bleep-config
---
apiVersion: v1
kind: Service
metadata:
  name: bleep-validator
  namespace: bleep
spec:
  selector:
    app: bleep
    role: validator
  ports:
  - name: rpc
    port: 8080
    targetPort: 8080
  - name: p2p
    port: 9000
    targetPort: 9000
  type: LoadBalancer
```

Deploy:
```bash
kubectl apply -f kubernetes/bleep-deployment.yaml
kubectl rollout status deployment/bleep-validator -n bleep
```

---

## Production Configuration

### Network Setup

#### Validator Node

```json
{
  "node_id": "validator-1",
  "role": "validator",
  "listen_addresses": [
    "/ip4/0.0.0.0/tcp/9000"
  ],
  "rpc_endpoints": [
    {
      "interface": "0.0.0.0",
      "port": 8080,
      "tls": true,
      "cert_path": "/etc/bleep/certs/node.crt",
      "key_path": "/etc/bleep/certs/node.key"
    }
  ],
  "peers": [
    "/ip4/validator-2-ip/tcp/9000/p2p/validator-2-peer-id",
    "/ip4/validator-3-ip/tcp/9000/p2p/validator-3-peer-id"
  ],
  "consensus_mode": "pos",
  "max_connections": 100,
  "timeout_seconds": 30
}
```

#### Full Archive Node

```json
{
  "node_id": "archive-1",
  "role": "full-node",
  "archive": true,
  "sync_mode": "full",
  "database": {
    "type": "rocksdb",
    "path": "/data/bleep/db",
    "cache_size_mb": 2048
  },
  "peers": [
    "/ip4/validator-1-ip/tcp/9000/p2p/validator-1-peer-id"
  ]
}
```

### Monitoring Setup

#### Prometheus Configuration

Edit `monitoring/prometheus.yml`:

```yaml
global:
  scrape_interval: 15s
  scrape_timeout: 10s

scrape_configs:
  - job_name: 'bleep-nodes'
    static_configs:
      - targets: ['validator-1:8080', 'validator-2:8080']
    metrics_path: '/metrics'
    scrape_interval: 5s
```

Start Prometheus:
```bash
docker run -d \
  --name prometheus \
  -p 9090:9090 \
  -v $(pwd)/monitoring/prometheus.yml:/etc/prometheus/prometheus.yml \
  prom/prometheus
```

#### Grafana Dashboards

```bash
# Start Grafana
docker run -d \
  --name grafana \
  -p 3000:3000 \
  grafana/grafana

# Access: http://localhost:3000
# Default: admin/admin
```

Import dashboards for:
- Node health and status
- Consensus metrics
- Network performance
- System resources

### Logging & Observability

#### Setup Structured Logging

Environment variables:
```bash
RUST_LOG=info,bleep_consensus=debug,bleep_p2p=debug
```

#### Log Aggregation (ELK Stack)

```bash
# Start Elasticsearch
docker run -d \
  --name elasticsearch \
  -e "discovery.type=single-node" \
  -p 9200:9200 \
  docker.elastic.co/elasticsearch/elasticsearch:8.0.0

# Start Logstash
docker run -d \
  --name logstash \
  -p 5000:5000 \
  docker.elastic.co/logstash/logstash:8.0.0

# Start Kibana
docker run -d \
  --name kibana \
  -p 5601:5601 \
  docker.elastic.co/kibana/kibana:8.0.0
```

---

## Node Maintenance

### Health Checks

```bash
# Check node health
curl http://localhost:8080/health

# Check sync status
curl http://localhost:8080/rpc -X POST \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_syncing","params":[],"id":1}'

# Check peer connections
curl http://localhost:8080/rpc -X POST \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"net_peerCount","params":[],"id":1}'
```

### Updates & Upgrades

```bash
# Build new version
cargo build --release

# Backup data
cp -r /data/bleep /data/bleep.backup

# Stop running node
systemctl stop bleep-node # or docker stop

# Deploy new binary
cp target/release/bleep-block /usr/local/bin/

# Restart
systemctl start bleep-node # or docker start
```

### Backups

```bash
# Daily automated backup
0 2 * * * tar -czf /backups/bleep-$(date +\%Y\%m\%d).tar.gz /data/bleep

# Test restore
tar -xzf /backups/bleep-20240101.tar.gz -C /tmp
```

### Pruning (if needed)

```bash
# Prune old data (requires restart)
./target/release/bleep-block --prune-mode archive --data-dir /data/bleep
```

---

## Security Best Practices

### Firewall Configuration

```bash
# Open RPC port only to trusted IPs
iptables -A INPUT -p tcp --dport 8080 -s 10.0.0.0/8 -j ACCEPT
iptables -A INPUT -p tcp --dport 8080 -j DROP

# P2P port should be open to all
iptables -A INPUT -p tcp --dport 9000 -j ACCEPT
```

### TLS/SSL Setup

```bash
# Generate certificates
openssl req -x509 -newkey rsa:4096 -keyout node.key -out node.crt -days 365

# Configure in node
{
  "rpc_endpoints": [{
    "tls": true,
    "cert_path": "/etc/bleep/node.crt",
    "key_path": "/etc/bleep/node.key"
  }]
}
```

### Secrets Management

```bash
# Use environment variables (don't commit secrets)
export VALIDATOR_SIGNING_KEY="your-secret-key"

# Or use secrets manager
aws secretsmanager get-secret-value --secret-id bleep-validator-key
```

---

## Troubleshooting

### Common Issues

**Node won't start**
```bash
# Check logs
journalctl -u bleep-node -n 50

# Verify configuration
./target/release/bleep-block --config config/testnet_config.json --validate-config
```

**Disk space issues**
```bash
# Check usage
du -sh /data/bleep/*

# Prune old blocks (if applicable)
./target/release/bleep-block --prune
```

**Network connectivity**
```bash
# Check peer connections
curl http://localhost:8080/metrics | grep p2p_peers

# Test outbound connectivity
nc -zv validator-2.example.com 9000
```

---

## Performance Tuning

### Kernel Parameters (Linux)

```bash
# Increase file descriptors
ulimit -n 65536

# Optimize network
sysctl -w net.core.rmem_max=2147483647
sysctl -w net.core.wmem_max=2147483647
sysctl -w net.ipv4.tcp_max_syn_backlog=65535
```

### Database Tuning

```bash
# RocksDB cache tuning
{
  "database": {
    "cache_size_mb": 8192,
    "max_open_files": 10000,
    "write_buffer_size_mb": 512
  }
}
```

---

## Support & Resources

- **Documentation**: [docs/CI_CD_PIPELINE.md](CI_CD_PIPELINE.md)
- **GitHub Issues**: [BLEEP Issues](https://github.com/BleepEcosystem/BLEEP-V1/issues)
- **Community Chat**: [Discord](https://discord.gg/bleep)
- **Monitoring**: [Prometheus](http://localhost:9090) | [Grafana](http://localhost:3000)
