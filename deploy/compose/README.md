# RER Docker Compose Deployments

This directory provides complete, reproducible Docker Compose deployments for RER (RER Engineering Relay), fulfilling SPEC §16.C and §17.

## Deployment Topologies

1. **Single-Instance Deployment** (`docker-compose.single.yml`):
   Runs an isolated RER instance listening on UDP port `5000` and forwarding to configured destinations.
2. **Relay-Chain Deployment** (`docker-compose.relay-chain.yml`):
   Runs a multi-instance relay chain (`relay-ingress` → `relay-egress` → destination) over an internal bridge network (`rer-chain-net`).

## Operational Commands

### 1. Configuration Validation

Validate Compose files without starting containers:

```bash
docker compose -f deploy/compose/docker-compose.single.yml config
docker compose -f deploy/compose/docker-compose.relay-chain.yml config
```

### 2. Startup

Start the service in detached mode:

```bash
# Single instance
docker compose -f deploy/compose/docker-compose.single.yml up -d

# Relay chain
docker compose -f deploy/compose/docker-compose.relay-chain.yml up -d
```

### 3. Status and Health

Check container status and health:

```bash
# Single instance
docker compose -f deploy/compose/docker-compose.single.yml ps

# Relay chain
docker compose -f deploy/compose/docker-compose.relay-chain.yml ps
```

To run a live health check inside the container directly:

```bash
docker exec rer-single /usr/local/bin/rer health
```

### 4. Viewing Logs

Stream structured logs:

```bash
docker compose -f deploy/compose/docker-compose.single.yml logs -f
```

### 5. Graceful Shutdown

Stop and remove containers gracefully (RER handles `SIGTERM` and flushes queues within the stop timeout):

```bash
docker compose -f deploy/compose/docker-compose.single.yml down
docker compose -f deploy/compose/docker-compose.relay-chain.yml down
```

### 6. Upgrade

Pull the new versioned image and recreate containers:

```bash
docker compose -f deploy/compose/docker-compose.single.yml pull
docker compose -f deploy/compose/docker-compose.single.yml up -d
```

## Security & Resource Specifications

- **Non-Root Execution**: Runs as user `65532:65532` (`nonroot`).
- **Dropped Capabilities**: Drops all Linux capabilities (`cap_drop: [ALL]`).
- **No New Privileges**: Hardened with `security_opt: [no-new-privileges:true]`.
- **Read-Only Root Filesystem**: `read_only: true` with persistent state mounted at `/var/lib/rer` and scratch storage at `/tmp`.
- **Resource Limits**: Bounded CPU (`0.50` limit, `0.10` reservation) and memory (`128M` limit, `32M` reservation).
- **Health Checks**: Automated 5-second interval health checks querying real application health (`rer health`).
