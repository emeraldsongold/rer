# RER Helm Chart

A Kubernetes Helm chart for deploying [RER (RER Engineering Relay)](https://github.com/emeraldsongold/rer), a high-performance network relay, telemetry routing, and distributed network diagnostics tool.

## Overview

This chart deploys RER onto a Kubernetes cluster with production-grade security hardening and reliability configurations conforming to SPEC §16.D:

- **Non-root execution**: Runs as UID:GID `65532:65532` with a `readOnlyRootFilesystem` and dropped `ALL` capabilities (Restricted Pod Security Standard).
- **Probes**: Configurable startup, liveness, and readiness probes exercising real application health via `/usr/local/bin/rer health` without inducing excessive mission traffic.
- **Resource bounds**: Default cpu and memory requests and limits to guarantee bounded memory and prevent node starvation.
- **Configurable services**: Flexible UDP and TCP port mappings supporting single-interface, paired-interface, and relay chain topologies.
- **Configuration management**: Mounts RER configuration via ConfigMap or an existing Kubernetes Secret for sensitive credentials.
- **Persistence**: Optional persistent volume support for persistent state directories under `/var/lib/rer`.

---

## CRITICAL: Replica Scaling and Routing Semantics

> **WARNING**: Scaling replicas does not preserve UDP/TCP routing semantics automatically.

RER relays streaming datagrams and framed byte streams with deterministic sequence continuity, bounded queues, and per-stream diagnostic accounting. Unlike stateless web applications (e.g. HTTP REST APIs) where individual requests can be dispatched to any arbitrary backend replica:

1. **UDP Telemetry Streams**: Standard Kubernetes `ClusterIP` or `LoadBalancer` services load-balance UDP datagrams packet-by-packet across backend pods based on IP/port hashing. Spreading inbound packets of a continuous telemetry stream across multiple replica pods scatters sequence numbers, breaks frame reassembly, and causes artificial packet loss, reordering, and corrupt state counters.
2. **Stateful Stream Tracking**: Stream statistics, queue drop policies, sequence gaps, and health checks are tracked in-memory per relay process. Spreading traffic across replicas fractures telemetry state.
3. **Topology Recommendations**:
   - For high availability or multi-hop forwarding, deploy distinct named instances or relay chains with explicit port ownership (see `values-multi-instance.yaml`).
   - For independent streams, route traffic to dedicated Services targeting single-replica pods or distinct relay instances.
   - Do **not** simply increase `replicaCount` behind a shared multi-stream Service expecting transparent load distribution.

---

## Installation

### Prerequisites

- Kubernetes 1.24+
- Helm 3.8+

### Install Chart

```bash
# Add or clone repository, then install:
helm install rer ./deploy/helm/rer

# Install using a specific values file:
helm install rer ./deploy/helm/rer -f ./deploy/helm/rer/values-simple.yaml
```

### Upgrade Chart

```bash
# Upgrade with custom values:
helm upgrade rer ./deploy/helm/rer -f custom-values.yaml

# Configuration changes trigger an automatic rolling deployment via config hash annotation.
```

### Rollback Chart

```bash
# View release revision history:
helm history rer

# Rollback to previous revision:
helm rollback rer 1
```

### Uninstall Chart

```bash
helm uninstall rer
```

---

## Configuration Reference

| Parameter | Description | Default |
|---|---|---|
| `replicaCount` | Number of pod replicas (see routing semantics warning above) | `1` |
| `image.repository` | RER container image repository | `ghcr.io/emeraldsongold/rer` |
| `image.tag` | Image tag (defaults to `Chart.appVersion`) | `""` |
| `image.digest` | Immutable container image digest | `""` |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `serviceAccount.create` | Create a dedicated ServiceAccount | `true` |
| `podSecurityContext.runAsNonRoot` | Enforce non-root execution | `true` |
| `podSecurityContext.runAsUser` | Pod UID | `65532` |
| `securityContext.readOnlyRootFilesystem` | Mount root filesystem read-only | `true` |
| `securityContext.allowPrivilegeEscalation` | Prohibit privilege escalation | `false` |
| `securityContext.capabilities.drop` | Capabilities to drop | `["ALL"]` |
| `service.type` | Kubernetes service type | `ClusterIP` |
| `service.ports` | List of mapped ports (name, port, protocol) | `[{name: telemetry-udp, port: 5000, protocol: UDP}]` |
| `resources.limits.cpu` | CPU limit | `500m` |
| `resources.limits.memory` | Memory limit | `128Mi` |
| `resources.requests.cpu` | CPU request | `100m` |
| `resources.requests.memory` | Memory request | `32Mi` |
| `probes.liveness.enabled` | Enable exec liveness probe (`rer health`) | `true` |
| `probes.readiness.enabled` | Enable exec readiness probe (`rer health`) | `true` |
| `probes.startup.enabled` | Enable exec startup probe (`rer health`) | `true` |
| `config` | Raw RER YAML configuration mounted into `/etc/rer/rer.yaml` | See `values.yaml` |
| `existingSecret` | Name of existing Secret for sensitive configuration | `""` |
| `secretKey` | Key within existing Secret containing configuration | `rer.yaml` |
| `persistence.enabled` | Mount persistent volume for state (`/var/lib/rer`) | `false` |
| `podDisruptionBudget.enabled` | Enable PodDisruptionBudget | `false` |
| `metrics.enabled` | Enable Prometheus metrics endpoint | `false` |
| `metrics.serviceMonitor.enabled` | Deploy Prometheus Operator ServiceMonitor | `false` |

---

## Example Topologies

1. **Simple Single Relay** (`values-simple.yaml`): Single UDP telemetry forwarding instance listening on port 5000 and forwarding to destination port 5001.
2. **Multi-Instance Relay Chain** (`values-multi-instance.yaml`): Ingress relay receiving UDP 5000 and forwarding across internal TCP stream 6000, connected to an egress relay delivering to destination UDP 7000.

---

## Smoke Deployment on Free CI Kubernetes (kind)

A smoke deployment script is provided at `deploy/helm/smoke-test.sh`. On environments where a Kubernetes cluster (e.g., [kind](https://kind.sigs.k8s.io/) or Minikube) is available:

```bash
# 1. Create kind cluster
kind create cluster --name rer-test

# 2. Run smoke tests
./deploy/helm/smoke-test.sh

# 3. Clean up cluster
kind delete cluster --name rer-test
```

### Limitation Notice

In environments lacking Docker daemon access, nested container support, or pre-configured Kubernetes clusters (such as lightweight build environments or standard non-containerized CI runners), cluster smoke deployment cannot provision ephemeral nodes. The smoke test script detects this condition automatically, skips live deployment, validates chart linting and schema rendering, and documents the limitation cleanly.
