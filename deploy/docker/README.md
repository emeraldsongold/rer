# RER Docker Container Image and Deployment

This directory contains the multi-architecture Dockerfile, SBOM, and security scanning tooling for RER (RER Engineering Relay), fulfilling SPEC §16.B and §17.

## Specifications and Guarantees

- **Multi-Architecture**: Supports Linux `amd64` (`x86_64`) and `arm64` (`aarch64`).
- **Minimal Distroless Base**: Based on `gcr.io/distroless/cc-debian12:nonroot`.
- **No Shell or Package Manager**: The runtime image contains no shell (`/bin/sh`, `/bin/bash`) and no package manager (`apt`, `dpkg`), strictly limiting attacker lateral movement.
- **Unprivileged Non-Root**: Executes by default as UID `65532` (`nonroot`), GID `65532`.
- **Zero Added Capabilities**: Designed to run with all Linux capabilities dropped (`--cap-drop=ALL`) and `no-new-privileges: true`.
- **Health Check**: Exercises real application health via the `rer health` exec command querying the internal relay socket.
- **Graceful Shutdown**: Traps `SIGTERM` and `SIGINT` to flush queues and shut down cleanly.

## Building Multi-Arch Images

Build with Docker Buildx:

```bash
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t ghcr.io/emeraldsongold/rer:0.1.0 \
  -f deploy/docker/Dockerfile \
  .
```

## Running the Container

```bash
docker run -d \
  --name rer \
  --read-only \
  --cap-drop=ALL \
  --security-opt no-new-privileges:true \
  -u 65532:65532 \
  -v /path/to/rer.yaml:/etc/rer/rer.yaml:ro \
  -v rer-state:/var/lib/rer \
  -p 5000:5000/udp \
  ghcr.io/emeraldsongold/rer:0.1.0
```

## Security Verification (SBOM and Vulnerability Scan)

Free and open-source tooling is used for security auditing:

- **SBOM**: Full SPDX 2.3 JSON specification generated via Syft at `deploy/docker/rer.spdx.json`.
- **Vulnerability Scan**: Free container vulnerability scanning with Aqua Security Trivy at `deploy/docker/vulnerability-scan.json`.

Run the scan script:

```bash
./deploy/docker/generate-sbom-and-scan.sh ghcr.io/emeraldsongold/rer:0.1.0
```
