# syntax=docker/dockerfile:1
#
# Multi-architecture Dockerfile for RER (RER Engineering Relay)
# Target architectures: linux/amd64, linux/arm64
#
# Security & Operational Constraints (SPEC §16.B, §17):
# - Minimal distroless base image (gcr.io/distroless/cc-debian12:nonroot)
# - Runs as unprivileged user nonroot (UID:GID 65532:65532)
# - Zero added capabilities (cap_drop: ALL)
# - No shell (/bin/sh, /bin/bash) in runtime image
# - No package manager (apt, dpkg, apk) in runtime image
# - Real application healthcheck via exec ["/usr/local/bin/rer", "health"]
# - Graceful SIGTERM shutdown
# - OCI image annotations matching binary version

ARG RUST_VERSION=1.80
ARG BUILDPLATFORM=linux/amd64

# ============================================================================
# Stage 1: Build binary
# ============================================================================
FROM --platform=$BUILDPLATFORM rust:${RUST_VERSION}-slim-bookworm AS builder

ARG TARGETARCH
ARG TARGETOS
ARG VERSION=0.1.0

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libc6-dev \
    pkg-config \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace manifests
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/

# Build release binary
RUN cargo build --release --locked --package rer

# ============================================================================
# Stage 2: Minimal runtime image (no shell, no package manager, non-root)
# ============================================================================
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime

ARG VERSION=0.1.0

# OCI standard annotations and version metadata (SPEC §16.E)
LABEL org.opencontainers.image.title="rer" \
      org.opencontainers.image.description="RER Engineering Relay — resilient network telemetry forwarder" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.source="https://github.com/emeraldsongold/rer" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="Ronald Edward Reeves Jr"

# Copy binary to standard path
COPY --from=builder --chown=65532:65532 /build/target/release/rer /usr/local/bin/rer

# Non-root user (nonroot: 65532)
USER 65532:65532

# Working directory and volumes for explicit configuration and state mounts
WORKDIR /var/lib/rer
VOLUME ["/etc/rer", "/var/lib/rer"]

# Exec-form health check exercising real application health without shell
HEALTHCHECK --interval=5s --timeout=3s --start-period=2s --retries=3 \
  CMD ["/usr/local/bin/rer", "health"]

# Default entrypoint and arguments
ENTRYPOINT ["/usr/local/bin/rer"]
CMD ["run", "--config", "/etc/rer/rer.yaml"]
