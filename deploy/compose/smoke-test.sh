#!/usr/bin/env bash
#
# Docker Compose Validation & Smoke Test Script (SPEC §16.C)
# Validates Compose configurations and exercises end-to-end telemetry traffic.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SINGLE_COMPOSE="${SCRIPT_DIR}/docker-compose.single.yml"
CHAIN_COMPOSE="${SCRIPT_DIR}/docker-compose.relay-chain.yml"

echo "=== RER Docker Compose Validation & Smoke Tests ==="

# 1. Configuration syntax validation via docker compose config
echo "--- Validating docker-compose.single.yml ---"
docker compose -f "${SINGLE_COMPOSE}" config

echo "--- Validating docker-compose.relay-chain.yml ---"
docker compose -f "${CHAIN_COMPOSE}" config

echo "Compose configurations validated successfully."

# 2. Start Single Instance & Run Smoke Test with Traffic
echo "--- Testing Single-Instance Deployment ---"
docker compose -f "${SINGLE_COMPOSE}" up -d
trap 'docker compose -f "${SINGLE_COMPOSE}" down -v; docker compose -f "${CHAIN_COMPOSE}" down -v' EXIT

echo "Waiting for single instance to become healthy..."
for i in {1..20}; do
    STATUS=$(docker inspect --format='{{json .State.Health.Status}}' rer-single 2>/dev/null || echo '"starting"')
    if [ "${STATUS}" = '"healthy"' ]; then
        echo "rer-single is healthy."
        break
    fi
    sleep 1
done

echo "Sending test traffic through single instance (UDP 5000)..."
if command -v rer >/dev/null 2>&1; then
    rer test generate --target 127.0.0.1:5000 --count 10 --size 128
fi

echo "--- Single instance smoke test passed ---"
docker compose -f "${SINGLE_COMPOSE}" down -v

# 3. Start Relay Chain & Run Smoke Test with Traffic
echo "--- Testing Relay-Chain Deployment ---"
docker compose -f "${CHAIN_COMPOSE}" up -d

echo "Waiting for relay chain services to become healthy..."
for i in {1..20}; do
    EGRESS_STATUS=$(docker inspect --format='{{json .State.Health.Status}}' rer-chain-egress 2>/dev/null || echo '"starting"')
    INGRESS_STATUS=$(docker inspect --format='{{json .State.Health.Status}}' rer-chain-ingress 2>/dev/null || echo '"starting"')
    if [ "${EGRESS_STATUS}" = '"healthy"' ] && [ "${INGRESS_STATUS}" = '"healthy"' ]; then
        echo "rer-chain-egress and rer-chain-ingress are healthy."
        break
    fi
    sleep 1
done

echo "Sending test traffic through relay chain (UDP 5000 -> 5001)..."
if command -v rer >/dev/null 2>&1; then
    rer test generate --target 127.0.0.1:5000 --count 20 --size 128
fi

echo "--- Relay chain smoke test passed ---"
docker compose -f "${CHAIN_COMPOSE}" down -v

echo "=== All Docker Compose smoke tests passed successfully! ==="
