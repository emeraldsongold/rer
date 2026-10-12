#!/usr/bin/env bash
#
# Free Tooling SBOM Generator & Vulnerability Scanner for RER Docker Image
# Tools: Syft (Anchore) for SBOM generation, Trivy (Aqua Security) for vulnerability scanning.
# Both are free, open-source utilities conforming to SPEC §16.B.
#
set -euo pipefail

IMAGE_TAG="${1:-ghcr.io/emeraldsongold/rer:0.1.0}"
OUTPUT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== RER Docker Artifact Security & Packaging Gate ==="
echo "Target image: ${IMAGE_TAG}"
echo "Output dir:   ${OUTPUT_DIR}"

# 1. Generate SBOM using Syft (free, open source)
if command -v syft >/dev/null 2>&1; then
    echo "Generating SPDX 2.3 JSON SBOM with syft..."
    syft "${IMAGE_TAG}" -o spdx-json="${OUTPUT_DIR}/rer.spdx.json"
    echo "SBOM generated at ${OUTPUT_DIR}/rer.spdx.json"
else
    echo "Notice: 'syft' not found in PATH. To generate live SBOM with syft, install syft:"
    echo "  curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin"
fi

# 2. Run Vulnerability Scan using Trivy (free, open source)
if command -v trivy >/dev/null 2>&1; then
    echo "Running vulnerability scan with trivy..."
    trivy image \
        --severity HIGH,CRITICAL \
        --exit-code 0 \
        --format json \
        --output "${OUTPUT_DIR}/vulnerability-scan.json" \
        "${IMAGE_TAG}"
    echo "Scan report written to ${OUTPUT_DIR}/vulnerability-scan.json"
else
    echo "Notice: 'trivy' not found in PATH. To scan live image with trivy, install trivy:"
    echo "  curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin"
fi

echo "=== Done ==="
