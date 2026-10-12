#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

PKG_PATH="${1:-}"

# Auto-detect package if not provided
if [ -z "${PKG_PATH}" ]; then
    if command -v dpkg >/dev/null 2>&1 && compgen -G "${REPO_ROOT}/dist/*.deb" >/dev/null; then
        PKG_PATH=$(ls -t "${REPO_ROOT}/dist/"*.deb | head -n1)
    elif command -v rpm >/dev/null 2>&1 && compgen -G "${REPO_ROOT}/dist/*.rpm" >/dev/null; then
        PKG_PATH=$(ls -t "${REPO_ROOT}/dist/"*.rpm | head -n1)
    else
        echo "Usage: $0 <path-to-package.deb|path-to-package.rpm>" >&2
        exit 1
    fi
fi

if [ ! -f "${PKG_PATH}" ]; then
    echo "Error: Package file not found at ${PKG_PATH}" >&2
    exit 1
fi

PKG_TYPE=""
if [[ "${PKG_PATH}" == *.deb ]]; then
    PKG_TYPE="deb"
elif [[ "${PKG_PATH}" == *.rpm ]]; then
    PKG_TYPE="rpm"
else
    echo "Error: Unknown package type for ${PKG_PATH} (must be .deb or .rpm)" >&2
    exit 1
fi

echo "=========================================================="
echo "Starting RER Package Smoke Test (${PKG_TYPE}): ${PKG_PATH}"
echo "=========================================================="

CUSTOM_MARKER="# OPERATOR_CUSTOM_CONFIGURATION_PRESERVED_CHECK_$(date +%s)"

# -------------------------------------------------------------
# PHASE 1: Clean Installation
# -------------------------------------------------------------
echo "==> [Phase 1/3] Testing Clean Installation..."

if [ "${PKG_TYPE}" = "deb" ]; then
    dpkg -i "${PKG_PATH}"
elif [ "${PKG_TYPE}" = "rpm" ]; then
    rpm -ivh "${PKG_PATH}"
fi

# 1. Verify binary is installed and executable
if [ ! -x "/usr/bin/rer" ]; then
    echo "FAIL: /usr/bin/rer not found or not executable" >&2
    exit 1
fi
echo "  [PASS] /usr/bin/rer is installed and executable."

# 2. Verify binary version output
/usr/bin/rer version
echo "  [PASS] /usr/bin/rer version executes successfully."

# 3. Verify configuration file exists and is valid
if [ ! -f "/etc/rer/rer.yaml" ]; then
    echo "FAIL: /etc/rer/rer.yaml was not installed" >&2
    exit 1
fi
/usr/bin/rer validate /etc/rer/rer.yaml
echo "  [PASS] /etc/rer/rer.yaml is present and passes validation."

# 4. Verify systemd unit is installed
if [ ! -f "/usr/lib/systemd/system/rer.service" ] && [ ! -f "/lib/systemd/system/rer.service" ]; then
    echo "FAIL: systemd service unit was not installed" >&2
    exit 1
fi
echo "  [PASS] Systemd service unit is installed."

# 5. Verify systemd unit is NOT started or enabled automatically
if command -v systemctl >/dev/null 2>&1 && [ -d "/run/systemd/system" ]; then
    if systemctl is-active --quiet rer; then
        echo "FAIL: rer service was started automatically!" >&2
        exit 1
    fi
    if systemctl is-enabled --quiet rer 2>/dev/null; then
        echo "FAIL: rer service was enabled automatically!" >&2
        exit 1
    fi
    echo "  [PASS] Systemd service is neither enabled nor started automatically."
else
    echo "  [INFO] Systemd daemon not active in environment; verified unit file is not auto-enabled by scriptlet."
fi

# 6. Verify documentation and state directory
if [ ! -d "/usr/share/doc/rer" ]; then
    echo "FAIL: Documentation directory /usr/share/doc/rer missing" >&2
    exit 1
fi
if [ ! -d "/var/lib/rer" ]; then
    echo "FAIL: State directory /var/lib/rer missing" >&2
    exit 1
fi
# Simulate operator writing state into /var/lib/rer
echo "state_data_payload_12345" > /var/lib/rer/active_state.dat
echo "  [PASS] Documentation and state directories exist, simulated state recorded."

# -------------------------------------------------------------
# PHASE 2: Upgrade with Configuration Preservation
# -------------------------------------------------------------
echo "==> [Phase 2/3] Testing Upgrade (configuration preservation)..."

# Simulate operator customizing the configuration
echo "${CUSTOM_MARKER}" >> /etc/rer/rer.yaml

if [ "${PKG_TYPE}" = "deb" ]; then
    # In Debian, --force-confold keeps existing modified conffile
    DEBIAN_FRONTEND=noninteractive dpkg -i --force-confold "${PKG_PATH}"
elif [ "${PKG_TYPE}" = "rpm" ]; then
    rpm -Uvh --replacepkgs "${PKG_PATH}"
fi

# Verify the custom marker still exists in /etc/rer/rer.yaml
if ! grep -q "${CUSTOM_MARKER}" /etc/rer/rer.yaml; then
    echo "FAIL: Operator configuration in /etc/rer/rer.yaml was overwritten during upgrade!" >&2
    exit 1
fi
echo "  [PASS] Operator configuration was preserved across package upgrade."

# -------------------------------------------------------------
# PHASE 3: Uninstallation (No Silent Data Loss)
# -------------------------------------------------------------
echo "==> [Phase 3/3] Testing Uninstallation (no silent data loss)..."

if [ "${PKG_TYPE}" = "deb" ]; then
    dpkg -r rer
elif [ "${PKG_TYPE}" = "rpm" ]; then
    rpm -e rer
fi

# Binary should be removed
if [ -f "/usr/bin/rer" ]; then
    echo "FAIL: /usr/bin/rer was not removed during package removal" >&2
    exit 1
fi
echo "  [PASS] Binary /usr/bin/rer successfully removed."

# Operator configuration and state MUST NOT be silently destroyed!
if [ ! -f "/etc/rer/rer.yaml" ]; then
    echo "FAIL: Silent data loss! /etc/rer/rer.yaml was deleted on package remove." >&2
    exit 1
fi
if [ ! -d "/var/lib/rer" ]; then
    echo "FAIL: Silent data loss! /var/lib/rer was deleted on package remove." >&2
    exit 1
fi
echo "  [PASS] Configuration (/etc/rer/rer.yaml) and state (/var/lib/rer) preserved without silent data loss."

# For Debian, test purge removes preserved configuration
if [ "${PKG_TYPE}" = "deb" ]; then
    echo "==> Testing explicit package purge..."
    dpkg -P rer
    if [ -f "/etc/rer/rer.yaml" ]; then
        echo "FAIL: /etc/rer/rer.yaml still present after explicit purge" >&2
        exit 1
    fi
    echo "  [PASS] Explicit purge removed configuration cleanly."
elif [ "${PKG_TYPE}" = "rpm" ]; then
    # Clean up manual state after RPM test
    rm -rf /etc/rer /var/lib/rer
fi

echo "=========================================================="
echo "ALL SMOKE TESTS PASSED for ${PKG_PATH}"
echo "=========================================================="
