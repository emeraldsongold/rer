#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

VERSION="${VERSION:-}"
if [ -z "${VERSION}" ]; then
    VERSION=$(grep -E '^version\s*=' "${REPO_ROOT}/Cargo.toml" | head -n1 | sed -E 's/.*"([^"]+)".*/\1/')
fi
if [ -z "${VERSION}" ]; then
    VERSION="0.1.0"
fi

TARGET_ARCH="${TARGET_ARCH:-x86_64}"
OUT_DIR="${OUT_DIR:-${REPO_ROOT}/dist}"
RER_BIN="${RER_BIN:-}"
BUILD_RELEASE="${BUILD_RELEASE:-false}"

usage() {
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  --arch <x86_64|aarch64|all>   Target architecture (default: x86_64)"
    echo "  --out-dir <dir>               Output directory (default: dist/)"
    echo "  --bin <path>                  Pre-built rer binary path"
    echo "  --build                       Compile release binaries before packaging"
    echo "  --version <version>           Set version explicitly"
    echo "  -h, --help                    Show this help"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --arch)
            TARGET_ARCH="$2"
            shift 2
            ;;
        --out-dir)
            OUT_DIR="$2"
            shift 2
            ;;
        --bin)
            RER_BIN="$2"
            shift 2
            ;;
        --build)
            BUILD_RELEASE=true
            shift
            ;;
        --version)
            VERSION="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage
            ;;
    esac
done

mkdir -p "${OUT_DIR}"

build_binary_if_needed() {
    local arch="$1"
    local bin_path="$2"

    if [ -n "${bin_path}" ] && [ -f "${bin_path}" ]; then
        echo "${bin_path}"
        return 0
    fi

    if [ "${arch}" = "x86_64" ]; then
        local candidate="${REPO_ROOT}/target/release/rer"
        if [ ! -f "${candidate}" ] || [ "${BUILD_RELEASE}" = "true" ]; then
            (cd "${REPO_ROOT}" && cargo build --release --locked --bin rer) >&2
        fi
        echo "${candidate}"
    elif [ "${arch}" = "aarch64" ]; then
        local candidate="${REPO_ROOT}/target/aarch64-unknown-linux-gnu/release/rer"
        if [ ! -f "${candidate}" ] || [ "${BUILD_RELEASE}" = "true" ]; then
            (cd "${REPO_ROOT}" && CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc cargo build --target aarch64-unknown-linux-gnu --release --locked --bin rer) >&2
        fi
        echo "${candidate}"
    else
        echo "Unsupported architecture for automated compilation: ${arch}" >&2
        exit 1
    fi
}

package_for_arch() {
    local arch="$1"
    local bin_input="$2"
    local bin_file

    bin_file=$(build_binary_if_needed "${arch}" "${bin_input}")

    if [ ! -f "${bin_file}" ]; then
        echo "Error: Binary not found at ${bin_file}" >&2
        exit 1
    fi

    local deb_arch="amd64"
    local rpm_arch="x86_64"
    if [ "${arch}" = "aarch64" ] || [ "${arch}" = "arm64" ]; then
        deb_arch="arm64"
        rpm_arch="aarch64"
        arch="aarch64"
    fi

    echo "==> Packaging RER v${VERSION} for ${arch}..."

    # 1. Standalone binary tarball
    local tarball_name="rer-${VERSION}-linux-${arch}.tar.gz"
    local tarball_stage
    tarball_stage=$(mktemp -d)
    local pkg_dir="${tarball_stage}/rer-${VERSION}-linux-${arch}"
    mkdir -p "${pkg_dir}/bin" "${pkg_dir}/doc" "${pkg_dir}/systemd" "${pkg_dir}/config" "${pkg_dir}/examples"

    cp "${bin_file}" "${pkg_dir}/bin/rer"
    chmod 0755 "${pkg_dir}/bin/rer"
    cp "${REPO_ROOT}/README.md" "${pkg_dir}/doc/"
    cp "${REPO_ROOT}/docs/CONFIGURATION.md" "${pkg_dir}/doc/"
    cp "${SCRIPT_DIR}/systemd/rer.service" "${pkg_dir}/systemd/"
    cp "${SCRIPT_DIR}/config/rer.yaml" "${pkg_dir}/config/"
    cp -r "${REPO_ROOT}/examples/"* "${pkg_dir}/examples/"

    tar -czf "${OUT_DIR}/${tarball_name}" -C "${tarball_stage}" "rer-${VERSION}-linux-${arch}"
    rm -rf "${tarball_stage}"
    echo "    Created standalone tarball: ${OUT_DIR}/${tarball_name}"

    # 2. Debian .deb package
    if command -v dpkg-deb >/dev/null 2>&1; then
        local deb_stage
        deb_stage=$(mktemp -d)
        mkdir -p "${deb_stage}/DEBIAN"
        mkdir -p "${deb_stage}/usr/bin"
        mkdir -p "${deb_stage}/etc/rer"
        mkdir -p "${deb_stage}/lib/systemd/system"
        mkdir -p "${deb_stage}/usr/share/doc/rer"

        sed -e "s/@VERSION@/${VERSION}/g" -e "s/@ARCH@/${deb_arch}/g" "${SCRIPT_DIR}/deb/control.template" > "${deb_stage}/DEBIAN/control"
        cp "${SCRIPT_DIR}/deb/conffiles" "${deb_stage}/DEBIAN/conffiles"
        cp "${SCRIPT_DIR}/deb/postinst" "${deb_stage}/DEBIAN/postinst"
        cp "${SCRIPT_DIR}/deb/prerm" "${deb_stage}/DEBIAN/prerm"
        cp "${SCRIPT_DIR}/deb/postrm" "${deb_stage}/DEBIAN/postrm"
        chmod 0755 "${deb_stage}/DEBIAN/postinst" "${deb_stage}/DEBIAN/prerm" "${deb_stage}/DEBIAN/postrm"

        cp "${bin_file}" "${deb_stage}/usr/bin/rer"
        chmod 0755 "${deb_stage}/usr/bin/rer"
        cp "${SCRIPT_DIR}/config/rer.yaml" "${deb_stage}/etc/rer/rer.yaml"
        chmod 0644 "${deb_stage}/etc/rer/rer.yaml"
        cp "${SCRIPT_DIR}/systemd/rer.service" "${deb_stage}/lib/systemd/system/rer.service"
        chmod 0644 "${deb_stage}/lib/systemd/system/rer.service"
        cp "${REPO_ROOT}/README.md" "${deb_stage}/usr/share/doc/rer/"
        cp "${REPO_ROOT}/docs/CONFIGURATION.md" "${deb_stage}/usr/share/doc/rer/"

        local deb_name="rer_${VERSION}_${deb_arch}.deb"
        dpkg-deb --build --root-owner-group "${deb_stage}" "${OUT_DIR}/${deb_name}" >/dev/null
        rm -rf "${deb_stage}"
        echo "    Created Debian package: ${OUT_DIR}/${deb_name}"
    else
        echo "    Notice: dpkg-deb not available, skipping .deb generation"
    fi

    # 3. RPM .rpm package
    if command -v rpmbuild >/dev/null 2>&1; then
        local rpm_stage
        rpm_stage=$(mktemp -d)
        mkdir -p "${rpm_stage}"/{BUILD,RPMS,SOURCES,SPECS,SRPMS,BUILDROOT}

        cp "${bin_file}" "${rpm_stage}/SOURCES/rer"
        cp "${SCRIPT_DIR}/config/rer.yaml" "${rpm_stage}/SOURCES/rer.yaml"
        cp "${SCRIPT_DIR}/systemd/rer.service" "${rpm_stage}/SOURCES/rer.service"
        cp "${REPO_ROOT}/README.md" "${rpm_stage}/SOURCES/README.md"
        cp "${REPO_ROOT}/docs/CONFIGURATION.md" "${rpm_stage}/SOURCES/CONFIGURATION.md"
        cp "${SCRIPT_DIR}/rpm/rer.spec" "${rpm_stage}/SPECS/rer.spec"

        local rpm_target_flag=""
        if [ "${rpm_arch}" = "aarch64" ]; then
            rpm_target_flag="--target aarch64"
        fi

        rpmbuild --define "_topdir ${rpm_stage}" \
                 --define "_version ${VERSION}" \
                 ${rpm_target_flag} \
                 -bb "${rpm_stage}/SPECS/rer.spec" >/dev/null 2>&1

        local generated_rpm
        generated_rpm=$(find "${rpm_stage}/RPMS" -name "*.rpm" | head -n1)
        if [ -n "${generated_rpm}" ] && [ -f "${generated_rpm}" ]; then
            local rpm_dest_name="rer-${VERSION}-1.${rpm_arch}.rpm"
            cp "${generated_rpm}" "${OUT_DIR}/${rpm_dest_name}"
            echo "    Created RPM package: ${OUT_DIR}/${rpm_dest_name}"
        fi
        rm -rf "${rpm_stage}"
    else
        echo "    Notice: rpmbuild not available, skipping .rpm generation"
    fi
}

# Run packaging for selected architecture(s)
ARCHES=()
if [ "${TARGET_ARCH}" = "all" ]; then
    ARCHES=("x86_64" "aarch64")
else
    ARCHES=("${TARGET_ARCH}")
fi

for arch in "${ARCHES[@]}"; do
    bin_for_arch=""
    if [ "${#ARCHES[@]}" -eq 1 ] && [ -n "${RER_BIN}" ]; then
        bin_for_arch="${RER_BIN}"
    fi
    package_for_arch "${arch}" "${bin_for_arch}"
done

# 4. Checksums (SHA256SUMS)
echo "==> Generating checksums..."
(
    cd "${OUT_DIR}"
    rm -f SHA256SUMS
    sha256sum * > SHA256SUMS 2>/dev/null || true
)
echo "    Created checksum file: ${OUT_DIR}/SHA256SUMS"

# 5. Version metadata (metadata.json)
echo "==> Generating version metadata..."
GIT_COMMIT="unknown"
if command -v git >/dev/null 2>&1 && [ -d "${REPO_ROOT}/.git" ]; then
    GIT_COMMIT=$(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo "unknown")
fi
BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

METADATA_FILE="${OUT_DIR}/metadata.json"
cat > "${METADATA_FILE}" << EOF
{
  "name": "rer",
  "version": "${VERSION}",
  "description": "RER Engineering Relay",
  "git_commit": "${GIT_COMMIT}",
  "build_timestamp": "${BUILD_DATE}",
  "architectures": [$(printf '"%s",' "${ARCHES[@]}" | sed 's/,$//')],
  "artifacts": [
EOF

FIRST=true
for f in "${OUT_DIR}"/*; do
    fname=$(basename "$f")
    if [ "${fname}" = "SHA256SUMS" ] || [ "${fname}" = "metadata.json" ]; then
        continue
    fi
    if [ -f "$f" ]; then
        fsize=$(stat -c%s "$f" 2>/dev/null || stat -f%z "$f" 2>/dev/null || echo 0)
        fhash=$(sha256sum "$f" | cut -d' ' -f1)
        ftype="unknown"
        farch="unknown"
        if [[ "${fname}" == *.deb ]]; then
            ftype="deb"
            if [[ "${fname}" == *amd64* ]]; then farch="x86_64"; else farch="aarch64"; fi
        elif [[ "${fname}" == *.rpm ]]; then
            ftype="rpm"
            if [[ "${fname}" == *x86_64* ]]; then farch="x86_64"; else farch="aarch64"; fi
        elif [[ "${fname}" == *.tar.gz ]]; then
            ftype="tarball"
            if [[ "${fname}" == *x86_64* ]]; then farch="x86_64"; else farch="aarch64"; fi
        fi

        if [ "$FIRST" = true ]; then
            FIRST=false
        else
            echo "," >> "${METADATA_FILE}"
        fi

        cat >> "${METADATA_FILE}" << ARTEOF
    {
      "filename": "${fname}",
      "type": "${ftype}",
      "architecture": "${farch}",
      "size_bytes": ${fsize},
      "sha256": "${fhash}"
    }
ARTEOF
    fi
done

cat >> "${METADATA_FILE}" << EOF

  ]
}
EOF
echo "    Created metadata file: ${METADATA_FILE}"
echo "==> Packaging complete in ${OUT_DIR}"
