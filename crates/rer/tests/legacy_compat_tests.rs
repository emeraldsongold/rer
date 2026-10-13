use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn rer_bin() -> &'static str {
    env!("CARGO_BIN_EXE_rer")
}

#[test]
fn test_legacy_os_evaluation_script_exists_and_executable() {
    let script_path = repo_root().join("packaging/legacy-compat-test.sh");
    assert!(
        script_path.exists(),
        "packaging/legacy-compat-test.sh must exist"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script_path).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "packaging/legacy-compat-test.sh must be executable"
        );
    }

    let content = std::fs::read_to_string(&script_path).expect("read legacy-compat-test.sh");

    // Acceptance criteria and spec verification
    assert!(
        content.contains("A successful compile alone is never claimed as support"),
        "script must emphasize SPEC §4 compile-alone principle"
    );
    assert!(
        content.contains("Debian 10"),
        "script must target Debian 10"
    );
    assert!(
        content.contains("Ubuntu 20.04"),
        "script must target Ubuntu 20.04"
    );
    assert!(
        content.contains("RHEL 7") || content.contains("CentOS 7"),
        "script must target RHEL 7 / CentOS 7"
    );
    assert!(
        content.contains("PLATFORM_SUPPORT.md"),
        "script must reference PLATFORM_SUPPORT.md"
    );
}

#[test]
fn test_legacy_compat_test_script_runs_cleanly() {
    let script_path = repo_root().join("packaging/legacy-compat-test.sh");

    // 1. Test --help flag
    let help_output = Command::new(&script_path)
        .arg("--help")
        .output()
        .expect("run script --help");
    assert!(
        help_output.status.success(),
        "script --help must exit successfully"
    );
    let help_str = String::from_utf8_lossy(&help_output.stdout);
    assert!(help_str.contains("Usage:"));
    assert!(help_str.contains("--dist-dir"));
    assert!(help_str.contains("--bin"));

    // 2. Test execution with current binary
    let temp_dist = std::env::temp_dir().join(format!("rer_legacy_test_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&temp_dist);

    let run_output = Command::new(&script_path)
        .arg("--dist-dir")
        .arg(&temp_dist)
        .arg("--bin")
        .arg(rer_bin())
        .output()
        .expect("run script execution");

    assert!(
        run_output.status.success(),
        "script execution failed: stderr: {}",
        String::from_utf8_lossy(&run_output.stderr)
    );

    let stdout = String::from_utf8_lossy(&run_output.stdout);
    assert!(
        stdout.contains("RER Legacy OS Compatibility Evaluation"),
        "stdout must have script title"
    );
    assert!(
        stdout.contains("Debian 10"),
        "stdout must evaluate Debian 10"
    );
    assert!(
        stdout.contains("Ubuntu 20.04"),
        "stdout must evaluate Ubuntu 20.04"
    );
    assert!(stdout.contains("RHEL 7"), "stdout must evaluate RHEL 7");
    assert!(
        stdout.contains("A successful compile alone is NEVER claimed as support"),
        "stdout must confirm SPEC §4 compile-alone principle"
    );

    let _ = std::fs::remove_dir_all(&temp_dist);
}

#[test]
fn test_documented_results_in_platform_support() {
    let platform_doc = repo_root().join("PLATFORM_SUPPORT.md");
    assert!(platform_doc.exists(), "PLATFORM_SUPPORT.md must exist");

    let content = std::fs::read_to_string(&platform_doc).expect("read PLATFORM_SUPPORT.md");

    // 1. Acceptance criteria: compile alone is never claimed as support
    assert!(
        content.contains("A successful compile alone is never claimed as support"),
        "PLATFORM_SUPPORT.md must explicitly record the SPEC §4 rule"
    );

    // 2. Section 3 exists with milestone identifier
    assert!(
        content.contains("## 3. Best-Effort Compatibility Targets (Milestone RER-F-018)"),
        "Section 3 must exist for Milestone RER-F-018"
    );

    // 3. Evaluation of Debian 10 Buster
    assert!(
        content.contains("Debian 10 (Buster)"),
        "Must evaluate Debian 10 Buster"
    );
    assert!(
        content.contains("glibc") && content.contains("2.28"),
        "Must record Debian 10 glibc 2.28 baseline"
    );
    assert!(
        content.contains("GLIBC_2.34' not found") || content.contains("GLIBC_2.34"),
        "Must record Debian 10 dynamic glibc failure"
    );

    // 4. Evaluation of Ubuntu 20.04 LTS
    assert!(
        content.contains("Ubuntu 20.04 LTS (Focal Fossa)"),
        "Must evaluate Ubuntu 20.04 LTS"
    );
    assert!(
        content.contains("2.31"),
        "Must record Ubuntu 20.04 glibc 2.31 baseline"
    );
    assert!(
        content.contains("GLIBC_2.32' not found") || content.contains("GLIBC_2.32"),
        "Must record Ubuntu 20.04 dynamic glibc failure"
    );

    // 5. Evaluation of RHEL 7 / CentOS 7
    assert!(
        content.contains("RHEL 7 / CentOS 7"),
        "Must evaluate RHEL 7 / CentOS 7"
    );
    assert!(
        content.contains("2.17"),
        "Must record RHEL 7 glibc 2.17 baseline"
    );
    assert!(
        content.contains("GLIBC_2.18' not found") || content.contains("GLIBC_2.18"),
        "Must record RHEL 7 dynamic glibc failure"
    );

    // 6. musl static alternative documented
    assert!(
        content.contains("x86_64-unknown-linux-musl") || content.contains("static musl"),
        "Must document static musl alternative for legacy platforms"
    );

    // 7. Systemd versions and hardening limitations
    assert!(
        content.contains("systemd 241")
            && content.contains("systemd 245")
            && content.contains("systemd 219"),
        "Must document systemd versions across legacy targets"
    );
    assert!(
        content.contains("ProtectSystem=strict"),
        "Must analyze ProtectSystem=strict compatibility on legacy systemd"
    );

    // 8. Security lifecycle / EOL status
    assert!(
        content.contains("End of Life") || content.contains("EOL"),
        "Must document security lifecycle / EOL status for legacy platforms"
    );

    // 9. Summary compatibility matrix
    assert!(
        content.contains("### Summary Compatibility Matrix"),
        "Must contain summary compatibility matrix table"
    );
    assert!(
        content.contains("Tier 1 (Supported)")
            && content.contains("Legacy Best-Effort Only (Static)")
            && content.contains("Unsupported"),
        "Matrix must classify support tiers accurately"
    );
}

#[test]
fn test_binary_glibc_dependency_analysis() {
    let binary_bytes = std::fs::read(rer_bin()).expect("read rer binary");

    // Scan for GLIBC_ version markers in binary strings / rodata
    let binary_str = String::from_utf8_lossy(&binary_bytes);
    let mut glibc_versions = Vec::new();

    for line in binary_str.lines() {
        for word in line.split_whitespace() {
            if let Some(pos) = word.find("GLIBC_2.") {
                let candidate = &word[pos..];
                let end = candidate
                    .find(|c: char| !c.is_ascii_digit() && c != '.' && c != '_')
                    .unwrap_or(candidate.len());
                let ver_str = &candidate[..end];
                if ver_str.starts_with("GLIBC_2.") && !glibc_versions.contains(&ver_str.to_string())
                {
                    glibc_versions.push(ver_str.to_string());
                }
            }
        }
    }

    // Binary must require glibc symbols if dynamically linked
    if !glibc_versions.is_empty() {
        let has_modern_glibc = glibc_versions
            .iter()
            .any(|v| v.contains("GLIBC_2.32") || v.contains("GLIBC_2.34"));
        assert!(
            has_modern_glibc,
            "Dynamically compiled binary on modern toolchain must reference GLIBC_2.32+ symbols: {:?}",
            glibc_versions
        );
    }
}
