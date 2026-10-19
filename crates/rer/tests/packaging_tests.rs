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
fn test_systemd_service_unit_configuration() {
    let service_file = repo_root().join("packaging/systemd/rer.service");
    assert!(
        service_file.exists(),
        "packaging/systemd/rer.service must exist"
    );

    let content = std::fs::read_to_string(&service_file).expect("read rer.service");

    assert!(
        content.contains("ExecStart=/usr/bin/rer run --config /etc/rer/rer.yaml"),
        "service must execute rer with /etc/rer/rer.yaml"
    );
    assert!(
        content.contains("ProtectSystem=strict"),
        "service must enforce strict file protection"
    );
    assert!(
        content.contains("NoNewPrivileges=true"),
        "service must disable privilege escalation"
    );
    assert!(
        content.contains("User=rer"),
        "service must run under unprivileged rer user"
    );
    assert!(
        content.contains("Group=rer"),
        "service must run under rer group"
    );
    assert!(
        content.contains("Restart=on-failure"),
        "service must restart on failure"
    );
    assert!(
        content.contains("WantedBy=multi-user.target"),
        "service must specify standard multi-user install target"
    );
}

#[test]
fn test_packaged_example_configuration_validity() {
    let config_file = repo_root().join("packaging/config/rer.yaml");
    assert!(config_file.exists(), "packaging/config/rer.yaml must exist");

    let content = std::fs::read_to_string(&config_file).expect("read rer.yaml");
    let config = rer::Config::from_yaml_str(&content).expect("config must parse cleanly");
    let validation_errors = config.validate();
    assert!(
        validation_errors.is_empty(),
        "packaging example config must be valid: {:?}",
        validation_errors
    );

    // Validate using the built CLI binary
    let output = Command::new(rer_bin())
        .arg("validate")
        .arg(&config_file)
        .output()
        .expect("rer validate execution");
    assert!(
        output.status.success(),
        "rer validate must pass on packaging/config/rer.yaml"
    );
}

#[test]
fn test_debian_packaging_specifications() {
    let deb_dir = repo_root().join("packaging/deb");

    // 1. Control template
    let control_tpl = deb_dir.join("control.template");
    let control_content = std::fs::read_to_string(&control_tpl).expect("read control.template");
    assert!(control_content.contains("Package: rer"));
    assert!(control_content.contains("Architecture: @ARCH@"));
    assert!(control_content.contains("Version: @VERSION@"));

    // 2. Conffiles
    let conffiles = deb_dir.join("conffiles");
    let conffiles_content = std::fs::read_to_string(&conffiles).expect("read conffiles");
    assert!(
        conffiles_content.contains("/etc/rer/rer.yaml"),
        "conffiles must register /etc/rer/rer.yaml to protect operator config during upgrades"
    );

    // 3. Postinst: safe defaults, NOT auto-started or auto-enabled
    let postinst = deb_dir.join("postinst");
    let postinst_content = std::fs::read_to_string(&postinst).expect("read postinst");
    for line in postinst_content.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("echo") && !trimmed.starts_with('#') {
            assert!(
                !trimmed.contains("systemctl enable"),
                "postinst must not execute systemctl enable: {}",
                trimmed
            );
            assert!(
                !trimmed.contains("systemctl start"),
                "postinst must not execute systemctl start: {}",
                trimmed
            );
        }
    }
    assert!(
        postinst_content.contains("NOT enabled or started automatically"),
        "postinst must inform user of safe defaults"
    );

    // 4. Postrm: removal preserves data, purge cleans up
    let postrm = deb_dir.join("postrm");
    let postrm_content = std::fs::read_to_string(&postrm).expect("read postrm");
    assert!(
        postrm_content.contains("remove)"),
        "postrm must handle package removal"
    );
    assert!(
        postrm_content.contains("purge)"),
        "postrm must handle package purge"
    );
    assert!(
        postrm_content.contains("have been preserved"),
        "postrm must notify operator of preserved state on removal"
    );
}

#[test]
fn test_rpm_packaging_specifications() {
    let spec_file = repo_root().join("packaging/rpm/rer.spec");
    assert!(spec_file.exists(), "packaging/rpm/rer.spec must exist");

    let content = std::fs::read_to_string(&spec_file).expect("read rer.spec");

    assert!(content.contains("Name:           rer"));
    assert!(content.contains("License:        Apache-2.0"));
    assert!(
        content.contains("%config(noreplace) %{_sysconfdir}/rer/rer.yaml"),
        "RPM spec must declare rer.yaml as %config(noreplace) to preserve operator changes on upgrade"
    );
    assert!(
        content.contains("%{_unitdir}/rer.service"),
        "RPM spec must install systemd unit"
    );
    assert!(
        content.contains("%{_bindir}/rer"),
        "RPM spec must install rer binary"
    );
    assert!(
        content.contains("/var/lib/rer"),
        "RPM spec must configure state directory"
    );

    // Check %post does not enable or start unit
    let post_section = content.split("%post").nth(1).unwrap_or("");
    let post_code = post_section.split("%preun").next().unwrap_or("");
    for line in post_code.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("echo") && !trimmed.starts_with('#') {
            assert!(
                !trimmed.contains("systemctl enable"),
                "RPM %post must not execute systemctl enable: {}",
                trimmed
            );
            assert!(
                !trimmed.contains("systemctl start"),
                "RPM %post must not execute systemctl start: {}",
                trimmed
            );
        }
    }

    // Check %postun preserves config and state on uninstall
    let postun_section = content.split("%postun").nth(1).unwrap_or("");
    let postun_code = postun_section.split("%files").next().unwrap_or("");
    assert!(
        postun_code.contains("have been preserved"),
        "RPM %postun must explain that state and config are preserved"
    );
}

#[test]
fn test_packaging_script_and_artifact_generation() {
    let pkg_script = repo_root().join("packaging/package.sh");
    assert!(pkg_script.exists(), "packaging/package.sh must exist");

    let temp_out = std::env::temp_dir().join(format!("rer_test_dist_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp_out);
    std::fs::create_dir_all(&temp_out).unwrap();

    let output = Command::new(&pkg_script)
        .arg("--arch")
        .arg("x86_64")
        .arg("--bin")
        .arg(rer_bin())
        .arg("--out-dir")
        .arg(&temp_out)
        .output()
        .expect("run packaging script");

    assert!(
        output.status.success(),
        "packaging script failed: stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // 1. Verify standalone tarball exists and contains required components
    let tarball = temp_out.join("rer-0.1.0-linux-x86_64.tar.gz");
    assert!(tarball.exists(), "standalone tarball must be generated");

    let tar_list = Command::new("tar")
        .arg("-tzf")
        .arg(&tarball)
        .output()
        .expect("inspect tarball");
    assert!(tar_list.status.success());
    let tar_entries = String::from_utf8_lossy(&tar_list.stdout);
    assert!(tar_entries.contains("bin/rer"));
    assert!(tar_entries.contains("doc/README.md"));
    assert!(tar_entries.contains("systemd/rer.service"));
    assert!(tar_entries.contains("config/rer.yaml"));

    // 2. Verify Debian .deb package
    let deb_pkg = temp_out.join("rer_0.1.0_amd64.deb");
    if Command::new("dpkg-deb").arg("--version").output().is_ok() {
        assert!(deb_pkg.exists(), "rer_0.1.0_amd64.deb must be generated");

        let dpkg_c = Command::new("dpkg-deb")
            .arg("-c")
            .arg(&deb_pkg)
            .output()
            .expect("dpkg-deb -c");
        assert!(dpkg_c.status.success());
        let deb_entries = String::from_utf8_lossy(&dpkg_c.stdout);
        assert!(deb_entries.contains("usr/bin/rer"));
        assert!(deb_entries.contains("etc/rer/rer.yaml"));
        assert!(deb_entries.contains("lib/systemd/system/rer.service"));
        assert!(deb_entries.contains("usr/share/doc/rer/"));

        let dpkg_i = Command::new("dpkg-deb")
            .arg("-I")
            .arg(&deb_pkg)
            .output()
            .expect("dpkg-deb -I");
        assert!(dpkg_i.status.success());
        let deb_info = String::from_utf8_lossy(&dpkg_i.stdout);
        assert!(deb_info.contains("Package: rer"));
        assert!(deb_info.contains("Version: 0.1.0"));
        assert!(deb_info.contains("Architecture: amd64"));
    }

    // 3. Verify RPM package if rpmbuild is present
    let rpm_pkg = temp_out.join("rer-0.1.0-1.x86_64.rpm");
    if Command::new("rpmbuild").arg("--version").output().is_ok() {
        assert!(rpm_pkg.exists(), "rer-0.1.0-1.x86_64.rpm must be generated");

        if Command::new("rpm").arg("--version").output().is_ok() {
            let rpm_list = Command::new("rpm")
                .arg("-qpl")
                .arg(&rpm_pkg)
                .output()
                .expect("rpm -qpl");
            assert!(rpm_list.status.success());
            let rpm_entries = String::from_utf8_lossy(&rpm_list.stdout);
            assert!(rpm_entries.contains("/usr/bin/rer"));
            assert!(rpm_entries.contains("/etc/rer/rer.yaml"));
            assert!(rpm_entries.contains("/usr/lib/systemd/system/rer.service"));

            let rpm_conf = Command::new("rpm")
                .arg("-qpc")
                .arg(&rpm_pkg)
                .output()
                .expect("rpm -qpc");
            assert!(rpm_conf.status.success());
            let rpm_confs = String::from_utf8_lossy(&rpm_conf.stdout);
            assert!(rpm_confs.contains("/etc/rer/rer.yaml"));
        }
    }

    // 4. Verify SHA256SUMS file
    let checksums_file = temp_out.join("SHA256SUMS");
    assert!(checksums_file.exists(), "SHA256SUMS must be generated");
    let checksums_content = std::fs::read_to_string(&checksums_file).expect("read SHA256SUMS");
    assert!(
        checksums_content.contains("rer-0.1.0-linux-x86_64.tar.gz"),
        "checksums must include standalone tarball"
    );

    // 5. Verify metadata.json
    let metadata_file = temp_out.join("metadata.json");
    assert!(metadata_file.exists(), "metadata.json must be generated");
    let metadata_content = std::fs::read_to_string(&metadata_file).expect("read metadata.json");
    let meta_json: serde_json::Value =
        serde_json::from_str(&metadata_content).expect("metadata.json must be valid JSON");
    assert_eq!(meta_json["name"], "rer");
    assert_eq!(meta_json["version"], "0.1.0");
    assert!(meta_json["artifacts"].as_array().is_some());
    let artifacts = meta_json["artifacts"].as_array().unwrap();
    assert!(
        !artifacts.is_empty(),
        "metadata.json must list generated artifacts"
    );

    // Clean up temporary output directory
    let _ = std::fs::remove_dir_all(&temp_out);
}

#[test]
fn test_smoke_test_script_content_and_safety_checks() {
    let script_path = repo_root().join("packaging/smoke-test.sh");
    assert!(
        script_path.exists(),
        "packaging/smoke-test.sh must exist and be committed"
    );

    let content = std::fs::read_to_string(&script_path).expect("read smoke-test.sh");

    // Phase 1: clean install
    assert!(content.contains("[Phase 1/3] Testing Clean Installation"));
    assert!(content.contains("/usr/bin/rer version"));
    assert!(content.contains("/usr/bin/rer validate /etc/rer/rer.yaml"));
    assert!(content.contains("Systemd service is neither enabled nor started automatically"));

    // Phase 2: upgrade with configuration preservation
    assert!(content.contains("[Phase 2/3] Testing Upgrade"));
    assert!(content.contains("Operator configuration was preserved across package upgrade"));

    // Phase 3: uninstall with no silent data loss
    assert!(content.contains("[Phase 3/3] Testing Uninstallation"));
    assert!(content.contains("Binary /usr/bin/rer successfully removed"));
    assert!(content.contains("preserved without silent data loss"));
}

#[test]
fn test_install_documentation_acceptance_criteria() {
    let readme_file = repo_root().join("README.md");
    let readme_content = std::fs::read_to_string(&readme_file).expect("read README.md");

    // Acceptance criterion 1: In README.md, Documentation Index includes link to INSTALL documenting installation procedures across supported deployment targets
    assert!(
        readme_content.contains(
            "[`INSTALL`](INSTALL): Installation procedures across supported deployment targets."
        ),
        "README.md Documentation Index must link to INSTALL"
    );

    let install_file = repo_root().join("INSTALL");
    assert!(install_file.exists(), "INSTALL document must exist");
    let install_content = std::fs::read_to_string(&install_file).expect("read INSTALL");

    // Acceptance criterion 2: In INSTALL, portable standalone section documents extracting rer-<version>-linux-<arch>.tar.gz with tar -xzf and running bin/rer with configuration /etc/rer/rer.yaml and systemd unit systemd/rer.service
    assert!(
        install_content.contains("rer-<version>-linux-<arch>.tar.gz"),
        "INSTALL must document portable tarball pattern"
    );
    assert!(
        install_content.contains("tar -xzf"),
        "INSTALL must document tar -xzf command"
    );
    assert!(
        install_content.contains("bin/rer"),
        "INSTALL must document running bin/rer"
    );
    assert!(
        install_content.contains("/etc/rer/rer.yaml"),
        "INSTALL must document configuration path /etc/rer/rer.yaml"
    );
    assert!(
        install_content.contains("systemd/rer.service"),
        "INSTALL must document systemd/rer.service unit"
    );

    // Acceptance criterion 3: In INSTALL, Docker section provides commands to run the container image ghcr.io/emeraldsongold/rer:0.1.0 with options --read-only, --cap-drop=ALL, and --security-opt no-new-privileges:true, mapping port 5000:5000/udp
    assert!(
        install_content.contains("ghcr.io/emeraldsongold/rer:0.1.0"),
        "INSTALL must document Docker container image"
    );
    assert!(
        install_content.contains("--read-only"),
        "INSTALL must specify --read-only docker option"
    );
    assert!(
        install_content.contains("--cap-drop=ALL"),
        "INSTALL must specify --cap-drop=ALL docker option"
    );
    assert!(
        install_content.contains("--security-opt no-new-privileges:true"),
        "INSTALL must specify --security-opt no-new-privileges:true docker option"
    );
    assert!(
        install_content.contains("5000:5000/udp"),
        "INSTALL must specify port mapping 5000:5000/udp"
    );

    // Acceptance criterion 4: In INSTALL, Docker Compose section provides startup commands using docker compose -f deploy/compose/docker-compose.single.yml up -d for single instances and docker compose -f deploy/compose/docker-compose.relay-chain.yml up -d for relay chains
    assert!(
        install_content
            .contains("docker compose -f deploy/compose/docker-compose.single.yml up -d"),
        "INSTALL must document single instance Compose startup command"
    );
    assert!(
        install_content
            .contains("docker compose -f deploy/compose/docker-compose.relay-chain.yml up -d"),
        "INSTALL must document relay chain Compose startup command"
    );

    // Notes: apt, deb, portable, docker, docker-compose, and helm installs
    assert!(install_content.contains("apt"));
    assert!(install_content.contains("deb"));
    assert!(install_content.contains("portable"));
    assert!(install_content.contains("docker"));
    assert!(install_content.contains("docker-compose"));
    assert!(install_content.contains("helm"));
}
