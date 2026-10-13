use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use rer::config::Config;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

// ============================================================================
// 1. Chart Metadata, Version Consistency, and Structure
// ============================================================================

#[test]
fn test_helm_chart_metadata_and_version() {
    let chart_yaml_path = repo_root().join("deploy/helm/rer/Chart.yaml");
    assert!(chart_yaml_path.exists(), "Chart.yaml must exist");

    let content = fs::read_to_string(&chart_yaml_path).expect("read Chart.yaml");
    let chart: serde_yaml::Value = serde_yaml::from_str(&content).expect("parse Chart.yaml");

    assert_eq!(
        chart["apiVersion"].as_str(),
        Some("v2"),
        "Chart apiVersion must be v2"
    );
    assert_eq!(
        chart["name"].as_str(),
        Some("rer"),
        "Chart name must be rer"
    );
    assert_eq!(
        chart["type"].as_str(),
        Some("application"),
        "Chart type must be application"
    );

    let expected_version = rer::version();
    assert_eq!(
        chart["version"].as_str(),
        Some(expected_version),
        "Chart version must match binary version {}",
        expected_version
    );
    assert_eq!(
        chart["appVersion"].as_str(),
        Some(expected_version),
        "Chart appVersion must match binary version {}",
        expected_version
    );
}

// ============================================================================
// 2. Values Schema JSON Validation & Structure
// ============================================================================

#[test]
fn test_helm_chart_values_schema_and_types() {
    let schema_path = repo_root().join("deploy/helm/rer/values.schema.json");
    assert!(
        schema_path.exists(),
        "values.schema.json must exist in chart root"
    );

    let content = fs::read_to_string(&schema_path).expect("read values.schema.json");
    let schema: serde_json::Value =
        serde_json::from_str(&content).expect("values.schema.json must be valid JSON");

    assert_eq!(
        schema["$schema"].as_str(),
        Some("http://json-schema.org/draft-07/schema#"),
        "Schema must use Draft 7"
    );
    assert_eq!(schema["type"].as_str(), Some("object"));

    let props = schema["properties"].as_object().expect("schema properties");
    assert!(props.contains_key("replicaCount"));
    assert!(props.contains_key("image"));
    assert!(props.contains_key("service"));
    assert!(props.contains_key("resources"));
    assert!(props.contains_key("securityContext"));
    assert!(props.contains_key("podSecurityContext"));
    assert!(props.contains_key("probes"));
    assert!(props.contains_key("config"));

    // Verify values files parse validly
    let values_path = repo_root().join("deploy/helm/rer/values.yaml");
    let values_content = fs::read_to_string(&values_path).expect("read values.yaml");
    let values: serde_yaml::Value =
        serde_yaml::from_str(&values_content).expect("parse values.yaml");

    let simple_path = repo_root().join("deploy/helm/rer/values-simple.yaml");
    let simple_content = fs::read_to_string(&simple_path).expect("read values-simple.yaml");
    let simple: serde_yaml::Value =
        serde_yaml::from_str(&simple_content).expect("parse values-simple.yaml");

    let multi_path = repo_root().join("deploy/helm/rer/values-multi-instance.yaml");
    let multi_content = fs::read_to_string(&multi_path).expect("read values-multi-instance.yaml");
    let multi: serde_yaml::Value =
        serde_yaml::from_str(&multi_content).expect("parse values-multi-instance.yaml");

    // All must have replicaCount >= 1
    assert!(values["replicaCount"].as_i64().unwrap_or(0) >= 1);
    assert!(simple["replicaCount"].as_i64().unwrap_or(0) >= 1);
    assert!(multi["replicaCount"].as_i64().unwrap_or(0) >= 1);
}

// ============================================================================
// 3. Security Context & Non-Root Hardening
// ============================================================================

#[test]
fn test_helm_chart_security_context_and_non_root() {
    let values_path = repo_root().join("deploy/helm/rer/values.yaml");
    let content = fs::read_to_string(&values_path).expect("read values.yaml");
    let values: serde_yaml::Value = serde_yaml::from_str(&content).expect("parse values.yaml");

    // Pod security context
    let pod_sec = &values["podSecurityContext"];
    assert_eq!(
        pod_sec["runAsNonRoot"].as_bool(),
        Some(true),
        "Pod must run as non-root"
    );
    assert_eq!(
        pod_sec["runAsUser"].as_i64(),
        Some(65532),
        "Pod UID must be 65532"
    );
    assert_eq!(
        pod_sec["runAsGroup"].as_i64(),
        Some(65532),
        "Pod GID must be 65532"
    );
    assert_eq!(
        pod_sec["fsGroup"].as_i64(),
        Some(65532),
        "Pod fsGroup must be 65532"
    );

    // Container security context
    let cont_sec = &values["securityContext"];
    assert_eq!(
        cont_sec["allowPrivilegeEscalation"].as_bool(),
        Some(false),
        "allowPrivilegeEscalation must be false"
    );
    assert_eq!(
        cont_sec["readOnlyRootFilesystem"].as_bool(),
        Some(true),
        "readOnlyRootFilesystem must be true"
    );
    let caps_drop = cont_sec["capabilities"]["drop"]
        .as_sequence()
        .expect("dropped capabilities");
    assert!(
        caps_drop.iter().any(|c| c.as_str() == Some("ALL")),
        "Container must drop ALL capabilities"
    );

    // Verify deployment template includes non-root securityContext and tmp mount
    let deploy_path = repo_root().join("deploy/helm/rer/templates/deployment.yaml");
    let deploy_tpl = fs::read_to_string(&deploy_path).expect("read deployment.yaml");
    assert!(
        deploy_tpl.contains("securityContext:"),
        "deployment.yaml must configure securityContext"
    );
    assert!(
        deploy_tpl.contains("mountPath: /tmp"),
        "deployment.yaml must mount /tmp for health socket under readOnlyRootFilesystem"
    );
    assert!(
        deploy_tpl.contains("mountPath: /etc/rer"),
        "deployment.yaml must mount /etc/rer for config"
    );
}

// ============================================================================
// 4. Probes and Resource Constraints
// ============================================================================

#[test]
fn test_helm_chart_probes_and_resources() {
    let values_path = repo_root().join("deploy/helm/rer/values.yaml");
    let content = fs::read_to_string(&values_path).expect("read values.yaml");
    let values: serde_yaml::Value = serde_yaml::from_str(&content).expect("parse values.yaml");

    // Probes
    let probes = &values["probes"];
    assert_eq!(
        probes["liveness"]["enabled"].as_bool(),
        Some(true),
        "Liveness probe must be enabled"
    );
    assert_eq!(
        probes["readiness"]["enabled"].as_bool(),
        Some(true),
        "Readiness probe must be enabled"
    );
    assert_eq!(
        probes["startup"]["enabled"].as_bool(),
        Some(true),
        "Startup probe must be enabled"
    );

    // Deployment template probe command check
    let deploy_path = repo_root().join("deploy/helm/rer/templates/deployment.yaml");
    let deploy_tpl = fs::read_to_string(&deploy_path).expect("read deployment.yaml");
    assert!(
        deploy_tpl.contains("/usr/local/bin/rer") && deploy_tpl.contains("health"),
        "deployment.yaml must configure probes invoking rer health"
    );

    // Resources
    let resources = &values["resources"];
    assert!(
        resources["limits"]["cpu"].is_string() && resources["limits"]["memory"].is_string(),
        "Resource limits must be specified"
    );
    assert!(
        resources["requests"]["cpu"].is_string() && resources["requests"]["memory"].is_string(),
        "Resource requests must be specified"
    );
}

// ============================================================================
// 5. Configurable Services and Ports
// ============================================================================

#[test]
fn test_helm_chart_configurable_services_and_ports() {
    let svc_tpl_path = repo_root().join("deploy/helm/rer/templates/service.yaml");
    assert!(svc_tpl_path.exists(), "service.yaml template must exist");

    let content = fs::read_to_string(&svc_tpl_path).expect("read service.yaml");
    assert!(
        content.contains("type: {{ .Values.service.type }}"),
        "Service type must be configurable"
    );
    assert!(
        content.contains("range .Values.service.ports"),
        "Service ports must be configurable"
    );

    // Validate port definitions across values files
    for filename in [
        "values.yaml",
        "values-simple.yaml",
        "values-multi-instance.yaml",
    ] {
        let path = repo_root().join("deploy/helm/rer").join(filename);
        let val_content = fs::read_to_string(&path).expect("read values file");
        let parsed: serde_yaml::Value =
            serde_yaml::from_str(&val_content).expect("parse values file");

        let ports = parsed["service"]["ports"]
            .as_sequence()
            .expect("service.ports array");
        assert!(!ports.is_empty(), "Must configure at least one port");

        for p in ports {
            let port_num = p["port"].as_i64().expect("port number");
            assert!(
                (1..=65535).contains(&port_num),
                "Port number {port_num} must be in 1..=65535"
            );
            let proto = p["protocol"].as_str().expect("protocol");
            assert!(
                proto == "UDP" || proto == "TCP",
                "Protocol must be UDP or TCP"
            );
        }
    }
}

// ============================================================================
// 6. Replica Scaling Semantics Documentation
// ============================================================================

#[test]
fn test_helm_chart_scaling_documentation() {
    let warning_needle =
        "scaling replicas does not preserve udp/tcp routing semantics automatically";

    let readme_chart = repo_root().join("deploy/helm/rer/README.md");
    let readme_top = repo_root().join("deploy/helm/README.md");
    let values_file = repo_root().join("deploy/helm/rer/values.yaml");
    let notes_file = repo_root().join("deploy/helm/rer/templates/NOTES.txt");

    for path in [&readme_chart, &readme_top, &values_file, &notes_file] {
        assert!(path.exists(), "File {} must exist", path.display());
        let text = fs::read_to_string(path).expect("read file").to_lowercase();
        assert!(
            text.contains(warning_needle),
            "File {} must explicitly document that scaling replicas does not preserve UDP/TCP routing semantics automatically",
            path.display()
        );
    }
}

// ============================================================================
// 7. Embedded RER Configurations Validate Successfully
// ============================================================================

#[test]
fn test_helm_embedded_configurations_validate() {
    for filename in [
        "values.yaml",
        "values-simple.yaml",
        "values-multi-instance.yaml",
    ] {
        let path = repo_root().join("deploy/helm/rer").join(filename);
        let content = fs::read_to_string(&path).expect("read values file");
        let parsed: serde_yaml::Value = serde_yaml::from_str(&content).expect("parse values file");

        let config_str = parsed["config"]
            .as_str()
            .expect("config field must be string");
        let config = Config::from_yaml_str(config_str).unwrap_or_else(|errs| {
            panic!(
                "Failed to parse embedded config in {}: {:?}",
                path.display(),
                errs
            )
        });

        let errors = config.validate();
        assert!(
            errors.is_empty(),
            "Embedded config in {} had validation errors: {:?}",
            path.display(),
            errors
        );
    }
}

// ============================================================================
// 8. Smoke Test Script Syntax, Safety, and Limitations
// ============================================================================

#[test]
fn test_helm_smoke_test_script_safety_and_syntax() {
    let script_path = repo_root().join("deploy/helm/smoke-test.sh");
    assert!(script_path.exists(), "smoke-test.sh must exist");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::metadata(&script_path).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "smoke-test.sh must be executable"
        );
    }

    let content = fs::read_to_string(&script_path).expect("read smoke-test.sh");
    assert!(
        content.contains("set -euo pipefail"),
        "smoke-test.sh must use strict bash mode"
    );
    assert!(
        content.contains("values.schema.json"),
        "smoke-test.sh must test values schema"
    );
    assert!(
        content.contains("helm lint"),
        "smoke-test.sh must test helm lint"
    );
    assert!(
        content.contains("helm template"),
        "smoke-test.sh must test helm template"
    );
    assert!(
        content.contains("LIMITATION DOCUMENTED") || content.contains("limitation"),
        "smoke-test.sh must document limitation when kind/k8s is not available"
    );

    // Verify bash syntax check
    let bash_check = Command::new("bash")
        .arg("-n")
        .arg(&script_path)
        .output()
        .expect("run bash -n");
    assert!(
        bash_check.status.success(),
        "smoke-test.sh failed syntax check: {}",
        String::from_utf8_lossy(&bash_check.stderr)
    );
}

// ============================================================================
// 9. Helm Lint and Template Execution (When Helm CLI Available)
// ============================================================================

#[test]
fn test_helm_cli_lint_and_template_when_installed() {
    let chart_dir = repo_root().join("deploy/helm/rer");

    if let Ok(version_out) = Command::new("helm").arg("version").output() {
        if version_out.status.success() {
            println!("Helm CLI detected. Running helm lint and helm template...");

            // helm lint --strict
            let lint_res = Command::new("helm")
                .args(["lint", "--strict", chart_dir.to_str().unwrap()])
                .output()
                .expect("run helm lint");
            assert!(
                lint_res.status.success(),
                "helm lint failed: {}",
                String::from_utf8_lossy(&lint_res.stderr)
            );

            // helm template
            for val_arg in [
                None,
                Some("values-simple.yaml"),
                Some("values-multi-instance.yaml"),
            ] {
                let mut cmd = Command::new("helm");
                cmd.args(["template", "rer", chart_dir.to_str().unwrap()]);
                if let Some(val_file) = val_arg {
                    cmd.args(["-f", chart_dir.join(val_file).to_str().unwrap()]);
                }
                let templ_res = cmd.output().expect("run helm template");
                assert!(
                    templ_res.status.success(),
                    "helm template failed for {:?}: {}",
                    val_arg,
                    String::from_utf8_lossy(&templ_res.stderr)
                );
                let rendered = String::from_utf8_lossy(&templ_res.stdout);
                assert!(
                    rendered.contains("kind: Deployment") && rendered.contains("kind: Service"),
                    "Rendered templates must contain Deployment and Service"
                );
            }
        }
    }
}
