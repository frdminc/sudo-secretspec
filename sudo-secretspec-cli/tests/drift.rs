/// Drift-check contract parsing tests using typed TOML configuration.
use std::path::{Path, PathBuf};
use sudo_secretspec_cli::platform;
use tempfile::TempDir;

fn write_config(dir: &TempDir, content: &str) -> PathBuf {
    let path = dir.path().join("sudo-secretspec.toml");
    std::fs::write(&path, content).unwrap();
    path
}

fn minimal_toml() -> String {
    let broker = platform::DEFAULT_BROKER_PATH;
    let vault = platform::DEFAULT_VAULT;
    let real = Path::new(platform::VAULT_REAL_PARENT).join("sudo-secretspec");
    let prefix = platform::PREFIX;
    let user = platform::DEFAULT_USER;
    let group = platform::DEFAULT_GROUP;
    format!(
        r#"
engine = "{broker}"
audit_helper = "{broker}"
vault = "{vault}"
vault_realpath = "{}"
declarations = "{prefix}/share/sudo-secretspec/secretspec.toml"
service_user = "{user}"
service_group = "{group}"
"#,
        real.display()
    )
}

#[test]
fn layout_derives_single_binary_paths() {
    let dir = TempDir::new().unwrap();
    let path = write_config(&dir, &minimal_toml());
    let layout = sudo_secretspec_cli::load_config(&path).unwrap();

    assert_eq!(layout.engine, PathBuf::from(platform::DEFAULT_BROKER_PATH));
    assert_eq!(layout.broker, PathBuf::from(platform::DEFAULT_BROKER_PATH));
    assert_eq!(
        layout.client,
        PathBuf::from(platform::client_path(platform::host()))
    );
    assert_eq!(
        layout.checker,
        PathBuf::from(platform::client_path(platform::host()))
    );
    assert_eq!(
        layout.retired,
        Path::new(platform::PREFIX).join("share/sudo-secretspec/sudo-secretspec-retired.toml")
    );
    assert_eq!(
        layout.guidance,
        Path::new(platform::PREFIX).join("share/sudo-secretspec/AI-GUIDANCE.md")
    );
    assert_eq!(
        layout.source_manifest,
        Path::new(platform::PREFIX).join("share/sudo-secretspec/MANIFEST.sha256")
    );
}

#[test]
fn layout_holds_all_config_values() {
    let dir = TempDir::new().unwrap();
    let path = write_config(&dir, &minimal_toml());
    let layout = sudo_secretspec_cli::load_config(&path).unwrap();

    assert_eq!(layout.config, path);
    assert_eq!(layout.vault, PathBuf::from(platform::DEFAULT_VAULT));
    assert_eq!(
        layout.vault_realpath,
        Path::new(platform::VAULT_REAL_PARENT).join("sudo-secretspec")
    );
    assert_eq!(layout.service_user, platform::DEFAULT_USER);
    assert_eq!(layout.service_group, platform::DEFAULT_GROUP);
    assert_eq!(
        layout.declarations,
        Some(Path::new(platform::PREFIX).join("share/sudo-secretspec/secretspec.toml"))
    );
    assert_eq!(layout.audit, PathBuf::from(platform::DEFAULT_BROKER_PATH));
}

#[test]
fn config_rejects_unknown_keys() {
    let dir = TempDir::new().unwrap();
    let bad = format!("{}\nextra = \"nope\"\n", minimal_toml());
    let path = write_config(&dir, &bad);
    assert!(sudo_secretspec_cli::load_config(&path).is_err());
}

#[test]
fn config_rejects_missing_keys() {
    let dir = TempDir::new().unwrap();
    let path = write_config(
        &dir,
        &format!("engine = \"{}\"\n", platform::DEFAULT_BROKER_PATH),
    );
    assert!(sudo_secretspec_cli::load_config(&path).is_err());
}

#[test]
fn config_rejects_relative_paths() {
    let dir = TempDir::new().unwrap();
    let invalid = minimal_toml().replace(platform::DEFAULT_BROKER_PATH, "relative/path");
    assert_ne!(invalid, minimal_toml());
    let path = write_config(&dir, &invalid);
    assert!(sudo_secretspec_cli::load_config(&path).is_err());
}

#[test]
fn config_rejects_parent_traversal_in_paths() {
    let dir = TempDir::new().unwrap();
    let invalid =
        minimal_toml().replace(platform::DEFAULT_BROKER_PATH, "/usr/libexec/../etc/passwd");
    assert_ne!(invalid, minimal_toml());
    let path = write_config(&dir, &invalid);
    assert!(sudo_secretspec_cli::load_config(&path).is_err());
}

#[test]
fn config_rejects_invalid_service_user() {
    let dir = TempDir::new().unwrap();
    let invalid = minimal_toml().replace(platform::DEFAULT_USER, "root");
    assert_ne!(invalid, minimal_toml());
    let path = write_config(&dir, &invalid);
    assert!(sudo_secretspec_cli::load_config(&path).is_err());
}

#[test]
fn config_handles_comments_and_empty_lines() {
    let dir = TempDir::new().unwrap();
    let commented = format!("# comment\n\n{}", minimal_toml());
    let path = write_config(&dir, &commented);
    assert!(sudo_secretspec_cli::load_config(&path).is_ok());
}

/// `doctor` is supposed to answer "which binary would actually run", not only
/// "is the installed one intact". This drives the whole public entry point so
/// the `InspectOptions` plumbing is covered, not just the classifier.
#[test]
fn inspect_reports_a_client_the_callers_path_would_reach_first() {
    let dir = TempDir::new().unwrap();
    let path = write_config(&dir, &minimal_toml());
    let layout = sudo_secretspec_cli::load_config(&path).unwrap();

    let shadow_dir = dir.path().join("shadow");
    std::fs::create_dir_all(&shadow_dir).unwrap();
    let shadow = shadow_dir.join("sudo-secretspec");
    std::fs::write(&shadow, b"not the installed client").unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&shadow, std::fs::Permissions::from_mode(0o755)).unwrap();

    let caller_path = std::env::join_paths([shadow_dir.as_path()]).unwrap();
    let report = sudo_secretspec_cli::inspect(
        &layout,
        &sudo_secretspec_cli::InspectOptions {
            caller_path: Some(caller_path),
            ..Default::default()
        },
    );

    let found = report
        .findings
        .iter()
        .find(|f| f.path.as_deref() == Some(shadow.display().to_string().as_str()))
        .unwrap_or_else(|| panic!("no finding for {}: {:?}", shadow.display(), report.findings));
    assert_eq!(found.code, "CLIENT_SHADOWED");
    assert!(!found.advisory);
    assert!(!report.ok);
}

/// Without a caller `PATH` the scan still runs, and it never invents a finding
/// for a directory that holds no `sudo-secretspec`.
#[test]
fn inspect_without_a_caller_path_ignores_unrelated_directories() {
    let dir = TempDir::new().unwrap();
    let path = write_config(&dir, &minimal_toml());
    let layout = sudo_secretspec_cli::load_config(&path).unwrap();

    let empty = dir.path().join("empty");
    std::fs::create_dir_all(&empty).unwrap();

    let report =
        sudo_secretspec_cli::inspect(&layout, &sudo_secretspec_cli::InspectOptions::default());
    assert!(
        !report.findings.iter().any(|f| f
            .path
            .as_deref()
            .is_some_and(|p| p.starts_with(empty.display().to_string().as_str()))),
        "{:?}",
        report.findings
    );
}

/// `inspect` must write nothing to stdout, so `doctor --json` emits only the
/// report.
///
/// `visudo -c` prints "<path>: parsed OK" on success. Inheriting its stdout put
/// that line ahead of the JSON, and anything consuming the report as JSON —
/// which is what `AI-GUIDANCE.md` tells automation to do — failed on the very
/// first character.
///
/// Re-execs this test binary because cargo captures the parent's stdout but not
/// a child's.
#[test]
fn inspect_writes_nothing_to_stdout() {
    const MARKER: &str = "SUDO_SECRETSPEC_STDOUT_CHILD";

    if std::env::var_os(MARKER).is_some() {
        let dir = TempDir::new().unwrap();
        let policy = dir.path().join("sudo-secretspec");
        // Valid on purpose: the leak only happens when visudo *succeeds*.
        std::fs::write(
            &policy,
            format!(
                "operator ALL=(root) NOPASSWD: {} doctor\n",
                platform::DEFAULT_BROKER_PATH
            ),
        )
        .unwrap();

        let mut layout = sudo_secretspec_cli::load_config(&write_config(&dir, &minimal_toml()))
            .expect("minimal config");
        layout.sudoers = policy;
        let _ =
            sudo_secretspec_cli::inspect(&layout, &sudo_secretspec_cli::InspectOptions::default());
        return;
    }

    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["inspect_writes_nothing_to_stdout", "--exact", "--nocapture"])
        .env(MARKER, "1")
        .output()
        .expect("re-exec the test binary");
    assert!(
        output.status.success(),
        "child failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        !stdout.contains("parsed OK"),
        "visudo output leaked into stdout: {stdout}"
    );
}
