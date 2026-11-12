use std::process::Command;

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_sudo-secretspec"))
}

#[test]
fn version_identifies_downstream_distribution() {
    let output = binary()
        .arg("--version")
        .output()
        .expect("run sudo-secretspec");
    assert!(output.status.success());
    let reported = String::from_utf8(output.stdout).unwrap().trim().to_string();

    // Assert the shape, not a literal: the point is that the binary announces
    // itself as the downstream distribution rather than plain upstream, and
    // pinning the number here only meant editing this test on every release.
    assert_eq!(
        reported,
        format!("sudo-secretspec {}", env!("CARGO_PKG_VERSION"))
    );
    assert!(
        reported.contains("-sudo."),
        "version must identify the fork: {reported}"
    );
}

#[test]
fn public_cli_rejects_control_plane_overrides() {
    for option in ["--file", "--provider", "--profile", "--direct"] {
        let output = binary()
            .args([option, "untrusted", "check"])
            .output()
            .expect("run sudo-secretspec");
        assert!(!output.status.success(), "accepted {option}");
    }
}

#[test]
fn help_exposes_typed_boundary_commands() {
    let output = binary()
        .arg("--help")
        .output()
        .expect("run sudo-secretspec");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    for command in [
        "get",
        "set",
        "add",
        "delete",
        "check",
        "export",
        "template-check",
        "schema",
        "audit-verify",
        "undeclare",
        "run",
        "install",
        "uninstall",
        "doctor",
        "rollback",
        "backup",
    ] {
        assert!(stdout.contains(command), "missing {command}");
    }
}

#[test]
fn backup_help_describes_privilege_and_restore_boundary() {
    let output = binary().args(["backup", "--help"]).output().unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    for text in [
        "status",
        "run",
        "restore",
        "0.21.1-sudo.6",
        "explicit backup setup",
    ] {
        assert!(help.contains(text), "missing {text}: {help}");
    }
    let output = binary()
        .args(["backup", "restore", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("Never overwrites the live vault")
    );
}

#[test]
fn backup_commands_reject_control_plane_overrides() {
    for args in [
        vec!["backup", "run", "--config", "/tmp/untrusted"],
        vec!["backup", "run", "--helper", "/tmp/untrusted"],
        vec!["backup", "restore", "--repo", "/tmp/untrusted"],
    ] {
        let output = binary().args(args).output().unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("unexpected argument"));
    }
}

#[cfg(target_os = "linux")]
#[test]
fn unsupported_backup_platform_is_explicit_and_never_elevates() {
    let output = binary().args(["backup", "status"]).output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("macOS only"));
}

#[test]
fn template_check_requires_a_reason() {
    // Every brokered operation is audited, and the ledger entry is keyed by the
    // reason digest. A `template-check` that could run without one would be an
    // unaudited read of the boundary's configuration.
    let output = binary()
        .arg("template-check")
        .output()
        .expect("run sudo-secretspec");
    assert!(
        !output.status.success(),
        "template-check ran without --reason"
    );
}

#[test]
fn schema_requires_a_reason() {
    // Every brokered operation is audited, and the ledger entry is keyed by the
    // reason digest. A `schema` that could run without one would be an
    // unaudited read of the boundary's typed shape.
    let output = binary()
        .arg("schema")
        .output()
        .expect("run sudo-secretspec");
    assert!(!output.status.success(), "schema ran without --reason");
}

#[test]
fn schema_rejects_a_caller_profile() {
    // The profile is pinned to the root-owned config. Accepting one here would
    // let a caller enumerate shapes of profiles the boundary is not configured
    // for.
    let output = binary()
        .args(["schema", "--profile", "production", "--reason", "why"])
        .output()
        .expect("run sudo-secretspec");
    assert!(
        !output.status.success(),
        "schema accepted a caller --profile"
    );
}

#[test]
fn add_requires_a_description() {
    // `add` used to be a silent alias for `set`: the broker mapped source-add
    // to the engine's `set`, which refuses a name that is not already
    // declared, so `add` could never perform the operation it is named for.
    // A declaration carries a description, so requiring one here is what keeps
    // the two operations distinct.
    let output = binary()
        .args(["add", "SOME_SECRET", "--reason", "why"])
        .output()
        .expect("run sudo-secretspec");
    assert!(!output.status.success(), "add ran without --description");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--description"),
        "error should name the missing flag: {stderr}"
    );
}

#[test]
fn add_rejects_an_empty_description() {
    let output = binary()
        .args([
            "add",
            "SOME_SECRET",
            "--description",
            "   ",
            "--reason",
            "why",
        ])
        .output()
        .expect("run sudo-secretspec");
    assert!(!output.status.success(), "add accepted a blank description");
}

#[test]
fn undeclare_requires_a_reason() {
    let output = binary()
        .args(["undeclare", "SOME_SECRET"])
        .output()
        .expect("run sudo-secretspec");
    assert!(!output.status.success(), "undeclare ran without --reason");
}

#[test]
fn add_and_undeclare_are_a_matched_pair() {
    // The asymmetry this subcommand exists to fix: `add` mutates the runtime
    // manifest on the cheap NOPASSWD path, and until `undeclare` there was no
    // way back on that same path -- `delete` removes a value and leaves the
    // declaration standing. An agent could dirty the manifest with an
    // unprivileged call and then need an operator at a Touch ID prompt to undo
    // it. Both must stay reachable from the same surface.
    let output = binary()
        .arg("--help")
        .output()
        .expect("run sudo-secretspec");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("add"), "add missing");
    assert!(stdout.contains("undeclare"), "undeclare missing");
}
