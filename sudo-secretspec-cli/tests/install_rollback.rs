use std::path::PathBuf;

use sudo_secretspec_cli::install::InstallRequest;
use sudo_secretspec_cli::platform;

#[test]
fn install_request_defaults_are_generic() {
    let req = InstallRequest::from_cli(Some(PathBuf::from("/tmp/decl.toml")), true, false);
    assert_eq!(req.vault, PathBuf::from(platform::DEFAULT_VAULT));
    assert_eq!(req.service_user, platform::DEFAULT_USER);
    assert_eq!(req.service_group, platform::DEFAULT_GROUP);
    assert_eq!(req.profile, "default");
    assert!(req.dry_run);
    assert!(!req.adopt_existing);
}

#[test]
fn rollback_rejects_unprotected_snapshot_path() {
    let err = sudo_secretspec_cli::rollback::run(std::path::Path::new("/tmp/not-a-snapshot"))
        .expect_err("unprotected snapshot must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("root") || msg.contains("outside") || msg.contains("invalid"),
        "{msg}"
    );
}

// --- snapshot trust decisions -------------------------------------------
//
// `plan_restore` is the half of rollback that decides what may be written.
// These cover the case that made the previous implementation an arbitrary
// root-owned write: a snapshot directory naming its own destinations.

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}

/// Write a `<index>.prior` / `<index>.path` pair, plus a manifest row.
fn write_pair(dir: &std::path::Path, index: usize, dest: &str, body: &[u8], manifest: &mut String) {
    std::fs::write(dir.join(format!("{index}.prior")), body).unwrap();
    std::fs::write(dir.join(format!("{index}.path")), dest).unwrap();
    manifest.push_str(&format!("{}  {}\n", sha256_hex(body), dest));
}

#[test]
fn plan_restore_requires_a_manifest() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("0.prior"), b"x").unwrap();
    std::fs::write(
        dir.path().join("0.path"),
        platform::client_path(platform::host()),
    )
    .unwrap();

    let err = sudo_secretspec_cli::rollback::plan_restore(dir.path())
        .expect_err("a snapshot without a manifest must be refused");
    assert!(err.to_string().contains("manifest"), "{err}");
}

#[test]
fn plan_restore_refuses_destinations_the_installer_does_not_own() {
    let dir = tempfile::tempdir().unwrap();
    let mut manifest = String::new();
    // A hash-consistent pair is still refused: the destination is the problem.
    write_pair(
        dir.path(),
        0,
        "/etc/sudoers",
        b"root ALL=(ALL) NOPASSWD: ALL\n",
        &mut manifest,
    );
    std::fs::write(dir.path().join("MANIFEST.sha256"), &manifest).unwrap();

    let err = sudo_secretspec_cli::rollback::plan_restore(dir.path())
        .expect_err("an unowned destination must be refused");
    assert!(err.to_string().contains("does not own"), "{err}");
}

#[test]
fn plan_restore_refuses_bytes_that_do_not_match_the_manifest() {
    let dir = tempfile::tempdir().unwrap();
    let mut manifest = String::new();
    write_pair(
        dir.path(),
        0,
        platform::client_path(platform::host()),
        b"original",
        &mut manifest,
    );
    std::fs::write(dir.path().join("MANIFEST.sha256"), &manifest).unwrap();
    // Swap the payload after the manifest was written.
    std::fs::write(dir.path().join("0.prior"), b"substituted").unwrap();

    let err = sudo_secretspec_cli::rollback::plan_restore(dir.path())
        .expect_err("a payload that does not match the manifest must be refused");
    assert!(err.to_string().contains("manifest hash"), "{err}");
}

#[test]
fn plan_restore_accepts_an_owned_verified_pair_with_its_installed_mode() {
    let dir = tempfile::tempdir().unwrap();
    let mut manifest = String::new();
    write_pair(
        dir.path(),
        0,
        platform::SUDOERS_FILE,
        b"policy",
        &mut manifest,
    );
    std::fs::write(dir.path().join("MANIFEST.sha256"), &manifest).unwrap();

    let plan = sudo_secretspec_cli::rollback::plan_restore(dir.path()).expect("valid snapshot");
    assert_eq!(plan.len(), 1);
    let (_, dest, mode) = &plan[0];
    assert_eq!(dest, std::path::Path::new(platform::SUDOERS_FILE));
    // Restored from the shared artifact table, never from the snapshot.
    assert_eq!(*mode, 0o440);
}

// --- sudoers is validated before it can take effect ---------------------
//
// An unparseable file under sudoers.d makes sudo refuse to run at all, which
// would strand the operator with no way to elevate and no way to re-run the
// installer to repair it. The policy must never reach its live name unchecked.

#[test]
fn a_valid_policy_stages_without_touching_the_live_path() {
    let dir = tempfile::tempdir().unwrap();
    let dst = dir.path().join("sudo-secretspec");
    let policy = "operator ALL=(root) NOPASSWD: /usr/local/libexec/sudo-secretspec doctor\n";

    let staged = sudo_secretspec_cli::install::stage_sudoers(&dst, policy, 0o440)
        .expect("visudo should accept this policy");

    assert!(staged.is_file(), "staged policy should exist");
    assert!(
        !dst.exists(),
        "staging must not create the live policy; only a later rename may"
    );
    // sudo ignores sudoers.d entries whose names contain a dot, so a crash
    // between staging and renaming cannot activate the staged file.
    assert!(
        staged.file_name().unwrap().to_string_lossy().contains('.'),
        "staged name must contain a dot so sudo ignores it"
    );
}

/// The policy this project actually ships, run through the real `visudo`.
///
/// The other two tests use hand-written stand-ins, so nothing before this
/// checked that the generated text parses — and an unparseable file under
/// `sudoers.d` strands the operator with no way to elevate.
#[test]
fn the_shipped_policy_parses_and_gates_boundary_lifecycle() {
    let dir = tempfile::tempdir().unwrap();
    let dst = dir.path().join("sudo-secretspec");
    let host = if platform::IS_MACOS {
        platform::Host::MacOs
    } else {
        platform::Host::Linux
    };
    let policy = sudo_secretspec_cli::install::sudoers_text_for_host(
        host,
        "someoperator",
        platform::DEFAULT_USER,
    )
    .unwrap();
    let broker = format!("{}/libexec/sudo-secretspec", platform::PREFIX);

    sudo_secretspec_cli::install::stage_sudoers(&dst, &policy, 0o440)
        .expect("visudo should accept the policy we ship");

    // Per-operation authentication for the client path. Without this the gate
    // is sudo's shared 5-minute timestamp, which any other command can satisfy.
    assert!(
        policy.contains(&format!(
            "Defaults!{} timestamp_timeout=0\n",
            platform::client_path(host)
        )),
        "{policy}"
    );
    // The broker stays NOPASSWD: mediated credential operations are the
    // autonomous path, and making them prompt would wedge every agent.
    assert!(
        policy.contains(&format!("NOPASSWD: {broker} __broker source-set --*\n")),
        "{policy}"
    );
    // Boundary lifecycle must never be granted without authentication. The
    // client path carries no NOPASSWD rule at all; it rides the host's own
    // admin grant, which is what `timestamp_timeout=0` then constrains.
    assert!(
        !policy.contains(&format!("NOPASSWD: {}", platform::client_path(host))),
        "{policy}"
    );
    // The broker must not inherit the caller's HOME: the engine resolves its
    // user-global config from it, and that config can aim a root writer at an
    // arbitrary path. `env_reset` does NOT cover this — macOS ships
    // `env_keep += "HOME"` globally and it wins. Probed on sudo 1.9.17p2:
    // `env_reset` alone gave the caller's home; each of these gave /var/root.
    for flag in ["env_keep-=\"HOME\"", "always_set_home"] {
        assert!(
            policy.lines().any(|line| line
                .starts_with(&format!("Defaults!{broker} "))
                && line.contains(flag)),
            "libexec policy line must carry {flag}:\n{policy}"
        );
    }
}

#[test]
fn an_invalid_policy_never_reaches_the_live_path() {
    let dir = tempfile::tempdir().unwrap();
    let dst = dir.path().join("sudo-secretspec");
    std::fs::write(&dst, "operator ALL=(root) NOPASSWD: /bin/true\n").unwrap();
    let before = std::fs::read(&dst).unwrap();

    let err =
        sudo_secretspec_cli::install::stage_sudoers(&dst, "this is not sudoers syntax\n", 0o440)
            .expect_err("visudo must reject this policy");
    assert!(err.to_string().contains("visudo"), "{err}");

    assert_eq!(
        std::fs::read(&dst).unwrap(),
        before,
        "an existing policy must be left byte-for-byte untouched"
    );
    let leftovers: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n != "sudo-secretspec")
        .collect();
    assert!(
        leftovers.is_empty(),
        "rejected policy must be cleaned up, found {leftovers:?}"
    );
}

#[test]
fn installed_artifact_table_pins_the_sensitive_modes() {
    use sudo_secretspec_cli::install::artifact_mode;
    assert_eq!(
        artifact_mode(std::path::Path::new(platform::SUDOERS_FILE)),
        Some(0o440)
    );
    assert_eq!(
        artifact_mode(std::path::Path::new(
            platform::client_path(platform::host())
        )),
        Some(0o755)
    );
    assert_eq!(
        artifact_mode(std::path::Path::new(platform::CONFIG_PATH)),
        Some(0o444)
    );
    assert_eq!(artifact_mode(std::path::Path::new("/etc/passwd")), None);
}

/// The ordering guarantee, checked against the real artifact table rather than
/// the rebased one the module's own tests use.
///
/// Uninstall closes the sudo grant before removing the paths it names, so the
/// policy has to come first no matter how the table is ordered or extended.
#[test]
fn uninstall_plans_the_real_sudo_policy_before_any_binary() {
    let artifacts = sudo_secretspec_cli::install::installed_artifacts();
    let plan = sudo_secretspec_cli::uninstall::plan_uninstall(
        &artifacts,
        &[],
        std::path::Path::new(platform::SUDOERS_DIR),
    );

    assert_eq!(plan.len(), artifacts.len(), "every owned path is planned");
    assert_eq!(plan[0].path, PathBuf::from(platform::SUDOERS_FILE));
    assert!(
        plan[1..]
            .iter()
            .all(|step| !step.path.starts_with(platform::SUDOERS_DIR)),
        "only one policy is owned, and it leads the plan: {plan:?}"
    );
}

/// With no manifest there is no proof of ownership, so the policy survives.
///
/// The empty slice is exactly what a missing or unreadable `MANIFEST.sha256`
/// parses to, which makes this the behaviour on a host where the manifest was
/// already removed by hand.
#[test]
fn uninstall_never_removes_a_policy_it_cannot_prove_it_wrote() {
    use sudo_secretspec_cli::uninstall::Action;

    let plan = sudo_secretspec_cli::uninstall::plan_uninstall(
        &sudo_secretspec_cli::install::installed_artifacts(),
        &[],
        std::path::Path::new(platform::SUDOERS_DIR),
    );
    assert!(
        !matches!(plan[0].action, Action::Remove),
        "an unproven policy must never be planned for removal: {:?}",
        plan[0]
    );
}

// `plan_prune` is the half of snapshot GC that decides what may be deleted, so
// it is tested here without root for the same reason `plan_restore` is: the
// retention decision is the part worth pinning.

use sudo_secretspec_cli::install::{Snapshot, list_snapshots, plan_prune};

fn snapshot(stamp: u64, restorable: bool) -> Snapshot {
    Snapshot {
        path: PathBuf::from(format!(
            "/usr/local/libexec/sudo-secretspec-rollback-{stamp}"
        )),
        stamp,
        restorable,
    }
}

#[test]
fn plan_prune_always_removes_unrestorable_snapshots() {
    // A first install captures nothing, and `plan_restore` rejects the result
    // outright, so keeping one only accumulates directories forever.
    let snaps = [
        snapshot(300, false),
        snapshot(200, false),
        snapshot(100, true),
    ];
    let doomed = plan_prune(&snaps, 3);
    assert_eq!(doomed.len(), 2, "{doomed:?}");
    assert!(
        doomed
            .iter()
            .all(|p| p.ends_with("sudo-secretspec-rollback-300")
                || p.ends_with("sudo-secretspec-rollback-200"))
    );
}

#[test]
fn plan_prune_keeps_the_newest_restorable_snapshots() {
    let snaps = [
        snapshot(100, true),
        snapshot(400, true),
        snapshot(200, true),
        snapshot(300, true),
    ];
    let doomed = plan_prune(&snaps, 2);
    // 400 and 300 are newest and survive; 200 and 100 age out.
    assert_eq!(doomed.len(), 2, "{doomed:?}");
    assert!(
        doomed
            .iter()
            .any(|p| p.ends_with("sudo-secretspec-rollback-100"))
    );
    assert!(
        doomed
            .iter()
            .any(|p| p.ends_with("sudo-secretspec-rollback-200"))
    );
}

#[test]
fn plan_prune_keeping_more_than_exist_deletes_nothing() {
    let snaps = [snapshot(100, true), snapshot(200, true)];
    assert!(plan_prune(&snaps, 3).is_empty());
}

#[test]
fn list_snapshots_ignores_directories_that_are_not_ours() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();

    // Restorable: holds a captured artifact.
    let restorable = root.join("sudo-secretspec-rollback-100");
    std::fs::create_dir(&restorable).unwrap();
    std::fs::write(restorable.join("0.prior"), b"bytes").unwrap();

    // Unrestorable: the shape a first install leaves behind.
    std::fs::create_dir(root.join("sudo-secretspec-rollback-200")).unwrap();

    // Neither of these may ever become a pruning candidate: one is an unrelated
    // neighbour in libexec, the other is not stamped with a number.
    std::fs::create_dir(root.join("stayturgid-secretspec-wrapper.d")).unwrap();
    std::fs::create_dir(root.join("sudo-secretspec-rollback-notanumber")).unwrap();

    let mut found = list_snapshots(root);
    found.sort_by_key(|s| s.stamp);

    assert_eq!(found.len(), 2, "{found:?}");
    assert_eq!(found[0].stamp, 100);
    assert!(found[0].restorable);
    assert_eq!(found[1].stamp, 200);
    assert!(
        !found[1].restorable,
        "no .prior file means nothing to restore"
    );
}
