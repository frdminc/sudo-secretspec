//! Artifact rollback for sudo-secretspec privileged installs.
//!
//! Restores previous installed binaries/config/sudoers from a protected
//! snapshot directory. Never touches vault secret values.

use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::install::{
    PREFIX, SNAPSHOT_PREFIX, SUDOERS_DIR, artifact_owner, installed_artifacts, set_owner,
};
use crate::platform;

fn sha256_file(path: &Path) -> Result<String, RollbackError> {
    let bytes = fs::read(path)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

#[derive(Debug, Error)]
pub enum RollbackError {
    #[error("{0}")]
    Denied(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

fn require_root() -> Result<(), RollbackError> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(RollbackError::Denied("rollback requires root".into()));
    }
    Ok(())
}

/// Restore installed artifacts from a protected snapshot directory.
///
/// Expected layout, as written by `install::capture_snapshot`:
/// - `<index>.prior` — the captured bytes of one installed artifact
/// - `<index>.path`  — that artifact's absolute destination
/// - `MANIFEST.sha256` — `hash  absolute-path` rows covering every pair
///
/// Every destination must be an owned install artifact and every prior file
/// must match its manifest hash, so a writable snapshot directory cannot be
/// turned into an arbitrary root-owned write. The snapshot is never executed.
pub fn run(snapshot: &Path) -> Result<(), RollbackError> {
    require_root()?;
    let snapshot = fs::canonicalize(snapshot)
        .map_err(|e| RollbackError::Denied(format!("invalid snapshot path: {e}")))?;
    if !in_snapshot_namespace(&snapshot, Path::new(PREFIX)) {
        return Err(RollbackError::Denied(
            "rollback snapshot is outside the protected rollback directory".into(),
        ));
    }
    if snapshot.is_symlink() {
        return Err(RollbackError::Denied(
            "snapshot must not be a symlink".into(),
        ));
    }
    let meta = fs::metadata(&snapshot)?;
    if meta.permissions().mode() & 0o777 != 0o700 {
        return Err(RollbackError::Denied(
            "snapshot directory mode must be 0700".into(),
        ));
    }
    if meta.uid() != 0 {
        return Err(RollbackError::Denied(
            "snapshot directory must be owned by root".into(),
        ));
    }

    let pairs = plan_restore(&snapshot)?;
    let host = platform::host();
    let layout = crate::load_config(Path::new(platform::CONFIG_PATH)).map_err(|e| {
        RollbackError::Denied(format!("cannot read installed service identity: {e}"))
    })?;

    for (prior, dest, mode) in pairs.iter().rev() {
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        // A sudoers policy is validated before it is allowed to take effect.
        // Restoring an unparseable one would leave the operator unable to
        // elevate — including unable to run this command again to undo it.
        if dest.starts_with(SUDOERS_DIR) {
            let text = fs::read_to_string(prior).map_err(|e| {
                RollbackError::Denied(format!("snapshot sudoers policy is unreadable: {e}"))
            })?;
            let staged = crate::install::stage_sudoers(dest, &text, *mode)
                .map_err(|e| RollbackError::Denied(e.to_string()))?;
            fs::rename(&staged, dest)?;
            continue;
        }
        let tmp = dest.with_extension(format!("restore.{}", std::process::id()));
        fs::copy(prior, &tmp)?;
        let mut perms = fs::metadata(&tmp)?.permissions();
        perms.set_mode(*mode);
        fs::set_permissions(&tmp, perms)?;
        let owner = artifact_owner(host, dest, &layout.service_user, &layout.service_group);
        set_owner(host, &tmp, &owner).map_err(|e| RollbackError::Denied(e.to_string()))?;
        fs::rename(&tmp, dest)?;
    }

    // Isolated validity is not combined validity; check the whole config. As in
    // the installer, only a fault in our own file is ours to fail on — an
    // unrelated bad policy elsewhere in sudoers.d is a warning.
    let visudo = platform::visudo_path(platform::host());
    let combined_ok = Command::new(visudo)
        .arg("-c")
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !combined_ok {
        let ours = Path::new(SUDOERS_DIR).join("sudo-secretspec");
        let ours_ok = !ours.exists()
            || Command::new(visudo)
                .args(["-c", "-f"])
                .arg(&ours)
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
        if !ours_ok {
            return Err(RollbackError::Denied(
                "restored sudoers policy is invalid; inspect \
                 /etc/sudoers.d/sudo-secretspec before elevating again"
                    .into(),
            ));
        }
        eprintln!(
            "warning: `visudo -c` reports a problem elsewhere in the sudoers configuration;\n\
             warning: the restored sudo-secretspec policy itself is valid."
        );
    }

    println!("sudo-secretspec artifacts restored; runtime vault preserved");
    Ok(())
}

/// Decide what an already-authorised snapshot directory is allowed to restore.
///
/// Returns `(prior file, destination, mode)` triples. Separated from [`run`] so
/// the trust decisions — destination allowlist and manifest verification — can
/// be tested without root.
pub fn plan_restore(snapshot: &Path) -> Result<Vec<(PathBuf, PathBuf, u32)>, RollbackError> {
    plan_restore_with(snapshot, &installed_artifacts())
}

/// True when `snapshot` is a direct child of `<prefix>/libexec` whose name
/// carries the snapshot prefix `install` writes.
///
/// Compared by path component, on the canonicalised path, rather than by
/// string prefix, so a directory *inside* a snapshot cannot pass for one. The
/// location is relative to the install prefix, which is `/usr/local` on macOS
/// and `/usr` on Linux, so it follows whatever layout `install` wrote.
fn in_snapshot_namespace(snapshot: &Path, prefix: &Path) -> bool {
    let libexec = prefix.join("libexec");
    let named = snapshot
        .file_name()
        .is_some_and(|name| name.to_string_lossy().starts_with(SNAPSHOT_PREFIX));
    named && snapshot.parent() == Some(libexec.as_path())
}

/// [`plan_restore`] against an explicit table of owned artifacts, so the
/// destination allowlist can be exercised for any platform's layout.
fn plan_restore_with(
    snapshot: &Path,
    artifacts: &[(PathBuf, u32)],
) -> Result<Vec<(PathBuf, PathBuf, u32)>, RollbackError> {
    // The manifest is mandatory: it is what binds each destination to the
    // bytes allowed to land there.
    let manifest_path = snapshot.join("MANIFEST.sha256");
    let manifest_text = fs::read_to_string(&manifest_path).map_err(|e| {
        RollbackError::Denied(format!("snapshot manifest missing or unreadable: {e}"))
    })?;
    let mut expected: HashMap<PathBuf, String> = HashMap::new();
    for line in manifest_text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (hash, dest) = line
            .split_once(char::is_whitespace)
            .ok_or_else(|| RollbackError::Denied("snapshot manifest row is malformed".into()))?;
        expected.insert(PathBuf::from(dest.trim()), hash.to_string());
    }

    let owned: HashMap<PathBuf, u32> = artifacts.iter().cloned().collect();

    let mut pairs = Vec::new();
    for entry in fs::read_dir(snapshot)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if let Some(idx) = name.strip_suffix(".path") {
            let prior = snapshot.join(format!("{idx}.prior"));
            if !prior.is_file() {
                continue;
            }
            let dest = PathBuf::from(fs::read_to_string(entry.path())?.trim().to_string());
            let Some(mode) = owned.get(&dest).copied() else {
                return Err(RollbackError::Denied(format!(
                    "snapshot targets a path this installer does not own: {}",
                    dest.display()
                )));
            };
            let want = expected.get(&dest).ok_or_else(|| {
                RollbackError::Denied(format!(
                    "snapshot manifest does not cover {}",
                    dest.display()
                ))
            })?;
            if &sha256_file(&prior)? != want {
                return Err(RollbackError::Denied(format!(
                    "snapshot artifact does not match its manifest hash: {}",
                    dest.display()
                )));
            }
            pairs.push((prior, dest, mode));
        }
    }
    if pairs.is_empty() {
        return Err(RollbackError::Denied(
            "snapshot contains no restorable prior artifacts".into(),
        ));
    }
    Ok(pairs)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Debian-shaped table the installer owns: the public client on the
    /// real `PATH`, the broker under `/usr/libexec`, the policy under
    /// `/etc/sudoers.d`.
    fn debian_artifacts() -> Vec<(PathBuf, u32)> {
        vec![
            (PathBuf::from("/usr/bin/sudo-secretspec"), 0o755),
            (PathBuf::from("/usr/libexec/sudo-secretspec"), 0o755),
            (PathBuf::from("/etc/sudoers.d/sudo-secretspec"), 0o440),
        ]
    }

    /// Lay out a snapshot the way `install::capture_snapshot` does.
    fn write_snapshot(dir: &Path, entries: &[(&str, &str)]) {
        let mut manifest = String::new();
        for (index, &(dest, content)) in entries.iter().enumerate() {
            fs::write(dir.join(format!("{index}.prior")), content).unwrap();
            fs::write(dir.join(format!("{index}.path")), dest).unwrap();
            manifest.push_str(&format!("{:x}  {dest}\n", Sha256::digest(content)));
        }
        fs::write(dir.join("MANIFEST.sha256"), manifest).unwrap();
    }

    /// Snapshots live under the install prefix, which differs per platform: a
    /// macOS snapshot path is not a Linux one and vice versa.
    #[test]
    fn snapshot_namespace_follows_the_install_prefix() {
        let linux = Path::new("/usr");
        assert!(in_snapshot_namespace(
            Path::new("/usr/libexec/sudo-secretspec-rollback-1700000000"),
            linux
        ));
        assert!(!in_snapshot_namespace(
            Path::new("/usr/local/libexec/sudo-secretspec-rollback-1700000000"),
            linux
        ));

        let macos = Path::new("/usr/local");
        assert!(in_snapshot_namespace(
            Path::new("/usr/local/libexec/sudo-secretspec-rollback-1700000000"),
            macos
        ));
        assert!(!in_snapshot_namespace(
            Path::new("/usr/libexec/sudo-secretspec-rollback-1700000000"),
            macos
        ));
    }

    #[test]
    fn snapshot_namespace_rejects_lookalikes() {
        let prefix = Path::new("/usr");
        for path in [
            "/usr/libexec/sudo-secretspec",
            "/usr/libexec/other-rollback-1",
            "/usr/libexec/sudo-secretspec-rollback-1/inner",
            "/tmp/sudo-secretspec-rollback-1",
            "/usr/libexec",
        ] {
            assert!(
                !in_snapshot_namespace(Path::new(path), prefix),
                "{path} must not pass for a snapshot"
            );
        }
    }

    #[test]
    fn a_snapshot_restores_only_into_the_debian_layout() {
        let dir = tempfile::tempdir().unwrap();
        write_snapshot(
            dir.path(),
            &[
                ("/usr/bin/sudo-secretspec", "client"),
                ("/usr/libexec/sudo-secretspec", "broker"),
            ],
        );

        let plan = plan_restore_with(dir.path(), &debian_artifacts()).unwrap();
        let mut targets: Vec<_> = plan
            .iter()
            .map(|(_, dest, mode)| (dest.clone(), *mode))
            .collect();
        targets.sort();
        assert_eq!(
            targets,
            vec![
                (PathBuf::from("/usr/bin/sudo-secretspec"), 0o755),
                (PathBuf::from("/usr/libexec/sudo-secretspec"), 0o755),
            ]
        );
    }

    /// A writable snapshot directory must not become an arbitrary root write:
    /// system binaries, another vendor's sudoers file, and even the client at
    /// a path this layout does not own are all refused.
    #[test]
    fn a_snapshot_cannot_target_a_path_outside_the_artifact_table() {
        for dest in [
            "/usr/bin/sudo",
            "/etc/sudoers",
            "/etc/sudoers.d/other",
            "/usr/local/bin/sudo-secretspec",
        ] {
            let dir = tempfile::tempdir().unwrap();
            write_snapshot(dir.path(), &[(dest, "payload")]);
            let err = plan_restore_with(dir.path(), &debian_artifacts())
                .expect_err("a destination outside the table must be refused");
            assert!(err.to_string().contains("does not own"), "{dest}: {err}");
        }
    }
}
