//! Privileged installer for the sudo-secretspec boundary.
//!
//! Fresh installs can create the dedicated service identity and vault.
//! Existing protected stores must be adopted explicitly. Dry-run validates
//! without mutating.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};
use thiserror::Error;

/// Vault belonging to the retired `stayturgid` `_secretspec` wrapper.
///
/// Adoptable, because a host that has only ever run the wrapper still keeps its
/// secrets here — but never in preference to [`DEFAULT_VAULT`]. Migration copies
/// the secrets out and deliberately leaves this directory in place as the second
/// copy and the pre-migration audit ledger, so its mere existence says nothing
/// about which vault the host actually serves from.
const LEGACY_VAULT: &str = "/var/db/stayturgid-secrets";
const LEGACY_USER: &str = "_secretspec";
const LEGACY_GROUP: &str = "staff";

pub(crate) const PREFIX: &str = "/usr/local";
const CONFIG_PATH: &str = "/usr/local/etc/sudo-secretspec.toml";
const SUDOERS_PATH: &str = "/private/etc/sudoers.d/sudo-secretspec";
/// Any file installed under here is a sudo policy and must be validated before
/// it is allowed to take effect.
pub(crate) const SUDOERS_DIR: &str = "/private/etc/sudoers.d";
const DEFAULT_VAULT: &str = "/var/db/sudo-secretspec";
const DEFAULT_USER: &str = "_sudo_secretspec";
const DEFAULT_GROUP: &str = "_sudo_secretspec";
/// Manifest profile assumed when the operator does not name one.
const DEFAULT_PROFILE: &str = "default";
/// Directory-name prefix for rollback snapshots under `<PREFIX>/libexec`.
/// `rollback::run` refuses any snapshot path outside this namespace.
pub(crate) const SNAPSHOT_PREFIX: &str = "sudo-secretspec-rollback-";
/// Restorable snapshots retained after a successful install. Every install
/// captures one, so without a bound they accumulate for the life of the host.
const SNAPSHOT_KEEP: usize = 3;
/// Version this binary installs, stamped into the protected config so a later
/// install can report what it replaced.
const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Error)]
pub enum InstallError {
    #[error("{0}")]
    Denied(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone)]
pub struct InstallRequest {
    pub declarations: Option<PathBuf>,
    pub dry_run: bool,
    pub adopt_existing: bool,
    pub vault: PathBuf,
    pub service_user: String,
    pub service_group: String,
    pub operator: String,
    /// Manifest profile the broker will resolve from. Written into the
    /// root-owned config so it is not left to the caller's environment.
    pub profile: String,
    pub source_root: Option<PathBuf>,
}

impl InstallRequest {
    pub fn from_cli(declarations: Option<PathBuf>, dry_run: bool, adopt_existing: bool) -> Self {
        let operator = std::env::var("SUDO_USER")
            .or_else(|_| std::env::var("USER"))
            .unwrap_or_else(|_| "root".into());
        Self {
            declarations,
            dry_run,
            adopt_existing,
            vault: PathBuf::from(DEFAULT_VAULT),
            service_user: DEFAULT_USER.into(),
            service_group: DEFAULT_GROUP.into(),
            operator,
            profile: DEFAULT_PROFILE.into(),
            source_root: None,
        }
    }
}

/// Every absolute path the installer owns, with the mode it must be installed
/// at.
///
/// This is the single source of truth shared by three callers: the installer
/// writes these modes, `capture_snapshot` preserves exactly these paths, and
/// `rollback` refuses to write anywhere outside this set. Rollback restoring a
/// mode from anywhere else would be a way to smuggle in a different one — the
/// sudoers policy at `0440` and the client binary at `0755` both matter.
pub fn installed_artifacts() -> Vec<(PathBuf, u32)> {
    let prefix = PathBuf::from(PREFIX);
    let share = prefix.join("share/sudo-secretspec");
    vec![
        (prefix.join("bin/sudo-secretspec"), 0o755),
        (prefix.join("libexec/sudo-secretspec"), 0o755),
        (share.join("secretspec.toml"), 0o444),
        (share.join("sudo-secretspec-retired.toml"), 0o444),
        (share.join("AI-GUIDANCE.md"), 0o444),
        (share.join("MANIFEST.sha256"), 0o444),
        (PathBuf::from(CONFIG_PATH), 0o444),
        (PathBuf::from(SUDOERS_PATH), 0o440),
    ]
}

/// Installed mode for `path`, or `None` when it is not an owned artifact.
pub fn artifact_mode(path: &Path) -> Option<u32> {
    installed_artifacts()
        .into_iter()
        .find(|(p, _)| p == path)
        .map(|(_, mode)| mode)
}

fn require_mode(path: &Path) -> Result<u32, InstallError> {
    artifact_mode(path).ok_or_else(|| {
        InstallError::Denied(format!("not an owned install artifact: {}", path.display()))
    })
}

/// Copy the current bytes of every installed artifact into `snapshot` so a
/// later `rollback` can restore exactly this state.
///
/// Each prior file is recorded as `<index>.prior` alongside `<index>.path`
/// holding its absolute destination, plus a `MANIFEST.sha256` binding every
/// destination to the hash of its captured bytes. Rollback verifies that
/// manifest, so a snapshot cannot be edited into a delivery vehicle for other
/// content. On a first install there is nothing to capture and the manifest is
/// written empty.
fn capture_snapshot(snapshot: &Path) -> Result<usize, InstallError> {
    fs::create_dir_all(snapshot)?;
    let mut perms = fs::metadata(snapshot)?.permissions();
    perms.set_mode(0o700);
    fs::set_permissions(snapshot, perms)?;

    let mut manifest = String::new();
    let mut captured = 0usize;
    for (index, (dest, _mode)) in installed_artifacts().iter().enumerate() {
        let meta = match fs::symlink_metadata(dest) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if !meta.is_file() {
            return Err(InstallError::Denied(format!(
                "refusing to snapshot a non-regular installed path: {}",
                dest.display()
            )));
        }
        let prior = snapshot.join(format!("{index}.prior"));
        fs::copy(dest, &prior)?;
        let mut p = fs::metadata(&prior)?.permissions();
        p.set_mode(0o600);
        fs::set_permissions(&prior, p)?;
        write_bytes(
            &snapshot.join(format!("{index}.path")),
            dest.display().to_string().as_bytes(),
            0o600,
            "root:wheel",
        )?;
        manifest.push_str(&format!("{}  {}\n", sha256_file(&prior)?, dest.display()));
        captured += 1;
    }
    write_bytes(
        &snapshot.join("MANIFEST.sha256"),
        manifest.as_bytes(),
        0o600,
        "root:wheel",
    )?;
    Ok(captured)
}

/// One rollback snapshot directory as it appears on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub path: PathBuf,
    /// Unix seconds parsed from the directory name.
    pub stamp: u64,
    /// False when the directory holds no `.prior` file. `plan_restore` rejects
    /// such a snapshot outright ("no restorable prior artifacts"), so it can
    /// never be used for anything — a first install produces one every time.
    pub restorable: bool,
}

/// Enumerate rollback snapshots directly under `dir`.
///
/// Only directories whose name carries [`SNAPSHOT_PREFIX`] followed by a
/// numeric stamp are reported, so an unrelated neighbour in libexec can never
/// become a pruning candidate.
pub fn list_snapshots(dir: &Path) -> Vec<Snapshot> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Some(stamp) = name.strip_prefix(SNAPSHOT_PREFIX) else {
            continue;
        };
        let Ok(stamp) = stamp.parse::<u64>() else {
            continue;
        };
        let path = entry.path();
        if path.is_symlink() || !path.is_dir() {
            continue;
        }
        let restorable = fs::read_dir(&path)
            .map(|mut e| {
                e.any(|f| {
                    f.map(|f| f.file_name().to_string_lossy().ends_with(".prior"))
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false);
        found.push(Snapshot {
            path,
            stamp,
            restorable,
        });
    }
    found
}

/// Choose which snapshots to delete: every unrestorable one, plus restorable
/// ones older than the newest `keep`.
///
/// Separated from [`prune_snapshots`] so the retention decision can be tested
/// without root, the same way `rollback::plan_restore` separates its trust
/// decisions from the filesystem work they authorise.
pub fn plan_prune(snapshots: &[Snapshot], keep: usize) -> Vec<PathBuf> {
    let mut restorable: Vec<&Snapshot> = snapshots.iter().filter(|s| s.restorable).collect();
    // Newest first, so the tail past `keep` is what ages out.
    restorable.sort_by(|a, b| b.stamp.cmp(&a.stamp));

    let mut doomed: Vec<PathBuf> = snapshots
        .iter()
        .filter(|s| !s.restorable)
        .map(|s| s.path.clone())
        .collect();
    doomed.extend(restorable.iter().skip(keep).map(|s| s.path.clone()));
    doomed.sort();
    doomed
}

/// Delete the snapshots [`plan_prune`] selects.
///
/// Each candidate is re-checked against the same guards `rollback::run`
/// applies before it trusts a snapshot — root-owned, mode 0700, not a symlink.
/// A directory failing any of them is left alone rather than removed: it is
/// not ours, and deleting it as root on a guess is the worse error.
/// Returns the number removed. Never fails an install: pruning is hygiene.
///
/// `uninstall` calls this with `keep = 0`: once the artifacts are gone every
/// snapshot restores paths that no longer exist, and reusing this rather than
/// walking the directory itself means they are vetted by exactly the same
/// guards a normal install prunes them under.
pub(crate) fn prune_snapshots(dir: &Path, keep: usize) -> usize {
    let mut removed = 0;
    for path in plan_prune(&list_snapshots(dir), keep) {
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if !meta.is_dir() || meta.uid() != 0 || meta.permissions().mode() & 0o777 != 0o700 {
            continue;
        }
        if fs::remove_dir_all(&path).is_ok() {
            removed += 1;
        }
    }
    removed
}

fn require_root() -> Result<(), InstallError> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(InstallError::Denied(
            "must run as root (Touch ID/sudo is expected, including dry-run)".into(),
        ));
    }
    Ok(())
}

fn resolve_path(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

fn sha256_file(path: &Path) -> Result<String, InstallError> {
    let bytes = fs::read(path)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn install_file(src: &Path, dst: &Path, mode: u32, owner: &str) -> Result<(), InstallError> {
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = dst.with_extension(format!("new.{}", std::process::id()));
    fs::copy(src, &tmp)?;
    let mut perms = fs::metadata(&tmp)?.permissions();
    perms.set_mode(mode);
    fs::set_permissions(&tmp, perms)?;
    let _ = Command::new("/usr/sbin/chown")
        .arg(owner)
        .arg(&tmp)
        .status();
    fs::rename(&tmp, dst)?;
    Ok(())
}

fn write_bytes(dst: &Path, bytes: &[u8], mode: u32, owner: &str) -> Result<(), InstallError> {
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = dst.with_extension(format!("new.{}", std::process::id()));
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(bytes)?;
    }
    let mut perms = fs::metadata(&tmp)?.permissions();
    perms.set_mode(mode);
    fs::set_permissions(&tmp, perms)?;
    let _ = Command::new("/usr/sbin/chown")
        .arg(owner)
        .arg(&tmp)
        .status();
    fs::rename(&tmp, dst)?;
    Ok(())
}

/// Write a candidate sudoers policy beside `dst` and validate it, returning the
/// staged path only if `visudo` accepts it.
///
/// A syntactically invalid file under `sudoers.d` makes sudo refuse to run at
/// all, which would strand the operator with no way to elevate — including no
/// way to re-run this installer and repair it. So the policy is never written
/// to its live name until it has parsed cleanly.
///
/// The staging name deliberately contains dots. sudo ignores files in
/// `sudoers.d` whose names contain a `.` or end in `~`, so even if this process
/// dies between writing and renaming, the staged file is inert.
pub fn stage_sudoers(
    dst: &Path,
    text: &str,
    mode: u32,
) -> Result<std::path::PathBuf, InstallError> {
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent)?;
    }
    let staged = dst.with_extension(format!("staged.{}", std::process::id()));
    {
        let mut f = fs::File::create(&staged)?;
        f.write_all(text.as_bytes())?;
    }
    let mut perms = fs::metadata(&staged)?.permissions();
    perms.set_mode(mode);
    fs::set_permissions(&staged, perms)?;
    let _ = Command::new("/usr/sbin/chown")
        .args(["root:wheel"])
        .arg(&staged)
        .status();

    let accepted = Command::new("/usr/sbin/visudo")
        .args(["-c", "-f"])
        .arg(&staged)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !accepted {
        let _ = fs::remove_file(&staged);
        return Err(InstallError::Denied(
            "generated sudoers policy failed visudo validation; the existing policy was left \
             untouched"
                .into(),
        ));
    }
    Ok(staged)
}

/// Install the sudoers policy so that a bad policy can never take effect.
///
/// Staged and validated in isolation first, then renamed into place, then the
/// combined configuration is re-checked with a bare `visudo -c`. If that final
/// check fails the previous policy is put back — or the file removed when there
/// was no previous policy — before returning an error.
fn install_sudoers(dst: &Path, text: &str, mode: u32) -> Result<(), InstallError> {
    let previous = fs::read(dst).ok();
    let staged = stage_sudoers(dst, text, mode)?;
    fs::rename(&staged, dst)?;

    // Valid in isolation is not the same as valid in combination; re-check the
    // whole configuration now that the file is live.
    //
    // A failure here is only ours to act on if *our* file is the one at fault.
    // Unrelated policies in sudoers.d — another package shipping a file with
    // the wrong mode, say — must not make this installer unusable, so re-check
    // our own file and treat anyone else's problem as a warning.
    let combined_ok = Command::new("/usr/sbin/visudo")
        .arg("-c")
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if combined_ok {
        return Ok(());
    }

    let ours_ok = Command::new("/usr/sbin/visudo")
        .args(["-c", "-f"])
        .arg(dst)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if ours_ok {
        eprintln!(
            "warning: `visudo -c` reports a problem elsewhere in the sudoers configuration.\n\
             warning: {} itself is valid and has been installed. Review the output above;\n\
             warning: sudo ignores files in sudoers.d with the wrong mode or a dot in the name.",
            dst.display()
        );
        return Ok(());
    }

    match &previous {
        Some(bytes) => {
            let restore = dst.with_extension(format!("restore.{}", std::process::id()));
            fs::write(&restore, bytes)?;
            let mut perms = fs::metadata(&restore)?.permissions();
            perms.set_mode(mode);
            fs::set_permissions(&restore, perms)?;
            let _ = Command::new("/usr/sbin/chown")
                .args(["root:wheel"])
                .arg(&restore)
                .status();
            fs::rename(&restore, dst)?;
        }
        None => {
            let _ = fs::remove_file(dst);
        }
    }
    Err(InstallError::Denied(
        "sudoers configuration failed validation with the new policy in place; the previous \
         policy has been restored"
            .into(),
    ))
}

fn ensure_service_group(name: &str, create: bool) -> Result<u32, InstallError> {
    let output = Command::new("/usr/bin/dscl")
        .args([".", "-read", &format!("/Groups/{name}"), "PrimaryGroupID"])
        .output()?;
    if output.status.success() {
        let text = String::from_utf8_lossy(&output.stdout);
        let gid = text
            .split_whitespace()
            .last()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| InstallError::Denied("cannot parse group id".into()))?;
        return Ok(gid);
    }
    if !create {
        return Err(InstallError::Denied(format!(
            "adopted group missing: {name}"
        )));
    }
    // Find free GID 400-499.
    let mut gid = 499u32;
    while gid >= 400 {
        let probe = Command::new("/usr/bin/dscl")
            .args([
                ".",
                "-search",
                "/Groups",
                "PrimaryGroupID",
                &gid.to_string(),
            ])
            .output()?;
        if !String::from_utf8_lossy(&probe.stdout).contains(char::is_alphanumeric) {
            break;
        }
        gid -= 1;
    }
    if gid < 400 {
        return Err(InstallError::Denied("no free hidden group id".into()));
    }
    for args in [
        vec![".", "-create", &format!("/Groups/{name}")],
        vec![
            ".",
            "-create",
            &format!("/Groups/{name}"),
            "PrimaryGroupID",
            &gid.to_string(),
        ],
        vec![".", "-create", &format!("/Groups/{name}"), "Password", "*"],
    ] {
        let status = Command::new("/usr/bin/dscl").args(&args).status()?;
        if !status.success() {
            return Err(InstallError::Denied(format!(
                "failed to create group {name}"
            )));
        }
    }
    Ok(gid)
}

fn ensure_service_user(name: &str, gid: u32, create: bool) -> Result<(), InstallError> {
    let output = Command::new("/usr/bin/id").arg(name).output()?;
    if output.status.success() {
        return Ok(());
    }
    if !create {
        return Err(InstallError::Denied(format!(
            "adopted user missing: {name}"
        )));
    }
    let mut uid = 499u32;
    while uid >= 400 {
        let probe = Command::new("/usr/bin/dscl")
            .args([".", "-search", "/Users", "UniqueID", &uid.to_string()])
            .output()?;
        if !String::from_utf8_lossy(&probe.stdout).contains(char::is_alphanumeric) {
            break;
        }
        uid -= 1;
    }
    if uid < 400 {
        return Err(InstallError::Denied("no free hidden user id".into()));
    }
    let home = "/var/empty";
    let shell = "/usr/bin/false";
    let path = format!("/Users/{name}");
    for args in [
        vec![".", "-create", &path],
        vec![".", "-create", &path, "UniqueID", &uid.to_string()],
        vec![".", "-create", &path, "PrimaryGroupID", &gid.to_string()],
        vec![".", "-create", &path, "UserShell", shell],
        vec![".", "-create", &path, "NFSHomeDirectory", home],
        vec![".", "-create", &path, "IsHidden", "1"],
        vec![".", "-create", &path, "Password", "*"],
    ] {
        let status = Command::new("/usr/bin/dscl").args(&args).status()?;
        if !status.success() {
            return Err(InstallError::Denied(format!(
                "failed to create user {name}"
            )));
        }
    }
    Ok(())
}

/// True when `path` is a real directory rather than a symlink to one.
fn is_real_dir(path: &Path) -> bool {
    path.is_dir() && !path.is_symlink()
}

/// True when only root can add, replace, or remove entries in `path`.
fn is_root_only_dir(path: &Path) -> bool {
    match fs::metadata(path) {
        Ok(meta) => meta.uid() == 0 && (meta.permissions().mode() & 0o022) == 0,
        Err(_) => false,
    }
}

/// True when `path` is a directory nobody but root can substitute files in.
///
/// This is the single predicate for "safe to deliver a privileged component
/// through". The installer requires it of every directory it writes into, and
/// `drift` applies the same one to every directory that could hand a caller a
/// `sudo-secretspec` binary — a copy under an `admin`-writable prefix such as
/// `/opt/homebrew/bin` is an unprivileged-write-to-privileged-exec path even
/// when its bytes are currently identical.
pub(crate) fn is_protected_dir(path: &Path) -> bool {
    is_real_dir(path) && is_root_only_dir(path)
}

/// Create a directory the installer is about to write into, then require that
/// it is root-owned and not writable by anyone else.
///
/// Ordering matters both ways. Validating first would fail on a machine where
/// the directory does not exist yet, which is every first install; creating
/// without validating is what left the gap. `is_protected_dir`'s own contract
/// says the installer requires this of every directory it writes into, but
/// `validate_protected_ancestors` covered only the shared roots — not
/// `<prefix>/{bin,libexec,etc,share}`, which is where the NOPASSWD broker
/// binary lands. The case this closes is a host carrying a legacy
/// Intel-Homebrew `chown -R` of `/usr/local`, where an unprivileged user owns
/// the directory root is about to execute from.
fn prepare_install_dir(path: &Path) -> Result<(), InstallError> {
    fs::create_dir_all(path)?;
    // `create_dir_all` takes the ambient umask, and the policy runs the broker
    // with `umask=0077`. A 0700 `/usr/local/bin` would be unreadable to the
    // operator it exists to serve, so set the mode rather than inherit it.
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
    if !is_protected_dir(path) {
        return Err(InstallError::Denied(format!(
            "unsafe install directory {}",
            path.display()
        )));
    }
    Ok(())
}

/// An adopted vault's `.env` is optional: present or absent is both fine.
///
/// Matches `broker::require_boundary`'s own reasoning -- `.env` is vestigial
/// since values moved into `secrets.db`, so a vault already migrated to the
/// sqlite-only store legitimately has none. When it *is* present, though, it
/// still must be a real file, never a symlink.
fn validate_adopted_env_if_present(vault: &Path) -> Result<(), InstallError> {
    let env_path = vault.join(".env");
    if let Ok(meta) = fs::symlink_metadata(&env_path)
        && (meta.file_type().is_symlink() || !meta.is_file())
    {
        return Err(InstallError::Denied(format!(
            "adopted runtime file missing or symlinked: {}",
            env_path.display()
        )));
    }
    Ok(())
}

fn validate_protected_ancestors() -> Result<(), InstallError> {
    for dir in [
        "/usr",
        "/usr/local",
        "/private",
        "/private/var",
        "/private/var/db",
        "/private/etc",
        "/private/etc/sudoers.d",
    ] {
        let path = Path::new(dir);
        if !is_real_dir(path) {
            return Err(InstallError::Denied(format!(
                "unsafe protected directory {dir}"
            )));
        }
        if !is_root_only_dir(path) {
            return Err(InstallError::Denied(format!(
                "unsafe protected directory metadata {dir}"
            )));
        }
    }
    Ok(())
}

fn config_toml(req: &InstallRequest, vault_real: &Path) -> String {
    let mut out = format!(
        "engine = \"{prefix}/libexec/sudo-secretspec\"\n\
         audit_helper = \"{prefix}/libexec/sudo-secretspec\"\n\
         vault = \"{vault}\"\n\
         vault_realpath = \"{vault_real}\"\n\
         service_user = \"{user}\"\n\
         service_group = \"{group}\"\n\
         profile = \"{profile}\"\n\
         version = \"{version}\"\n\
         adopted_vault = {adopted}\n",
        prefix = PREFIX,
        vault = req.vault.display(),
        vault_real = vault_real.display(),
        user = req.service_user,
        group = req.service_group,
        profile = req.profile,
        version = VERSION,
        adopted = req.adopt_existing,
    );
    if req.declarations.is_some() {
        out.push_str(&format!(
            "declarations = \"{PREFIX}/share/sudo-secretspec/secretspec.toml\"\n"
        ));
    }
    out
}

/// Files the installer copies from the distribution media.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Media {
    broker: PathBuf,
    guidance: PathBuf,
    retired: PathBuf,
}

/// Root of the distribution media this install copies from.
///
/// Inferred from `current_exe()`: the package manager runs
/// `<keg>/libexec/sudo-secretspec`, so the keg root is two levels up. An
/// explicit [`InstallRequest::source_root`] overrides the inference, which is
/// what makes the media checks testable without a real keg.
fn resolve_source_root(explicit: Option<&Path>) -> Result<PathBuf, InstallError> {
    if let Some(root) = explicit {
        return Ok(root.to_path_buf());
    }
    let self_exe = std::env::current_exe()
        .map_err(|e| InstallError::Denied(format!("cannot resolve current exe: {e}")))?;
    self_exe
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| InstallError::Denied("current exe is not nested in libexec".into()))
}

/// True when both paths exist and name the same file.
///
/// Compared by `(dev, ino)` rather than by canonicalized path so that a hard
/// link — which canonicalization cannot see through — counts as the same file.
fn same_file(a: &Path, b: &Path) -> bool {
    match (fs::metadata(a), fs::metadata(b)) {
        (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
        _ => false,
    }
}

/// Resolve the media layout under `source_root`, refusing to install from the
/// installed boundary itself.
///
/// `<PREFIX>` is shaped exactly like the distribution media — install puts a
/// `libexec/sudo-secretspec` and a `share/sudo-secretspec` there — so the
/// destination is always a structurally *valid* source. Running the installed
/// client's own `install` therefore infers `source_root = <PREFIX>`, copies
/// every artifact onto itself, rewrites the rollback snapshot and exits 0
/// having upgraded nothing. Nothing is malformed at any step, so no other check
/// can fail; only comparing source against destination sees it.
///
/// `main`'s allowlist already refuses lifecycle through the *broker* path on
/// the same principle — the installed copy must not be the installer. This is
/// that rule applied to the installed *client* path, which reaches
/// `install` because `invoked_as_privileged_broker` is false for it by
/// construction.
///
/// A destination that does not exist yet is a first install and cannot be
/// self-sourced.
fn resolve_media(source_root: &Path, broker_dst: &Path) -> Result<Media, InstallError> {
    let media = Media {
        broker: source_root.join("libexec/sudo-secretspec"),
        guidance: source_root.join("share/sudo-secretspec/AI-GUIDANCE.md"),
        retired: source_root.join("share/sudo-secretspec/sudo-secretspec-retired.toml"),
    };

    if same_file(&media.broker, broker_dst) {
        return Err(InstallError::Denied(format!(
            "refusing to install from the installed boundary itself ({}).\n\
             This would copy every artifact onto itself and report success while upgrading \
             nothing.\n\
             Run install from the copy your package manager ships, which is kept off PATH so \
             it cannot shadow the installed client:\n  \
             $(brew --prefix)/opt/sudo-secretspec/libexec/sudo-secretspec install",
            media.broker.display()
        )));
    }

    for path in [&media.broker, &media.guidance, &media.retired] {
        if !path.is_file() {
            return Err(InstallError::Denied(format!(
                "source media is incomplete: {} is missing",
                path.display()
            )));
        }
    }
    Ok(media)
}

/// Resolve and validate the source media without needing root, so a doomed
/// install can be refused *before* it asks the operator to authenticate.
///
/// [`run`] performs the same checks again as root, and that copy is the
/// authoritative one — this is not a security boundary and must not be treated
/// as one. It exists because being told "this would upgrade nothing" is only
/// useful before a Touch ID prompt, not after it. It also means the refusal is
/// reachable with no authentication at all, so the behaviour can be exercised
/// unattended rather than only by an operator standing at the machine.
pub fn preflight_media(source_root: Option<&Path>) -> Result<(), InstallError> {
    resolve_media(
        &resolve_source_root(source_root)?,
        &PathBuf::from(PREFIX).join("libexec/sudo-secretspec"),
    )
    .map(|_| ())
}

/// Version recorded by the installer that last wrote `config_dst`.
///
/// `None` when no boundary is installed yet, or when it was installed before
/// the version stamp existed. Read from the root-owned config rather than by
/// running the outgoing binary: `install` is already root here, and executing
/// the very binary it is about to replace to ask what it is would be a needless
/// exec of soon-to-be-stale code.
fn installed_version(config_dst: &Path) -> Option<String> {
    let content = fs::read_to_string(config_dst).ok()?;
    crate::config::Config::parse(&content).ok()?.version
}

/// How this install moves the boundary's version, for the operator-facing line.
///
/// The success message used to say only "installed sudo-secretspec", which is
/// true of a no-op as much as of a real upgrade — so confirming that an upgrade
/// had happened meant separately running `--version`, and not doing so is how a
/// silent no-op went unnoticed.
fn version_transition(previous: Option<&str>) -> String {
    match previous {
        Some(old) if old == VERSION => format!("{VERSION} (reinstalled, unchanged)"),
        Some(old) => format!("{old} -> {VERSION}"),
        None => VERSION.to_string(),
    }
}

/// Sudoers policy for the operator.
///
/// The grant is deliberately per-subcommand. A blanket `sudo-secretspec *`
/// would also cover `install` and `rollback` — the same binary serves as both
/// client and broker — which would let any caller running as the operator
/// reconfigure or restore the boundary with no interactive authentication.
/// Boundary lifecycle must stay behind Touch ID via the public client, so only
/// the mediated broker operations and the read-only doctor are NOPASSWD here.
/// `main` enforces the same restriction inside the binary, because sudoers
/// argument matching alone is easy to get subtly wrong.
///
/// `timestamp_timeout=0` on the *client* path is what makes "behind Touch ID"
/// mean per-operation. Without it the grant is enforced by sudo's shared
/// timestamp — five minutes by default, and satisfied by any other command:
/// `sudo true` followed by `sudo -n sudo-secretspec install` was observed to
/// run with no authentication at all. The boundary still held, but the
/// interactive-authentication guarantee was borrowed from state this project
/// does not own. Zero also means the time stamp is not *updated*, so running
/// boundary lifecycle cannot pay for some later command either.
///
/// This binds to the installed client path only. Running the Homebrew keg's
/// `libexec` bootstrap directly is outside the policy — that path exists for a
/// first install, when there is no policy yet, and `doctor`'s `CLIENT_SHADOWED`
/// check is what keeps it from becoming the everyday entry point.
///
/// `env_keep-="HOME"` and `always_set_home` are what stop the broker inheriting
/// the *caller's* `HOME`. That matters because the engine resolves its
/// user-global config through etcetera's XDG strategy — `$XDG_CONFIG_HOME`,
/// else `$HOME/.config` — and that file's `[audit] path` would aim a root
/// writer at any absolute path the caller chose. `env_reset` alone does not
/// close this: macOS ships `env_keep += "HOME"` in the global `/etc/sudoers`,
/// which wins. Measured on sudo 1.9.17p2 with a throwaway drop-in gating
/// `/usr/bin/printenv`: `env_reset` alone yielded the caller's home, while
/// either flag below yielded `/var/root`. Both are set because which one is
/// load-bearing depends on a platform default this project does not own; the
/// broker also pins `HOME` in-process (`broker::purge_ambient_env`), so the
/// guarantee does not rest on the policy alone.
///
/// `source-restore --*` is deliberately narrower than the wildcard reads: it
/// grants NOPASSWD only for the plain `source-restore` verb, never for
/// `source-restore-force`. That second verb has no line here at all, so it
/// falls through to the operator's ordinary interactive sudo (Touch ID),
/// exactly like `install`/`uninstall` do. The client sends `--all` restores
/// through `source-restore-force` for the same reason it sends `--force`
/// ones there: sudoers argument matching is a glob, so a NOPASSWD grant on
/// `source-restore --*` would also match `source-restore --all`, making a
/// mass, unattended restore of the whole vault indistinguishable — to
/// sudoers — from the single-name, forward-safe restore the NOPASSWD grant
/// exists for. See `main.rs`'s `lifecycle_restore`.
pub fn sudoers_text(operator: &str, service_user: &str) -> String {
    format!(
        "Defaults!{prefix}/libexec/sudo-secretspec env_reset,env_keep-=\"HOME\",secure_path=/usr/bin:/bin:/usr/sbin:/sbin,umask=0077,always_set_home\n\
         Defaults!{prefix}/bin/sudo-secretspec timestamp_timeout=0\n\
         {operator} ALL=({service_user}) NOPASSWD: {prefix}/libexec/sudo-secretspec __broker source-add --*\n\
         {operator} ALL=({service_user}) NOPASSWD: {prefix}/libexec/sudo-secretspec __broker source-set --*\n\
         {operator} ALL=({service_user}) NOPASSWD: {prefix}/libexec/sudo-secretspec __broker source-delete --*\n\
         {operator} ALL=({service_user}) NOPASSWD: {prefix}/libexec/sudo-secretspec __broker source-undeclare --*\n\
         {operator} ALL=({service_user}) NOPASSWD: {prefix}/libexec/sudo-secretspec __broker source-get --*\n\
         {operator} ALL=({service_user}) NOPASSWD: {prefix}/libexec/sudo-secretspec __broker source-check --*\n\
         {operator} ALL=({service_user}) NOPASSWD: {prefix}/libexec/sudo-secretspec __broker source-export --*\n\
         {operator} ALL=({service_user}) NOPASSWD: {prefix}/libexec/sudo-secretspec __broker source-template-check --*\n\
         {operator} ALL=({service_user}) NOPASSWD: {prefix}/libexec/sudo-secretspec __broker source-schema --*\n\
         {operator} ALL=({service_user}) NOPASSWD: {prefix}/libexec/sudo-secretspec __broker audit-verify\n\
         {operator} ALL=({service_user}) NOPASSWD: {prefix}/libexec/sudo-secretspec __broker source-restore --*\n\
         {operator} ALL=(root) NOPASSWD: {prefix}/libexec/sudo-secretspec doctor\n\
         {operator} ALL=(root) NOPASSWD: {prefix}/libexec/sudo-secretspec doctor *\n",
        prefix = PREFIX,
        operator = operator,
        service_user = service_user,
    )
}

/// Run the installer. Returns Ok(()) on success.
pub fn run(req: InstallRequest) -> Result<(), InstallError> {
    require_root()?;
    if let Some(decl) = &req.declarations {
        if !decl.is_file() || decl.is_symlink() {
            return Err(InstallError::Denied(
                "declarations must be a regular file".into(),
            ));
        }
    }
    validate_protected_ancestors()?;

    // Resolve and validate the source media before the dry-run return, not
    // after it. These checks used to sit ~110 lines further down, past this
    // early exit, which left `--dry-run` — the one command reached for to
    // pre-flight an install — structurally unable to report the most likely
    // thing to be wrong with one.
    let client_dst = PathBuf::from(PREFIX).join("bin/sudo-secretspec");
    let broker_dst = PathBuf::from(PREFIX).join("libexec/sudo-secretspec");
    let media = resolve_media(
        &resolve_source_root(req.source_root.as_deref())?,
        &broker_dst,
    )?;
    let previous_version = installed_version(Path::new(CONFIG_PATH));

    if !req.adopt_existing && req.declarations.is_none() {
        return Err(InstallError::Denied(
            "a declarations file is required for a fresh install".into(),
        ));
    }

    // Refuse a fresh install onto an existing boundary, on the LIVE path as well
    // as the rehearsal. This guard used to sit inside the `req.dry_run` block
    // below, so `--dry-run` refused exactly what the real run went on to do: the
    // fresh-install branch at the end of this function truncates the vault's
    // `.env` with `File::create`, destroying every stored secret value. A
    // pre-flight that refuses what the live command performs is worse than no
    // pre-flight, because it is read as permission to proceed.
    if !req.adopt_existing
        && (Path::new(&req.vault).exists()
            || Command::new("/usr/bin/id")
                .arg(&req.service_user)
                .status()
                .map(|s| s.success())
                .unwrap_or(false))
    {
        return Err(fresh_install_refusal(req.declarations.as_deref()));
    }

    if req.dry_run {
        if req.adopt_existing {
            // Metadata-only validation of existing identity/vault.
            let id_status = Command::new("/usr/bin/id")
                .arg(&req.service_user)
                .status()
                .map_err(|e| InstallError::Denied(e.to_string()))?;
            if !id_status.success() {
                return Err(InstallError::Denied(format!(
                    "adopted user missing: {}",
                    req.service_user
                )));
            }
            let group_status = Command::new("/usr/bin/dscl")
                .args([".", "-read", &format!("/Groups/{}", req.service_group)])
                .status()
                .map_err(|e| InstallError::Denied(e.to_string()))?;
            if !group_status.success() {
                return Err(InstallError::Denied(format!(
                    "adopted group missing: {}",
                    req.service_group
                )));
            }
            if !req.vault.is_dir() || req.vault.is_symlink() {
                return Err(InstallError::Denied(
                    "adopted vault missing or symlinked".into(),
                ));
            }
            // Root-only metadata checks of vault contents (never open
            // values). `secretspec.toml` is required; an adopted vault with
            // no manifest has nothing to adopt. `.env` is optional -- see
            // `validate_adopted_env_if_present`.
            let manifest_path = req.vault.join("secretspec.toml");
            let meta = fs::symlink_metadata(&manifest_path).map_err(|_| {
                InstallError::Denied(format!(
                    "adopted runtime file missing or unreadable: {}",
                    manifest_path.display()
                ))
            })?;
            if meta.file_type().is_symlink() || !meta.is_file() {
                return Err(InstallError::Denied(format!(
                    "adopted runtime file missing or symlinked: {}",
                    manifest_path.display()
                )));
            }
            validate_adopted_env_if_present(&req.vault)?;
            let vault_real = resolve_path(&req.vault);
            if !vault_real.starts_with("/private/var/db/") {
                return Err(InstallError::Denied(
                    "vault resolves outside /private/var/db".into(),
                ));
            }
        }
        println!(
            "would install sudo-secretspec {}",
            version_transition(previous_version.as_deref())
        );
        println!("source={}", media.broker.display());
        println!("operator={}", req.operator);
        println!("service={}:{}", req.service_user, req.service_group);
        println!("vault={}", req.vault.display());
        println!("prefix={PREFIX}");
        println!("adopt_existing={}", u8::from(req.adopt_existing));
        return Ok(());
    }

    // Create or adopt service identity.
    let gid = ensure_service_group(&req.service_group, !req.adopt_existing)?;
    ensure_service_user(&req.service_user, gid, !req.adopt_existing)?;

    // Vault.
    let mut created_vault = false;
    if !req.vault.exists() {
        if req.adopt_existing {
            return Err(InstallError::Denied("adopted vault missing".into()));
        }
        fs::create_dir_all(&req.vault)?;
        created_vault = true;
    }
    if req.vault.is_symlink() {
        return Err(InstallError::Denied("vault must not be a symlink".into()));
    }
    if req.adopt_existing {
        // Never rewrite ownership of an adopted vault; only verify metadata.
        let meta = fs::metadata(&req.vault)?;
        if (meta.permissions().mode() & 0o777) != 0o700 {
            return Err(InstallError::Denied(
                "adopted vault must be mode 0700".into(),
            ));
        }
    } else {
        let _ = Command::new("/usr/sbin/chown")
            .arg(format!("{}:{}", req.service_user, req.service_group))
            .arg(&req.vault)
            .status();
        let mut perms = fs::metadata(&req.vault)?.permissions();
        perms.set_mode(0o700);
        fs::set_permissions(&req.vault, perms)?;
    }

    let vault_real = resolve_path(&req.vault);
    if !vault_real.starts_with("/private/var/db/") {
        return Err(InstallError::Denied(
            "vault resolves outside /private/var/db".into(),
        ));
    }

    // Source media resolved and validated above, before the dry-run return.
    let share = PathBuf::from(PREFIX).join("share/sudo-secretspec");
    let declarations_dst = share.join("secretspec.toml");
    let retired_dst = share.join("sudo-secretspec-retired.toml");
    let guidance_dst = share.join("AI-GUIDANCE.md");
    let manifest_dst = share.join("MANIFEST.sha256");
    let config_dst = PathBuf::from(CONFIG_PATH);
    let sudoers_dst = PathBuf::from(SUDOERS_PATH);

    // `is_protected_dir`'s contract is that the installer requires it of every
    // directory it writes into, but `validate_protected_ancestors` covered only
    // the shared roots — not `<prefix>/{bin,libexec,etc,share}`, which is where
    // the NOPASSWD broker binary itself lands. A machine carrying a legacy
    // Intel-Homebrew `chown -R` of the prefix would hand an unprivileged user
    // write access to the path root then executes.
    //
    // Create first, then validate: on a first install these may not exist yet.
    // The nested `share/sudo-secretspec` is created by the same loop for the
    // same reason — it holds the manifest `rollback` verifies against.
    for dir in ["bin", "libexec", "etc", "share"] {
        prepare_install_dir(&PathBuf::from(PREFIX).join(dir))?;
    }
    prepare_install_dir(&share)?;

    // Preserve the outgoing artifacts before anything is overwritten, so the
    // snapshot this install reports is actually restorable.
    let stamp = chrono_like_stamp();
    let libexec = PathBuf::from(PREFIX).join("libexec");
    let rollback = libexec.join(format!("{SNAPSHOT_PREFIX}{stamp}"));
    let captured = capture_snapshot(&rollback)?;

    let root_owner = "root:wheel";
    let service_owner = format!("{}:{}", req.service_user, req.service_group);

    install_file(
        &media.broker,
        &client_dst,
        require_mode(&client_dst)?,
        root_owner,
    )?;
    install_file(
        &media.broker,
        &broker_dst,
        require_mode(&broker_dst)?,
        &service_owner,
    )?;
    if let Some(decl) = &req.declarations {
        install_file(
            decl,
            &declarations_dst,
            require_mode(&declarations_dst)?,
            &service_owner,
        )?;
    }
    install_file(
        &media.retired,
        &retired_dst,
        require_mode(&retired_dst)?,
        &service_owner,
    )?;
    install_file(
        &media.guidance,
        &guidance_dst,
        require_mode(&guidance_dst)?,
        &service_owner,
    )?;
    write_bytes(
        &config_dst,
        config_toml(&req, &vault_real).as_bytes(),
        require_mode(&config_dst)?,
        &service_owner,
    )?;
    // Validated before it can take effect, and rolled back if the combined
    // configuration is rejected — a broken sudoers.d file would leave the
    // operator unable to elevate at all.
    install_sudoers(
        &sudoers_dst,
        &sudoers_text(&req.operator, &req.service_user),
        require_mode(&sudoers_dst)?,
    )?;

    // Release manifest of installed artifacts.
    let mut manifest = String::new();
    let mut artifacts = vec![
        &client_dst,
        &broker_dst,
        &retired_dst,
        &guidance_dst,
        &config_dst,
        &sudoers_dst,
    ];
    if req.declarations.is_some() {
        artifacts.push(&declarations_dst);
    }
    for path in artifacts {
        manifest.push_str(&format!("{}  {}\n", sha256_file(path)?, path.display()));
    }
    write_bytes(
        &manifest_dst,
        manifest.as_bytes(),
        require_mode(&manifest_dst)?,
        &service_owner,
    )?;

    // Runtime files for fresh install only.
    if !req.adopt_existing {
        let (manifest_rt, env_rt) = create_fresh_runtime_files(&req.vault, &declarations_dst)?;
        for path in [&manifest_rt, &env_rt] {
            let mut p = fs::metadata(path)?.permissions();
            p.set_mode(0o600);
            fs::set_permissions(path, p)?;
            let _ = Command::new("/usr/sbin/chown")
                .arg(format!("{}:{}", req.service_user, req.service_group))
                .arg(path)
                .status();
        }
    } else {
        let manifest_path = req.vault.join("secretspec.toml");
        if !manifest_path.is_file() || manifest_path.is_symlink() {
            return Err(InstallError::Denied(format!(
                "adopted runtime file missing or symlinked: {}",
                manifest_path.display()
            )));
        }
        validate_adopted_env_if_present(&req.vault)?;
    }

    // Hygiene, after the install itself has succeeded: every install captures
    // a snapshot, and a first install captures an empty one that can never be
    // restored from. Unbounded, they accumulate for the life of the host.
    let pruned = prune_snapshots(&libexec, SNAPSHOT_KEEP);

    println!(
        "installed sudo-secretspec {}",
        version_transition(previous_version.as_deref())
    );
    println!("source={}", media.broker.display());
    println!("config={}", config_dst.display());
    println!("vault={}", req.vault.display());
    if captured == 0 {
        // Pruned just above; naming it would point at a directory that is gone.
        println!("rollback_snapshot=none");
    } else {
        println!("rollback_snapshot={}", rollback.display());
    }
    println!("rollback_artifacts={captured}");
    println!("pruned_snapshots={pruned}");
    if created_vault {
        println!("created_vault=1");
    }
    Ok(())
}

/// How [`detect_existing_vault`] arrived at the store it names.
///
/// This is a trust boundary, not bookkeeping. An installed boundary naming its
/// own vault is a fact the host recorded about itself; a path scan is a guess
/// that happens to be right most of the time. `install` treats only the first
/// as sufficient grounds to adopt without being told to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultOrigin {
    /// Named by the installed root-owned config: the boundary vouching for the
    /// vault it already serves from. Reinstalling over this is an upgrade.
    InstalledConfig,
    /// Guessed by scanning well-known paths, with nothing installed to confirm
    /// it. May name [`LEGACY_VAULT`], which migration leaves on disk on purpose.
    PathScan,
}

/// A store `install` could adopt, and the evidence for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExistingVault {
    pub vault: PathBuf,
    pub service_user: String,
    pub service_group: String,
    pub origin: VaultOrigin,
}

/// Refusal for a fresh install onto a boundary that already exists.
///
/// Split out of [`run`] so the wording is reachable from a test: the guard
/// itself only fires as root against a populated `/var/db`, which is exactly
/// the situation no test can set up, and the last thing hidden behind that
/// unreachability truncated a vault.
///
/// It names the command that works rather than only the flag that is missing.
/// The failure mode this guard invites is a script or an operator "fixing" the
/// refusal by removing the obstacle -- deleting the vault so that a fresh
/// install succeeds.
fn fresh_install_refusal(declarations: Option<&Path>) -> InstallError {
    let decl_arg = match declarations {
        Some(d) => format!(" --declarations {}", d.display()),
        None => "".into(),
    };
    InstallError::Denied(format!(
        "refusing to install over existing service identity/vault\n\
         \n\
         The service identity or vault path already exists. A fresh install\n\
         would destroy any stored secrets. If you intend to take over an\n\
         existing installation, use `--adopt-existing`:\n\
         \n\
         sudo-secretspec install{} --adopt-existing",
        decl_arg
    ))
}

/// Whether `install` adopts a detected vault without `--adopt-existing`.
///
/// Lives here, named and tested, rather than as a comparison inline in the
/// binary's `run_install`: the trust rule is the whole point of the
/// distinction, and the last guard that decided something this consequential
/// from inside an unreachable code path truncated a populated vault.
///
/// Only [`VaultOrigin::InstalledConfig`] qualifies. That is the host's own
/// record of the store it serves from, so reinstalling over it is an upgrade.
/// A [`VaultOrigin::PathScan`] answer is a guess whose candidates include the
/// retired [`LEGACY_VAULT`]; binding a new boundary to retired secrets is not
/// something to infer from a directory listing.
pub fn adopts_without_flag(origin: VaultOrigin) -> bool {
    matches!(origin, VaultOrigin::InstalledConfig)
}

/// Vault and service identity an unattended `install` should adopt.
///
/// `config_path` is the installed protected config; `dir_exists` reports whether
/// a path is a real directory (injected so the precedence below is testable
/// without root or a populated `/var/db`).
///
/// An installed boundary is authoritative. It records the vault this host
/// actually serves from, which a directory scan cannot infer: migration leaves
/// the retired [`LEGACY_VAULT`] on disk on purpose, so scanning still finds it
/// long after it stopped being the answer. Preferring the scan is how a routine
/// reinstall silently repoints a migrated boundary back at retired secrets and a
/// retired service identity.
///
/// The returned [`VaultOrigin`] carries that distinction to the caller rather
/// than discarding it. Both answers name a vault; only one of them is the host
/// telling you about itself.
///
/// Unprivileged and read-only. The config is root-owned `0444`, and the
/// privileged side re-validates every value before acting on it, so a config
/// that is missing, unreadable, or invalid falls through to detection rather
/// than failing the install.
pub fn detect_existing_vault(
    config_path: &Path,
    dir_exists: impl Fn(&Path) -> bool,
) -> Option<ExistingVault> {
    if let Some(existing) = installed_identity(config_path, &dir_exists) {
        return Some(existing);
    }

    // Nothing installed yet: name a vault by its path. The canonical vault wins;
    // the wrapper's vault is adoptable only when it is the sole candidate.
    for (vault, user, group) in [
        (DEFAULT_VAULT, DEFAULT_USER, DEFAULT_GROUP),
        (LEGACY_VAULT, LEGACY_USER, LEGACY_GROUP),
    ] {
        let vault = PathBuf::from(vault);
        if dir_exists(&vault) {
            return Some(ExistingVault {
                vault,
                service_user: user.into(),
                service_group: group.into(),
                origin: VaultOrigin::PathScan,
            });
        }
    }
    None
}

fn installed_identity(
    config_path: &Path,
    dir_exists: &impl Fn(&Path) -> bool,
) -> Option<ExistingVault> {
    let content = fs::read_to_string(config_path).ok()?;
    let config = crate::config::Config::parse(&content).ok()?;
    let vault = config.vault().to_path_buf();
    if !dir_exists(&vault) {
        return None;
    }
    Some(ExistingVault {
        vault,
        service_user: config.service_user,
        service_group: config.service_group,
        origin: VaultOrigin::InstalledConfig,
    })
}

/// Create the vault's runtime files for a fresh install, refusing to overwrite.
///
/// Split out of [`run`] so the refusal is reachable without root: the live
/// install path is what truncated a populated vault, and the destructive call
/// sat in the middle of a function no test can run.
///
/// Create-only-if-missing, independent of `adopt_existing`. [`run`] already
/// refuses a fresh install onto an existing boundary, but these two writes are
/// the ones that actually destroy data, so they refuse on their own rather than
/// trusting a caller further up to have checked. The `File::create` this
/// replaces truncated `.env` to zero bytes, losing every stored secret value.
fn create_fresh_runtime_files(
    vault: &Path,
    declarations: &Path,
) -> Result<(PathBuf, PathBuf), InstallError> {
    let manifest_rt = vault.join("secretspec.toml");
    let env_rt = vault.join(".env");
    for path in [&manifest_rt, &env_rt] {
        if path.symlink_metadata().is_ok() {
            return Err(InstallError::Denied(format!(
                "refusing to overwrite existing runtime file: {}",
                path.display()
            )));
        }
    }
    fs::copy(declarations, &manifest_rt)?;
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&env_rt)?;
    Ok((manifest_rt, env_rt))
}

fn chrono_like_stamp() -> String {
    // UTC-ish timestamp without extra deps.
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{secs}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A directory shaped like distribution media: `libexec/sudo-secretspec`
    /// plus the two shared assets install copies.
    fn media_root(tmp: &Path) -> PathBuf {
        let root = tmp.to_path_buf();
        fs::create_dir_all(root.join("libexec")).unwrap();
        fs::create_dir_all(root.join("share/sudo-secretspec")).unwrap();
        fs::write(root.join("libexec/sudo-secretspec"), b"broker").unwrap();
        fs::write(root.join("share/sudo-secretspec/AI-GUIDANCE.md"), b"docs").unwrap();
        fs::write(
            root.join("share/sudo-secretspec/sudo-secretspec-retired.toml"),
            b"retired",
        )
        .unwrap();
        root
    }

    #[test]
    fn installing_over_a_populated_vault_leaves_env_byte_identical() {
        // The incident: a plain `install` (no --adopt-existing) over a populated
        // vault truncated `.env` to 0 bytes with `File::create`, destroying every
        // stored secret value. The bytes must survive the refusal untouched.
        let tmp = tempfile::tempdir().unwrap();
        let vault = tmp.path().join("vault");
        fs::create_dir_all(&vault).unwrap();
        let declarations = tmp.path().join("secretspec.toml");
        fs::write(&declarations, b"[project]\nname = \"fresh\"\n").unwrap();

        let env_rt = vault.join(".env");
        let secrets = b"DATABASE_URL=postgres://real\nAPI_KEY=sk-live\n";
        fs::write(&env_rt, secrets).unwrap();
        let manifest_rt = vault.join("secretspec.toml");
        fs::write(&manifest_rt, b"[project]\nname = \"installed\"\n").unwrap();

        let err = create_fresh_runtime_files(&vault, &declarations)
            .expect_err("a fresh install over a populated vault must be refused");
        assert!(
            err.to_string()
                .contains("refusing to overwrite existing runtime file"),
            "{err}"
        );

        assert_eq!(
            fs::read(&env_rt).unwrap(),
            secrets,
            ".env must be byte-identical after the refusal"
        );
        assert_eq!(
            fs::read(&manifest_rt).unwrap(),
            b"[project]\nname = \"installed\"\n",
            "the vault's manifest must not be replaced by the distribution copy"
        );
    }

    #[test]
    fn a_dangling_env_symlink_is_refused_rather_than_written_through() {
        // `Path::exists` follows symlinks and reports false for a dangling one,
        // which would let `fs::copy`/`create_new` write through the link to a
        // path outside the vault. The check is on `symlink_metadata`.
        let tmp = tempfile::tempdir().unwrap();
        let vault = tmp.path().join("vault");
        fs::create_dir_all(&vault).unwrap();
        let declarations = tmp.path().join("secretspec.toml");
        fs::write(&declarations, b"[project]\nname = \"fresh\"\n").unwrap();

        let target = tmp.path().join("elsewhere/.env");
        std::os::unix::fs::symlink(&target, vault.join(".env")).unwrap();
        assert!(!vault.join(".env").exists(), "precondition: dangling");

        let err = create_fresh_runtime_files(&vault, &declarations)
            .expect_err("a dangling runtime symlink must be refused");
        assert!(
            err.to_string()
                .contains("refusing to overwrite existing runtime file"),
            "{err}"
        );
        assert!(!target.exists(), "nothing may be written through the link");
    }

    #[test]
    fn adopting_a_vault_with_no_env_is_not_refused() {
        // The regression: a vault already migrated to the sqlite-only
        // `secrets.db` store has no `.env` at all, and `install
        // --adopt-existing` must not treat that as a missing runtime file.
        let tmp = tempfile::tempdir().unwrap();
        let vault = tmp.path().join("vault");
        fs::create_dir_all(&vault).unwrap();
        fs::write(vault.join("secretspec.toml"), b"[project]\nname = \"v\"\n").unwrap();
        assert!(!vault.join(".env").exists(), "precondition: no .env");

        validate_adopted_env_if_present(&vault).expect(".env absence must not refuse the adoption");
    }

    #[test]
    fn adopting_a_vault_with_a_real_env_is_not_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let vault = tmp.path().join("vault");
        fs::create_dir_all(&vault).unwrap();
        fs::write(vault.join(".env"), b"API_KEY=sk-live\n").unwrap();

        validate_adopted_env_if_present(&vault).expect("a real .env file is fine");
    }

    #[test]
    fn adopting_a_vault_with_an_env_symlink_is_refused() {
        // Present-but-a-symlink must still be refused, dangling or not --
        // `.env` being optional must not weaken the symlink guard.
        let tmp = tempfile::tempdir().unwrap();
        let vault = tmp.path().join("vault");
        fs::create_dir_all(&vault).unwrap();
        let target = tmp.path().join("elsewhere/.env");
        std::os::unix::fs::symlink(&target, vault.join(".env")).unwrap();
        assert!(!vault.join(".env").exists(), "precondition: dangling");

        let err = validate_adopted_env_if_present(&vault)
            .expect_err("a symlinked .env must be refused even when dangling");
        assert!(
            err.to_string()
                .contains("adopted runtime file missing or symlinked")
        );
    }

    #[test]
    fn a_fresh_vault_still_gets_both_runtime_files() {
        // The refusal must not cost a real fresh install its runtime files.
        let tmp = tempfile::tempdir().unwrap();
        let vault = tmp.path().join("vault");
        fs::create_dir_all(&vault).unwrap();
        let declarations = tmp.path().join("secretspec.toml");
        let body = b"[project]\nname = \"fresh\"\n";
        fs::write(&declarations, body).unwrap();

        let (manifest_rt, env_rt) =
            create_fresh_runtime_files(&vault, &declarations).expect("fresh install must succeed");
        assert_eq!(fs::read(&manifest_rt).unwrap(), body);
        assert_eq!(fs::read(&env_rt).unwrap(), b"", ".env starts empty");
    }

    #[test]
    fn source_restore_force_has_no_nopasswd_grant() {
        // Finding 1 of the ultra review: sudoers argument matching is a glob,
        // so a NOPASSWD grant on `source-restore --*` also matches
        // `source-restore --all` -- an unattended, whole-vault restore, not
        // the single-name forward-safe one the grant exists for. The client
        // (`main.rs::lifecycle_restore`) now routes both `--force` and
        // `--all` through `source-restore-force`, so pin both halves here:
        // the plain verb keeps its NOPASSWD grant for agents, and the force
        // verb has no grant at all, falling through to interactive sudo.
        let text = sudoers_text("alice", "_svc");
        assert!(
            text.contains(&format!(
                "NOPASSWD: {PREFIX}/libexec/sudo-secretspec __broker source-restore --*\n"
            )),
            "plain source-restore must keep its NOPASSWD grant for agents:\n{text}"
        );
        assert!(
            !text.contains("source-restore-force"),
            "source-restore-force must have no sudoers grant at all, NOPASSWD or otherwise:\n{text}"
        );
    }

    #[test]
    fn installing_from_the_installed_tree_itself_is_refused() {
        // The exact incident: the installed client infers `source_root` from
        // its own location, so `broker_src` resolves to the boundary that is
        // already installed. Every copy is a file onto itself, nothing is
        // malformed, and the install reports success having upgraded nothing.
        let tmp = tempfile::tempdir().unwrap();
        let root = media_root(tmp.path());
        let broker_dst = root.join("libexec/sudo-secretspec");

        let err = resolve_media(&root, &broker_dst)
            .expect_err("installing from the installed boundary must be refused");
        assert!(
            err.to_string()
                .contains("refusing to install from the installed boundary itself"),
            "{err}"
        );
        // The message has to carry the way out, because the operator reaches
        // this by running the obvious command.
        assert!(
            err.to_string().contains("libexec/sudo-secretspec install"),
            "{err}"
        );
    }

    #[test]
    fn a_hard_link_to_the_installed_broker_is_still_the_same_file() {
        // Why the check compares (dev, ino) and not canonicalized paths: a hard
        // link has no link to follow, so path comparison would call these two
        // distinct files and wave the no-op through.
        let tmp = tempfile::tempdir().unwrap();
        let root = media_root(tmp.path());
        let broker_dst = tmp.path().join("installed-broker");
        fs::hard_link(root.join("libexec/sudo-secretspec"), &broker_dst).unwrap();

        assert_ne!(root.join("libexec/sudo-secretspec"), broker_dst);
        let err = resolve_media(&root, &broker_dst)
            .expect_err("a hard link to the installed broker is the same no-op");
        assert!(
            err.to_string()
                .contains("refusing to install from the installed boundary itself"),
            "{err}"
        );
    }

    #[test]
    fn real_media_resolves_to_its_three_artifacts() {
        let tmp = tempfile::tempdir().unwrap();
        let root = media_root(tmp.path());

        let media = resolve_media(&root, Path::new("/usr/local/libexec/sudo-secretspec"))
            .expect("distribution media distinct from the destination must be accepted");
        assert_eq!(media.broker, root.join("libexec/sudo-secretspec"));
        assert_eq!(
            media.guidance,
            root.join("share/sudo-secretspec/AI-GUIDANCE.md")
        );
        assert_eq!(
            media.retired,
            root.join("share/sudo-secretspec/sudo-secretspec-retired.toml")
        );
    }

    #[test]
    fn a_first_install_has_no_destination_to_be_confused_with() {
        // Nothing installed yet: the destination does not exist, so it cannot
        // be the source, and the media checks must not turn that into a refusal.
        let tmp = tempfile::tempdir().unwrap();
        let root = media_root(tmp.path());

        resolve_media(&root, &tmp.path().join("absent/libexec/sudo-secretspec"))
            .expect("a first install must not be blocked by a missing destination");
    }

    #[test]
    fn incomplete_media_names_the_missing_file() {
        let tmp = tempfile::tempdir().unwrap();
        let root = media_root(tmp.path());
        fs::remove_file(root.join("share/sudo-secretspec/AI-GUIDANCE.md")).unwrap();

        let err = resolve_media(&root, Path::new("/usr/local/libexec/sudo-secretspec"))
            .expect_err("media missing an artifact must be refused");
        assert!(
            err.to_string().contains("source media is incomplete"),
            "{err}"
        );
        assert!(err.to_string().contains("AI-GUIDANCE.md"), "{err}");
    }

    #[test]
    fn an_explicit_source_root_overrides_the_current_exe_inference() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(resolve_source_root(Some(tmp.path())).unwrap(), tmp.path());
        // Without one it falls back to the running binary's grandparent, which
        // under `cargo test` is the target directory rather than a keg.
        assert!(resolve_source_root(None).is_ok());
    }

    #[test]
    fn the_version_line_distinguishes_an_upgrade_from_a_reinstall() {
        // Deliberately not a real predecessor: pinning one would make this test
        // pass or fail on whatever `VERSION` happens to be today.
        assert_eq!(
            version_transition(Some("0.0.0-older")),
            format!("0.0.0-older -> {VERSION}")
        );
        assert_eq!(
            version_transition(Some(VERSION)),
            format!("{VERSION} (reinstalled, unchanged)")
        );
        // A boundary installed before the stamp existed: report this build
        // rather than inventing a predecessor.
        assert_eq!(version_transition(None), VERSION);
    }

    #[test]
    fn the_installed_version_is_read_back_from_the_config_it_wrote() {
        let tmp = tempfile::tempdir().unwrap();
        let config = tmp.path().join("sudo-secretspec.toml");
        let req = InstallRequest::from_cli(Some(PathBuf::from("/dev/null")), false, false);
        fs::write(
            &config,
            config_toml(&req, Path::new("/private/var/db/sudo-secretspec")),
        )
        .unwrap();

        assert_eq!(installed_version(&config).as_deref(), Some(VERSION));
        // No boundary installed, and a config predating the stamp.
        assert_eq!(installed_version(&tmp.path().join("absent.toml")), None);
    }

    #[test]
    fn an_install_directory_the_operator_owns_is_refused() {
        // The scenario is a host carrying a legacy Intel-Homebrew `chown -R` of
        // /usr/local: the directory exists, looks ordinary, and is writable by
        // an unprivileged user — who could then replace the binary root
        // executes through the NOPASSWD rule. A tempdir is owned by whoever
        // runs the tests, which is the same condition.
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("bin");

        let err = prepare_install_dir(&path).expect_err("a user-owned prefix must be refused");
        assert!(
            err.to_string().contains("unsafe install directory"),
            "{err}"
        );
        // Created before it was judged: a first install has to be able to make
        // these, so the refusal cannot be "it does not exist yet".
        assert!(path.is_dir());
    }

    #[test]
    fn an_install_directory_is_created_at_0755_not_the_ambient_umask() {
        // The policy runs the broker with umask=0077. Inheriting that would
        // give /usr/local/bin mode 0700, unreadable to the operator it exists
        // to serve, so the mode is set explicitly.
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("libexec");
        let previous = unsafe { libc::umask(0o077) };
        let _ = prepare_install_dir(&path);
        unsafe { libc::umask(previous) };

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755, "got {mode:o}");
    }

    /// A protected config naming `vault`, as `install` would have written it.
    fn installed_config(vault: &str, user: &str, group: &str) -> String {
        format!(
            r#"
engine = "/usr/local/libexec/sudo-secretspec"
audit_helper = "/usr/local/libexec/sudo-secretspec"
vault = "/var/db/{vault}"
vault_realpath = "/private/var/db/{vault}"
declarations = "/usr/local/share/sudo-secretspec/secretspec.toml"
service_user = "{user}"
service_group = "{group}"
profile = "default"
adopted_vault = true
"#
        )
    }

    fn write_config(contents: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sudo-secretspec.toml");
        fs::write(&path, contents).unwrap();
        (dir, path)
    }

    #[test]
    fn an_installed_boundary_outranks_a_retired_vault_still_on_disk() {
        // The regression this function exists for. Migration copies secrets to
        // the canonical vault and leaves the wrapper's vault in place as the
        // second copy plus the pre-migration ledger, so BOTH directories exist.
        // A reinstall must follow the installed config, not the older directory.
        let (_tmp, config) = write_config(&installed_config(
            "sudo-secretspec",
            "_sudo_secretspec",
            "_sudo_secretspec",
        ));

        let found = detect_existing_vault(&config, |_| true).unwrap();

        assert_eq!(found.vault, PathBuf::from(DEFAULT_VAULT));
        assert_eq!(found.service_user, DEFAULT_USER);
        assert_eq!(found.service_group, DEFAULT_GROUP);
        assert_eq!(found.origin, VaultOrigin::InstalledConfig);
    }

    #[test]
    fn an_installed_boundary_on_the_legacy_vault_is_still_followed() {
        // Control for the test above: the config is obeyed, not merely a route
        // to the canonical answer. A host that adopted the wrapper's vault and
        // has not migrated must keep resolving to it.
        let (_tmp, config) = write_config(&installed_config(
            "stayturgid-secrets",
            LEGACY_USER,
            LEGACY_GROUP,
        ));

        let found = detect_existing_vault(&config, |_| true).unwrap();

        assert_eq!(found.vault, PathBuf::from(LEGACY_VAULT));
        assert_eq!(found.service_user, LEGACY_USER);
        assert_eq!(found.service_group, LEGACY_GROUP);
        // Origin, not path, is what decides automatic adoption: this IS the
        // legacy vault, but the installed config named it, so an upgrade here
        // is still an upgrade.
        assert_eq!(found.origin, VaultOrigin::InstalledConfig);
    }

    #[test]
    fn with_no_boundary_installed_the_canonical_vault_wins() {
        let missing = PathBuf::from("/nonexistent/sudo-secretspec.toml");

        let found = detect_existing_vault(&missing, |_| true).unwrap();

        assert_eq!(found.vault, PathBuf::from(DEFAULT_VAULT));
        assert_eq!(found.service_user, DEFAULT_USER);
        assert_eq!(found.origin, VaultOrigin::PathScan);
    }

    #[test]
    fn with_no_boundary_installed_the_legacy_vault_is_detected_when_alone() {
        let missing = PathBuf::from("/nonexistent/sudo-secretspec.toml");

        let found = detect_existing_vault(&missing, |p| p == Path::new(LEGACY_VAULT)).unwrap();

        assert_eq!(found.vault, PathBuf::from(LEGACY_VAULT));
        assert_eq!(found.service_user, LEGACY_USER);
        assert_eq!(found.service_group, LEGACY_GROUP);
        // Nothing installed vouches for this, and it is the retired store.
        // `install` must not adopt it without being told to.
        assert_eq!(found.origin, VaultOrigin::PathScan);
    }

    #[test]
    fn a_config_naming_a_vault_that_is_gone_falls_back_to_detection() {
        // A config left behind by an uninstall that purged the vault must not
        // pin the installer to a directory that no longer exists.
        let (_tmp, config) = write_config(&installed_config(
            "sudo-secretspec",
            "_sudo_secretspec",
            "_sudo_secretspec",
        ));

        let found = detect_existing_vault(&config, |p| p == Path::new(LEGACY_VAULT));

        assert_eq!(
            found,
            Some(ExistingVault {
                vault: PathBuf::from(LEGACY_VAULT),
                service_user: LEGACY_USER.into(),
                service_group: LEGACY_GROUP.into(),
                // The config named a vault that is gone, so this answer came
                // from the scan after all -- and must demand the flag, even
                // though a config exists.
                origin: VaultOrigin::PathScan,
            })
        );
    }

    #[test]
    fn an_unparseable_config_falls_back_instead_of_failing() {
        let (_tmp, config) = write_config("this is not toml {{{");

        let found = detect_existing_vault(&config, |_| true).unwrap();

        assert_eq!(found.vault, PathBuf::from(DEFAULT_VAULT));
        // An unparseable config vouches for nothing, so the fallback answer is
        // a guess and is reported as one.
        assert_eq!(found.origin, VaultOrigin::PathScan);
    }

    #[test]
    fn nothing_on_disk_detects_nothing() {
        let missing = PathBuf::from("/nonexistent/sudo-secretspec.toml");

        assert_eq!(detect_existing_vault(&missing, |_| false), None);
    }

    #[test]
    fn an_installed_vault_is_adopted_without_the_flag_but_a_scanned_one_is_not() {
        // The whole trust rule, in one assertion pair. Reinstalling over the
        // vault the installed config names is an upgrade, so it needs no flag.
        // A scanned vault is a guess -- and one of the candidates is the retired
        // wrapper's store -- so it still does.
        assert!(adopts_without_flag(VaultOrigin::InstalledConfig));
        assert!(!adopts_without_flag(VaultOrigin::PathScan));
    }

    #[test]
    fn a_scanned_legacy_vault_never_adopts_itself_even_when_it_is_the_only_one() {
        // The regression that makes the split worth having. With nothing
        // installed, detection happily names the retired vault; if that answer
        // adopted automatically, a first install on a not-yet-migrated host
        // would silently bind the new boundary to retired secrets and a retired
        // service identity, with no operator decision anywhere in the flow.
        let missing = PathBuf::from("/nonexistent/sudo-secretspec.toml");

        let found = detect_existing_vault(&missing, |p| p == Path::new(LEGACY_VAULT)).unwrap();

        assert_eq!(found.vault, PathBuf::from(LEGACY_VAULT));
        assert!(!adopts_without_flag(found.origin));
    }

    #[test]
    fn the_fresh_install_refusal_names_a_runnable_command() {
        // The refusal is the only thing standing between a script and the
        // truncation path, and the failure mode it invites is "make the
        // obstacle go away" -- deleting the vault so a fresh install succeeds.
        // Handing back the command that works is what makes that unnecessary,
        // so the text is asserted rather than left to drift.
        let text = fresh_install_refusal(Some(Path::new("/tmp/decl.toml"))).to_string();
        assert!(text.contains("--adopt-existing"), "{text}");
        assert!(text.contains("/tmp/decl.toml"), "{text}");
        assert!(
            text.contains("sudo-secretspec install --declarations"),
            "{text}"
        );
    }

    #[test]
    fn a_root_owned_system_directory_passes() {
        // Control for the refusal above: the predicate is not simply always
        // false. `/usr` is root-owned and not group- or world-writable on both
        // platforms this suite runs on.
        assert!(is_protected_dir(Path::new("/usr")));
    }
}
