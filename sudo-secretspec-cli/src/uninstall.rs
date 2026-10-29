//! Removal of the sudo-secretspec privileged boundary.
//!
//! The inverse of [`crate::install`], driven by the same ownership manifest
//! ([`crate::install::installed_artifacts`]). Two things it deliberately does
//! not do by default: delete the vault, and delete the service identity. Both
//! outlive any single install — the vault holds the secrets themselves, and the
//! service user has other dependents — so each needs its own opt-in flag.
//!
//! It also never unlinks a sudo policy it cannot show this install wrote. The
//! policy path is predictable and `sudoers.d` is shared with other vendors, so
//! a file sitting at our name is not proof of ownership.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::drift::parse_manifest;
use crate::install::{PREFIX, SUDOERS_DIR, installed_artifacts, prune_snapshots};
use crate::platform::{self, Host};

/// Lowest and highest uid/gid the macOS installer will allocate for the service
/// identity (`install::ensure_service_group`, `install::ensure_service_user`).
/// Linux has no such window; see [`check_linux_service_identity`].
///
/// `--remove-service-user` refuses anything outside this window. An adopted
/// identity can be an ordinary account — the deployed configuration on the
/// development host adopts group `staff` — and deleting one of those because a
/// configuration file named it would be far worse than declining to.
const SERVICE_ID_RANGE: std::ops::RangeInclusive<u32> = 400..=499;

/// Highest id Debian's `base-passwd` reserves for static system accounts
/// (`root`, `daemon`, `www-data`, ...). A service identity the installer
/// created with `useradd --system` always lands above it, so anything at or
/// below it is somebody else's account and `uid` 0 can never qualify.
const LINUX_STATIC_ID_CEILING: u32 = 99;

/// `SYS_UID_MAX`/`SYS_GID_MAX` when `/etc/login.defs` names neither them nor
/// `UID_MIN`/`GID_MIN`: `login.defs(5)` defines the maximum as the regular
/// minimum (default 1000) minus one.
const LINUX_DEFAULT_SYS_ID_MAX: u32 = 999;

/// Absolute, never resolved through `PATH`. `passwd` ships both in `/usr/sbin`
/// on Debian (`/sbin` is a symlink to it on a merged-usr system).
const USERDEL: &str = "/usr/sbin/userdel";
const GROUPDEL: &str = "/usr/sbin/groupdel";
/// The local account databases `userdel`/`groupdel` edit. Read directly rather
/// than through NSS so the check judges exactly what is about to be deleted:
/// an LDAP or NIS account of the same name is not removable by them anyway.
const PASSWD_DB: &str = "/etc/passwd";
const GROUP_DB: &str = "/etc/group";
const LOGIN_DEFS: &str = "/etc/login.defs";

#[derive(Debug, Error)]
pub enum UninstallError {
    #[error("{0}")]
    Denied(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone)]
pub struct UninstallRequest {
    pub dry_run: bool,
    /// Delete the vault directory and every secret in it.
    pub purge_vault: bool,
    /// Delete the service user and group named by the installed configuration.
    pub remove_service_user: bool,
    pub config: PathBuf,
}

/// What uninstall will do with one path from the ownership manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Unlink it.
    Remove,
    /// Nothing is there. Reported rather than skipped so a partial install is
    /// visible in the plan instead of silently absent from it.
    Absent,
    /// Left in place, with the reason. Either the path holds something other
    /// than a regular file, or it is a sudo policy this install cannot account
    /// for.
    Keep(String),
}

/// One owned path and the decision made about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    pub path: PathBuf,
    pub action: Action,
}

impl Step {
    /// True when this path is a sudo policy, which decides both its position in
    /// the plan and how a failure to remove it is treated.
    fn is_policy(&self, sudoers_dir: &Path) -> bool {
        self.path.starts_with(sudoers_dir)
    }
}

/// Decide what may be unlinked, in the order it must happen.
///
/// The artifact table, the manifest rows, and the sudoers directory are all
/// parameters rather than the installed constants, so every ownership branch is
/// testable against a temporary directory without root — the same reason
/// [`crate::rollback::plan_restore`] and [`crate::install::plan_prune`] are
/// split out from the filesystem work they authorise.
///
/// Sudo policies come first in the returned plan. Closing the grant before
/// removing the paths it names is harmless on a prefix only root can write, and
/// correct on one where that is not true.
pub fn plan_uninstall(
    artifacts: &[(PathBuf, u32)],
    manifest: &[(String, PathBuf)],
    sudoers_dir: &Path,
) -> Vec<Step> {
    let (mut policies, rest): (Vec<Step>, Vec<Step>) = artifacts
        .iter()
        .map(|(path, _mode)| Step {
            action: classify(path, manifest, sudoers_dir),
            path: path.clone(),
        })
        .partition(|step| step.is_policy(sudoers_dir));
    policies.extend(rest);
    policies
}

/// Decide the disposition of a single owned path.
///
/// Ownership is proven by hash only for sudo policies, and the asymmetry is
/// deliberate. `sudoers.d` is a shared directory — `yabai` and a legacy
/// `secretspec` wrapper are live neighbours on the development host — so the
/// predictable name proves nothing there. The remaining paths are exact,
/// specific names inside a prefix only root can write, and the installer
/// already overwrites each of them unconditionally; refusing to remove a client
/// binary because it had been upgraded out of band would leave the operator
/// with a half-removed boundary and no command left to finish the job.
fn classify(path: &Path, manifest: &[(String, PathBuf)], sudoers_dir: &Path) -> Action {
    let Ok(meta) = fs::symlink_metadata(path) else {
        return Action::Absent;
    };
    // Not just a type check: `symlink_metadata` stats rather than opens, so a
    // fifo left at an owned path can never reach the read below and block the
    // root process. It is also what keeps a symlink from being followed out of
    // the owned set.
    if !meta.is_file() {
        return Action::Keep(format!(
            "holds a {} rather than a regular file",
            file_kind(&meta)
        ));
    }
    if !path.starts_with(sudoers_dir) {
        return Action::Remove;
    }

    let Some((expected, _)) = manifest.iter().find(|(_, dest)| dest == path) else {
        return Action::Keep(
            "the install manifest does not cover this sudo policy, so this install cannot show \
             it wrote it"
                .into(),
        );
    };
    match sha256_file(path) {
        Ok(actual) if &actual == expected => Action::Remove,
        Ok(_) => Action::Keep(
            "this sudo policy does not match the install manifest; it was replaced or edited \
             after installation"
                .into(),
        ),
        Err(e) => Action::Keep(format!("this sudo policy could not be read: {e}")),
    }
}

fn file_kind(meta: &fs::Metadata) -> &'static str {
    let ty = meta.file_type();
    if ty.is_symlink() {
        "symlink"
    } else if ty.is_dir() {
        "directory"
    } else {
        "special file"
    }
}

fn sha256_file(path: &Path) -> Result<String, UninstallError> {
    let bytes = fs::read(path)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn require_root() -> Result<(), UninstallError> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(UninstallError::Denied(
            "must run as root (Touch ID/sudo is expected, including dry-run)".into(),
        ));
    }
    Ok(())
}

/// Remove the boundary. Returns Ok(()) on success.
pub fn run(req: UninstallRequest) -> Result<(), UninstallError> {
    require_root()?;
    let host = platform::host();

    // Read before anything is unlinked. The configuration names the vault and
    // service identity the opt-in flags act on, and it is itself an owned
    // artifact this run is about to remove.
    let layout = crate::load_config(&req.config).ok();
    if (req.purge_vault || req.remove_service_user) && layout.is_none() {
        return Err(UninstallError::Denied(format!(
            "--purge-vault and --remove-service-user need the installed configuration at {}, \
             which is missing or unreadable",
            req.config.display()
        )));
    }

    // Both opt-in removals are decided here, before a single artifact is
    // unlinked. They are the two that can refuse — an adopted vault or an
    // adopted identity is not ours to delete — and a refusal arriving halfway
    // through would leave the operator with a half-removed boundary and no
    // client left to finish the job. `--dry-run` returns these verdicts too,
    // so an ineligible flag combination is discovered before it is committed
    let vault_real = match (req.purge_vault, &layout) {
        (true, Some(layout)) if layout.adopted_vault => {
            return Err(UninstallError::Denied(
                "the vault was adopted rather than created by this installer; remove it by hand if that is really what you want".into(),
            ));
        }
        (true, Some(layout)) => Some(resolve_purgeable_vault(&layout.vault)?),
        _ => None,
    };
    if let (true, Some(layout)) = (req.remove_service_user, &layout) {
        check_service_identity(host, &layout.service_user, &layout.service_group)?;
    }

    let prefix = PathBuf::from(PREFIX);
    let libexec = prefix.join("libexec");
    let share = prefix.join("share/sudo-secretspec");
    // Same reason: the manifest is what proves the sudo policy is ours, and it
    // is removed by this very plan.
    let manifest = parse_manifest(&share.join("MANIFEST.sha256"));
    let sudoers_dir = Path::new(SUDOERS_DIR);
    let steps = plan_uninstall(&installed_artifacts(), &manifest, sudoers_dir);

    if req.dry_run {
        println!("would uninstall sudo-secretspec");
        for step in &steps {
            match &step.action {
                Action::Remove => println!("would_remove={}", step.path.display()),
                Action::Absent => println!("absent={}", step.path.display()),
                Action::Keep(reason) => {
                    println!("would_keep={} ({reason})", step.path.display())
                }
            }
        }
        println!("purge_vault={}", u8::from(req.purge_vault));
        println!("remove_service_user={}", u8::from(req.remove_service_user));
        if let Some(vault_real) = &vault_real {
            println!("would_purge_vault={}", vault_real.display());
        }
        if let Some(layout) = &layout {
            println!("vault={}", layout.vault.display());
            println!("service={}:{}", layout.service_user, layout.service_group);
        }
        return Ok(());
    }

    let mut removed = 0usize;
    let mut kept = Vec::new();
    let mut failed = Vec::new();
    for step in &steps {
        match &step.action {
            Action::Remove => match fs::remove_file(&step.path) {
                Ok(()) => {
                    removed += 1;
                    println!("removed={}", step.path.display());
                }
                // A policy that will not come off is the one failure worth
                // stopping for: the whole point of removing it first is that the
                // paths it grants are still present. Carrying on would strip the
                // binaries out from under a live grant.
                Err(e) if step.is_policy(sudoers_dir) => {
                    return Err(UninstallError::Denied(format!(
                        "cannot remove the sudo policy {}: {e}; nothing else was removed",
                        step.path.display()
                    )));
                }
                Err(e) => {
                    eprintln!("warning: cannot remove {}: {e}", step.path.display());
                    failed.push(step.path.clone());
                }
            },
            Action::Absent => {}
            Action::Keep(reason) => {
                eprintln!("warning: left in place: {} — {reason}", step.path.display());
                kept.push(step.path.clone());
            }
        }
    }

    // `remove_dir` refuses a non-empty directory, and that refusal is the
    // guard: this directory only ever holds artifacts the plan above removed,
    // so anything still in it is not ours to delete.
    let share_removed = fs::remove_dir(&share).is_ok();
    println!("removed_share_dir={}", u8::from(share_removed));

    // Every retained snapshot restores artifacts that no longer exist. Keeping
    // `keep = 0` here rather than a bespoke walk means these directories are
    // vetted by exactly the guards a normal install prunes them under.
    println!("pruned_snapshots={}", prune_snapshots(&libexec, 0));

    if let Some(vault_real) = &vault_real {
        fs::remove_dir_all(vault_real)?;
        println!("purged_vault={}", vault_real.display());
    }
    if let (true, Some(layout)) = (req.remove_service_user, &layout) {
        remove_service_identity(host, &layout.service_user, &layout.service_group)?;
        println!(
            "removed_service_identity={}:{}",
            layout.service_user, layout.service_group
        );
        // `useradd --system` hands out the highest free id, so the numeric ids
        // just released are the likeliest to be reused. Files left behind keep
        // them, and the next account to receive one would own the vault.
        if host == Host::Linux && vault_real.is_none() {
            eprintln!(
                "warning: the preserved vault {} stays owned by the numeric uid/gid of the \
                 removed service account; a later account given the same ids would own it",
                layout.vault.display()
            );
        }
    }

    println!("uninstalled sudo-secretspec");
    println!("removed_artifacts={removed}");
    // Say so explicitly: the secrets surviving an uninstall is the default, and
    // an operator who wanted them gone needs to see that they are not.
    if let (false, Some(layout)) = (req.purge_vault, &layout) {
        println!("vault_preserved={}", layout.vault.display());
    }
    if !kept.is_empty() {
        eprintln!(
            "warning: {} path(s) were left in place and need review by hand:",
            kept.len()
        );
        for path in &kept {
            eprintln!("warning:   {}", path.display());
        }
        if kept.iter().any(|p| p.starts_with(sudoers_dir)) {
            eprintln!(
                "warning: a sudo policy for sudo-secretspec is still installed. It now grants\n\
                 warning: paths that no longer exist. Inspect it and, if it is yours to remove,\n\
                 warning: delete it with `visudo -c` afterwards to confirm sudo still parses."
            );
        }
    }
    if !failed.is_empty() {
        return Err(UninstallError::Denied(format!(
            "{} owned path(s) could not be removed; see the warnings above",
            failed.len()
        )));
    }
    Ok(())
}

/// Resolve the one directory `--purge-vault` is allowed to delete.
///
/// Purging is the only part of uninstall that destroys secret values, which is
/// why it is opt-in. The path is re-derived and re-checked here rather than
/// trusted from the configuration that named it: a later `remove_dir_all` that
/// followed a symlink out of the protected database root would delete something
/// else entirely. Returning the resolved path is what makes the caller delete
/// the directory that was checked rather than the name that was configured.
///
/// Split from the deletion so [`run`] can settle it before it unlinks anything.
fn resolve_purgeable_vault(vault: &Path) -> Result<PathBuf, UninstallError> {
    resolve_purgeable_vault_under(vault, Path::new(platform::VAULT_REAL_PARENT))
}

/// [`resolve_purgeable_vault`] against an explicit protected database root.
///
/// The root is `/private/var/db` on macOS and `/var/lib` on Linux
/// ([`platform::VAULT_REAL_PARENT`]); taking it as a parameter lets each be
/// exercised without owning either directory.
fn resolve_purgeable_vault_under(
    vault: &Path,
    real_parent: &Path,
) -> Result<PathBuf, UninstallError> {
    let meta = fs::symlink_metadata(vault)
        .map_err(|e| UninstallError::Denied(format!("vault is missing or unreadable: {e}")))?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err(UninstallError::Denied(format!(
            "vault is not a directory: {}",
            vault.display()
        )));
    }
    let real = fs::canonicalize(vault)
        .map_err(|e| UninstallError::Denied(format!("cannot resolve vault: {e}")))?;
    // A direct child of the protected database root and nothing else — not the
    // root itself, and not something nested deeper that a doctored
    // configuration could point at.
    if real.parent() != Some(real_parent) {
        return Err(UninstallError::Denied(format!(
            "vault resolves to {}, which is not a direct child of {}; refusing to purge it",
            real.display(),
            real_parent.display()
        )));
    }
    Ok(real)
}

/// Refusal for a host whose service account is declared rather than installed.
fn declared_identity_refusal() -> UninstallError {
    UninstallError::Denied(
        platform::lifecycle_refusal_for(Host::NixOs, platform::DEFAULT_BROKER_PATH, "uninstall")
            .unwrap_or_default(),
    )
}

/// Refuse any identity that does not look like one this installer created.
///
/// Dispatches on the running host: macOS judges directory-service records,
/// ordinary Linux judges the local `passwd`/`group` files. Split from
/// [`remove_service_identity`] so [`run`] can settle it before it unlinks
/// anything.
fn check_service_identity(host: Host, user: &str, group: &str) -> Result<(), UninstallError> {
    match host {
        Host::MacOs => check_macos_service_identity(user, group),
        Host::Linux => {
            let passwd = read_account_db(PASSWD_DB)?;
            let group_db = read_account_db(GROUP_DB)?;
            // Absent `login.defs` just means the documented defaults apply.
            let login_defs = fs::read_to_string(LOGIN_DEFS).unwrap_or_default();
            check_linux_service_identity(user, group, &passwd, &group_db, &login_defs)
        }
        Host::NixOs => Err(declared_identity_refusal()),
    }
}

/// Delete the service user and group, once [`check_service_identity`] has
/// allowed it.
fn remove_service_identity(host: Host, user: &str, group: &str) -> Result<(), UninstallError> {
    match host {
        Host::MacOs => remove_macos_service_identity(user, group),
        Host::Linux => remove_linux_service_identity(user, group),
        Host::NixOs => Err(declared_identity_refusal()),
    }
}

/// Look up a numeric id from the local directory service.
fn directory_id(record: &str, key: &str) -> Option<u32> {
    let output = Command::new("/usr/bin/dscl")
        .args([".", "-read", record, key])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .last()
        .and_then(|s| s.parse().ok())
}

/// macOS: a leading underscore plus an id inside [`SERVICE_ID_RANGE`], which is
/// exactly what `install::ensure_service_user` and `ensure_service_group`
/// allocate. An install that *adopted* an existing identity therefore declines
/// here rather than deleting an account that predates it and may still have
/// dependents: the deployed configuration on the development host adopts
/// `_secretspec:staff`, where the group is an ordinary system group and the
/// user's other consumer is the legacy stayturgid wrapper.
fn check_macos_service_identity(user: &str, group: &str) -> Result<(), UninstallError> {
    for (name, record, key) in [
        (user, format!("/Users/{user}"), "UniqueID"),
        (group, format!("/Groups/{group}"), "PrimaryGroupID"),
    ] {
        // Absent already: nothing to delete, and nothing to object to.
        let Some(id) = directory_id(&record, key) else {
            continue;
        };
        if !name.starts_with('_') {
            return Err(UninstallError::Denied(format!(
                "{record} does not look like a dedicated service identity (no leading \
                 underscore); it was adopted rather than created here, so remove it by hand if \
                 that is really what you want"
            )));
        }
        if !SERVICE_ID_RANGE.contains(&id) {
            return Err(UninstallError::Denied(format!(
                "{record} has id {id}, outside the {}-{} range this installer allocates, so it \
                 was not created here; remove it by hand if that is really what you want",
                SERVICE_ID_RANGE.start(),
                SERVICE_ID_RANGE.end()
            )));
        }
    }
    Ok(())
}

fn remove_macos_service_identity(user: &str, group: &str) -> Result<(), UninstallError> {
    for (record, key) in [
        (format!("/Users/{user}"), "UniqueID"),
        (format!("/Groups/{group}"), "PrimaryGroupID"),
    ] {
        if directory_id(&record, key).is_none() {
            continue;
        }
        let status = Command::new("/usr/bin/dscl")
            .args([".", "-delete", &record])
            .status()?;
        if !status.success() {
            return Err(UninstallError::Denied(format!("failed to delete {record}")));
        }
    }
    Ok(())
}

fn read_account_db(path: &str) -> Result<String, UninstallError> {
    fs::read_to_string(path).map_err(|e| {
        UninstallError::Denied(format!(
            "cannot read {path} to vet the service identity before removing it: {e}"
        ))
    })
}

/// Debian's `NAME_REGEX` shape, minus the trailing `$`: lower-case letter or
/// underscore, then letters, digits, `_` or `-`, at most 32 bytes. The names
/// come from a root-owned file, but they are handed to `userdel`/`groupdel` as
/// argv, so one that could parse as an option (`-f`) or name a different
/// account never reaches them.
fn linux_account_name_valid(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    name.len() <= 32
        && (first.is_ascii_lowercase() || first == '_')
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

/// Split one `/etc/passwd` row into `(name, uid, primary gid)`.
fn passwd_row(line: &str) -> Option<(&str, u32, u32)> {
    let mut fields = line.split(':');
    let name = fields.next()?;
    let _password = fields.next()?;
    let uid = fields.next()?.parse().ok()?;
    let gid = fields.next()?.parse().ok()?;
    Some((name, uid, gid))
}

/// `(uid, primary gid)` of the local account `name`.
fn passwd_entry(passwd: &str, name: &str) -> Option<(u32, u32)> {
    passwd
        .lines()
        .filter_map(passwd_row)
        .find(|(row_name, _, _)| *row_name == name)
        .map(|(_, uid, gid)| (uid, gid))
}

/// A local `/etc/group` row: its id and listed (supplementary) members.
struct GroupEntry {
    gid: u32,
    members: Vec<String>,
}

fn group_entry(group_db: &str, name: &str) -> Option<GroupEntry> {
    group_db.lines().find_map(|line| {
        let mut fields = line.split(':');
        if fields.next()? != name {
            return None;
        }
        let _password = fields.next()?;
        let gid: u32 = fields.next()?.parse().ok()?;
        let members = fields
            .next()
            .unwrap_or("")
            .split(',')
            .filter(|member| !member.is_empty())
            .map(str::to_owned)
            .collect();
        Some(GroupEntry { gid, members })
    })
}

/// Accounts other than `except` whose primary group is `gid`.
fn other_primary_members<'a>(passwd: &'a str, gid: u32, except: &str) -> Vec<&'a str> {
    passwd
        .lines()
        .filter_map(passwd_row)
        .filter(|(name, _, primary)| *primary == gid && *name != except)
        .map(|(name, _, _)| name)
        .collect()
}

/// A `login.defs` number: decimal, `0x` hex, or leading-`0` octal.
fn parse_login_defs_number(raw: &str) -> Option<u32> {
    if let Some(hex) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).ok()
    } else if let Some(octal) = raw.strip_prefix('0').filter(|rest| !rest.is_empty()) {
        u32::from_str_radix(octal, 8).ok()
    } else {
        raw.parse().ok()
    }
}

fn login_defs_value(login_defs: &str, key: &str) -> Option<u32> {
    login_defs.lines().find_map(|line| {
        let line = line.trim();
        if line.starts_with('#') {
            return None;
        }
        let mut fields = line.split_whitespace();
        if fields.next()? != key {
            return None;
        }
        parse_login_defs_number(fields.next()?)
    })
}

/// Highest id `useradd --system` allocates: `max_key` (`SYS_UID_MAX`), else the
/// regular minimum (`UID_MIN`) minus one, else [`LINUX_DEFAULT_SYS_ID_MAX`] —
/// the order `login.defs(5)` documents.
fn linux_system_id_max(login_defs: &str, max_key: &str, regular_min_key: &str) -> u32 {
    login_defs_value(login_defs, max_key)
        .or_else(|| {
            login_defs_value(login_defs, regular_min_key).map(|regular| regular.saturating_sub(1))
        })
        .unwrap_or(LINUX_DEFAULT_SYS_ID_MAX)
}

fn linux_id_in_system_range(id: u32, system_max: u32) -> bool {
    id > LINUX_STATIC_ID_CEILING && id <= system_max
}

/// Linux counterpart of [`check_macos_service_identity`], over the text of
/// the local account databases so every rule is testable without root.
///
/// Linux has no hidden-id window like macOS's 400-499, so "this installer
/// created it" is established from what a dedicated service account looks
/// like instead: a valid account name; ids above the static `base-passwd`
/// range and within `SYS_UID_MAX`/`SYS_GID_MAX`; a user whose primary group is
/// the named service group; and a group with no other members and no other
/// account using it as primary. An adopted account — `www-data`, a login
/// user, a group shared with other services — fails at least one of these and
/// declines, because deleting one on the strength of a configuration file
/// naming it is far worse than declining to.
///
/// An identity that is already absent is not an error.
fn check_linux_service_identity(
    user: &str,
    group: &str,
    passwd: &str,
    group_db: &str,
    login_defs: &str,
) -> Result<(), UninstallError> {
    for (kind, name) in [("user", user), ("group", group)] {
        if !linux_account_name_valid(name) {
            return Err(UninstallError::Denied(format!(
                "the configured service {kind} name {name:?} is not a valid account name; \
                 refusing to pass it to userdel/groupdel"
            )));
        }
    }
    let uid_max = linux_system_id_max(login_defs, "SYS_UID_MAX", "UID_MIN");
    let gid_max = linux_system_id_max(login_defs, "SYS_GID_MAX", "GID_MIN");
    let service_group = group_entry(group_db, group);

    if let Some((uid, primary_gid)) = passwd_entry(passwd, user) {
        if !linux_id_in_system_range(uid, uid_max) {
            return Err(UninstallError::Denied(format!(
                "user {user} has uid {uid}, outside the {}-{uid_max} system range this installer \
                 allocates from, so it was not created here; remove it by hand if that is really \
                 what you want",
                LINUX_STATIC_ID_CEILING + 1
            )));
        }
        if service_group.as_ref().map(|entry| entry.gid) != Some(primary_gid) {
            return Err(UninstallError::Denied(format!(
                "user {user} has primary gid {primary_gid}, which is not group {group}; a \
                 dedicated service account is created with that group as its own, so this one was \
                 adopted rather than created here, and you should remove it by hand if that is \
                 really what you want"
            )));
        }
    }

    if let Some(entry) = &service_group {
        if !linux_id_in_system_range(entry.gid, gid_max) {
            return Err(UninstallError::Denied(format!(
                "group {group} has gid {}, outside the {}-{gid_max} system range this installer \
                 allocates from, so it was not created here; remove it by hand if that is really \
                 what you want",
                entry.gid,
                LINUX_STATIC_ID_CEILING + 1
            )));
        }
        if let Some(member) = entry.members.iter().find(|member| member.as_str() != user) {
            return Err(UninstallError::Denied(format!(
                "group {group} also has member {member}; it is shared rather than dedicated to \
                 this service, so remove it by hand if that is really what you want"
            )));
        }
        if let Some(other) = other_primary_members(passwd, entry.gid, user).first() {
            return Err(UninstallError::Denied(format!(
                "account {other} uses group {group} as its primary group; it is shared rather \
                 than dedicated to this service, so remove it by hand if that is really what you \
                 want"
            )));
        }
    }
    Ok(())
}

/// Program and argv that delete the local account `name`. Never `-f` (which
/// removes a group still in use) and never `-r` (which would delete a home
/// directory this installer does not own); the name is validated by
/// [`check_linux_service_identity`] before it gets here.
fn linux_userdel_command(name: &str) -> (&'static str, Vec<String>) {
    (USERDEL, vec![name.to_owned()])
}

/// Program and argv that delete the local group `name`; see
/// [`linux_userdel_command`].
fn linux_groupdel_command(name: &str) -> (&'static str, Vec<String>) {
    (GROUPDEL, vec![name.to_owned()])
}

fn run_account_command(command: (&'static str, Vec<String>)) -> Result<(), UninstallError> {
    let (program, args) = command;
    let status = Command::new(program).args(&args).status()?;
    if !status.success() {
        return Err(UninstallError::Denied(format!(
            "failed to run {program} {}",
            args.join(" ")
        )));
    }
    Ok(())
}

/// Delete the user, then the group. The group is looked up again after the
/// user is gone: with `USERGROUPS_ENAB yes`, Debian's default, `userdel`
/// already removes a same-named group that has no other members, and
/// `groupdel` on a group that no longer exists would fail the whole uninstall
/// for nothing.
fn remove_linux_service_identity(user: &str, group: &str) -> Result<(), UninstallError> {
    if passwd_entry(&read_account_db(PASSWD_DB)?, user).is_some() {
        run_account_command(linux_userdel_command(user))?;
    }
    if group_entry(&read_account_db(GROUP_DB)?, group).is_some() {
        run_account_command(linux_groupdel_command(group))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt as _;

    fn hash(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }

    /// The artifact table shape, rebased onto a temporary directory.
    fn artifacts(root: &Path) -> Vec<(PathBuf, u32)> {
        vec![
            (root.join("bin/sudo-secretspec"), 0o755),
            (root.join("share/MANIFEST.sha256"), 0o444),
            (root.join("sudoers.d/sudo-secretspec"), 0o440),
        ]
    }

    fn write(path: &Path, bytes: &[u8]) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }

    #[test]
    fn the_sudo_policy_is_always_planned_first() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let sudoers_dir = root.join("sudoers.d");
        let policy = sudoers_dir.join("sudo-secretspec");
        write(&root.join("bin/sudo-secretspec"), b"client");
        write(&root.join("share/MANIFEST.sha256"), b"manifest");
        write(&policy, b"policy");

        let manifest = vec![(hash(b"policy"), policy.clone())];
        let plan = plan_uninstall(&artifacts(root), &manifest, &sudoers_dir);

        // The grant has to close before the paths it names go away.
        assert_eq!(plan[0].path, policy, "{plan:?}");
        assert_eq!(plan[0].action, Action::Remove, "{plan:?}");
        assert_eq!(plan.len(), 3);
        assert!(
            plan[1..].iter().all(|s| s.action == Action::Remove),
            "{plan:?}"
        );
    }

    #[test]
    fn a_sudo_policy_the_manifest_does_not_cover_is_kept() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let sudoers_dir = root.join("sudoers.d");
        let policy = sudoers_dir.join("sudo-secretspec");
        write(&policy, b"someone else's policy");

        // An empty manifest is what a missing or unreadable one parses to.
        let plan = plan_uninstall(&artifacts(root), &[], &sudoers_dir);
        let step = plan.iter().find(|s| s.path == policy).unwrap();
        match &step.action {
            Action::Keep(reason) => assert!(reason.contains("manifest"), "{reason}"),
            other => panic!("expected the policy to be kept, got {other:?}"),
        }
    }

    #[test]
    fn a_sudo_policy_edited_after_installation_is_kept() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let sudoers_dir = root.join("sudoers.d");
        let policy = sudoers_dir.join("sudo-secretspec");
        write(&policy, b"edited by hand");

        // The manifest records what we installed; the bytes on disk differ.
        let manifest = vec![(hash(b"as installed"), policy.clone())];
        let plan = plan_uninstall(&artifacts(root), &manifest, &sudoers_dir);
        let step = plan.iter().find(|s| s.path == policy).unwrap();
        match &step.action {
            Action::Keep(reason) => assert!(reason.contains("does not match"), "{reason}"),
            other => panic!("expected the policy to be kept, got {other:?}"),
        }
    }

    #[test]
    fn a_missing_artifact_is_reported_not_removed() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let sudoers_dir = root.join("sudoers.d");

        let plan = plan_uninstall(&artifacts(root), &[], &sudoers_dir);
        assert!(
            plan.iter().all(|s| s.action == Action::Absent),
            "nothing exists, so nothing may be removed: {plan:?}"
        );
    }

    #[test]
    fn a_directory_at_an_owned_path_is_never_unlinked() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let sudoers_dir = root.join("sudoers.d");
        let client = root.join("bin/sudo-secretspec");
        fs::create_dir_all(&client).unwrap();

        let plan = plan_uninstall(&artifacts(root), &[], &sudoers_dir);
        let step = plan.iter().find(|s| s.path == client).unwrap();
        match &step.action {
            Action::Keep(reason) => assert!(reason.contains("directory"), "{reason}"),
            other => panic!("expected the directory to be kept, got {other:?}"),
        }
    }

    #[test]
    fn a_symlink_at_an_owned_path_is_never_followed() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let sudoers_dir = root.join("sudoers.d");
        let target = root.join("elsewhere");
        fs::write(&target, b"not ours").unwrap();
        let client = root.join("bin/sudo-secretspec");
        fs::create_dir_all(client.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&target, &client).unwrap();

        let plan = plan_uninstall(&artifacts(root), &[], &sudoers_dir);
        let step = plan.iter().find(|s| s.path == client).unwrap();
        match &step.action {
            Action::Keep(reason) => assert!(reason.contains("symlink"), "{reason}"),
            other => panic!("expected the symlink to be kept, got {other:?}"),
        }
        assert!(target.exists(), "the symlink target must be untouched");
    }

    #[test]
    fn purge_refuses_a_vault_outside_the_protected_database_root() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("vault");
        fs::create_dir(&vault).unwrap();

        let err = resolve_purgeable_vault(&vault)
            .expect_err("a vault outside the protected database root must be refused");
        assert!(
            err.to_string().contains(platform::VAULT_REAL_PARENT),
            "{err}"
        );
        assert!(vault.is_dir(), "the directory must survive the refusal");
    }

    #[test]
    fn purge_refuses_a_symlinked_vault() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        fs::create_dir(&real).unwrap();
        let link = dir.path().join("vault");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let err = resolve_purgeable_vault(&link).expect_err("a symlinked vault must be refused");
        assert!(err.to_string().contains("not a directory"), "{err}");
        assert!(real.is_dir(), "the symlink target must be untouched");
    }

    /// An adopted group is an ordinary system group. Nothing about the name
    /// says this installer made it, so `--remove-service-user` declines.
    #[cfg(target_os = "macos")]
    #[test]
    fn an_identity_without_the_service_naming_is_never_deleted() {
        let err = check_macos_service_identity("_no_such_user_for_this_test", "staff")
            .expect_err("an ordinary system group must be refused");
        assert!(err.to_string().contains("underscore"), "{err}");
    }

    /// The naming alone is not enough: plenty of macOS system accounts carry a
    /// leading underscore. `_www` is uid 70, far below the range the installer
    /// allocates from, so it cannot be one of ours.
    #[cfg(target_os = "macos")]
    #[test]
    fn an_identity_outside_the_allocated_id_range_is_never_deleted() {
        let err = check_macos_service_identity("_www", "_www")
            .expect_err("a system account outside the allocated range must be refused");
        assert!(err.to_string().contains("outside the"), "{err}");
    }

    /// An identity that is already gone is not an error — there is nothing to
    /// delete and nothing to object to.
    #[cfg(target_os = "macos")]
    #[test]
    fn an_absent_identity_is_not_an_error() {
        check_macos_service_identity(
            "_no_such_user_for_this_test",
            "_no_such_group_for_this_test",
        )
        .expect("an identity that does not exist needs no removal");
    }

    /// A Debian-shaped account database: the installer's own account at the
    /// top of the system range, next to a static system account, a login user
    /// and root.
    const DEBIAN_PASSWD: &str = "root:x:0:0:root:/root:/bin/bash\n\
        www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n\
        alice:x:1000:1000:Alice:/home/alice:/bin/bash\n\
        sudo-secretspec:x:998:998::/var/lib/sudo-secretspec:/usr/sbin/nologin\n";
    const DEBIAN_GROUP: &str = "root:x:0:\n\
        www-data:x:33:\n\
        alice:x:1000:\n\
        sudo-secretspec:x:998:\n";
    const DEBIAN_LOGIN_DEFS: &str = "# comment\nUID_MIN\t\t1000\nUID_MAX 60000\nGID_MIN 1000\n";

    fn linux_check(
        user: &str,
        group: &str,
        passwd: &str,
        group_db: &str,
    ) -> Result<(), UninstallError> {
        check_linux_service_identity(user, group, passwd, group_db, DEBIAN_LOGIN_DEFS)
    }

    #[test]
    fn linux_removes_the_dedicated_service_identity() {
        linux_check(
            "sudo-secretspec",
            "sudo-secretspec",
            DEBIAN_PASSWD,
            DEBIAN_GROUP,
        )
        .expect("a system-range account with its own group is one this installer created");
    }

    #[test]
    fn linux_absent_identity_is_not_an_error() {
        linux_check("sudo-secretspec", "sudo-secretspec", "", "")
            .expect("an identity that does not exist needs no removal");
        // The group can outlive the user (userdel only drops it with the user).
        let group_only = "sudo-secretspec:x:998:\n";
        linux_check("sudo-secretspec", "sudo-secretspec", "", group_only)
            .expect("a dedicated group without its user is still removable");
    }

    /// An adopted ordinary account is never deleted just because the
    /// configuration named it: a login user, a static system account and root
    /// all fall outside the range `useradd --system` allocates from.
    #[test]
    fn linux_accounts_outside_the_system_range_are_never_deleted() {
        for name in ["alice", "www-data", "root"] {
            let err = linux_check(name, name, DEBIAN_PASSWD, DEBIAN_GROUP)
                .expect_err("an account outside the system range must be refused");
            assert!(err.to_string().contains("outside the"), "{name}: {err}");
        }
    }

    /// An adopted identity whose group is not the one named: the user lives in
    /// the system range but its primary group is `users` (gid 100).
    #[test]
    fn linux_user_whose_primary_group_is_not_the_service_group_is_refused() {
        let passwd = "sudo-secretspec:x:998:100::/nonexistent:/usr/sbin/nologin\n";
        let err = linux_check("sudo-secretspec", "sudo-secretspec", passwd, DEBIAN_GROUP)
            .expect_err("an adopted user must be refused");
        assert!(err.to_string().contains("primary gid"), "{err}");
    }

    #[test]
    fn linux_shared_group_is_never_deleted() {
        let with_member = "sudo-secretspec:x:998:alice\n";
        let err = linux_check(
            "sudo-secretspec",
            "sudo-secretspec",
            DEBIAN_PASSWD,
            with_member,
        )
        .expect_err("a group with another member is not dedicated");
        assert!(err.to_string().contains("also has member alice"), "{err}");

        // Another account's primary group: groupdel would refuse it halfway,
        // after the user was already gone.
        let passwd = format!("{DEBIAN_PASSWD}svc:x:997:998::/nonexistent:/usr/sbin/nologin\n");
        let err = linux_check("sudo-secretspec", "sudo-secretspec", &passwd, DEBIAN_GROUP)
            .expect_err("a group another account uses as primary is not dedicated");
        assert!(err.to_string().contains("account svc"), "{err}");
    }

    /// The range is the host's own: `SYS_UID_MAX` wins, then `UID_MIN - 1`.
    #[test]
    fn linux_system_range_follows_login_defs() {
        let check = |defs: &str| {
            check_linux_service_identity(
                "sudo-secretspec",
                "sudo-secretspec",
                DEBIAN_PASSWD,
                DEBIAN_GROUP,
                defs,
            )
        };
        check("").expect("uid 998 is inside the documented 999 default");
        check("SYS_UID_MAX 0x3e7\nSYS_GID_MAX 999\n").expect("hex values are numbers");
        let err = check("SYS_UID_MAX 499\n").expect_err("998 is above an explicit maximum");
        assert!(err.to_string().contains("outside the 100-499"), "{err}");
        let err = check("UID_MIN 500\n").expect_err("no SYS_UID_MAX: the maximum is UID_MIN - 1");
        assert!(err.to_string().contains("outside the 100-499"), "{err}");
        let err = check("GID_MIN 500\n").expect_err("the gid range is derived on its own");
        assert!(err.to_string().contains("gid 998"), "{err}");
    }

    /// Names reach `userdel`/`groupdel` as argv, so one that parses as an
    /// option, or is not an account name at all, never gets there.
    #[test]
    fn linux_invalid_account_names_are_refused() {
        let too_long = "a".repeat(33);
        for bad in ["", "-f", "Root", "a b", "x:y", too_long.as_str()] {
            let err = linux_check(bad, "sudo-secretspec", DEBIAN_PASSWD, DEBIAN_GROUP)
                .expect_err("an invalid name must be refused");
            assert!(
                err.to_string().contains("not a valid account name"),
                "{bad:?}: {err}"
            );
            let err = linux_check("sudo-secretspec", bad, DEBIAN_PASSWD, DEBIAN_GROUP)
                .expect_err("an invalid name must be refused");
            assert!(
                err.to_string().contains("not a valid account name"),
                "{bad:?}: {err}"
            );
        }
    }

    /// Absolute program, the bare name and nothing else: no `-f` (removes a
    /// group still in use) and no `-r` (removes a home directory).
    #[test]
    fn linux_removal_commands_are_absolute_and_carry_only_the_name() {
        assert_eq!(
            linux_userdel_command("sudo-secretspec"),
            ("/usr/sbin/userdel", vec!["sudo-secretspec".to_string()])
        );
        assert_eq!(
            linux_groupdel_command("sudo-secretspec"),
            ("/usr/sbin/groupdel", vec!["sudo-secretspec".to_string()])
        );
    }

    /// A NixOS service account is declared by the module; uninstall never
    /// reaches for it, and says where to change it.
    #[test]
    fn nixos_identity_is_never_touched_by_uninstall() {
        let err = check_service_identity(Host::NixOs, "sudo-secretspec", "sudo-secretspec")
            .expect_err("NixOS declares its service account");
        assert!(
            err.to_string().contains("services.sudo-secretspec"),
            "{err}"
        );
        let err = remove_service_identity(Host::NixOs, "sudo-secretspec", "sudo-secretspec")
            .expect_err("NixOS declares its service account");
        assert!(
            err.to_string().contains("services.sudo-secretspec"),
            "{err}"
        );
    }

    /// The protected database root is the platform's: purging only ever
    /// deletes a direct child of it.
    #[test]
    fn purge_accepts_only_a_direct_child_of_the_database_root() {
        let dir = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        let vault = root.join("sudo-secretspec");
        fs::create_dir(&vault).unwrap();
        assert_eq!(resolve_purgeable_vault_under(&vault, &root).unwrap(), vault);

        let nested = root.join("nested/sudo-secretspec");
        fs::create_dir_all(&nested).unwrap();
        let err = resolve_purgeable_vault_under(&nested, &root)
            .expect_err("a vault nested below a child must be refused");
        assert!(err.to_string().contains("not a direct child"), "{err}");

        let other = tempfile::tempdir().unwrap();
        let err = resolve_purgeable_vault_under(&vault, &fs::canonicalize(other.path()).unwrap())
            .expect_err("a vault under some other root must be refused");
        assert!(err.to_string().contains("not a direct child"), "{err}");
    }

    #[test]
    fn uninstall_requires_root() {
        // The suite does not run as root, so this is the real refusal path.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let err = run(UninstallRequest {
            dry_run: true,
            purge_vault: false,
            remove_service_user: false,
            config: PathBuf::from("/usr/local/etc/sudo-secretspec.toml"),
        })
        .expect_err("uninstall must require root, including dry-run");
        assert!(err.to_string().contains("root"), "{err}");
    }

    #[test]
    fn owned_modes_are_untouched_by_planning() {
        // Planning must never mutate; the plan is inspected before it is run.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let client = root.join("bin/sudo-secretspec");
        write(&client, b"client");
        let before = fs::metadata(&client).unwrap().mode();

        let _ = plan_uninstall(&artifacts(root), &[], &root.join("sudoers.d"));
        assert_eq!(fs::metadata(&client).unwrap().mode(), before);
        assert!(client.is_file());
    }
}
