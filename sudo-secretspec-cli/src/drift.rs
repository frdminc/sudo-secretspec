//! Metadata-only, non-repairing drift validation for sudo-secretspec.
//!
//! Never reads secret values. Never mutates state.
//!
//! The second promise reaches through the audit ledger too, which is why the
//! integrity check here goes through [`audit::verify_read_only`]. The ordinary
//! [`audit::verify`] path opens the ledger read-write and normalises it on the
//! way in — mode, ownership, and `CREATE TABLE IF NOT EXISTS` — so running it
//! from a checker meant a `doctor` invocation could quietly rewrite the thing it
//! was reporting on.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::audit;
use crate::config::Config;

#[derive(Debug, Error)]
pub enum DriftError {
    #[error("config: {0}")]
    Config(#[from] crate::config::ConfigError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    pub config: PathBuf,
    pub vault: PathBuf,
    pub vault_realpath: PathBuf,
    pub service_user: String,
    pub service_group: String,
    pub declarations: Option<PathBuf>,
    pub engine: PathBuf,
    pub audit: PathBuf,
    pub broker: PathBuf,
    pub client: PathBuf,
    pub checker: PathBuf,
    pub retired: PathBuf,
    pub guidance: PathBuf,
    pub sudoers: PathBuf,
    pub source_manifest: PathBuf,
    pub adopted_vault: bool,
    /// Version stamped into the config by the installer that wrote it, or
    /// `None` for a boundary installed before the stamp existed.
    pub installed_version: Option<String>,
}

impl Layout {
    fn from_config(cfg: Config, config_path: PathBuf) -> Self {
        // Prefer deriving the install prefix from the configured engine path.
        // Single-binary installs place the privileged binary under libexec and
        // the public client under bin.
        let prefix = cfg
            .engine
            .parent()
            .and_then(Path::parent)
            .unwrap_or_else(|| Path::new("/usr/local"))
            .to_path_buf();
        let libexec = prefix.join("libexec");
        let bin = prefix.join("bin");
        let share = prefix.join("share").join("sudo-secretspec");

        Self {
            vault: cfg.vault,
            vault_realpath: cfg.vault_realpath,
            service_user: cfg.service_user,
            service_group: cfg.service_group,
            declarations: cfg.declarations,
            engine: cfg.engine.clone(),
            // In the Rust single-binary model the audit helper is the same
            // privileged binary; keep a distinct field for compatibility.
            audit: cfg.audit_helper,
            broker: libexec.join("sudo-secretspec"),
            client: bin.join("sudo-secretspec"),
            checker: bin.join("sudo-secretspec"),
            retired: share.join("sudo-secretspec-retired.toml"),
            guidance: share.join("AI-GUIDANCE.md"),
            sudoers: PathBuf::from("/private/etc/sudoers.d/sudo-secretspec"),
            source_manifest: share.join("MANIFEST.sha256"),
            config: config_path,
            adopted_vault: cfg.adopted_vault,
            installed_version: cfg.version,
        }
    }
}

/// Findings that require operator review but do not invalidate the boundary.
///
/// Each describes state the operator must clean up by hand — non-secret tool
/// state left under the vault, a mutation backup a crash left behind, a
/// harmless second copy of the client — and none means a credential operation
/// would be unsafe. They must not fail `doctor`: agents are instructed to treat
/// a drift failure as a hard stop, so a permanent advisory would wedge every
/// automated caller indefinitely.
///
/// The three `SUDOERS_NEIGHBOUR_*` codes are advisory for a second reason on
/// top of that one: the files they describe belong to other vendors.
/// `uninstall` already refuses to touch a neighbour's drop-in, so a finding
/// here is something only the operator can act on, and failing `doctor` over it
/// would hand every automated caller a stop condition this project cannot
/// clear.
const ADVISORY_CODES: &[&str] = &[
    "LEGACY_VAULT_CLUTTER",
    "PENDING_ROLLBACK",
    "CLIENT_DUPLICATE",
    "SUDOERS_NEIGHBOUR_IGNORED",
    "SUDOERS_NEIGHBOUR_SKIPPED",
    "SUDOERS_NEIGHBOUR_VISUDO_REJECTED",
    "UPGRADE_AVAILABLE",
];

/// Where a package manager keeps the bootstrap copy of the boundary.
///
/// Deliberately a fixed list of the two conventional Homebrew prefixes rather
/// than an invocation of `brew --prefix`: `doctor` reaches this code as root,
/// and asking an operator-writable tool where to look would let whoever can
/// write there choose the path a root process stats. Nothing here is executed —
/// the version is supplied by the unprivileged client, see
/// [`InspectOptions::available_build`].
const MEDIA_PREFIXES: &[&str] = &["/opt/homebrew", "/usr/local"];

/// Directories scanned unconditionally for a second copy of the public client.
///
/// `doctor` re-execs itself as root through `sudo`, and the policy this project
/// installs replaces `PATH` with `secure_path` (`install::sudoers_text`). The
/// privileged process therefore cannot see the `PATH` whose shadowing we care
/// about, and resolving the client through its own `PATH` would answer a
/// question nobody asked. These are the conventional macOS search directories,
/// checked from a fixed list so the result never depends on a caller-supplied
/// value.
const SEARCH_DIRS: &[&str] = &[
    "/usr/local/bin",
    "/usr/local/sbin",
    "/opt/homebrew/bin",
    "/opt/homebrew/sbin",
    "/opt/local/bin",
    "/opt/local/sbin",
    "/usr/bin",
    "/usr/sbin",
    "/bin",
    "/sbin",
];

/// Inputs `inspect` cannot obtain for itself from inside the privileged process.
#[derive(Debug, Clone, Default)]
pub struct InspectOptions {
    /// Executable search path of the unprivileged caller, when known.
    ///
    /// Supplied by the public client before it elevates, because `sudo`
    /// discards the caller's `PATH`. It can only *widen* the shadow scan:
    /// [`SEARCH_DIRS`] is always covered, so a caller passing a doctored value
    /// can add findings but never hide one.
    pub caller_path: Option<OsString>,
    /// Version reported by the package manager's bootstrap copy, when one is
    /// present and could be asked.
    ///
    /// Obtained by the *unprivileged* client running `<media> --version` before
    /// it elevates, on the same principle as `caller_path`: the fact is gathered
    /// where executing it is no more dangerous than the operator doing it by
    /// hand, and handed in as data. Running that binary from inside the root
    /// process would be materially different — the Homebrew prefix is routinely
    /// operator-writable, so it is not code this boundary may execute as root.
    ///
    /// Advisory-only, and it can only *add* the [`UPGRADE_AVAILABLE`] finding:
    /// a caller passing a doctored value nags itself and changes nothing else.
    ///
    /// [`UPGRADE_AVAILABLE`]: ADVISORY_CODES
    pub available_build: Option<AvailableBuild>,
}

/// A copy of the boundary sitting in package-manager media, not yet installed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvailableBuild {
    pub path: PathBuf,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Finding {
    pub code: String,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Advisory findings are reported but do not clear `Report.ok`.
    pub advisory: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Report {
    pub ok: bool,
    pub findings: Vec<Finding>,
}

impl Report {
    fn from_findings(findings: Vec<Finding>) -> Self {
        Self {
            ok: findings.iter().all(|f| f.advisory),
            findings,
        }
    }
}

fn finding(code: &str, path: Option<&Path>, detail: impl Into<String>) -> Finding {
    Finding {
        code: code.into(),
        detail: detail.into(),
        path: path.map(|p| p.display().to_string()),
        advisory: ADVISORY_CODES.contains(&code),
    }
}

/// Load and validate the protected TOML configuration at `path`.
pub fn load_config(path: &Path) -> Result<Layout, DriftError> {
    // `O_NOFOLLOW`: refuse to follow a symlink. This function is also used by
    // the privileged `doctor`, and a symlinked config could redirect a root
    // read at an arbitrary file (e.g. `doctor --config /tmp/link`). The failure
    // surfaces as `Io` without ever opening the target.
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let mut content = String::new();
    std::io::Read::read_to_string(&mut file, &mut content)?;
    let cfg = Config::parse(&content)?;
    Ok(Layout::from_config(cfg, path.to_path_buf()))
}

fn owner_name(uid: u32) -> String {
    unsafe {
        let pw = libc::getpwuid(uid);
        if pw.is_null() {
            return uid.to_string();
        }
        std::ffi::CStr::from_ptr((*pw).pw_name)
            .to_string_lossy()
            .into_owned()
    }
}

/// Resolve a service-user name to its uid, or `None` if the account is absent.
///
/// The inverse of [`owner_name`]. `drift` carries the configured identity as a
/// name, but the audit ledger's ownership check compares uids.
fn uid_for_user(name: &str) -> Option<u32> {
    let c = std::ffi::CString::new(name).ok()?;
    // SAFETY: `getpwnam` is called with a valid NUL-terminated string and the
    // returned pointer is only dereferenced while non-null.
    unsafe {
        let pw = libc::getpwnam(c.as_ptr());
        if pw.is_null() {
            None
        } else {
            Some((*pw).pw_uid)
        }
    }
}

fn group_name(gid: u32) -> String {
    unsafe {
        let gr = libc::getgrgid(gid);
        if gr.is_null() {
            return gid.to_string();
        }
        std::ffi::CStr::from_ptr((*gr).gr_name)
            .to_string_lossy()
            .into_owned()
    }
}

fn metadata_owner_group_mode(path: &Path) -> std::io::Result<(String, String, u32)> {
    let meta = fs::symlink_metadata(path)?;
    Ok((
        owner_name(meta.uid()),
        group_name(meta.gid()),
        meta.permissions().mode() & 0o777,
    ))
}

fn has_extended_acl(path: &Path) -> bool {
    let output = Command::new("/bin/ls")
        .args(["-lde", &path.display().to_string()])
        .output();
    match output {
        Ok(out) if out.status.success() => {
            String::from_utf8_lossy(&out.stdout).lines().count() != 1
        }
        _ => true,
    }
}

fn check_protected_file(
    path: &Path,
    owner: &str,
    group: &str,
    mode: u32,
    findings: &mut Vec<Finding>,
) {
    if path.is_symlink() {
        findings.push(finding(
            "SYMLINK_FORBIDDEN",
            Some(path),
            "path must not be a symlink",
        ));
        return;
    }
    match metadata_owner_group_mode(path) {
        Ok((o, g, m)) => {
            if o != owner || g != group || m != mode {
                findings.push(finding(
                    "METADATA_MISMATCH",
                    Some(path),
                    format!("expected {owner}:{group}:{mode:o}, got {o}:{g}:{m:o}"),
                ));
            }
            if has_extended_acl(path) {
                findings.push(finding(
                    "ACL_PRESENT",
                    Some(path),
                    "extended ACL present on protected path",
                ));
            }
        }
        Err(_) => findings.push(finding(
            "PATH_MISSING",
            Some(path),
            "required protected path is missing",
        )),
    }
}

fn check_ancestor_chain(path: &Path, findings: &mut Vec<Finding>) {
    // Validate the resolved path's parents for root ownership and non-writability.
    let resolved = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let mut current = resolved.as_path();
    while let Some(parent) = current.parent() {
        if parent == Path::new("/") {
            break;
        }
        // Accept the conventional macOS alias roots only as leaf public names;
        // validation always walks the resolved private chain.
        if parent.is_symlink()
            && !matches!(parent.to_string_lossy().as_ref(), "/var" | "/etc" | "/tmp")
        {
            findings.push(finding(
                "ANCESTOR_SYMLINK",
                Some(parent),
                "protected ancestor must not be a symlink",
            ));
        }
        if let Ok((o, _g, m)) = metadata_owner_group_mode(parent) {
            if o != "root" || m & 0o022 != 0 {
                findings.push(finding(
                    "REMOVABLE_ANCESTOR",
                    Some(parent),
                    "ancestor is not root-owned or is group/world-writable",
                ));
            }
            if has_extended_acl(parent) {
                findings.push(finding(
                    "ACL_PRESENT",
                    Some(parent),
                    "extended ACL present on ancestor",
                ));
            }
        }
        current = parent;
        if parent == Path::new("/private") || parent == Path::new("/usr") {
            break;
        }
    }
}

fn sha256_file(path: &Path) -> Option<String> {
    let bytes = fs::read(path).ok()?;
    Some(format!("{:x}", Sha256::digest(bytes)))
}

/// Parse `hash  absolute-path` rows. An unreadable manifest yields no rows,
/// which every caller must treat as "cannot prove anything about these paths"
/// rather than "these paths are fine".
pub(crate) fn parse_manifest(path: &Path) -> Vec<(String, PathBuf)> {
    let Ok(text) = fs::read_to_string(path) else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let (hash, rest) = line.split_once(char::is_whitespace)?;
            let rest = rest.trim();
            Some((hash.to_string(), PathBuf::from(rest)))
        })
        .collect()
}

/// Ordered directories to scan for a second copy of the client.
///
/// The fixed list comes first and is never removable; `caller_path` only
/// appends. Relative entries are dropped: `PATH` may legitimately contain them,
/// but resolving one inside a root process would depend on its working
/// directory, which the caller also controls.
fn search_dirs(caller_path: Option<&OsStr>) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = SEARCH_DIRS.iter().map(PathBuf::from).collect();
    if let Some(path) = caller_path {
        dirs.extend(std::env::split_paths(path).filter(|p| p.is_absolute()));
    }
    let mut seen = std::collections::HashSet::new();
    dirs.retain(|d| seen.insert(d.clone()));
    dirs
}

/// Would a shell execute this path, or step over it and keep looking?
///
/// Existence is not the rule. A shell searching `PATH` skips an entry that is
/// not a regular file it can execute — a directory of that name, or a
/// non-executable file — and falls through to the next directory. Metadata is
/// followed through symlinks, because that is what `execve` does.
fn is_executable_file(path: &Path) -> bool {
    match fs::metadata(path) {
        Ok(meta) => meta.is_file() && meta.permissions().mode() & 0o111 != 0,
        Err(_) => false,
    }
}

/// The first `name` the caller's `PATH` would execute, when that `PATH` is
/// known. `None` when it was not supplied or resolves to nothing.
///
/// Treating mere existence as "this wins" made a stray non-executable file — or
/// a directory — named `sudo-secretspec` anywhere on the caller's `PATH` raise
/// `CLIENT_SHADOWED`, which is not advisory and so fails `doctor`. Agents are
/// told to treat that as a hard stop, so a file the shell would have ignored
/// could wedge every automated caller.
fn path_winner(caller_path: Option<&OsStr>, name: &OsStr) -> Option<PathBuf> {
    std::env::split_paths(caller_path?)
        .filter(|d| d.is_absolute())
        .map(|d| d.join(name))
        .find(|c| is_executable_file(c))
}

/// Nearest ancestor of `dir` (inclusive) that root alone cannot control, or
/// `None` when the whole chain is protected.
fn unsafe_prefix(dir: &Path) -> Option<PathBuf> {
    let mut current = dir.canonicalize().ok()?;
    loop {
        if !crate::install::is_protected_dir(&current) {
            return Some(current);
        }
        match current.parent() {
            Some(parent) if parent != current => current = parent.to_path_buf(),
            _ => return None,
        }
    }
}

/// Decide what one candidate copy of the client means.
///
/// Split out from the filesystem walk so every branch is testable without root
/// and without depending on what happens to be installed on the host.
fn classify_candidate(
    candidate: &Path,
    installed: &Path,
    installed_hash: Option<&str>,
    candidate_hash: Option<&str>,
    wins: bool,
    unsafe_dir: Option<&Path>,
) -> Option<Finding> {
    if candidate == installed {
        return None;
    }
    let identical = candidate_hash.is_some() && candidate_hash == installed_hash;
    match (wins, unsafe_dir) {
        (true, _) => Some(finding(
            "CLIENT_SHADOWED",
            Some(candidate),
            format!(
                "this resolves ahead of the installed client {} in the caller's PATH{}",
                installed.display(),
                if identical {
                    "; its bytes match today, but updates land on the installed path only"
                } else {
                    " and its bytes differ"
                }
            ),
        )),
        (false, Some(dir)) => Some(finding(
            "CLIENT_SHADOWED",
            Some(candidate),
            format!(
                "a copy of the client is reachable through {}, which is not root-owned or is \
                 group/world-writable; anyone who can write there chooses what the operator runs",
                dir.display()
            ),
        )),
        (false, None) if identical => Some(finding(
            "CLIENT_DUPLICATE",
            Some(candidate),
            format!(
                "byte-identical copy of the installed client {}; harmless now, but it will not \
                 be updated and PATH order decides which one runs",
                installed.display()
            ),
        )),
        (false, None) => Some(finding(
            "CLIENT_SHADOWED",
            Some(candidate),
            format!(
                "a different `sudo-secretspec` is on the executable search path; the installed \
                 client is {}",
                installed.display()
            ),
        )),
    }
}

/// Bootstrap copies of the boundary that a package manager may have staged.
///
/// The keg layout is `<prefix>/opt/sudo-secretspec/libexec/sudo-secretspec`,
/// which the package manager re-points on every upgrade. Note this is *not*
/// `<prefix>/libexec/sudo-secretspec`: under an Intel Homebrew the install
/// prefix and the brew prefix are the same `/usr/local`, and those two paths
/// are what keep the staged copy and the installed boundary distinct there.
pub fn media_candidates() -> Vec<PathBuf> {
    MEDIA_PREFIXES
        .iter()
        .map(|p| PathBuf::from(p).join("opt/sudo-secretspec/libexec/sudo-secretspec"))
        .filter(|p| p.is_file())
        .collect()
}

/// Decide whether a staged build is worth telling the operator about.
///
/// Split out from the filesystem and the subprocess so every branch is testable
/// without a package manager installed.
///
/// Reports only a version *difference*, never an ordering: comparing these
/// strings as versions would need a parser for a scheme this project does not
/// own, and "differs" is the honest claim. A staged build that is older than
/// the installed one is worth surfacing anyway — after a rollback that is
/// exactly the state the operator needs to see.
fn classify_available_build(
    installed_version: Option<&str>,
    available: Option<&AvailableBuild>,
) -> Option<Finding> {
    let available = available?;
    match installed_version {
        // Same version staged as installed: the ordinary steady state, and
        // saying so every run would train the operator to ignore the report.
        Some(installed) if installed == available.version => None,
        Some(installed) => Some(finding(
            "UPGRADE_AVAILABLE",
            Some(&available.path),
            format!(
                "a different build is staged here ({}) than the one installed ({}); install it \
                 by running that path directly -- it is kept off PATH so it cannot shadow the \
                 installed client",
                available.version, installed
            ),
        )),
        // Nothing to compare against: the installed boundary predates the
        // version stamp. Reporting a difference would be a guess, and the next
        // install records the stamp and resolves it.
        None => None,
    }
}

/// Report any `sudo-secretspec` outside the installed client path.
///
/// `doctor` otherwise verifies the installation and never asks whether those
/// are the paths that would actually run.
fn check_client_shadowing(
    layout: &Layout,
    dirs: &[PathBuf],
    winner: Option<&Path>,
    findings: &mut Vec<Finding>,
) {
    let Some(name) = layout.client.file_name() else {
        return;
    };
    let installed_real = layout.client.canonicalize().ok();
    let installed_hash = sha256_file(&layout.client);

    let mut reported = std::collections::HashSet::new();
    for dir in dirs {
        let candidate = dir.join(name);
        if candidate.symlink_metadata().is_err() {
            continue;
        }
        // A symlink deliberately pointing at the installed client is the same
        // file, not a shadow.
        if matches!(candidate.canonicalize(), Ok(real) if Some(&real) == installed_real.as_ref()) {
            continue;
        }
        if !reported.insert(candidate.clone()) {
            continue;
        }
        // Hash only regular files: opening a fifo left in a caller-supplied
        // directory would block this process as root.
        let candidate_hash = match fs::metadata(&candidate) {
            Ok(meta) if meta.is_file() => sha256_file(&candidate),
            _ => None,
        };
        if let Some(f) = classify_candidate(
            &candidate,
            &layout.client,
            installed_hash.as_deref(),
            candidate_hash.as_deref(),
            winner == Some(candidate.as_path()),
            unsafe_prefix(dir).as_deref(),
        ) {
            findings.push(f);
        }
    }
}

/// The facts sudo consults about a `sudoers.d` entry, as plain values.
///
/// Separated from the filesystem so every branch of [`refusal_for`] is testable
/// without root: an unprivileged test cannot create a uid-0 file, which is
/// exactly the case that must be proven to load.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EntryFacts {
    is_regular_file: bool,
    is_dir: bool,
    uid: u32,
    gid: u32,
    mode: u32,
}

/// Sudo never reads a `#includedir` entry whose name contains a `.` or ends in
/// `~`. The skip happens *before* any mode or ownership check, so such a file is
/// invisible no matter how it is chmod'd — which makes it a different problem
/// with a different fix (rename) from the ones [`refusal_for`] describes.
fn skipped_by_name(name: &str) -> bool {
    name.contains('.') || name.ends_with('~')
}

/// What sudo and `visudo -c` each make of one `sudoers.d` entry.
///
/// They disagree, and that disagreement is the whole reason this is three
/// verdicts rather than one boolean. Sudo's loader (`sudo_secure_file`) asks
/// only that the file be root-owned and not writable by anyone who is not root.
/// `visudo -c` additionally demands gid 0 and a mode of exactly `0440`. A
/// drop-in can therefore be **fully live** while `visudo -c` fails the host
/// over it — which is exactly what `/etc/sudoers.d/yabai` was doing here.
///
/// Probed against sudo 1.9.17p2, not derived. The first version of this check
/// assumed `visudo -c`'s verdict *was* sudo's and reported working drop-ins as
/// dead.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Neighbour {
    /// Sudo reads it and `visudo -c` accepts it.
    Fine,
    /// `#includedir` skips the name before it ever stats the file.
    SkippedByName,
    /// Sudo will not read it, so its rules do not apply.
    NotLoaded(String),
    /// Sudo reads and applies it, but `visudo -c` fails over it.
    VisudoRejects(String),
}

/// Decide what one neighbouring drop-in means.
///
/// Split from the filesystem so every branch is testable without root: an
/// unprivileged test cannot create a uid-0 file, which is the case that must be
/// proven to load.
fn classify_neighbour(name: &str, facts: Option<EntryFacts>) -> Neighbour {
    if skipped_by_name(name) {
        return Neighbour::SkippedByName;
    }
    let Some(f) = facts else {
        // A dangling symlink. Sudo passes over it in silence and `visudo -c`
        // does not mention it either, so if this check stays quiet, nothing on
        // the host will say anything at all.
        return Neighbour::NotLoaded(
            "it cannot be resolved (dangling symlink or unreadable)".into(),
        );
    };
    if f.is_dir {
        return Neighbour::NotLoaded("it is a directory".into());
    }
    if !f.is_regular_file {
        return Neighbour::NotLoaded("it is not a regular file".into());
    }

    // sudo_secure_file: root-owned, never world-writable, and not
    // group-writable unless the owning group is gid 0. Each of these three was
    // observed refusing a live NOPASSWD rule.
    if f.uid != 0 {
        return Neighbour::NotLoaded(format!(
            "it is owned by {} rather than root",
            owner_name(f.uid)
        ));
    }
    if f.mode & 0o002 != 0 {
        return Neighbour::NotLoaded(format!("it is world-writable (mode {:04o})", f.mode));
    }
    if f.gid != 0 && f.mode & 0o020 != 0 {
        return Neighbour::NotLoaded(format!(
            "it is group-writable (mode {:04o}) and its group {} is not gid 0",
            f.mode,
            group_name(f.gid)
        ));
    }

    // Past this point sudo is applying the file. What remains is visudo's
    // stricter opinion of it, which matters because `visudo -c` checks the
    // whole directory at once.
    if f.gid != 0 {
        return Neighbour::VisudoRejects(format!(
            "its group is {} rather than gid 0",
            group_name(f.gid)
        ));
    }
    if f.mode != 0o440 {
        return Neighbour::VisudoRejects(format!(
            "its mode is {:04o} rather than exactly 0440",
            f.mode
        ));
    }
    Neighbour::Fine
}

/// Read the facts sudo would read about `path`.
///
/// This follows symlinks, where the rest of this module deliberately does not.
/// Sudo opens a drop-in and stats the descriptor, so a link to a root:wheel
/// 0440 file loads normally — verified on this host. The job here is to model
/// what sudo actually does, not to decide whether a path is trustworthy, and
/// using `symlink_metadata` would report every symlinked drop-in as broken when
/// sudo applies it happily.
fn sudoers_facts(path: &Path) -> Option<EntryFacts> {
    let meta = fs::metadata(path).ok()?;
    Some(EntryFacts {
        is_regular_file: meta.is_file(),
        is_dir: meta.is_dir(),
        uid: meta.uid(),
        gid: meta.gid(),
        mode: meta.permissions().mode() & 0o7777,
    })
}

/// Report drop-ins beside ours that sudo silently declines to apply.
///
/// `doctor` already proves our own policy is installed and parses. It said
/// nothing about a neighbour in a state that makes sudo ignore it, and such a
/// file looks installed while doing nothing at all — `/etc/sudoers.d/yabai` sat
/// at mode 0640 on the development host for a month in exactly that condition,
/// visible only as a stray warning during `install`.
///
/// Scope is deliberately narrow: this reports, never repairs, and never widens
/// to judging a neighbour's *contents*. What another vendor grants is that
/// vendor's business; whether sudo is reading it at all is diagnosable fact.
fn check_sudoers_neighbours(layout: &Layout, findings: &mut Vec<Finding>) {
    let Some(dir) = layout.sudoers.parent() else {
        return;
    };
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    // `read_dir` order is not defined; sort so the report is stable run to run.
    let mut names: Vec<OsString> = entries.flatten().map(|e| e.file_name()).collect();
    names.sort();

    for name in names {
        let path = dir.join(&name);
        // Ours is already judged as a protected file, with the same 0440
        // root:wheel expectation, and by `visudo -c -f` below.
        if path == layout.sudoers {
            continue;
        }
        let name = name.to_string_lossy();
        // Leading-dot names are not attempted rules. `.DS_Store` is on every
        // macOS host and would otherwise be a permanent finding.
        if name.starts_with('.') {
            continue;
        }
        let (code, detail) = match classify_neighbour(&name, sudoers_facts(&path)) {
            Neighbour::Fine => continue,
            Neighbour::SkippedByName => (
                "SUDOERS_NEIGHBOUR_SKIPPED",
                "sudo's `#includedir` skips this drop-in because its name contains `.` or ends \
                 in `~`, so its rules never take effect; rename it to activate it"
                    .to_string(),
            ),
            Neighbour::NotLoaded(why) => (
                "SUDOERS_NEIGHBOUR_IGNORED",
                format!(
                    "sudo does not read this drop-in because {why}, so its rules never take effect"
                ),
            ),
            Neighbour::VisudoRejects(why) => (
                "SUDOERS_NEIGHBOUR_VISUDO_REJECTED",
                format!(
                    "sudo reads and applies this drop-in, but `visudo -c` rejects it because \
                     {why}. `visudo -c` validates the whole directory at once, so this fails the \
                     syntax check for every tool on the host — including this installer's own \
                     install and rollback, which is why both scope their check to a single file"
                ),
            ),
        };
        findings.push(finding(code, Some(&path), detail));
    }
}

/// Inspect the live installation described by `layout`.
///
/// This never repairs and never opens secret-bearing file contents for parsing.
pub fn inspect(layout: &Layout, opts: &InspectOptions) -> Report {
    let mut findings = Vec::new();

    // Config file itself.
    check_protected_file(
        &layout.config,
        &layout.service_user,
        &layout.service_group,
        0o444,
        &mut findings,
    );
    check_ancestor_chain(&layout.config, &mut findings);

    // Installed binaries / shared assets.
    let root_artifacts = vec![(&layout.client, 0o755), (&layout.sudoers, 0o440)];
    let mut service_artifacts = vec![
        (&layout.broker, 0o755),
        (&layout.engine, 0o755),
        (&layout.retired, 0o444),
        (&layout.guidance, 0o444),
        (&layout.source_manifest, 0o444),
    ];
    if let Some(decl) = &layout.declarations {
        service_artifacts.push((decl, 0o444));
    }
    for (path, mode) in root_artifacts {
        check_protected_file(path, "root", "wheel", mode, &mut findings);
        check_ancestor_chain(path, &mut findings);
    }
    for (path, mode) in service_artifacts {
        check_protected_file(
            path,
            &layout.service_user,
            &layout.service_group,
            mode,
            &mut findings,
        );
        check_ancestor_chain(path, &mut findings);
    }

    // Which binary would actually run, not just whether the installed one is intact.
    let caller_path = opts.caller_path.as_deref();
    let winner = layout
        .client
        .file_name()
        .and_then(|name| path_winner(caller_path, name));
    check_client_shadowing(
        layout,
        &search_dirs(caller_path),
        winner.as_deref(),
        &mut findings,
    );

    // A build staged by the package manager but never installed. This is the
    // standing counterpart to the installer's self-source guard: the guard
    // catches an upgrade attempted the wrong way, this reports an upgrade never
    // attempted at all.
    if let Some(f) = classify_available_build(
        layout.installed_version.as_deref(),
        opts.available_build.as_ref(),
    ) {
        findings.push(f);
    }

    // Source manifest hashes, when present.
    if layout.source_manifest.is_file() {
        for (expected, path) in parse_manifest(&layout.source_manifest) {
            match sha256_file(&path) {
                Some(actual) if actual == expected => {}
                Some(_) => findings.push(finding(
                    "INSTALLED_HASH_MISMATCH",
                    Some(&path),
                    "installed artifact hash differs from release manifest",
                )),
                None => findings.push(finding(
                    "INSTALLED_FILE_MISSING",
                    Some(&path),
                    "manifest lists a missing installed artifact",
                )),
            }
        }
    }

    // Sudoers syntax.
    //
    // Captured, not inherited: `visudo -c` writes "<path>: parsed OK" to
    // stdout, and letting that through put a non-JSON line ahead of the report
    // in `doctor --json`. Anything consuming the report as JSON — which is what
    // AI-GUIDANCE tells automation to do — failed to parse it.
    if layout.sudoers.exists() {
        let checked = Command::new("/usr/sbin/visudo")
            .args(["-c", "-f"])
            .arg(&layout.sudoers)
            .output();
        match checked {
            Ok(out) if out.status.success() => {}
            _ => findings.push(finding(
                "SUDOERS_INVALID",
                Some(&layout.sudoers),
                "visudo rejected the sudoers policy",
            )),
        }
    }

    // Neighbours in the same directory that sudo is silently not applying.
    //
    // Scoped per-file above for a reason — another vendor's broken drop-in must
    // never fail our own check — but "not our problem to fail on" is not the
    // same as "not worth saying", and nothing else on the host reports it.
    check_sudoers_neighbours(layout, &mut findings);

    // Vault metadata and allowlisted runtime entries only.
    if layout.vault.is_symlink() {
        findings.push(finding(
            "VAULT_SYMLINK",
            Some(&layout.vault),
            "vault must not be a symlink",
        ));
    } else {
        check_protected_file(
            &layout.vault,
            &layout.service_user,
            &layout.service_group,
            0o700,
            &mut findings,
        );
    }

    // Resolve public /var spelling through the macOS private chain.
    match layout.vault.canonicalize() {
        Ok(resolved) if resolved != layout.vault_realpath => findings.push(finding(
            "VAULT_REALPATH_MISMATCH",
            Some(&layout.vault),
            format!(
                "vault resolves to {}, expected {}",
                resolved.display(),
                layout.vault_realpath.display()
            ),
        )),
        Ok(resolved) => check_ancestor_chain(&resolved, &mut findings),
        Err(_) => findings.push(finding(
            "VAULT_UNRESOLVABLE",
            Some(&layout.vault),
            "vault path cannot be resolved",
        )),
    }

    let allowed = [
        "secretspec.toml",
        ".env",
        "broker-audit.sqlite3",
        "broker-audit.sqlite3-wal",
        "broker-audit.sqlite3-shm",
        "broker-audit.sqlite3-journal",
        "broker-history.sqlite3",
        "broker-history.sqlite3-wal",
        "broker-history.sqlite3-shm",
        "broker-history.sqlite3-journal",
        "secrets.db",
        "secrets.db-wal",
        "secrets.db-shm",
        "secrets.db-journal",
        // The engine's JSONL audit sink, pointed here by the broker because the
        // vault is the only directory the service user owns. See the
        // `XDG_STATE_HOME` note in `broker::execute`.
        ".state",
    ];
    if let Ok(entries) = fs::read_dir(&layout.vault) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let path = entry.path();
            if name.contains(".rollback.") {
                findings.push(finding(
                    "PENDING_ROLLBACK",
                    Some(&path),
                    "pending rollback artifact requires operator review",
                ));
                // A transient mutation artifact is reported by its own code and
                // deliberately not also judged by the steady-state metadata
                // rule. `fs::copy` does not carry ownership, so a backup left
                // behind by an older broker is root-owned; letting that raise a
                // non-advisory METADATA_MISMATCH would turn any crashed
                // mutation into a hard `doctor` failure, wedging every agent
                // told to treat one as a stop.
                //
                // A symlink here is still refused. That is not drift — it is a
                // redirection of a path `Mutation::restore` copies back over.
                if path.is_symlink() {
                    findings.push(finding(
                        "SYMLINK_FORBIDDEN",
                        Some(&path),
                        "path must not be a symlink",
                    ));
                }
                continue;
            } else if matches!(name.as_ref(), ".local" | ".ansible" | ".cache") {
                findings.push(finding(
                    "LEGACY_VAULT_CLUTTER",
                    Some(&path),
                    "non-secret tool state under the vault; safe to remove after review",
                ));
            } else if !allowed.iter().any(|a| *a == name) {
                findings.push(finding(
                    "UNEXPECTED_RUNTIME_ENTRY",
                    Some(&path),
                    "vault contains a file outside the runtime allowlist",
                ));
            }
            if path.is_file() || path.is_symlink() {
                check_protected_file(
                    &path,
                    &layout.service_user,
                    &layout.service_group,
                    0o600,
                    &mut findings,
                );
            }
        }
    }

    // Audit integrity via library (no secret contents, and no writes: this
    // module promises never to mutate state, and the read-write path repairs
    // the ledger's mode and ownership and creates its schema).
    //
    // A missing service account leaves the ownership assertion off rather than
    // failing here; the identity itself is already reported by the checks above.
    if let Err(e) = audit::verify_read_only(&layout.vault, uid_for_user(&layout.service_user)) {
        findings.push(finding(
            "AUDIT_VERIFY_FAILED",
            Some(&layout.vault.join(audit::DB_NAME)),
            format!("audit verification failed: {e}"),
        ));
    }

    Report::from_findings(findings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    fn staged(version: &str) -> AvailableBuild {
        AvailableBuild {
            path: PathBuf::from("/opt/homebrew/opt/sudo-secretspec/libexec/sudo-secretspec"),
            version: version.into(),
        }
    }

    #[test]
    fn a_staged_build_that_differs_from_the_installed_one_is_advised() {
        let f = classify_available_build(Some("0.19.1-sudo.12"), Some(&staged("0.19.1-sudo.13")))
            .expect("a staged build the operator has not installed must be reported");
        assert_eq!(f.code, "UPGRADE_AVAILABLE");
        // Advisory: `doctor` must still pass, or every automated caller that
        // treats a drift failure as a hard stop would wedge until the operator
        // upgraded.
        assert!(f.advisory);
        assert!(f.detail.contains("0.19.1-sudo.13"), "{}", f.detail);
        assert!(f.detail.contains("0.19.1-sudo.12"), "{}", f.detail);
    }

    #[test]
    fn the_steady_state_of_staged_matching_installed_is_silent() {
        assert!(
            classify_available_build(Some("0.19.1-sudo.13"), Some(&staged("0.19.1-sudo.13")))
                .is_none()
        );
    }

    #[test]
    fn nothing_staged_reports_nothing() {
        assert!(classify_available_build(Some("0.19.1-sudo.13"), None).is_none());
    }

    #[test]
    fn a_boundary_predating_the_version_stamp_is_not_guessed_about() {
        // No recorded installed version: any claim of difference would be
        // invented. The next install writes the stamp and resolves it.
        assert!(classify_available_build(None, Some(&staged("0.19.1-sudo.13"))).is_none());
    }

    #[test]
    fn a_staged_build_older_than_the_installed_one_is_still_reported() {
        // After a rollback this is exactly the state worth surfacing, and the
        // check deliberately claims only "differs" -- ordering these strings
        // would need a version parser this project does not own.
        let f = classify_available_build(Some("0.19.1-sudo.13"), Some(&staged("0.19.1-sudo.12")))
            .expect("a downgrade is a difference the operator should see");
        assert_eq!(f.code, "UPGRADE_AVAILABLE");
    }

    #[test]
    fn media_candidates_never_name_the_installed_boundary() {
        // Under an Intel Homebrew the brew prefix and the install prefix are
        // both /usr/local; the keg path is what keeps the staged copy and the
        // installed one distinct. If these ever collided, `doctor` would
        // compare the installed boundary against itself.
        for candidate in MEDIA_PREFIXES
            .iter()
            .map(|p| PathBuf::from(p).join("opt/sudo-secretspec/libexec/sudo-secretspec"))
        {
            assert_ne!(
                candidate,
                PathBuf::from("/usr/local/libexec/sudo-secretspec")
            );
        }
    }

    fn write_cfg(dir: &Path) -> PathBuf {
        let path = dir.join("sudo-secretspec.toml");
        fs::write(
            &path,
            r#"
engine = "/usr/local/libexec/sudo-secretspec"
audit_helper = "/usr/local/libexec/sudo-secretspec"
vault = "/var/db/sudo-secretspec"
vault_realpath = "/private/var/db/sudo-secretspec"
declarations = "/usr/local/share/sudo-secretspec/secretspec.toml"
service_user = "_sudo_secretspec"
service_group = "_sudo_secretspec"
"#,
        )
        .unwrap();
        path
    }

    #[test]
    fn load_config_builds_single_binary_layout() {
        let tmp = tempdir().unwrap();
        let path = write_cfg(tmp.path());
        let layout = load_config(&path).unwrap();
        assert_eq!(
            layout.broker,
            PathBuf::from("/usr/local/libexec/sudo-secretspec")
        );
        assert_eq!(
            layout.client,
            PathBuf::from("/usr/local/bin/sudo-secretspec")
        );
        assert_eq!(layout.vault, PathBuf::from("/var/db/sudo-secretspec"));
    }

    #[test]
    fn load_config_refuses_a_symlink() {
        // `load_config` opens with O_NOFOLLOW, so a config reached through a
        // symlink must be rejected before the target is read. This is the
        // defence-in-depth for C1: even if a root `doctor` is handed an
        // attacker-chosen path that is a symlink into a root-only file, the
        // read itself fails rather than following the link.
        let tmp = tempdir().unwrap();
        let real = write_cfg(tmp.path());
        let link = tmp.path().join("link.toml");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(load_config(&link).is_err());
    }

    #[test]
    fn advisory_findings_do_not_fail_the_report() {
        // Agents are instructed to treat a drift failure as a hard stop, so
        // vault clutter and a leftover mutation backup must be reported without
        // clearing `ok` — otherwise every automated caller stalls permanently.
        let report = Report::from_findings(vec![
            finding("LEGACY_VAULT_CLUTTER", None, "tool state"),
            finding("PENDING_ROLLBACK", None, "leftover backup"),
        ]);
        assert!(report.ok, "{:?}", report.findings);
        assert!(report.findings.iter().all(|f| f.advisory));
    }

    #[test]
    fn non_advisory_findings_still_fail_the_report() {
        let report = Report::from_findings(vec![
            finding("LEGACY_VAULT_CLUTTER", None, "tool state"),
            finding("METADATA_MISMATCH", None, "wrong owner"),
        ]);
        assert!(!report.ok);
    }

    #[test]
    fn an_empty_report_is_ok() {
        assert!(Report::from_findings(vec![]).ok);
    }

    #[test]
    fn unexpected_runtime_entry_is_reported() {
        let tmp = tempdir().unwrap();
        let vault = tmp.path().join("vault");
        fs::create_dir_all(&vault).unwrap();
        fs::set_permissions(&vault, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(vault.join("secretspec.toml"), "x = 1").unwrap();
        fs::write(vault.join(".env"), "").unwrap();
        fs::write(vault.join("evil.txt"), "nope").unwrap();

        let layout = Layout {
            config: tmp.path().join("missing.toml"),
            vault: vault.clone(),
            vault_realpath: vault.clone(),
            service_user: owner_name(unsafe { libc::getuid() }),
            service_group: group_name(unsafe { libc::getgid() }),
            declarations: Some(tmp.path().join("decl.toml")),
            engine: tmp.path().join("engine"),
            audit: tmp.path().join("audit"),
            broker: tmp.path().join("broker"),
            client: tmp.path().join("client"),
            checker: tmp.path().join("checker"),
            retired: tmp.path().join("retired"),
            guidance: tmp.path().join("guidance"),
            sudoers: tmp.path().join("sudoers"),
            source_manifest: tmp.path().join("MANIFEST.sha256"),
            adopted_vault: false,
            installed_version: None,
        };
        let report = inspect(&layout, &InspectOptions::default());
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.code == "UNEXPECTED_RUNTIME_ENTRY"),
            "{:?}",
            report.findings
        );
    }

    /// A `Layout` whose vault is `vault` and whose every other path is absent.
    /// Only the vault-scan findings are meaningful for callers of this.
    fn layout_for_vault(tmp: &Path, vault: &Path) -> Layout {
        Layout {
            config: tmp.join("missing.toml"),
            vault: vault.to_path_buf(),
            vault_realpath: vault.to_path_buf(),
            service_user: owner_name(unsafe { libc::getuid() }),
            service_group: group_name(unsafe { libc::getgid() }),
            declarations: Some(tmp.join("decl.toml")),
            engine: tmp.join("engine"),
            audit: tmp.join("audit"),
            broker: tmp.join("broker"),
            client: tmp.join("client"),
            checker: tmp.join("checker"),
            retired: tmp.join("retired"),
            guidance: tmp.join("guidance"),
            sudoers: tmp.join("sudoers"),
            source_manifest: tmp.join("MANIFEST.sha256"),
            adopted_vault: false,
            installed_version: None,
        }
    }

    fn findings_for<'a>(report: &'a Report, path: &Path) -> Vec<&'a str> {
        report
            .findings
            .iter()
            .filter(|f| f.path.as_deref() == Some(path.to_string_lossy().as_ref()))
            .map(|f| f.code.as_str())
            .collect()
    }

    #[test]
    fn a_pending_rollback_backup_is_not_also_judged_by_the_steady_state_rule() {
        // `fs::copy` preserves mode but not ownership, so a backup made by the
        // root broker lands root-owned inside a service-user vault. The
        // per-entry metadata rule then turned the deliberately-advisory
        // PENDING_ROLLBACK into a non-advisory METADATA_MISMATCH, failing
        // `doctor` — and every agent is told to treat that as a hard stop, so a
        // single crashed mutation wedged the host until someone cleaned up by
        // hand. Ownership cannot be forged in an unprivileged test; a differing
        // mode trips the very same rule on the very same entry.
        let tmp = tempdir().unwrap();
        let vault = tmp.path().join("vault");
        fs::create_dir_all(&vault).unwrap();
        fs::set_permissions(&vault, fs::Permissions::from_mode(0o700)).unwrap();

        let backup = vault.join(".secretspec.toml.rollback.0f9c1e6a");
        fs::write(&backup, "manifest backup").unwrap();
        fs::set_permissions(&backup, fs::Permissions::from_mode(0o644)).unwrap();

        // Control: an entry with the same wrong mode that is *not* a rollback
        // artifact must still be judged, or this test would pass vacuously.
        let control = vault.join("secretspec.toml");
        fs::write(&control, "x = 1").unwrap();
        fs::set_permissions(&control, fs::Permissions::from_mode(0o644)).unwrap();

        let report = inspect(&layout_for_vault(tmp.path(), &vault), &Default::default());

        assert_eq!(
            findings_for(&report, &backup),
            ["PENDING_ROLLBACK"],
            "the backup must be reported by its own code and nothing else"
        );
        assert!(
            findings_for(&report, &control).contains(&"METADATA_MISMATCH"),
            "control entry must still be judged: {:?}",
            report.findings
        );
    }

    #[test]
    fn a_symlinked_rollback_backup_is_still_refused() {
        // Skipping the metadata rule must not also skip this: `restore` copies
        // a backup back over the live manifest, so a symlink in that position
        // redirects what a root process is about to read.
        let tmp = tempdir().unwrap();
        let vault = tmp.path().join("vault");
        fs::create_dir_all(&vault).unwrap();
        fs::set_permissions(&vault, fs::Permissions::from_mode(0o700)).unwrap();

        let target = tmp.path().join("elsewhere");
        fs::write(&target, "attacker controlled").unwrap();
        let backup = vault.join(".secretspec.env.rollback.0f9c1e6a");
        std::os::unix::fs::symlink(&target, &backup).unwrap();

        let report = inspect(&layout_for_vault(tmp.path(), &vault), &Default::default());
        let codes = findings_for(&report, &backup);
        assert!(codes.contains(&"SYMLINK_FORBIDDEN"), "{codes:?}");
        assert!(!report.ok, "a symlinked backup must fail the report");
    }

    const INSTALLED: &str = "/usr/local/bin/sudo-secretspec";

    fn classify(
        candidate: &str,
        candidate_hash: Option<&str>,
        wins: bool,
        unsafe_dir: Option<&str>,
    ) -> Option<Finding> {
        classify_candidate(
            Path::new(candidate),
            Path::new(INSTALLED),
            Some("aaaa"),
            candidate_hash,
            wins,
            unsafe_dir.map(Path::new),
        )
    }

    #[test]
    fn the_installed_client_is_not_its_own_shadow() {
        assert!(classify(INSTALLED, Some("aaaa"), true, None).is_none());
    }

    #[test]
    fn a_copy_that_wins_the_callers_path_fails_even_when_identical() {
        // Identical bytes today are not reassurance: `install` only ever writes
        // the installed path, so the next release makes them diverge silently.
        let f = classify(
            "/opt/homebrew/bin/sudo-secretspec",
            Some("aaaa"),
            true,
            None,
        )
        .unwrap();
        assert_eq!(f.code, "CLIENT_SHADOWED");
        assert!(!f.advisory);
    }

    #[test]
    fn a_copy_under_a_writable_prefix_fails_even_when_it_loses_path_order() {
        // Losing today is an accident of PATH order; anyone who can write the
        // directory can still swap the bytes.
        let f = classify(
            "/opt/homebrew/bin/sudo-secretspec",
            Some("aaaa"),
            false,
            Some("/opt/homebrew"),
        )
        .unwrap();
        assert_eq!(f.code, "CLIENT_SHADOWED");
        assert!(!f.advisory);
        assert!(f.detail.contains("/opt/homebrew"), "{}", f.detail);
    }

    #[test]
    fn differing_bytes_fail_wherever_they_sit() {
        let f = classify("/usr/local/sbin/sudo-secretspec", Some("bbbb"), false, None).unwrap();
        assert_eq!(f.code, "CLIENT_SHADOWED");
        assert!(!f.advisory);
    }

    #[test]
    fn an_unreadable_or_non_regular_candidate_is_not_treated_as_identical() {
        let f = classify("/usr/local/sbin/sudo-secretspec", None, false, None).unwrap();
        assert_eq!(f.code, "CLIENT_SHADOWED");
    }

    #[test]
    fn an_identical_losing_copy_under_a_root_only_prefix_is_advisory() {
        let f = classify("/usr/local/sbin/sudo-secretspec", Some("aaaa"), false, None).unwrap();
        assert_eq!(f.code, "CLIENT_DUPLICATE");
        assert!(f.advisory, "must not wedge automated callers");
    }

    #[test]
    fn caller_path_can_only_widen_the_scan() {
        let dirs = search_dirs(Some(OsStr::new("/opt/mine/bin:relative/bin:/usr/bin")));
        for fixed in SEARCH_DIRS {
            assert!(
                dirs.iter().any(|d| d == Path::new(fixed)),
                "caller PATH must not be able to drop {fixed}"
            );
        }
        assert!(dirs.iter().any(|d| d == Path::new("/opt/mine/bin")));
        // Relative entries would resolve against a working directory the caller
        // also controls.
        assert!(!dirs.iter().any(|d| d.as_os_str() == "relative/bin"));
        // /usr/bin is fixed and repeated in the caller value; it appears once.
        assert_eq!(
            dirs.iter().filter(|d| *d == Path::new("/usr/bin")).count(),
            1
        );
    }

    #[test]
    fn no_caller_path_means_the_fixed_list_only() {
        assert_eq!(search_dirs(None).len(), SEARCH_DIRS.len());
    }

    /// Write `name` into `dir` and make it executable, as an installed client is.
    fn executable(dir: &Path, name: &str) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, b"x").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    #[test]
    fn path_winner_picks_the_first_entry_a_shell_would_run() {
        let tmp = tempdir().unwrap();
        let empty = tmp.path().join("empty");
        let real = tmp.path().join("real");
        fs::create_dir_all(&empty).unwrap();
        fs::create_dir_all(&real).unwrap();
        let winner = executable(&real, "sudo-secretspec");

        let path = std::env::join_paths([&empty, &real]).unwrap();
        assert_eq!(
            path_winner(Some(&path), OsStr::new("sudo-secretspec")),
            Some(winner)
        );
        assert_eq!(path_winner(None, OsStr::new("sudo-secretspec")), None);
    }

    #[test]
    fn a_non_executable_file_is_stepped_over_the_way_a_shell_steps_over_it() {
        // Existence is not the rule. Reporting this as the winner raised a
        // non-advisory CLIENT_SHADOWED, and `doctor` failing is a hard stop for
        // every agent -- over a file the shell would never have run.
        let tmp = tempdir().unwrap();
        let inert = tmp.path().join("inert");
        let real = tmp.path().join("real");
        fs::create_dir_all(&inert).unwrap();
        fs::create_dir_all(&real).unwrap();
        let unreadable = inert.join("sudo-secretspec");
        fs::write(&unreadable, b"not executable").unwrap();
        fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o644)).unwrap();
        let winner = executable(&real, "sudo-secretspec");

        let path = std::env::join_paths([&inert, &real]).unwrap();
        assert_eq!(
            path_winner(Some(&path), OsStr::new("sudo-secretspec")),
            Some(winner)
        );
    }

    #[test]
    fn a_directory_of_that_name_is_not_a_winner() {
        // `mkdir ~/bin/sudo-secretspec` is enough to wedge the boundary when
        // existence is the test: a directory is executable-bit-set by default.
        let tmp = tempdir().unwrap();
        let masked = tmp.path().join("masked");
        fs::create_dir_all(masked.join("sudo-secretspec")).unwrap();

        let path = std::env::join_paths([&masked]).unwrap();
        assert_eq!(
            path_winner(Some(&path), OsStr::new("sudo-secretspec")),
            None
        );
    }

    #[test]
    fn shadowing_walks_the_supplied_directories() {
        let tmp = tempdir().unwrap();
        let installed_dir = tmp.path().join("bin");
        let other = tmp.path().join("other");
        fs::create_dir_all(&installed_dir).unwrap();
        fs::create_dir_all(&other).unwrap();
        let installed = installed_dir.join("sudo-secretspec");
        fs::write(&installed, b"real").unwrap();
        fs::write(other.join("sudo-secretspec"), b"different").unwrap();

        let mut layout = layout_for(tmp.path());
        layout.client = installed.clone();

        let mut findings = Vec::new();
        check_client_shadowing(
            &layout,
            &[installed_dir.clone(), other.clone()],
            None,
            &mut findings,
        );
        // The installed directory contributes nothing; the other one does.
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].code, "CLIENT_SHADOWED");
        assert_eq!(
            findings[0].path.as_deref(),
            Some(other.join("sudo-secretspec").display().to_string().as_str())
        );
    }

    #[test]
    fn a_symlink_to_the_installed_client_is_not_a_shadow() {
        let tmp = tempdir().unwrap();
        let installed_dir = tmp.path().join("bin");
        let other = tmp.path().join("other");
        fs::create_dir_all(&installed_dir).unwrap();
        fs::create_dir_all(&other).unwrap();
        let installed = installed_dir.join("sudo-secretspec");
        fs::write(&installed, b"real").unwrap();
        std::os::unix::fs::symlink(&installed, other.join("sudo-secretspec")).unwrap();

        let mut layout = layout_for(tmp.path());
        layout.client = installed;

        let mut findings = Vec::new();
        check_client_shadowing(&layout, &[installed_dir, other], None, &mut findings);
        assert!(findings.is_empty(), "{findings:?}");
    }

    fn facts(uid: u32, gid: u32, mode: u32) -> Option<EntryFacts> {
        Some(EntryFacts {
            is_regular_file: true,
            is_dir: false,
            uid,
            gid,
            mode,
        })
    }

    fn neighbour(uid: u32, gid: u32, mode: u32) -> Neighbour {
        classify_neighbour("ordinary-name", facts(uid, gid, mode))
    }

    #[test]
    fn a_correctly_installed_neighbour_is_not_reported() {
        assert_eq!(neighbour(0, 0, 0o440), Neighbour::Fine);
    }

    #[test]
    fn sudo_still_applies_a_drop_in_that_visudo_rejects() {
        // The finding that rewrote this check. `visudo -c` compares the mode for
        // equality with 0440, so it refuses 0640, 0444, 0400 and 0460 — but
        // sudo's loader asks only that nobody outside root can write the file,
        // and it happily applies every one of them. Each was confirmed against
        // sudo 1.9.17p2 by observing a live NOPASSWD rule take effect.
        //
        // Calling these "ignored by sudo" told the operator their rules were
        // dead when they were in force the whole time.
        for mode in [0o640, 0o444, 0o400, 0o460, 0o600, 0o644] {
            assert!(
                matches!(neighbour(0, 0, mode), Neighbour::VisudoRejects(_)),
                "mode {mode:04o} is applied by sudo and refused by visudo"
            );
        }
        // root:staff, not group-writable: sudo applies it, visudo refuses it.
        assert!(matches!(
            neighbour(0, 20, 0o440),
            Neighbour::VisudoRejects(_)
        ));
    }

    #[test]
    fn sudo_refuses_only_what_someone_other_than_root_can_write() {
        // World-writable at any ownership.
        assert!(matches!(neighbour(0, 0, 0o442), Neighbour::NotLoaded(_)));
        // Group-writable *and* a group that is not gid 0. Confirmed both ways:
        // the same mode with gid 0 is applied, because only root is in wheel.
        assert!(matches!(neighbour(0, 20, 0o460), Neighbour::NotLoaded(_)));
        assert!(matches!(neighbour(0, 20, 0o420), Neighbour::NotLoaded(_)));
        assert!(matches!(
            neighbour(0, 0, 0o460),
            Neighbour::VisudoRejects(_)
        ));
        // Not owned by root.
        assert!(matches!(neighbour(501, 0, 0o440), Neighbour::NotLoaded(_)));
    }

    #[test]
    fn an_unresolvable_neighbour_is_reported() {
        // A dangling symlink: sudo passes over it in silence and `visudo -c`
        // does not mention it either, so if this check stays quiet nothing on
        // the host will say anything.
        let Neighbour::NotLoaded(why) = classify_neighbour("dangling", None) else {
            panic!("a dangling symlink must be reported as not loaded");
        };
        assert!(why.contains("cannot be resolved"), "{why}");
    }

    #[test]
    fn a_directory_or_special_file_is_reported() {
        let dir = classify_neighbour(
            "adir",
            Some(EntryFacts {
                is_regular_file: false,
                is_dir: true,
                uid: 0,
                gid: 0,
                mode: 0o440,
            }),
        );
        assert!(matches!(&dir, Neighbour::NotLoaded(w) if w.contains("directory")));

        let fifo = classify_neighbour(
            "afifo",
            Some(EntryFacts {
                is_regular_file: false,
                is_dir: false,
                uid: 0,
                gid: 0,
                mode: 0o440,
            }),
        );
        assert!(matches!(&fifo, Neighbour::NotLoaded(w) if w.contains("regular file")));
    }

    #[test]
    fn the_name_rule_is_decided_before_anything_is_stated() {
        // Sudo skips the name before it stats the file, so a perfectly-moded
        // `foo.conf` is still dead and a broken-moded one still needs a rename
        // rather than a chmod.
        assert_eq!(
            classify_neighbour("custom.conf", facts(0, 0, 0o440)),
            Neighbour::SkippedByName
        );
        assert_eq!(
            classify_neighbour("custom.conf", facts(501, 20, 0o777)),
            Neighbour::SkippedByName
        );
        assert_eq!(
            classify_neighbour("backup~", None),
            Neighbour::SkippedByName
        );
    }

    #[test]
    fn skipped_by_name_matches_sudos_includedir_rule() {
        assert!(skipped_by_name("custom.conf"));
        assert!(skipped_by_name("policy.dpkg-old"));
        assert!(skipped_by_name("policy~"));
        assert!(!skipped_by_name("sudo-secretspec"));
        assert!(!skipped_by_name("yabai"));
        assert!(!skipped_by_name("90-my-rules"));
    }

    /// A layout whose sudoers policy sits inside a real, scannable directory.
    fn layout_with_sudoers_dir(tmp: &Path) -> (Layout, PathBuf) {
        let dir = tmp.join("sudoers.d");
        fs::create_dir_all(&dir).unwrap();
        let mut layout = layout_for(tmp);
        layout.sudoers = dir.join("sudo-secretspec");
        (layout, dir)
    }

    fn neighbour_findings(layout: &Layout) -> Vec<(String, String)> {
        let mut findings = Vec::new();
        check_sudoers_neighbours(layout, &mut findings);
        findings
            .into_iter()
            .map(|f| (f.code, f.path.unwrap_or_default()))
            .collect()
    }

    #[test]
    fn a_broken_neighbour_is_reported_but_never_fails_the_report() {
        // The whole point: these are other vendors' files. Agents are told to
        // treat a `doctor` failure as a hard stop, and this project cannot fix
        // a neighbour, so a failing code here would wedge automation forever.
        let tmp = tempdir().unwrap();
        let (layout, dir) = layout_with_sudoers_dir(tmp.path());
        // Test runs unprivileged, so this file is not uid 0 and is refused for
        // ownership — the same branch a real root:staff drop-in takes.
        fs::write(dir.join("yabai"), "Defaults env_reset\n").unwrap();

        let reported = neighbour_findings(&layout);
        assert_eq!(
            reported,
            vec![(
                "SUDOERS_NEIGHBOUR_IGNORED".to_string(),
                dir.join("yabai").display().to_string()
            )]
        );
        let mut findings = Vec::new();
        check_sudoers_neighbours(&layout, &mut findings);
        assert!(
            Report::from_findings(findings).ok,
            "a neighbour must not fail the report"
        );
    }

    #[test]
    fn the_name_skip_rule_wins_over_the_metadata_rule() {
        // Precedence matters: sudo skips the name before it ever stats the
        // file, so reporting `custom.conf` as a permissions problem would send
        // the operator to chmod when the fix is a rename.
        let tmp = tempdir().unwrap();
        let (layout, dir) = layout_with_sudoers_dir(tmp.path());
        fs::write(dir.join("custom.conf"), "Defaults env_reset\n").unwrap();

        assert_eq!(
            neighbour_findings(&layout),
            vec![(
                "SUDOERS_NEIGHBOUR_SKIPPED".to_string(),
                dir.join("custom.conf").display().to_string()
            )]
        );
    }

    #[test]
    fn dotfiles_and_our_own_policy_are_not_neighbours() {
        // `.DS_Store` is on every macOS host and is not an attempted rule;
        // our own drop-in is already judged by `check_protected_file`, so
        // reporting it here would double every real finding about it.
        let tmp = tempdir().unwrap();
        let (layout, dir) = layout_with_sudoers_dir(tmp.path());
        fs::write(dir.join(".DS_Store"), "junk").unwrap();
        fs::write(&layout.sudoers, "Defaults env_reset\n").unwrap();

        assert!(neighbour_findings(&layout).is_empty());
    }

    #[test]
    fn neighbours_are_reported_in_a_stable_order() {
        // `read_dir` order is unspecified; an unstable report is noise for
        // anything diffing `doctor --json` between runs.
        let tmp = tempdir().unwrap();
        let (layout, dir) = layout_with_sudoers_dir(tmp.path());
        for name in ["zebra", "alpha", "middle"] {
            fs::write(dir.join(name), "Defaults env_reset\n").unwrap();
        }
        let paths: Vec<String> = neighbour_findings(&layout)
            .into_iter()
            .map(|(_, p)| p)
            .collect();
        assert_eq!(
            paths,
            [
                dir.join("alpha").display().to_string(),
                dir.join("middle").display().to_string(),
                dir.join("zebra").display().to_string(),
            ]
        );
    }

    #[test]
    fn every_neighbour_code_is_advisory() {
        // A neighbour belongs to another vendor and this project refuses to
        // touch it, so none of these may ever clear `ok` — an agent told to
        // treat a `doctor` failure as a hard stop would wedge on a file only
        // the operator can fix.
        for code in [
            "SUDOERS_NEIGHBOUR_IGNORED",
            "SUDOERS_NEIGHBOUR_SKIPPED",
            "SUDOERS_NEIGHBOUR_VISUDO_REJECTED",
        ] {
            assert!(finding(code, None, "x").advisory, "{code} must be advisory");
        }
    }

    #[test]
    fn a_missing_sudoers_directory_is_not_an_error() {
        let tmp = tempdir().unwrap();
        let mut layout = layout_for(tmp.path());
        layout.sudoers = tmp.path().join("absent").join("sudo-secretspec");
        assert!(neighbour_findings(&layout).is_empty());
    }

    fn layout_for(root: &Path) -> Layout {
        Layout {
            config: root.join("config.toml"),
            vault: root.join("vault"),
            vault_realpath: root.join("vault"),
            service_user: owner_name(unsafe { libc::getuid() }),
            service_group: group_name(unsafe { libc::getgid() }),
            declarations: Some(root.join("decl.toml")),
            engine: root.join("engine"),
            audit: root.join("audit"),
            broker: root.join("broker"),
            client: root.join("client"),
            checker: root.join("checker"),
            retired: root.join("retired"),
            guidance: root.join("guidance"),
            sudoers: root.join("sudoers"),
            source_manifest: root.join("MANIFEST.sha256"),
            adopted_vault: false,
            installed_version: None,
        }
    }
}
