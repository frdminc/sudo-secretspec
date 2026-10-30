//! Root-owned fail-closed SecretSpec broker.
//!
//! The hidden `__broker` subcommand receives operation + options as trailing
//! arguments and validates the privilege boundary before running any operation.
//! All provider operations are value-free audited.
//!
//! Mutation safety: before any set/add/delete/undeclare, the manifest and
//! dotenv are backed up to `.rollback.<transaction>` copies. On success the
//! backups are archived into [`crate::history`] and then removed; on failure
//! they are restored atomically. A crash during mutation leaves the backups
//! visible to `doctor` but the original state recoverable.

use std::ffi::OsString;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

use clap::Parser;
use sha2::{Digest, Sha256};

use crate::audit::{self, AppendEventRequest, ClientFamily, Outcome};
use crate::config::Config;

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

const CONFIG_PATH: &str = crate::platform::CONFIG_PATH;

// ---------------------------------------------------------------------------
// Broker CLI (sub-parser for __broker)
// ---------------------------------------------------------------------------

#[derive(Debug, Parser)]
#[command(
    about = "Internal broker (sudo-only, hidden)",
    override_usage = "sudo sudo-secretspec __broker <OPERATION> [OPTIONS]"
)]
pub(crate) struct Broker {
    /// Broker operation
    #[arg()]
    pub(crate) operation: String,

    #[arg(long, default_value = "unknown")]
    pub(crate) client: String,

    /// SHA-256 of the operator's reason, hex, computed by the client.
    ///
    /// The reason crosses the boundary already hashed. It used to cross as
    /// plaintext in argv, where `ps` and `KERN_PROCARGS2` expose it to every
    /// process running as the same user — and it landed in shell history —
    /// while the design's stated invariant was that the ledger stores only
    /// `SHA-256(reason)`. Now the plaintext never leaves the client.
    #[arg(long, default_value = "")]
    pub(crate) reason_sha256: String,

    #[arg(long)]
    pub(crate) name: Option<String>,

    #[arg(long)]
    pub(crate) command_basename: Option<String>,

    /// Declaration description, for `source-add` only.
    ///
    /// Declarations carry a human description, so `add` cannot be satisfied by
    /// a name alone. This arrives as an ordinary argument rather than a prompt
    /// because the broker never has a usable terminal.
    #[arg(long)]
    pub(crate) description: Option<String>,

    /// Write `required = false` on the declaration, for `source-add` only.
    #[arg(long, conflicts_with = "required")]
    pub(crate) optional: bool,

    /// Write `required = true` on the declaration, for `source-add` only.
    ///
    /// Neither flag omits the key, leaving the secret to inherit `[defaults]
    /// required` from its profile. That inherited value is not always
    /// required, which is why this is a separate flag rather than the absence
    /// of `--optional`.
    #[arg(long)]
    pub(crate) required: bool,

    #[arg(long)]
    pub(crate) to: Option<String>,

    #[arg(long)]
    pub(crate) force: bool,

    #[arg(long)]
    pub(crate) all: bool,
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

/// Parse broker args from raw trailing arguments and route to the operation.
pub fn dispatch(raw: &[OsString]) -> Result<(), i32> {
    let broker = match Broker::try_parse_from(
        std::iter::once(OsString::from("__broker")).chain(raw.iter().cloned()),
    ) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("broker: {e}");
            return Err(2);
        }
    };
    run(&broker)
}

// ---------------------------------------------------------------------------
// Environment validation
// ---------------------------------------------------------------------------

fn require_service_user(service_uid: u32) -> Result<(), i32> {
    if unsafe { libc::geteuid() } != service_uid {
        eprintln!("broker: must run as service user");
        return Err(2);
    }
    Ok(())
}

fn load_config() -> Result<Config, i32> {
    let content = std::fs::read_to_string(CONFIG_PATH).map_err(|e| {
        eprintln!("broker: cannot read config: {e}");
        2
    })?;
    Config::parse(&content).map_err(|e| {
        eprintln!("broker: invalid config: {e}");
        2
    })
}

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

/// Validate the privilege boundary before any operation, and return the uid the
/// protected state must be owned by.
///
/// Existence and symlink checks alone are not a boundary: they say nothing
/// about who can rewrite the manifest that decides which secrets exist, or the
/// dotenv that holds their values. Ownership, mode, and the resolved path chain
/// are all enforced here rather than being left to `doctor`, which is
/// out-of-band, non-repairing, and may never have run.
fn require_boundary(cfg: &Config) -> Result<u32, i32> {
    let vault = &cfg.vault;
    let meta = std::fs::symlink_metadata(vault).map_err(|e| {
        eprintln!("broker: vault unreadable: {e}");
        2
    })?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        eprintln!("broker: vault missing, symlinked, or not a directory");
        return Err(2);
    }
    if meta.permissions().mode() & 0o777 != 0o700 {
        eprintln!("broker: vault must be mode 0700");
        return Err(2);
    }

    let service_uid = uid_for_user(&cfg.service_user).ok_or_else(|| {
        eprintln!("broker: unknown service user {}", cfg.service_user);
        2
    })?;
    if meta.uid() != service_uid {
        eprintln!("broker: vault owner is not the configured service user");
        return Err(2);
    }

    // The public `/var/db/...` spelling must resolve to the pinned private
    // chain; anything else means the vault was moved or redirected.
    match vault.canonicalize() {
        Ok(resolved) if resolved == cfg.vault_realpath => {}
        Ok(resolved) => {
            eprintln!(
                "broker: vault resolves to {}, expected {}",
                resolved.display(),
                cfg.vault_realpath.display()
            );
            return Err(2);
        }
        Err(e) => {
            eprintln!("broker: vault path cannot be resolved: {e}");
            return Err(2);
        }
    }

    // `secretspec.toml` is required: the boundary cannot resolve anything
    // without a manifest. The value store and the retired dotenv are checked
    // *if present* instead.
    //
    // `secrets.db` is created lazily by the provider on its first write, so a
    // freshly installed vault legitimately has none — requiring it would refuse
    // every operation on a new install, including the `set` that would create
    // it. Its absence means "no values yet", which `check` reports on its own.
    //
    // `.env` is vestigial since values moved into `secrets.db`, but a leftover
    // one is still worth refusing to run beside if it has been swapped for a
    // symlink or re-owned. Listing it as required, as this loop did before the
    // migration, meant deleting the file the boundary no longer reads would
    // brick every broker call.
    for (name, required) in [
        ("secretspec.toml", true),
        ("secrets.db", false),
        (".env", false),
    ] {
        let path = vault.join(name);
        let meta = match std::fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(e) if !required && e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                eprintln!("broker: {name} unreadable: {e}");
                return Err(2);
            }
        };
        if meta.file_type().is_symlink() || !meta.is_file() {
            eprintln!("broker: {name} missing, symlinked, or not a regular file");
            return Err(2);
        }
        if meta.uid() != service_uid {
            eprintln!("broker: {name} owner is not the configured service user");
            return Err(2);
        }
        // Exactly 0600, not merely "nothing for group or world". The looser
        // rule also admitted 0700 and 0400, while `drift` already required
        // exactly 0600 — leaving the *enforcing* side more permissive than the
        // *reporting* one, which is backwards. A fresh install writes 0600
        // (`install::run`) and an adopted vault is checked here, so there is no
        // mode this rejects that the installer would have produced.
        if meta.permissions().mode() & 0o777 != 0o600 {
            eprintln!("broker: {name} must be mode 0600");
            return Err(2);
        }
    }
    Ok(service_uid)
}

/// `chown(2)` on a path, without following a final symlink.
///
/// `lchown` rather than `chown`: the caller has just created this path and a
/// symlink appearing at it would otherwise redirect a root-owned ownership
/// change onto whatever it points at.
fn chown(path: &std::path::Path, uid: u32, gid: u32) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::other("path contains an interior NUL"))?;
    // SAFETY: `c_path` is a valid NUL-terminated string that outlives the call.
    if unsafe { libc::lchown(c_path.as_ptr(), uid, gid) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Mutation helpers — backup/restore/commit for manifest and dotenv
// ---------------------------------------------------------------------------

struct Mutation {
    vault: std::path::PathBuf,
    manifest: std::path::PathBuf,
    dotenv: std::path::PathBuf,
    transaction: uuid::Uuid,
    /// The operation these copies precede, recorded with them in history.
    operation: String,
    /// The identity the vault's protected state must belong to, passed through
    /// to the history store's own metadata checks.
    service_uid: u32,
    /// Whether each rollback source existed when the mutation began, indexed in
    /// the same order the copy loop visits them: `[manifest, dotenv]`.
    ///
    /// Without this, `restore` cannot tell "there was no backup because there
    /// was nothing to copy" from "the backup went missing", and reported the
    /// first mutating operation on a fresh install as an unknown outcome.
    existed: [bool; 2],
}

impl Mutation {
    fn begin(
        cfg: &Config,
        transaction: uuid::Uuid,
        operation: &str,
        uid: u32,
        gid: u32,
    ) -> Result<Self, i32> {
        let vault = cfg.vault.clone();
        let manifest = vault.join("secretspec.toml");
        let dotenv = vault.join("secrets.db");

        let mut m = Self {
            vault,
            manifest,
            dotenv,
            transaction,
            operation: operation.to_string(),
            service_uid: uid,
            // Filled in by the copy loop below.
            existed: [true; 2],
        };

        // Create rollback copies.
        //
        // All-or-nothing. A failure part way through used to leave the earlier
        // source's copy behind: `begin` returns `Err` *before* any Mutation
        // exists, so there is no `commit`/`restore` left to clean up after it,
        // and `drift` reports the leftover only as an advisory PENDING_ROLLBACK
        // — so nothing on the host would ever remove it.
        let mut created: Vec<std::path::PathBuf> = Vec::new();
        let mut existed = [true; 2];
        let staged = (|| -> Result<(), i32> {
            for (index, (src, suffix)) in [(&m.manifest, "toml"), (&m.dotenv, "db")]
                .into_iter()
                .enumerate()
            {
                let dst = m.rollback_path(suffix);
                if dst.exists() {
                    eprintln!("broker: rollback path collision: {}", dst.display());
                    return Err(2);
                }
                match std::fs::copy(src, &dst) {
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        // File doesn't exist yet (e.g. first run for secrets.db),
                        // nothing to backup. Recorded so `restore` can tell this
                        // apart from a backup that went missing.
                        existed[index] = false;
                        continue;
                    }
                    Err(e) => {
                        eprintln!("broker: cannot create rollback copy: {e}");
                        return Err(2);
                    }
                }
                created.push(dst.clone());
                // `fs::copy` carries the mode across but *not* the owner, so a copy
                // made by this root process lands root-owned inside a vault owned by
                // the service user. `drift` checks the vault entry by entry, and a
                // root-owned entry there turns the deliberately-advisory
                // PENDING_ROLLBACK into a hard METADATA_MISMATCH — which fails
                // `doctor`, which every agent is told to treat as a stop. A crashed
                // mutation would then wedge the host.
                chown(&dst, uid, gid).map_err(|e| {
                    eprintln!("broker: cannot set rollback copy ownership: {e}");
                    2
                })?;
            }
            Ok(())
        })();

        if let Err(code) = staged {
            for path in &created {
                let _ = std::fs::remove_file(path);
            }
            return Err(code);
        }

        m.existed = existed;
        Ok(m)
    }

    fn rollback_path(&self, suffix: &str) -> std::path::PathBuf {
        self.vault.join(format!(
            ".secretspec.{}.rollback.{}",
            suffix, self.transaction
        ))
    }

    /// Put the pre-mutation bytes back, and discard the copies.
    ///
    /// Deliberately does **not** archive: a rolled-back mutation never took
    /// effect, so there is no prior state to recover to that is not simply the
    /// current one. Recording it would fill history with entries identical to
    /// the state beside them.
    fn restore(&self) -> bool {
        let mut ok = true;
        for (index, (dest, suffix)) in [(&self.manifest, "toml"), (&self.dotenv, "db")]
            .into_iter()
            .enumerate()
        {
            let backup = self.rollback_path(suffix);
            if backup.is_file() {
                if std::fs::copy(&backup, dest).is_err() {
                    ok = false;
                    continue;
                }
                let _ = std::fs::remove_file(&backup);
            } else if self.existed[index] {
                // There was something to back up and the copy is gone, so the
                // pre-mutation state really is unrecoverable.
                ok = false;
            } else if dest.exists() {
                // This source did not exist when the mutation began, so the
                // pre-state is "absent" and restoring it means removing what the
                // failed mutation created. Leaving the file while reporting a
                // clean rollback would be the same misreport in the other
                // direction. `restore` runs only on the failed-operation path,
                // so the only thing that can have created this is the mutation
                // being undone.
                if std::fs::remove_file(dest).is_err() {
                    ok = false;
                }
            }
        }
        ok
    }

    /// Archive the pre-mutation copies, then remove them.
    ///
    /// This is where infinite history comes from: the bytes were already being
    /// captured correctly before every mutation and then thrown away on
    /// success. They are now kept.
    ///
    /// A failed archive does **not** fail the operation — the mutation has
    /// already committed and cannot be undone, so reporting failure would
    /// misdescribe what happened. Instead the rollback copies are deliberately
    /// left on disk. That is not a silent swallow: the bytes survive, `drift`
    /// already reports leftover copies as `PENDING_ROLLBACK`, and the warning
    /// below names the transaction. The degraded state is exactly the
    /// pre-history behaviour rather than a loss.
    fn commit(&self) {
        match self.archive() {
            Ok(()) => {
                for suffix in ["toml", "db"] {
                    let _ = std::fs::remove_file(self.rollback_path(suffix));
                }
            }
            Err(e) => {
                eprintln!("broker: could not archive pre-mutation state to history: {e}");
                eprintln!(
                    "broker: the operation succeeded; its rollback copies are kept in the \
                     vault for transaction {} and `doctor` will report them",
                    self.transaction
                );
            }
        }
    }

    fn archive(&self) -> Result<(), crate::history::HistoryError> {
        let manifest = std::fs::read(self.rollback_path("toml"))?;
        crate::history::capture(
            &self.vault,
            crate::history::CaptureRequest {
                transaction: self.transaction,
                operation: self.operation.clone(),
                manifest,
                expected_uid: Some(self.service_uid),
            },
        )?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Operation classification
// ---------------------------------------------------------------------------

/// Every operation dispatched through the source funnel in [`run`].
///
/// A single list so [`mutates_vault`] can be checked against it. A new verb
/// added here without a matching decision about whether it writes fails a test
/// rather than silently joining the read-only majority — which is exactly how
/// `source-undeclare` came to rewrite the runtime manifest with no rollback
/// copy while its three siblings had one.
pub const SOURCE_OPS: &[&str] = &[
    "source-get",
    "source-set",
    "source-add",
    "source-undeclare",
    "source-delete",
    "source-check",
    "source-export",
    "source-template-check",
    "source-schema",
    "source-restore",
    "source-restore-force",
    "source-destroy",
];

/// Whether an operation writes to the vault, and so needs a rollback copy.
///
/// Named and tested rather than left as a `matches!` inside [`run`], which only
/// executes as root against a real vault and is therefore reachable by no test.
/// Same reasoning that moved the adoption rule out of `main.rs`'s `run_install`
/// into [`crate::install::adopts_without_flag`]: an untestable trust decision is
/// where the last one hid.
#[must_use]
pub fn mutates_vault(operation: &str) -> bool {
    matches!(
        operation,
        "source-set"
            | "source-add"
            | "source-undeclare"
            | "source-delete"
            | "source-restore"
            | "source-restore-force"
            | "source-destroy"
    )
}

// ---------------------------------------------------------------------------
// Client resolution
// ---------------------------------------------------------------------------

fn resolve_client(raw: &str) -> ClientFamily {
    match raw {
        "hermes" => ClientFamily::Hermes,
        "claude" => ClientFamily::Claude,
        "codex" => ClientFamily::Codex,
        "opencode" => ClientFamily::OpenCode,
        "cursor" => ClientFamily::Cursor,
        "agy" => ClientFamily::Agy,
        "fixed-consumer" => ClientFamily::FixedConsumer,
        _ => ClientFamily::Unknown,
    }
}

/// `SHA-256("")`. Never a valid reason digest: it is what a caller sends when
/// it has no reason at all, and the gate exists to make that impossible.
pub const EMPTY_REASON_SHA256: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Digest a reason for transport across the privilege boundary.
///
/// `None` for a blank reason, so a caller cannot satisfy the gate by sending
/// the digest of nothing. Used by the client before it elevates; the broker
/// only ever sees the result.
pub fn reason_sha256(reason: &str) -> Option<String> {
    let reason = reason.trim();
    if reason.is_empty() {
        return None;
    }
    Some(format!("{:x}", Sha256::digest(reason.as_bytes())))
}

/// True for a well-formed reason digest the broker will accept.
///
/// Lowercase hex, 64 characters, and not the digest of the empty string.
pub fn is_valid_reason_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .as_bytes()
            .iter()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        && value != EMPTY_REASON_SHA256
}

fn actor_from_env() -> String {
    std::env::var("SUDO_USER").unwrap_or_else(|_| "root".into())
}

// ---------------------------------------------------------------------------
// Ambient environment
// ---------------------------------------------------------------------------

/// True for any variable that could steer the engine's control plane.
///
/// A predicate rather than a list, because a list is only correct on the day it
/// is written. The engine reads roughly twenty `SECRETSPEC_*` knobs today, four
/// of which (`SECRETSPEC_OPCLI_PATH` and its `BWS`/`PASSBOLT`/`PROTONPASS`
/// siblings) name an executable it will spawn — and this process is root. The
/// `XDG_*` family is here for the same reason: it decides which directory the
/// engine's user-global config is read from.
pub(crate) fn is_ambient_control_var(key: &str) -> bool {
    key.starts_with("SECRETSPEC_") || key.starts_with("XDG_")
}

/// Drop every ambient variable that could redirect the engine, then pin the
/// environment its user-global config resolves from.
///
/// Called at the top of [`run`], before the operation is even dispatched:
/// nothing between here and execution has any business consulting ambient
/// state, so there is no window in which a later reader could see the caller's
/// values.
fn purge_ambient_env() {
    // `vars_os`, not `vars`: the latter panics on a non-UTF-8 environment, and
    // the caller controls this environment entirely.
    for (key, _) in std::env::vars_os() {
        if is_ambient_control_var(&key.to_string_lossy()) {
            // SAFETY: single-threaded broker process; no concurrent env readers.
            unsafe { std::env::remove_var(&key) }
        }
    }

    // Clearing `XDG_CONFIG_HOME` is not enough on its own: the engine resolves
    // its user-global config through etcetera's XDG strategy, which falls back
    // to `$HOME/.config`, and `sudo` on this platform hands the *caller's*
    // `HOME` to the broker. Left alone, the broker reads a config file an
    // unprivileged caller can write — one whose `[audit] path` aims a
    // privileged writer at any absolute path, and whose `[defaults] profile`
    // picks which profile of the protected manifest resolves.
    //
    // Point HOME at the service user's passwd-entry home (`/var/empty`).
    // `/var/empty` is world-readable (`0755 root:sys`) so the engine's
    // `GlobalConfig::load()` can safely `try_exists()` on the derived config
    // path without hitting Permission Denied. The previous `/var/root` was
    // `0750 root:wheel`, which `_sudo_secretspec` cannot traverse.
    //
    // `set` rather than `remove`: with `HOME` unset, etcetera falls back to
    // `getpwuid(getuid())` — which is the correct `/var/empty` for the service
    // user, but an explicit value avoids the directory-service round trip and
    // keeps the resolved path a build-time constant.
    //
    // SAFETY: single-threaded broker process; no concurrent env readers.
    unsafe {
        std::env::set_var("HOME", "/var/empty");
    }
}

/// Map what happened during a mediated operation onto the terminal audit event.
///
/// Split out of [`run`] because it is the part of the funnel that can actually
/// be tested. The failures it classifies need a root process and a real vault
/// to provoke — a rollback-path collision needs a colliding fresh UUID, and
/// root ignores mode bits, so the copy cannot be made to fail by permissions —
/// but the mapping from "what happened" to "what the ledger records" is pure.
///
/// `attempted` is the name list from the attempt event: on the error path
/// `execute` never ran, so it never reported names of its own.
fn classify_terminal(
    outcome: Result<(u8, bool, Vec<String>), i32>,
    attempted: &[String],
) -> (Outcome, u8, Vec<String>) {
    match outcome {
        // The mutation could not be rolled back. The store's state is genuinely
        // unknown, which is neither success nor a clean failure.
        Ok((_, true, names)) => (Outcome::Unknown, 125, names),
        Ok((0, false, names)) => (Outcome::Success, 0, names),
        Ok((rc, false, names)) => (Outcome::Failure, rc, names),
        // Failed before `execute` ran: nothing was attempted against the store
        // and nothing was mutated. This arm is the whole point of the funnel —
        // it used to return bare, leaving an attempt with no terminal event.
        Err(code) => (
            Outcome::Failure,
            u8::try_from(code).unwrap_or(2),
            attempted.to_vec(),
        ),
    }
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

fn run(broker: &Broker) -> Result<(), i32> {
    purge_ambient_env();
    match broker.operation.as_str() {
        "audit-verify" => run_audit_verify(broker),
        op if SOURCE_OPS.contains(&op) => {
            let cfg = load_config()?;
            let service_uid = require_boundary(&cfg)?;
            require_service_user(service_uid)?;
            // The group the vault itself carries, not the one named in the
            // config: `audit::open_connection` already reassigns the ledger to
            // the vault's own gid, and rollback backups must land beside it
            // under the same identity.
            let service_gid = std::fs::metadata(&cfg.vault)
                .map_err(|e| {
                    eprintln!("broker: vault unreadable: {e}");
                    2
                })?
                .gid();

            // The digest arrives already computed; the broker's job is to
            // refuse anything that is not one. Rejecting SHA-256("") matters as
            // much as the format check: without it a caller with no reason
            // could still satisfy the gate by sending the digest of nothing.
            let reason_hash = broker.reason_sha256.trim().to_string();
            if !is_valid_reason_digest(&reason_hash) {
                eprintln!("broker: --reason-sha256 must be the hex SHA-256 of a non-empty reason");
                return Err(2);
            }

            let client = resolve_client(&broker.client);
            let transaction = uuid::Uuid::new_v4();
            let names = broker
                .name
                .as_deref()
                .map(|n| vec![n.to_string()])
                .unwrap_or_default();
            let actor = actor_from_env();

            // Fail-closed audit attempt before any secret operation.
            audit::append_event(
                &cfg.vault,
                AppendEventRequest {
                    operation: broker.operation.clone(),
                    phase: Outcome::Attempt,
                    transaction,
                    actor: actor.clone(),
                    client,
                    reason_sha256: Some(reason_hash.clone()),
                    command_basename: broker.command_basename.clone(),
                    names: names.clone(),
                    result_code: None,
                    expected_uid: Some(service_uid),
                },
            )
            .map_err(|e| {
                eprintln!("broker: audit attempt failed: {e}");
                2
            })?;

            // Everything between the attempt and the terminal event runs inside
            // this closure so that *no* path can leave an attempt unterminated.
            // `Mutation::begin` used to `?` straight out of `run`, which left
            // exactly that: an attempt with no outcome, indistinguishable in the
            // ledger from a broker killed mid-operation. Funnelling makes the
            // guarantee structural instead of something each new `?` has to
            // remember.
            let outcome = (|| -> Result<(u8, bool, Vec<String>), i32> {
                let mutation = if mutates_vault(&broker.operation) {
                    Some(Mutation::begin(
                        &cfg,
                        transaction,
                        &broker.operation,
                        service_uid,
                        service_gid,
                    )?)
                } else {
                    None
                };

                let (rc, names) = execute(broker, &cfg, &reason_hash);

                // Commit or restore mutation
                let mut unknown = false;
                if let Some(m) = &mutation {
                    if rc == 0 {
                        m.commit();
                    } else if !m.restore() {
                        unknown = true;
                    }
                }

                Ok((rc, unknown, names))
            })();

            // Terminal audit must also succeed.
            let (phase, terminal_rc, names) = classify_terminal(outcome, &names);
            audit::append_event(
                &cfg.vault,
                AppendEventRequest {
                    operation: broker.operation.clone(),
                    phase,
                    transaction,
                    actor,
                    client,
                    reason_sha256: Some(reason_hash),
                    command_basename: broker.command_basename.clone(),
                    names,
                    result_code: Some(terminal_rc),
                    expected_uid: Some(service_uid),
                },
            )
            .map_err(|e| {
                // Fail closed, but do not report this as a plain policy error:
                // the operation itself has already committed or rolled back, and
                // only the ledger is incomplete. 126 distinguishes "outcome
                // unrecorded" from an operation that simply failed.
                eprintln!("broker: audit terminal failed: {e}");
                eprintln!(
                    "broker: operation outcome was rc={terminal_rc} but could not be recorded"
                );
                126
            })?;

            if terminal_rc != 0 {
                Err(i32::from(terminal_rc))
            } else {
                Ok(())
            }
        }
        op => {
            eprintln!("broker: unknown operation: {op}");
            Err(2)
        }
    }
}

fn run_audit_verify(_broker: &Broker) -> Result<(), i32> {
    let cfg = load_config()?;
    let expected_uid = uid_for_user(&cfg.service_user).ok_or_else(|| {
        eprintln!("broker: unknown service user {}", cfg.service_user);
        2
    })?;
    require_service_user(expected_uid)?;
    // Assert who the ledger must belong to, but deliberately *without*
    // `require_boundary`. This is the one command whose job is to prove the
    // ledger is intact, and running the full boundary check first would mean a
    // drifted install (wrong binary mode, missing manifest) could no longer
    // verify its own ledger — precisely when the answer matters most. Passing
    // `None` here, though, skipped the owner comparison in both
    // `check_protected_dir` and `check_ledger_metadata`, so "verified" said
    // nothing about ownership at all.
    match audit::verify(&cfg.vault, Some(expected_uid)) {
        Ok(result) => {
            println!("audit-verify: {} events, tip {}", result.count, result.hash);
            Ok(())
        }
        Err(e) => {
            eprintln!("audit-verify failed: {e}");
            Err(1)
        }
    }
}

/// The runtime manifest with one declaration added, revalidated as a whole.
///
/// Goes through [`secretspec::SpecBuilder`]'s format-preserving edit rather
/// than raw TOML surgery, so the edit is re-derived through the same validated
/// path every other load takes: a declaration that would not load is refused
/// here instead of being written into the vault and surfacing at the next
/// `check`.
///
/// `Spec::from_toml` is the deliberate constructor. It never touches the
/// filesystem and refuses `project.extends`, so this root process cannot be
/// induced to read parent files while editing the manifest.
///
/// Extracted from `execute` for the same reason `install`'s guards were: the
/// call site only runs as root against a real vault, and an edit to the
/// operator's manifest is the last thing that should be reachable only there.
fn manifest_with_declaration(
    source: &str,
    profile: &str,
    name: &str,
    secret: secretspec::Secret,
) -> Result<String, String> {
    let spec = secretspec::Spec::from_toml(source).map_err(|e| e.to_string())?;
    let edited = spec
        .into_builder()
        .add_secret(profile, name, secret)
        .build()
        .map_err(|e| e.to_string())?;
    preserved(edited)
}

/// The runtime manifest with one declaration removed, revalidated as a whole.
///
/// The inverse of [`manifest_with_declaration`] and, because both go through
/// the one implementation, byte-exact: adding a declaration and removing it
/// again restores the original document exactly, which is the property
/// `Mutation::restore` compares.
fn manifest_without_declaration(source: &str, profile: &str, name: &str) -> Result<String, String> {
    let spec = secretspec::Spec::from_toml(source).map_err(|e| e.to_string())?;
    let edited = spec
        .into_builder()
        .remove_secret(profile, name)
        .build()
        .map_err(|e| e.to_string())?;
    preserved(edited)
}

/// The edited document's exact text.
///
/// An edited spec always carries its source, so `None` here means the API
/// changed under us — reported rather than unwrapped, because the caller is
/// about to overwrite the operator's manifest with whatever this returns.
fn preserved(edited: secretspec::Spec) -> Result<String, String> {
    edited
        .preserved_text()
        .map(str::to_string)
        .ok_or_else(|| "edited manifest kept no source text".to_string())
}

/// Guard 1 of `source-undeclare`, as a decision over text rather than files.
///
/// `None` is the installer stating there is no tracked declaration source at
/// all. A name cannot be Git content of a file that does not exist, so nothing
/// is protected and `undeclare` proceeds. That is a positive fact about the
/// configuration, and deliberately *not* the same as a configured template that
/// will not parse — which stays fail-closed in the `Err` arm, because an
/// unparseable template is not evidence that the name is absent from it, and
/// this guard exists to protect exactly the names it might have failed to read.
///
/// Distinguishing the two at the type level is the only reason relaxing a
/// deliberately fail-closed guard is sound here. Were `None` refused instead,
/// `add` could dirty the runtime manifest on the cheap NOPASSWD path while
/// nothing could ever move it back — the exact asymmetry this verb exists to
/// fix.
///
/// Answered from the TOML text itself rather than through `Spec`, for two
/// reasons specific to this guard:
///
/// 1. An unparseable document must be an `Err`, never "not declared" — the
///    fail-*open* answer this must never give.
/// 2. Reaching a `Spec` needs a constructor, and the only filesystem-free one,
///    `Spec::from_toml`, refuses `project.extends`. The template is
///    operator-controlled Git content; the day it inherits, `undeclare` would
///    start refusing every name.
///
/// Parsed, not searched: a substring test would match the name inside a
/// comment or another secret's description, silently.
fn tracked_source_protects(
    template: Option<&str>,
    profile: &str,
    name: &str,
) -> Result<bool, String> {
    match template {
        None => Ok(false),
        Some(text) => {
            let doc: toml::Table = toml::from_str(text)
                .map_err(|e| format!("Failed to parse secretspec.toml: {e}"))?;
            Ok(doc
                .get("profiles")
                .and_then(toml::Value::as_table)
                .and_then(|profiles| profiles.get(profile))
                .and_then(toml::Value::as_table)
                .is_some_and(|table| table.contains_key(name)))
        }
    }
}

fn execute(broker: &Broker, cfg: &Config, reason_hash: &str) -> (u8, Vec<String>) {
    // The ambient environment was purged in `run` before dispatch; see
    // `purge_ambient_env`.

    // The engine's JSONL audit sink defaults to the XDG state directory, which
    // with `HOME=/var/empty` resolves under a directory nothing may write:
    // every operation then warned "Operation not permitted" and dropped its
    // event. The sink is not decorative here — it records the same reason
    // digest as the SQLite ledger, which is what lets the two be joined.
    //
    // State it rather than deriving it. The vault is the only directory the
    // service user owns, and the sink creates its own parent at 0700, so
    // `<vault>/.state/secretspec/audit.log` needs no installer support. `drift`
    // allows `.state` for exactly this reason; everything else in the vault
    // stays on the strict allowlist.
    //
    // SAFETY: single-threaded broker process; no concurrent env readers.
    unsafe {
        std::env::set_var("XDG_STATE_HOME", cfg.vault.join(".state"));
    }

    let manifest = cfg.vault.join("secretspec.toml");
    let db = cfg.vault.join("secrets.db");
    // `?history=true` is not optional for the boundary, whatever it is for an
    // ordinary user of the provider. `source-restore` reads `captured_values`
    // and `source-destroy` tombstones it, so without retention the restore
    // verbs have nothing to work from — and `destroy` in particular deletes the
    // live value *before* it touches history, making an inert chain a silent
    // path to irrecoverable loss rather than a missing feature.
    let provider = format!("sqlite://{}?history=true", db.display());
    let secrets = match secretspec::Secrets::load_from(&manifest) {
        Ok(mut s) => {
            s.set_provider(provider);
            // Pin the profile from the protected config. Without this the
            // engine's `resolve_profile_name` falls through to its user-global
            // config — which, inside a root process, is the caller's file.
            s.set_profile(cfg.profile.clone());
            // The digest, because that is all this side has. The engine's own
            // JSONL audit therefore records the same value as the SQLite
            // ledger, so the two join on it — which prose never allowed.
            s = s.with_reason(reason_hash.to_string());
            s
        }
        Err(e) => {
            eprintln!("broker: cannot load secrets: {e}");
            return (2, vec![]);
        }
    };

    let name = broker.name.as_deref().unwrap_or("");

    match broker.operation.as_str() {
        "source-get" => match secrets.resolve_named(name) {
            Ok(secretspec::NamedResolution::Resolved(secret)) => {
                if let Some(value) = secret.value {
                    println!("{value}");
                    (0, vec![name.into()])
                } else {
                    eprintln!("broker: {name} has no value");
                    (1, vec![name.into()])
                }
            }
            Ok(_) => {
                eprintln!("broker: {name} is not resolved");
                (1, vec![name.into()])
            }
            Err(e) => {
                eprintln!("broker: {e}");
                (1, vec![name.into()])
            }
        },
        // `add` declares; `set` assigns a value. These used to share this arm,
        // which made `add` an alias for `set` — and `set` refuses a name that
        // is not already declared, so `add` could never once perform the
        // operation it is named for.
        "source-add" => {
            let Some(description) = broker.description.as_deref() else {
                eprintln!("broker: source-add requires --description");
                return (2, vec![name.into()]);
            };
            // The engine's builder only rejects the empty string; the broker
            // path is NOPASSWD, so a whitespace-only description must be
            // refused here as it was before the engine took over the edit.
            if description.trim().is_empty() {
                eprintln!("broker: source-add requires a non-empty --description");
                return (2, vec![name.into()]);
            }
            let source = match std::fs::read_to_string(&manifest) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("broker: cannot read manifest: {e}");
                    return (2, vec![name.into()]);
                }
            };
            // `Secret`'s three constructors are the tri-state this used to pass
            // as `Option<bool>`: `new` leaves requiredness to the profile
            // default, the other two pin it.
            let declaration = match (broker.optional, broker.required) {
                (true, _) => secretspec::Secret::optional(description),
                (_, true) => secretspec::Secret::required(description),
                _ => secretspec::Secret::new(description),
            };
            let updated = match manifest_with_declaration(&source, &cfg.profile, name, declaration)
            {
                Ok(text) => text,
                Err(e) => {
                    eprintln!("broker: {e}");
                    return (1, vec![name.into()]);
                }
            };
            // Write IN PLACE, never temp-file-and-rename. The vault manifest is
            // owned by the service user; a rename would replace it with a file
            // this root process created, leaving it root-owned inside a vault
            // that `drift` checks entry by entry — which fails `doctor`. An
            // in-place truncate keeps the inode, and with it the owner and mode.
            // `Mutation::restore` relies on the same property.
            match std::fs::write(&manifest, updated) {
                Ok(()) => {
                    println!(
                        "declaration added to the runtime manifest; mirror {name} into the \
                         tracked declarations and release it, or `template-check` will report drift"
                    );
                    (0, vec![name.into()])
                }
                Err(e) => {
                    eprintln!("broker: cannot write manifest: {e}");
                    (1, vec![name.into()])
                }
            }
        }
        // The inverse of `source-add`, and deliberately narrower than it.
        //
        // `add` can only ever move the runtime manifest *away* from the tracked
        // template, and until this existed nothing could move it back on the
        // mediated path: `delete` removes a value and leaves the declaration
        // standing. An agent could therefore dirty the manifest with an
        // unprivileged NOPASSWD call and then need an operator at a Touch ID
        // prompt to undo it, which is the wrong way round for a cheap operation
        // to fail.
        //
        // Two guards keep this from becoming a way to edit policy:
        //
        // 1. A name present in the tracked declaration template is refused.
        //    Those are Git content; removing one stays a review-and-release
        //    decision, exactly as AI-GUIDANCE says. So this can only ever move
        //    the manifest *toward* the template, never further from it.
        // 2. A name that still resolves to a value is refused. Undeclaring it
        //    would strand the value in the dotenv with nothing declaring it —
        //    a secret on disk that no longer appears in `check`. `delete`
        //    first, then undeclare; that mirrors `add` then `set`.
        "source-undeclare" => {
            // Reading is the only part of guard 1 that touches the filesystem;
            // the decision itself is `tracked_source_protects`, over text.
            //
            // A *configured* path that will not open stays fail-closed: that is
            // equally consistent with a broken install. An absent key is not —
            // see `tracked_source_protects`.
            let template = match &cfg.declarations {
                Some(path) => match std::fs::read_to_string(path) {
                    Ok(text) => Some(text),
                    Err(e) => {
                        eprintln!("broker: cannot read declaration template: {e}");
                        return (2, vec![name.into()]);
                    }
                },
                None => None,
            };
            match tracked_source_protects(template.as_deref(), &cfg.profile, name) {
                Ok(true) => {
                    eprintln!(
                        "broker: {name} is in the tracked declaration template; remove it \
                         through review and release, not at runtime"
                    );
                    return (1, vec![name.into()]);
                }
                Err(e) => {
                    eprintln!("broker: cannot parse declaration template: {e}");
                    return (2, vec![name.into()]);
                }
                Ok(false) => {}
            }

            if let Ok(secretspec::NamedResolution::Resolved(secret)) = secrets.resolve_named(name)
                && secret.value.is_some()
            {
                eprintln!(
                    "broker: {name} still holds a value; `delete` it first, or undeclaring would \
                     leave the value in the store with nothing declaring it"
                );
                return (1, vec![name.into()]);
            }

            let source = match std::fs::read_to_string(&manifest) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("broker: cannot read manifest: {e}");
                    return (2, vec![name.into()]);
                }
            };
            let updated = match manifest_without_declaration(&source, &cfg.profile, name) {
                Ok(text) => text,
                Err(e) => {
                    eprintln!("broker: {e}");
                    return (1, vec![name.into()]);
                }
            };
            // In place, for the same ownership reason as `source-add`.
            match std::fs::write(&manifest, updated) {
                Ok(()) => {
                    println!("declaration removed from the runtime manifest");
                    (0, vec![name.into()])
                }
                Err(e) => {
                    eprintln!("broker: cannot write manifest: {e}");
                    (1, vec![name.into()])
                }
            }
        }
        "source-set" => match secrets.prompt_and_set(name) {
            Ok(()) => (0, vec![name.into()]),
            Err(e) => {
                eprintln!("broker: {e}");
                (1, vec![name.into()])
            }
        },
        "source-delete" => match secrets.delete(name) {
            Ok(_) => (0, vec![name.into()]),
            Err(e) => {
                eprintln!("broker: {e}");
                (1, vec![name.into()])
            }
        },
        "source-restore" | "source-restore-force" | "source-destroy" => {
            let op = broker.operation.as_str();

            // `--all` and `--force` on the *plain* `source-restore` verb are
            // refused here. The NOPASSWD grant for the plain verb is a `--*`
            // glob, which also matches `source-restore --all`/`--force`, so a
            // caller who invokes sudo directly (not the client, which routes
            // those flags to `source-restore-force`) could reach an unattended
            // whole-vault restore through the NOPASSWD grant. The authorisation
            // gate must be the sudoers verb, not client routing.
            if op == "source-restore" && (broker.all || broker.force) {
                eprintln!(
                    "broker: source-restore --all/--force must run through source-restore-force"
                );
                return (2, vec![]);
            }

            let db_path = cfg.vault.join("secrets.db");
            // `Connection::open` defaults to SQLITE_OPEN_CREATE, so on a fresh
            // vault these verbs used to *create* an empty, schema-less
            // secrets.db and leave it behind on their way to failing rc 2. The
            // provider guards every read with the same existence check for
            // exactly this reason; a history verb must not be what brings the
            // value store into being.
            if !db_path.is_file() {
                eprintln!(
                    "broker: no secret store at {}; nothing to {op}",
                    db_path.display()
                );
                return (2, vec![]);
            }
            let conn = match rusqlite::Connection::open(&db_path) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("broker: cannot open secrets.db: {e}");
                    return (2, vec![]);
                }
            };
            // Foreign keys are per-connection and default off. The provider
            // enables them on its own connections; this one writes the
            // `destroyed_by` tombstones that the REFERENCES clause exists to
            // constrain, so it has to enable them too or the constraint does not
            // apply to the write that matters most.
            // `secure_delete` is per-connection too, and off by default in the
            // linked library. This connection is the one that runs `destroy`,
            // so without it the verb whose entire purpose is to make a value
            // unrecoverable left the plaintext sitting on a freed page.
            if let Err(e) = conn.execute_batch("PRAGMA foreign_keys=ON;PRAGMA secure_delete=ON;") {
                eprintln!("broker: cannot configure secret store connection: {e}");
                return (2, vec![]);
            }

            if op == "source-destroy" {
                let name = match broker.name.as_deref() {
                    Some(n) => n,
                    None => {
                        eprintln!("broker: --name is required for destroy");
                        return (2, vec![]);
                    }
                };

                // First delete from active secrets, which will capture a new history entry
                //
                // The bool matters. The provider only captures an entry when it
                // actually removed a row, so `Ok(false)` — a name already
                // source-deleted — means no new sequence exists. `MAX(sequence)`
                // would then return whatever unrelated entry sits at the tip and
                // stamp *that* as the destroyer: the value would be destroyed,
                // but the ledger would name the wrong event.
                //
                // Rather than refuse (which left captured copies of an
                // already-deleted name undestroyable), append a real entry for
                // this destroy using the provider's own chain code. That keeps
                // hashing in exactly one place, which was the objection to
                // synthesising an entry here.
                match secrets.delete(name) {
                    Ok(true) => {}
                    Ok(false) => {
                        if let Err(e) =
                            secretspec::sqlite_history::capture_history(&conn, "source-destroy")
                        {
                            eprintln!(
                                "broker: '{name}' has no live value and a history entry to \
                                 attribute its destruction to could not be appended: {e}"
                            );
                            return (2, vec![name.into()]);
                        }
                    }
                    Err(e) => {
                        eprintln!("broker: {e}");
                        return (1, vec![name.into()]);
                    }
                }

                // The new sequence just created by delete. Not `unwrap_or(0)`:
                // the value is already gone by this point, so failing to learn
                // the sequence must be reported, not papered over with a
                // sequence no entry has — which would write a tombstone
                // pointing at nothing while reporting success.
                let seq: i64 =
                    match conn.query_row("SELECT MAX(sequence) FROM entries", [], |row| row.get(0))
                    {
                        Ok(seq) => seq,
                        Err(e) => {
                            eprintln!("broker: cannot determine the history sequence: {e}");
                            return (2, vec![name.into()]);
                        }
                    };

                // `captured_values.item` holds the provider's full address
                // (`{project}/{profile}/{key}`), not the bare secret name.
                // Matching `item = name` therefore updated *zero* rows, so
                // `destroy` reported success while every captured copy of the
                // value stayed readable — the one outcome this verb exists to
                // prevent. Resolve the addresses first, then tombstone each by
                // its exact key.
                let suffix = format!("/{name}");
                let items: Vec<String> = {
                    let mut stmt = match conn.prepare("SELECT DISTINCT item FROM captured_values") {
                        Ok(stmt) => stmt,
                        Err(e) => {
                            eprintln!("broker: cannot enumerate history items: {e}");
                            return (2, vec![name.into()]);
                        }
                    };
                    let rows = match stmt.query_map([], |row| row.get::<_, String>(0)) {
                        Ok(rows) => rows,
                        Err(e) => {
                            eprintln!("broker: cannot enumerate history items: {e}");
                            return (2, vec![name.into()]);
                        }
                    };
                    let mut items = Vec::new();
                    for row in rows {
                        match row {
                            Ok(item) => items.push(item),
                            Err(e) => {
                                eprintln!("broker: cannot enumerate history items: {e}");
                                return (2, vec![name.into()]);
                            }
                        }
                    }
                    items
                };
                let targets: Vec<&String> = items
                    .iter()
                    .filter(|item| item.as_str() == name || item.ends_with(&suffix))
                    .collect();
                if targets.is_empty() {
                    eprintln!("broker: no captured history for {name}; nothing to tombstone");
                    return (1, vec![name.into()]);
                }

                let mut tombstoned = 0usize;
                for item in targets {
                    match conn.execute(
                        "UPDATE captured_values SET destroyed_by = ?1 \
                         WHERE item = ?2 AND destroyed_by IS NULL",
                        rusqlite::params![seq, item],
                    ) {
                        Ok(updated) => tombstoned += updated,
                        Err(e) => {
                            eprintln!("broker: cannot update history tombstones: {e}");
                            return (2, vec![name.into()]);
                        }
                    }

                    // The tombstone marks the row; this removes the bytes it
                    // used to carry. Blobs are keyed per item, so nothing
                    // another name depends on can be reached from here. The
                    // live guard matters only for a name destroyed and later
                    // re-set to the same value: that value is live again by
                    // the operator's own action, so its blob stays.
                    //
                    // Selecting `live_blob_id` rather than a digest is what
                    // makes the guard exact — it is NULL for every tombstone
                    // by construction, so a destroyed snapshot cannot vouch
                    // for bytes. `IS NOT NULL` in the subquery is required,
                    // not tidiness: a single NULL makes `NOT IN` never true
                    // and this statement would silently delete nothing.
                    // `ON DELETE RESTRICT` is the backstop if it ever does
                    // get this wrong.
                    if let Err(e) = conn.execute(
                        "DELETE FROM value_blobs WHERE item = ?1 AND blob_id NOT IN \
                         (SELECT live_blob_id FROM captured_values \
                          WHERE item = ?1 AND live_blob_id IS NOT NULL)",
                        rusqlite::params![item],
                    ) {
                        eprintln!("broker: cannot remove destroyed history values: {e}");
                        return (2, vec![name.into()]);
                    }
                }
                if tombstoned == 0 {
                    eprintln!("broker: no captured values remained to tombstone for {name}");
                    return (1, vec![name.into()]);
                }

                println!("destroyed {}", name);
                (0, vec![name.into()])
            } else {
                let to_str = match &broker.to {
                    Some(t) => t,
                    None => {
                        eprintln!("broker: --to is required for restore");
                        return (2, vec![]);
                    }
                };
                let seq: i64 = match to_str.parse() {
                    Ok(s) => s,
                    Err(_) => {
                        eprintln!("broker: --to must be a sequence integer");
                        return (2, vec![]);
                    }
                };

                // `captured_values.item` holds the provider's full address
                // (`{project}/{profile}/{key}`), while `secrets.set` and the
                // caller's `--name` both speak bare secret names. Reading the
                // sequence once and translating here keeps that mismatch in a
                // single place: `--name` used to compare a bare name against a
                // full address and so never matched, while `--all` fed full
                // addresses back into `set` as if they were names.
                let captured: Vec<(String, Vec<u8>)> = {
                    // Joining on `live_blob_id` is what keeps the tombstone
                    // authoritative, and it needs no companion filter: the
                    // column is NULL for every destroyed row, so those rows
                    // cannot join at all. Matching on `(item, value_sha256)`
                    // instead — the shape this replaced — let a destroyed
                    // snapshot restore again as soon as an identical value was
                    // re-set under the same name, because the recreated blob
                    // matched the tombstone's digest. It took a `destroyed_by
                    // IS NULL` filter to hold that shut, and mutation testing
                    // showed the filter could be deleted with the suite green.
                    let mut stmt = match conn.prepare(
                        "SELECT cv.item, b.value_blob FROM captured_values cv \
                         JOIN value_blobs b ON b.blob_id = cv.live_blob_id \
                         WHERE cv.sequence = ?1",
                    ) {
                        Ok(stmt) => stmt,
                        Err(e) => {
                            eprintln!("broker: cannot read captured values: {e}");
                            return (2, vec![]);
                        }
                    };
                    let rows = match stmt
                        .query_map(rusqlite::params![seq], |row| Ok((row.get(0)?, row.get(1)?)))
                    {
                        Ok(rows) => rows,
                        Err(e) => {
                            eprintln!("broker: cannot read captured values: {e}");
                            return (2, vec![]);
                        }
                    };
                    let mut captured = Vec::new();
                    for row in rows {
                        match row {
                            Ok(pair) => captured.push(pair),
                            Err(e) => {
                                eprintln!("broker: cannot read captured values: {e}");
                                return (2, vec![]);
                            }
                        }
                    }
                    captured
                };

                // The bare name is the last address segment; an address with no
                // separator is already one.
                let bare =
                    |item: &str| -> String { item.rsplit('/').next().unwrap_or(item).to_string() };

                let mut items_to_restore = Vec::new();
                let wanted = if broker.all {
                    None
                } else if let Some(n) = broker.name.as_deref() {
                    Some(n.to_string())
                } else {
                    eprintln!("broker: restore requires either --name or --all");
                    return (2, vec![]);
                };

                for (item, blob) in captured {
                    let name = bare(&item);
                    if let Some(wanted) = &wanted
                        && &name != wanted
                    {
                        continue;
                    }
                    // Refused, not lossily replaced. `unwrap_or_default` here
                    // turned an unreadable capture into the empty string, so a
                    // restore would overwrite a live secret with "" and report
                    // success -- a silent value loss dressed as a recovery.
                    match String::from_utf8(blob) {
                        Ok(value) => items_to_restore.push((name, value)),
                        Err(_) => {
                            eprintln!(
                                "broker: captured value for {item} at sequence {seq} is not \
                                 valid UTF-8; refusing to restore it"
                            );
                            return (2, vec![name]);
                        }
                    }
                }

                if let Some(wanted) = &wanted
                    && items_to_restore.is_empty()
                {
                    eprintln!("broker: sequence {seq} does not contain a value for {wanted}");
                    return (1, vec![wanted.clone()]);
                }
                if items_to_restore.is_empty() {
                    eprintln!("broker: nothing to restore");
                    return (1, vec![]);
                }

                if op == "source-restore" {
                    for (n, _) in &items_to_restore {
                        if let Ok(secretspec::NamedResolution::Resolved(secret)) =
                            secrets.resolve_named(n)
                            && secret.value.is_some()
                        {
                            eprintln!(
                                "broker: {n} still holds a value; cannot restore without --force"
                            );
                            return (
                                1,
                                items_to_restore.into_iter().map(|(name, _)| name).collect(),
                            );
                        }
                    }
                }

                let mut restored_names = Vec::new();
                for (n, val) in items_to_restore {
                    if let Err(e) = secrets.set_text(&n, &val) {
                        eprintln!("broker: cannot restore {n}: {e}");
                        return (1, restored_names);
                    }
                    restored_names.push(n);
                }

                (0, restored_names)
            }
        }
        // `no_prompt: true`. With prompting enabled this reports missing
        // secrets by dropping into the engine's interactive value-entry flow --
        // inside a root process that has no usable terminal, reading from
        // whatever stdin the caller happened to pass, and writing the answers
        // into the vault. That turns an operation named `check` into a write,
        // and with stdout redirected the prompt is invisible and it simply
        // hangs. The retired wrapper passed `--no-prompt` for this reason.
        "source-check" => match secrets.check(true) {
            Ok(_) => (0, vec![]),
            Err(e) => {
                eprintln!("broker: {e}");
                (1, vec![])
            }
        },
        "source-export" => {
            use std::io;
            match secrets.export(secretspec::ExportFormat::Json, &mut io::stdout().lock()) {
                Ok(()) => (0, vec![]),
                Err(e) => {
                    eprintln!("broker: {e}");
                    (1, vec![])
                }
            }
        }
        "source-template-check" => {
            // Retirement is a statement the installer makes, not a condition
            // inferred from a failed read. `None` means no tracked declaration
            // source is configured, which is a reportable steady state, not a
            // failure — a check that can never pass teaches operators to ignore
            // `doctor`, which is the convention every agent here is told to
            // treat as a stop.
            //
            // A *configured* path that is missing or symlinked stays rc 2
            // below: that is equally consistent with a broken install, which is
            // exactly what this check exists to catch.
            let Some(declarations) = &cfg.declarations else {
                println!("no tracked declaration source configured");
                return (0, vec![]);
            };
            if !declarations.is_file() || declarations.is_symlink() {
                eprintln!("broker: declaration template missing or symlinked");
                return (2, vec![]);
            }
            let manifest_bytes = std::fs::read(&manifest).unwrap_or_default();
            let template_bytes = std::fs::read(declarations).unwrap_or_default();
            if manifest_bytes == template_bytes {
                println!("runtime manifest matches tracked declaration example");
                (0, vec![])
            } else {
                eprintln!("broker: manifest differs from declaration template");
                (1, vec![])
            }
        }
        // Manifest only: `codegen` never resolves a provider value. The
        // profile is the one in the root-owned config, not a caller flag —
        // an arbitrary profile would enumerate shapes the boundary is not
        // configured for.
        // Loaded from the protected manifest path rather than taken off
        // `secrets`: the schema needs the declarations only, and `Spec` is the
        // supported way to obtain them. `manifest` is the same root-owned file
        // `Secrets` was loaded from, so the two cannot describe different
        // declarations.
        "source-schema" => match secretspec::Spec::try_from(manifest.as_path())
            .map_err(|e| e.to_string())
            .and_then(|spec| emit_schema(&spec, &cfg.profile))
        {
            Ok(schema) => {
                print!("{schema}");
                (0, vec![])
            }
            Err(e) => {
                eprintln!("broker: {e}");
                (1, vec![])
            }
        },
        _ => (2, vec![]),
    }
}

/// JSON Schema of a manifest for one profile.
///
/// Value-free: `Spec::schema_json` reads declarations only. The caller supplies
/// the profile; the broker always passes the one from the root-owned config.
fn emit_schema(spec: &secretspec::Spec, profile: &str) -> Result<String, String> {
    spec.schema_json(Some(profile)).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every `SECRETSPEC_*` name the engine reads, as of the pinned upstream.
    ///
    /// The predicate is what ships, so this list is a *witness* rather than the
    /// implementation: it proves the prefix rule covers the names that exist
    /// today, and a name added upstream tomorrow is covered without an edit
    /// here. The four `*_CLI_PATH` entries are the reason this matters — each
    /// names an executable the engine spawns, and the broker is root.
    const ENGINE_VARS: &[&str] = &[
        "SECRETSPEC_AGENT",
        "SECRETSPEC_BWS_CLI_PATH",
        "SECRETSPEC_FILE",
        "SECRETSPEC_KDBX_PASSWORD",
        "SECRETSPEC_OPCLI_PATH",
        "SECRETSPEC_PASSBOLT_CLI_PATH",
        "SECRETSPEC_PASSBOLT_PASSPHRASE",
        "SECRETSPEC_PASSBOLT_PRIVATE_KEY",
        "SECRETSPEC_PASSBOLT_PRIVATE_KEY_FILE",
        "SECRETSPEC_PASSBOLT_SERVER",
        "SECRETSPEC_PROFILE",
        "SECRETSPEC_PROTONPASS_CLI_PATH",
        "SECRETSPEC_PROVIDER",
        "SECRETSPEC_PROVIDER_CONCURRENCY",
        "SECRETSPEC_REASON",
        "SECRETSPEC_SCOPE",
    ];

    /// The XDG names etcetera consults. `XDG_CONFIG_HOME` is the one that
    /// decides where the engine's user-global config is read from; the rest are
    /// covered by the same prefix so none of them can be the next surprise.
    const XDG_VARS: &[&str] = &[
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_RUNTIME_DIR",
        "XDG_STATE_HOME",
    ];

    // The predicate is tested directly rather than by exercising
    // `purge_ambient_env`: `std::env::set_var` is process-global and the test
    // harness is multi-threaded, so mutating the environment to observe the
    // loop would race every other test in this binary.
    #[test]
    fn ambient_control_predicate_covers_every_engine_and_xdg_variable() {
        for name in ENGINE_VARS.iter().chain(XDG_VARS) {
            assert!(
                is_ambient_control_var(name),
                "{name} must be purged before the engine runs"
            );
        }
    }

    /// Every arm must produce a terminal event. An attempt with no terminal is
    /// indistinguishable in the ledger from a broker killed mid-operation, so
    /// "some code path returns early" is the failure this guards against.
    #[test]
    fn every_outcome_maps_to_exactly_one_terminal_phase() {
        let attempted = vec!["DATABASE_URL".to_string()];
        let done = vec!["API_KEY".to_string()];

        let cases = [
            (Ok((0, false, done.clone())), Outcome::Success, 0, &done),
            (Ok((1, false, done.clone())), Outcome::Failure, 1, &done),
            // Rollback failed: the store's state is unknown, not merely failed.
            (Ok((1, true, done.clone())), Outcome::Unknown, 125, &done),
            (Ok((0, true, done.clone())), Outcome::Unknown, 125, &done),
            // The path that previously returned with no terminal event at all.
            (Err(2), Outcome::Failure, 2, &attempted),
        ];

        for (outcome, want_phase, want_rc, want_names) in cases {
            let (phase, rc, names) = classify_terminal(outcome, &attempted);
            assert_eq!(phase, want_phase);
            assert_eq!(rc, want_rc);
            assert_eq!(&names, want_names);
        }
    }

    #[test]
    fn an_out_of_range_error_code_still_terminates_the_attempt() {
        // A terminal event is required to carry a result code, so the mapping
        // must not be able to produce "no code" for a code it cannot represent.
        let (phase, rc, _) = classify_terminal(Err(i32::MAX), &[]);
        assert_eq!(phase, Outcome::Failure);
        assert_eq!(rc, 2);
    }

    // --- the reason never crosses the boundary as prose ---------------------

    #[test]
    fn the_empty_reason_digest_constant_is_actually_sha256_of_nothing() {
        // Hardcoded so the gate does not depend on computing it at startup;
        // pinned by this test so it cannot drift into being merely decorative.
        assert_eq!(
            format!("{:x}", Sha256::digest(b"")),
            EMPTY_REASON_SHA256,
            "the rejected constant must be the digest it claims to be"
        );
    }

    #[test]
    fn a_blank_reason_produces_no_digest_to_send() {
        for blank in ["", "   ", "\t\n"] {
            assert!(reason_sha256(blank).is_none(), "{blank:?}");
        }
        assert!(reason_sha256("rotate integration credential").is_some());
    }

    #[test]
    fn the_digest_of_nothing_never_satisfies_the_gate() {
        // The whole point of requiring a reason is defeated if a caller can
        // send the digest of the empty string, which is a fixed public value.
        assert!(!is_valid_reason_digest(EMPTY_REASON_SHA256));
        assert!(is_valid_reason_digest(&format!(
            "{:x}",
            Sha256::digest(b"rotate integration credential")
        )));
    }

    #[test]
    fn malformed_reason_digests_are_refused() {
        let real = format!("{:x}", Sha256::digest(b"rotate"));
        for bad in [
            "",
            "not-a-digest",
            &real[..63],             // too short
            &format!("{real}0"),     // too long
            &real.to_uppercase(),    // hex must be lowercase
            &real.replace('a', "g"), // not hex
            &format!(" {real}"),     // the broker trims before this check
        ] {
            assert!(!is_valid_reason_digest(bad), "{bad:?} must be refused");
        }
        assert!(is_valid_reason_digest(&real));
    }

    #[test]
    fn ambient_control_predicate_leaves_unrelated_variables_alone() {
        // `SUDO_USER` in particular: the broker reads it to attribute the audit
        // event, so purging it would blind the ledger.
        for name in ["SUDO_USER", "HOME", "PATH", "TERM", "SECRETSPE", "XDG"] {
            assert!(
                !is_ambient_control_var(name),
                "{name} must survive the purge"
            );
        }
    }

    #[test]
    fn schema_is_pinned_to_the_configured_profile_and_contains_no_values() {
        // The public client does not take `--profile`. This helper is what the
        // broker calls with the root-owned config's profile, so a production-
        // only name must not appear when that profile is `default`.
        let spec = secretspec::Spec::from_toml(
            r#"
[project]
name = "schema-test"
revision = "1.0"

[profiles.default]
DATABASE_URL = { description = "app database", required = true }
API_KEY = { description = "optional api key", required = false }

[profiles.production]
DATABASE_URL = { description = "prod database", required = true }
PROD_ONLY = { description = "production-only token", required = true }
"#,
        )
        .unwrap();

        let schema: serde_json::Value =
            serde_json::from_str(&emit_schema(&spec, "default").unwrap()).unwrap();
        assert_eq!(schema["title"], "DefaultSecrets");
        assert_eq!(schema["properties"]["DATABASE_URL"]["type"], "string");
        assert_eq!(
            schema["properties"]["API_KEY"]["type"],
            serde_json::json!(["string", "null"])
        );
        assert!(schema["properties"].get("PROD_ONLY").is_none());
        assert!(
            schema["properties"]["DATABASE_URL"]
                .get("default")
                .is_none()
        );
        assert!(schema["properties"]["DATABASE_URL"].get("const").is_none());

        let production: serde_json::Value =
            serde_json::from_str(&emit_schema(&spec, "production").unwrap()).unwrap();
        assert!(production["properties"]["PROD_ONLY"].is_object());
        // Effective profile fields include inheritance from `default`.
        assert!(production["properties"]["API_KEY"].is_object());

        assert!(emit_schema(&spec, "staging").is_err());
    }

    /// A `Mutation` over a temporary vault, with its rollback copies already
    /// written — the state `commit` runs against.
    ///
    /// `Mutation::begin` needs root and a real boundary, so the struct is built
    /// directly here. The thing under test is `commit`'s contract, not
    /// `begin`'s copying, and that contract is otherwise reachable only on the
    /// one path no test can enter.
    fn staged_mutation(
        vault: &std::path::Path,
        manifest: &[u8],
        dotenv: &[u8],
    ) -> (Mutation, uuid::Uuid) {
        use std::os::unix::fs::MetadataExt;
        let transaction = uuid::Uuid::new_v4();
        let mutation = Mutation {
            vault: vault.to_path_buf(),
            manifest: vault.join("secretspec.toml"),
            dotenv: vault.join("secrets.db"),
            transaction,
            operation: "source-set".into(),
            service_uid: std::fs::metadata(vault).unwrap().uid(),
            // This helper writes both rollback copies below, which is the state
            // `begin` leaves behind when both sources already existed.
            existed: [true; 2],
        };
        std::fs::write(mutation.rollback_path("toml"), manifest).unwrap();
        std::fs::write(mutation.rollback_path("db"), dotenv).unwrap();
        (mutation, transaction)
    }

    fn temp_vault() -> tempfile::TempDir {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    #[test]
    fn a_commit_archives_the_pre_mutation_state_and_then_clears_the_copies() {
        // The whole feature in one assertion: the bytes that used to be deleted
        // on success now land in history instead.
        let vault = temp_vault();
        let (mutation, transaction) =
            staged_mutation(vault.path(), b"[project]\nname = \"f\"\n", b"A=1\n");

        mutation.commit();

        let result = crate::history::verify(vault.path(), None).unwrap();
        assert_eq!(result.entries, 1, "the pre-mutation state must be archived");
        assert!(
            !mutation.rollback_path("toml").exists() && !mutation.rollback_path("db").exists(),
            "archived copies must not be left behind as well"
        );
        // The history entry joins to the ledger on the transaction uuid, which
        // is the only thing tying the two stores together.
        let entries = crate::history::list(vault.path(), None).unwrap();
        assert_eq!(entries[0].transaction, transaction);
    }

    #[test]
    fn a_failed_archive_keeps_the_rollback_copies_rather_than_losing_them() {
        // The mutation has already committed by this point and cannot be
        // undone, so `commit` must not report failure. What it must not do
        // either is delete the only surviving copy of the prior state: the
        // degraded outcome is the pre-history behaviour, not a loss.
        let vault = temp_vault();
        // A dotenv with a comment does not round-trip through the renderer, so
        // `history::capture` refuses it.
        let mut mutation = staged_mutation(vault.path(), b"[project]\nname = \"f\"\n", b"A=1\n").0;
        mutation.operation = "invalid_op!".to_string();

        mutation.commit();

        assert_eq!(
            crate::history::verify(vault.path(), None).unwrap().entries,
            0,
            "a refused capture must store nothing"
        );
        assert!(
            mutation.rollback_path("toml").exists() && mutation.rollback_path("db").exists(),
            "the prior state must survive an archive failure"
        );
    }

    #[test]
    fn a_restored_mutation_is_not_archived() {
        // A rolled-back mutation never took effect, so there is no prior state
        // to recover to other than the current one. Archiving it would fill
        // history with entries identical to the state beside them.
        let vault = temp_vault();
        std::fs::write(vault.path().join("secretspec.toml"), b"live").unwrap();
        std::fs::write(vault.path().join("secrets.db"), b"live").unwrap();
        let (mutation, _) = staged_mutation(vault.path(), b"[project]\nname = \"f\"\n", b"A=1\n");

        assert!(mutation.restore());

        assert_eq!(
            crate::history::verify(vault.path(), None).unwrap().entries,
            0
        );
    }

    #[test]
    fn undeclare_mutates_because_it_rewrites_the_runtime_manifest() {
        // Regression. `source-undeclare` performs `fs::write` on the runtime
        // manifest in `execute`, but was left out of the mutation set, so a
        // write that failed part way left the manifest corrupt with no rollback
        // copy — while `set`, `add` and `delete` all had one.
        assert!(mutates_vault("source-undeclare"));
    }

    #[test]
    fn the_mutating_source_ops_are_exactly_these() {
        // Pinned deliberately. A new verb in `SOURCE_OPS` breaks this test, and
        // the only way to fix it is to state whether the verb writes — which is
        // the decision that was missed for `undeclare`.
        let mutating: Vec<&str> = SOURCE_OPS
            .iter()
            .copied()
            .filter(|op| mutates_vault(op))
            .collect();
        assert_eq!(
            mutating,
            [
                "source-set",
                "source-add",
                "source-undeclare",
                "source-delete",
                "source-restore",
                "source-restore-force",
                "source-destroy",
            ]
        );
    }

    #[test]
    fn read_only_ops_take_no_rollback_copy() {
        // The cost is not merely wasted work: `Mutation::begin` writes two files
        // into the vault and refuses on collision, so classifying a read as a
        // mutation would make concurrent reads fail each other.
        for op in [
            "source-get",
            "source-check",
            "source-export",
            "source-template-check",
            "source-schema",
        ] {
            assert!(!mutates_vault(op), "{op} must not take a rollback copy");
        }
    }

    #[test]
    fn an_operation_outside_the_list_does_not_reach_the_source_funnel() {
        // `run` dispatches on `SOURCE_OPS.contains`, so this is what keeps an
        // unknown verb on the "unknown operation" arm instead of running with a
        // loaded `Secrets` and a root euid.
        assert!(!SOURCE_OPS.contains(&"source-nonsense"));
        assert!(!SOURCE_OPS.contains(&"audit-verify"));
    }

    /// A manifest with the shapes an edit is most likely to destroy: comments,
    /// a blank line, alignment, and a declaration written as an inline table.
    const MANIFEST: &str = r#"[project]
name = "fixture"
revision = "1.0"

# The comment below the header, which no semantic model represents.
[profiles.default]
API_KEY = { description = "An existing key", required = true }

# A trailing comment, deliberately last.
"#;

    #[test]
    fn adding_then_undeclaring_restores_the_document_byte_for_byte() {
        // The property `Mutation::restore` depends on: undo compares bytes, so
        // a round trip that merely preserves *meaning* would still fail it.
        let added = manifest_with_declaration(
            MANIFEST,
            "default",
            "NEW_TOKEN",
            secretspec::Secret::required("A new token"),
        )
        .expect("add");
        assert_ne!(added, MANIFEST, "the add must actually change the document");

        let restored =
            manifest_without_declaration(&added, "default", "NEW_TOKEN").expect("undeclare");
        assert_eq!(restored, MANIFEST);
    }

    #[test]
    fn an_edit_preserves_comments_and_the_declarations_it_did_not_touch() {
        let added = manifest_with_declaration(
            MANIFEST,
            "default",
            "NEW_TOKEN",
            secretspec::Secret::required("A new token"),
        )
        .expect("add");

        assert!(added.contains("# The comment below the header"));
        assert!(added.contains("# A trailing comment, deliberately last."));
        assert!(
            added.contains(r#"API_KEY = { description = "An existing key", required = true }"#)
        );
    }

    #[test]
    fn the_three_secret_constructors_are_the_tri_state_the_cli_flags_select() {
        // `--required` and `--optional` pin requiredness; neither leaves it to
        // the profile default. Writing `required` when the caller asked for
        // neither would silently override that default.
        let required =
            manifest_with_declaration(MANIFEST, "default", "T", secretspec::Secret::required("d"))
                .expect("required");
        assert!(required.contains("required = true"));

        let optional =
            manifest_with_declaration(MANIFEST, "default", "T", secretspec::Secret::optional("d"))
                .expect("optional");
        assert!(optional.contains("required = false"));

        let inherited =
            manifest_with_declaration(MANIFEST, "default", "T", secretspec::Secret::new("d"))
                .expect("inherited");
        let line = inherited
            .lines()
            .find(|l| l.starts_with("T ="))
            .expect("the new declaration");
        assert!(
            !line.contains("required"),
            "requiredness must be left to the profile default: {line}"
        );
    }

    #[test]
    fn a_duplicate_declaration_is_refused_rather_than_written_twice() {
        let err = manifest_with_declaration(
            MANIFEST,
            "default",
            "API_KEY",
            secretspec::Secret::required("A second one"),
        )
        .expect_err("API_KEY is already declared");
        assert!(err.contains("API_KEY"), "{err}");
    }

    #[test]
    fn undeclaring_a_name_the_profile_does_not_declare_is_refused() {
        // A silent no-op here would report success for an undo that never
        // happened, which is worse than a refusal on a path that writes to the
        // operator's vault.
        let err = manifest_without_declaration(MANIFEST, "default", "NEVER_DECLARED")
            .expect_err("not declared");
        assert!(err.contains("NEVER_DECLARED"), "{err}");
    }

    /// The retirement decision: an absent tracked source is a positive fact,
    /// so guard 1 has nothing to protect and `undeclare` proceeds. Refusing
    /// here is what left the runtime manifest un-cleanable on a host whose
    /// tracked declarations file was deliberately deleted.
    #[test]
    fn no_tracked_source_protects_nothing_so_undeclare_proceeds() {
        assert_eq!(
            tracked_source_protects(None, "default", "ANY_NAME"),
            Ok(false)
        );
    }

    /// The other half of the same decision, and the reason `None` may relax the
    /// guard at all: a *configured* template that will not parse is still not
    /// evidence the name is absent from it.
    #[test]
    fn an_unparseable_tracked_source_still_fails_closed() {
        let err = tracked_source_protects(Some("this is not toml at all"), "default", "ANY_NAME")
            .expect_err("unparseable template must not answer 'not declared'");
        assert!(!err.is_empty());
    }

    #[test]
    fn a_configured_tracked_source_still_protects_the_names_it_declares() {
        let template = r#"[project]
name = "fixture"
revision = "1.0"

[profiles.default]
TRACKED_NAME = { description = "git content", required = true }
"#;
        assert_eq!(
            tracked_source_protects(Some(template), "default", "TRACKED_NAME"),
            Ok(true)
        );
        assert_eq!(
            tracked_source_protects(Some(template), "default", "RUNTIME_ONLY_NAME"),
            Ok(false)
        );
    }

    #[test]
    fn a_manifest_that_would_not_load_is_refused_before_anything_is_written() {
        let err = manifest_with_declaration(
            "this is not toml at all",
            "default",
            "T",
            secretspec::Secret::required("d"),
        )
        .expect_err("unparseable manifest");
        assert!(!err.is_empty());
    }

    #[test]
    fn an_inheriting_manifest_is_refused_rather_than_resolved_from_disk() {
        // The reason `Spec::from_toml` is the constructor here: this runs as
        // root, and resolving `extends` would read whatever the parent path
        // points at.
        let inheriting = r#"[project]
name = "fixture"
revision = "1.0"
extends = ["../parent"]

[profiles.default]
API_KEY = { description = "k", required = true }
"#;
        let err = manifest_with_declaration(
            inheriting,
            "default",
            "T",
            secretspec::Secret::required("d"),
        )
        .expect_err("extends must not be resolved here");
        assert!(err.contains("extends"), "{err}");
    }

    // -----------------------------------------------------------------------
    // source-restore / source-restore-force / source-destroy
    // -----------------------------------------------------------------------
    //
    // These verbs shipped with no coverage at all, and every one of the four
    // defects found in them was found by hand against the live vault while the
    // rest of this suite passed green. The fixture below therefore drives the
    // real `execute` against a real `sqlite://…?history=true` vault rather than
    // hand-seeding `captured_values`: three of those defects were mismatches
    // between the bare name the caller passes and the full
    // `{project}/{profile}/{key}` address the provider actually stores, which a
    // hand-seeded table would have reproduced wrongly and so still missed.

    /// `execute` sets `XDG_STATE_HOME` process-wide, so its tests cannot run
    /// concurrently with each other.
    static EXECUTE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    const FIXTURE_MANIFEST: &str = r#"[project]
name = "fixture"
revision = "1.0"

[profiles.default]
ALPHA = { description = "first", required = true }
BETA = { description = "second", required = false }
"#;

    /// A temp vault with the fixture manifest in place, plus the `Config` that
    /// points `execute` at it.
    ///
    /// Built as a struct literal rather than through `Config::parse`: the
    /// parser requires the vault to be a direct child of `/var/db`, which no
    /// test may create. That validation is `config.rs`'s to cover, and these
    /// tests are about what `execute` does once it holds a config.
    fn execute_fixture() -> (tempfile::TempDir, Config) {
        let vault = temp_vault();
        std::fs::write(vault.path().join("secretspec.toml"), FIXTURE_MANIFEST).unwrap();
        let cfg = Config {
            engine: "/usr/local/libexec/secretspec".into(),
            audit_helper: "/usr/local/libexec/sudo-secretspec-audit".into(),
            vault: vault.path().to_path_buf(),
            vault_realpath: vault.path().to_path_buf(),
            declarations: None,
            service_user: "_sudosecretspec".into(),
            service_group: "_sudosecretspec".into(),
            profile: "default".into(),
            version: None,
            adopted_vault: false,
        };
        (vault, cfg)
    }

    /// A stand-in for the digest the client computes. Not `EMPTY_REASON_SHA256`:
    /// that constant is specifically the one the gate refuses, so using it here
    /// would read as testing the refusal rather than the verb.
    fn fixture_reason() -> String {
        reason_sha256("restore fixture").unwrap()
    }

    /// The engine handle `execute` builds, reproduced so a fixture can seed the
    /// vault through the same provider — including its history capture.
    fn fixture_secrets(cfg: &Config) -> secretspec::Secrets {
        let mut secrets =
            secretspec::Secrets::load_from(&cfg.vault.join("secretspec.toml")).unwrap();
        secrets.set_provider(format!(
            "sqlite://{}?history=true",
            cfg.vault.join("secrets.db").display()
        ));
        secrets.set_profile(cfg.profile.clone());
        secrets.with_reason(fixture_reason())
    }

    fn broker_op(operation: &str) -> Broker {
        Broker {
            operation: operation.into(),
            client: "test".into(),
            reason_sha256: String::new(),
            name: None,
            command_basename: None,
            description: None,
            optional: false,
            required: false,
            to: None,
            force: false,
            all: false,
        }
    }

    fn live_value(cfg: &Config, name: &str) -> Option<String> {
        match fixture_secrets(cfg).resolve_named(name) {
            Ok(secretspec::NamedResolution::Resolved(secret)) => secret.value,
            _ => None,
        }
    }

    #[test]
    fn restore_matches_a_bare_name_against_the_full_provider_address() {
        // The defect this pins: `captured_values.item` holds
        // `{project}/{profile}/{key}`, and `--name` is a bare key. Comparing the
        // two directly matched nothing, so restore could never find a value —
        // and reported "sequence N does not contain a value" for a sequence that
        // did.
        let _guard = EXECUTE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (_vault, cfg) = execute_fixture();
        let secrets = fixture_secrets(&cfg);

        secrets.set_text("ALPHA", "original").unwrap(); // sequence 1
        secrets.delete("ALPHA").unwrap(); // sequence 2, ALPHA already gone
        assert_eq!(
            live_value(&cfg, "ALPHA"),
            None,
            "delete must clear the value"
        );

        // Sequence 1 is the last entry that still held ALPHA: `delete` captures
        // *after* removing the row, so the deleted value lives only in the
        // preceding entry.
        let mut broker = broker_op("source-restore");
        broker.name = Some("ALPHA".into());
        broker.to = Some("1".into());

        let (code, names) = execute(&broker, &cfg, &fixture_reason());

        assert_eq!(code, 0, "restore must find ALPHA at sequence 1");
        assert_eq!(names, vec!["ALPHA".to_string()]);
        assert_eq!(live_value(&cfg, "ALPHA").as_deref(), Some("original"));
    }

    #[test]
    fn restore_refuses_to_overwrite_a_name_that_still_holds_a_value() {
        // Forward-safe by default: without `--force`, restoring over a live
        // secret is refused rather than silently rewinding it.
        let _guard = EXECUTE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (_vault, cfg) = execute_fixture();
        let secrets = fixture_secrets(&cfg);

        secrets.set_text("ALPHA", "original").unwrap(); // sequence 1
        secrets.set_text("ALPHA", "current").unwrap(); // sequence 2

        let mut broker = broker_op("source-restore");
        broker.name = Some("ALPHA".into());
        broker.to = Some("1".into());

        let (code, names) = execute(&broker, &cfg, &fixture_reason());

        assert_eq!(code, 1, "a live value must block an unforced restore");
        assert_eq!(names, vec!["ALPHA".to_string()]);
        assert_eq!(
            live_value(&cfg, "ALPHA").as_deref(),
            Some("current"),
            "the refused restore must not have written anything"
        );

        // …and the force verb is what gets past it.
        let mut forced = broker_op("source-restore-force");
        forced.name = Some("ALPHA".into());
        forced.to = Some("1".into());

        let (code, _) = execute(&forced, &cfg, &fixture_reason());

        assert_eq!(code, 0);
        assert_eq!(live_value(&cfg, "ALPHA").as_deref(), Some("original"));
    }

    #[test]
    fn restore_all_feeds_bare_names_back_to_the_engine_not_addresses() {
        // The mirror of the first defect: `--all` used to hand the full
        // `{project}/{profile}/{key}` address straight to `set`, which speaks
        // bare names, so every restore failed on an undeclared name.
        let _guard = EXECUTE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (_vault, cfg) = execute_fixture();
        let secrets = fixture_secrets(&cfg);

        secrets.set_text("ALPHA", "a1").unwrap(); // sequence 1
        secrets.set_text("BETA", "b1").unwrap(); // sequence 2: both present
        secrets.delete("ALPHA").unwrap();
        secrets.delete("BETA").unwrap();

        let mut broker = broker_op("source-restore-force");
        broker.all = true;
        broker.to = Some("2".into());

        let (code, mut names) = execute(&broker, &cfg, &fixture_reason());
        names.sort();

        assert_eq!(code, 0);
        assert_eq!(names, vec!["ALPHA".to_string(), "BETA".to_string()]);
        assert_eq!(live_value(&cfg, "ALPHA").as_deref(), Some("a1"));
        assert_eq!(live_value(&cfg, "BETA").as_deref(), Some("b1"));
    }

    #[test]
    fn plain_source_restore_refuses_all_and_force() {
        // M2: the plain verb's NOPASSWD grant is a `--*` glob that also matches
        // `--all`/`--force`, so a direct sudo caller could reach an unattended
        // whole-vault restore. The broker must refuse, so the gate is the
        // sudoers verb and not client routing.
        let _guard = EXECUTE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (_vault, cfg) = execute_fixture();
        fixture_secrets(&cfg).set_text("ALPHA", "a1").unwrap();

        let mut all = broker_op("source-restore");
        all.all = true;
        all.to = Some("1".into());
        assert_eq!(
            execute(&all, &cfg, &fixture_reason()).0,
            2,
            "source-restore --all must refuse on the plain verb"
        );

        let mut force = broker_op("source-restore");
        force.force = true;
        force.name = Some("ALPHA".into());
        force.to = Some("1".into());
        assert_eq!(
            execute(&force, &cfg, &fixture_reason()).0,
            2,
            "source-restore --force must refuse on the plain verb"
        );
    }

    #[test]
    fn restore_requires_a_target_and_a_selector() {
        let _guard = EXECUTE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (_vault, cfg) = execute_fixture();
        fixture_secrets(&cfg).set_text("ALPHA", "a1").unwrap();

        // No `--to` at all.
        let mut broker = broker_op("source-restore");
        broker.name = Some("ALPHA".into());
        assert_eq!(execute(&broker, &cfg, &fixture_reason()).0, 2);

        // A `--to` that is not a sequence integer.
        broker.to = Some("yesterday".into());
        assert_eq!(execute(&broker, &cfg, &fixture_reason()).0, 2);

        // Neither `--name` nor `--all`.
        let mut unselective = broker_op("source-restore");
        unselective.to = Some("1".into());
        assert_eq!(execute(&unselective, &cfg, &fixture_reason()).0, 2);
    }

    #[test]
    fn restoring_a_name_absent_from_that_sequence_reports_not_found() {
        // rc 1, not rc 0: the name is real and the sequence is real, but that
        // sequence never held it. Reporting success here is what let the
        // address-mismatch defect hide.
        let _guard = EXECUTE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (_vault, cfg) = execute_fixture();
        fixture_secrets(&cfg).set_text("ALPHA", "a1").unwrap(); // sequence 1: ALPHA only

        let mut broker = broker_op("source-restore");
        broker.name = Some("BETA".into());
        broker.to = Some("1".into());

        let (code, names) = execute(&broker, &cfg, &fixture_reason());

        assert_eq!(code, 1);
        assert_eq!(names, vec!["BETA".to_string()]);
        assert_eq!(live_value(&cfg, "BETA"), None);
    }

    #[test]
    fn a_non_utf8_capture_is_refused_rather_than_restored_as_an_empty_string() {
        // `unwrap_or_default` here turned an unreadable capture into "", so the
        // restore overwrote a live secret with nothing and reported success — a
        // value loss dressed as a recovery. The blob is written directly because
        // the engine's own `set` only accepts a `String`.
        let _guard = EXECUTE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (_vault, cfg) = execute_fixture();
        let secrets = fixture_secrets(&cfg);
        secrets.set_text("ALPHA", "original").unwrap(); // sequence 1

        let conn = rusqlite::Connection::open(cfg.vault.join("secrets.db")).unwrap();
        conn.execute(
            "UPDATE value_blobs SET value_blob = ?1 WHERE (item, value_sha256) IN \
             (SELECT item, value_sha256 FROM captured_values WHERE sequence = 1)",
            rusqlite::params![&[0xff_u8, 0xfe][..]],
        )
        .unwrap();
        drop(conn);

        let mut broker = broker_op("source-restore-force");
        broker.name = Some("ALPHA".into());
        broker.to = Some("1".into());

        let (code, _) = execute(&broker, &cfg, &fixture_reason());

        assert_eq!(code, 2, "an unreadable capture must not restore");
        assert_eq!(
            live_value(&cfg, "ALPHA").as_deref(),
            Some("original"),
            "the live value must survive a refused restore untouched"
        );
    }

    #[test]
    fn destroy_tombstones_every_captured_copy_of_the_name() {
        // The defect: `UPDATE … WHERE item = <bare name>` matched zero rows, so
        // `destroy` reported success while every captured copy stayed readable —
        // the single outcome this verb exists to prevent. Asserting "the value
        // is gone from history" is therefore the whole test; a rc-0 assertion
        // alone would have passed throughout.
        let _guard = EXECUTE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (_vault, cfg) = execute_fixture();
        let secrets = fixture_secrets(&cfg);
        secrets.set_text("ALPHA", "leaked").unwrap(); // sequence 1
        secrets.set_text("BETA", "keep-me").unwrap(); // sequence 2: both captured

        let mut broker = broker_op("source-destroy");
        broker.name = Some("ALPHA".into());

        let (code, names) = execute(&broker, &cfg, &fixture_reason());

        assert_eq!(code, 0);
        assert_eq!(names, vec!["ALPHA".to_string()]);
        assert_eq!(live_value(&cfg, "ALPHA"), None, "destroy also deletes");

        let conn = rusqlite::Connection::open(cfg.vault.join("secrets.db")).unwrap();
        let readable: i64 = conn
            .query_row(
                "SELECT count(*) FROM captured_values cv \
                 JOIN value_blobs b \
                   ON b.item = cv.item AND b.value_sha256 = cv.value_sha256 \
                 WHERE cv.item LIKE '%/ALPHA'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(readable, 0, "no captured copy of ALPHA may remain readable");

        // Tombstoning is per-name, and the entry still proves what was
        // destroyed: the digest and `destroyed_by` survive the nulled blob.
        let (with_digest, destroyed_by): (i64, Option<i64>) = conn
            .query_row(
                "SELECT count(*), max(destroyed_by) FROM captured_values \
                 WHERE item LIKE '%/ALPHA' AND value_sha256 IS NOT NULL",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert!(
            with_digest > 0,
            "the proof of what was destroyed must remain"
        );
        assert!(destroyed_by.is_some(), "destroyed_by must record the entry");

        let beta_readable: i64 = conn
            .query_row(
                "SELECT count(*) FROM captured_values cv \
                 JOIN value_blobs b \
                   ON b.item = cv.item AND b.value_sha256 = cv.value_sha256 \
                 WHERE cv.item LIKE '%/BETA'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(beta_readable > 0, "destroy must not touch other names");
    }

    #[test]
    fn a_destroyed_snapshot_stays_unrestorable_once_the_same_value_is_set_again() {
        // The one case where "has readable bytes" and "was not destroyed"
        // disagree. Re-setting a destroyed name to the value it used to hold
        // writes back a byte-identical blob under the same `(item,
        // value_sha256)`, so a restore that decided what is recoverable by
        // matching on the digest would hand back a tombstoned snapshot --
        // undestroying it.
        //
        // Restore joins on `live_blob_id` instead, which is NULL for every
        // tombstone, so the destroyed row cannot join at all. The recreated
        // blob carries a *new* `blob_id`, and the tombstone's own `blob_id`
        // still names the one that was deleted. This used to need an explicit
        // `destroyed_by IS NULL` filter, and mutation testing showed that
        // filter could be deleted with the whole suite green.
        let _guard = EXECUTE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (_vault, cfg) = execute_fixture();
        let secrets = fixture_secrets(&cfg);

        secrets.set_text("ALPHA", "recurring").unwrap(); // sequence 1

        let mut destroy = broker_op("source-destroy");
        destroy.name = Some("ALPHA".into());
        let (code, _) = execute(&destroy, &cfg, &fixture_reason()); // sequence 2
        assert_eq!(code, 0, "destroy must succeed");

        // The same value comes back under the same name, so the blob destroy
        // deleted is written again -- byte-identical, same digest, same item.
        secrets.set_text("ALPHA", "recurring").unwrap(); // sequence 3
        secrets.delete("ALPHA").unwrap(); // sequence 4; clears the live value

        let conn = rusqlite::Connection::open(cfg.vault.join("secrets.db")).unwrap();

        // Anti-vacuity: unless the tombstoned row really does resolve to live
        // bytes right now, this test would pass no matter how restore filters.
        let joinable: i64 = conn
            .query_row(
                "SELECT count(*) FROM captured_values cv \
                 JOIN value_blobs b \
                   ON b.item = cv.item AND b.value_sha256 = cv.value_sha256 \
                 WHERE cv.sequence = 1 AND cv.item LIKE '%/ALPHA'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            joinable, 1,
            "precondition: the destroyed snapshot must currently join to a \
             recreated blob, or this test proves nothing"
        );
        let destroyed_by: Option<i64> = conn
            .query_row(
                "SELECT destroyed_by FROM captured_values \
                 WHERE sequence = 1 AND item LIKE '%/ALPHA'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            destroyed_by.is_some(),
            "precondition: sequence 1 must still be tombstoned"
        );

        let mut restore = broker_op("source-restore");
        restore.name = Some("ALPHA".into());
        restore.to = Some("1".into());

        let (code, names) = execute(&restore, &cfg, &fixture_reason());

        assert_eq!(code, 1, "a destroyed snapshot must never restore");
        assert_eq!(names, vec!["ALPHA".to_string()]);
        assert_eq!(
            live_value(&cfg, "ALPHA"),
            None,
            "the destroyed value must not be written back"
        );
    }

    #[test]
    fn destroy_requires_a_name_and_refuses_one_with_no_history() {
        let _guard = EXECUTE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (_vault, cfg) = execute_fixture();
        fixture_secrets(&cfg).set_text("ALPHA", "a1").unwrap();

        // `--all` is not a destroy selector; destroy is one name at a time.
        assert_eq!(
            execute(&broker_op("source-destroy"), &cfg, &fixture_reason()).0,
            2,
            "destroy without --name must not proceed"
        );

        // BETA is declared but was never set, so `delete` finds nothing and the
        // verb stops before it can claim to have tombstoned anything.
        let mut broker = broker_op("source-destroy");
        broker.name = Some("BETA".into());
        assert_ne!(
            execute(&broker, &cfg, &fixture_reason()).0,
            0,
            "a name with no captured history must not report success"
        );
    }

    #[test]
    fn executes_own_provider_uri_retains_history_so_a_mutation_is_recoverable() {
        // `?history=true` on the URI `execute` builds is what makes the restore
        // verbs possible at all, and it is invisible from their side: seeding a
        // fixture through a history-enabled handle leaves enough history for
        // `destroy` and `restore` to pass even when `execute` itself retains
        // nothing. What that combination actually produces is a `delete` that
        // discards the value with no capture behind it — irrecoverable loss
        // rather than a missing feature — so the retention is asserted on the
        // entry *`execute` itself* writes.
        let _guard = EXECUTE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (_vault, cfg) = execute_fixture();
        fixture_secrets(&cfg).set_text("ALPHA", "a1").unwrap(); // sequence 1

        let count_entries = || -> i64 {
            rusqlite::Connection::open(cfg.vault.join("secrets.db"))
                .unwrap()
                .query_row("SELECT count(*) FROM entries", [], |row| row.get(0))
                .unwrap()
        };
        assert_eq!(count_entries(), 1);

        let mut broker = broker_op("source-delete");
        broker.name = Some("ALPHA".into());
        assert_eq!(execute(&broker, &cfg, &fixture_reason()).0, 0);

        assert_eq!(
            count_entries(),
            2,
            "a mutation made through `execute` must leave a history entry behind it"
        );

        // And the value really is recoverable from the entry that preceded it,
        // which is the property the retention exists for.
        let mut restore = broker_op("source-restore");
        restore.name = Some("ALPHA".into());
        restore.to = Some("1".into());
        assert_eq!(execute(&restore, &cfg, &fixture_reason()).0, 0);
        assert_eq!(live_value(&cfg, "ALPHA").as_deref(), Some("a1"));
    }

    #[test]
    fn the_restore_verbs_refuse_a_vault_with_no_history_database() {
        // rc 2 rather than a panic or a silent success: an absent `secrets.db`
        // means the vault was never migrated, which is a broken install, not an
        // empty history.
        let _guard = EXECUTE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (_vault, cfg) = execute_fixture();

        let mut broker = broker_op("source-restore");
        broker.name = Some("ALPHA".into());
        broker.to = Some("1".into());

        assert_ne!(execute(&broker, &cfg, &fixture_reason()).0, 0);
        // And it must not have *created* the store on its way out. `Connection::open`
        // defaults to SQLITE_OPEN_CREATE, so refusing while leaving an empty,
        // schema-less secrets.db behind turned "never migrated" into "migrated to
        // nothing" — a worse state than the one it refused.
        assert!(
            !cfg.vault.join("secrets.db").exists(),
            "a refusing history verb must not bring the value store into being"
        );
    }

    #[test]
    fn destroying_an_already_deleted_name_attributes_it_to_a_new_entry() {
        // The provider captures a history entry only when it actually removed a
        // row, so a name already source-deleted produces none. Taking
        // MAX(sequence) anyway stamped whatever unrelated entry sat at the tip as
        // the destroyer: the value is gone either way, but the ledger names the
        // wrong event, and this ledger's whole purpose is to be believable.
        //
        // This used to refuse, which kept the ledger honest but left captured
        // copies of an already-deleted name undestroyable. It now appends a real
        // entry for the destroy — so the tombstone points at the event that
        // actually caused it, which is what the refusal was protecting.
        let _guard = EXECUTE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (_vault, cfg) = execute_fixture();

        let secrets = fixture_secrets(&cfg);
        secrets.set_text("ALPHA", "a1").unwrap();
        assert!(secrets.delete("ALPHA").unwrap(), "fixture must remove it");

        let tip_before: i64 = {
            let conn = rusqlite::Connection::open(cfg.vault.join("secrets.db")).unwrap();
            conn.query_row("SELECT MAX(sequence) FROM entries", [], |row| row.get(0))
                .unwrap()
        };

        let mut broker = broker_op("source-destroy");
        broker.name = Some("ALPHA".into());
        assert_eq!(
            execute(&broker, &cfg, &fixture_reason()).0,
            0,
            "destroying captured copies of an already-deleted name must succeed"
        );

        let conn = rusqlite::Connection::open(cfg.vault.join("secrets.db")).unwrap();
        let tip_after: i64 = conn
            .query_row("SELECT MAX(sequence) FROM entries", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            tip_after,
            tip_before + 1,
            "the destroy must append its own entry rather than borrow one"
        );

        // The original point of this test, preserved: every tombstone names the
        // entry that destroyed it, never an unrelated one that happened to sit
        // at the tip.
        let misattributed: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM captured_values \
                 WHERE destroyed_by IS NOT NULL AND destroyed_by != ?1",
                rusqlite::params![tip_after],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            misattributed, 0,
            "no tombstone may name an entry other than the destroy that caused it"
        );

        let tombstoned: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM captured_values WHERE destroyed_by IS NOT NULL",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(tombstoned > 0, "the captured copies must actually be gone");

        let readable: i64 = conn
            .query_row(
                "SELECT count(*) FROM captured_values cv \
                 JOIN value_blobs b \
                   ON b.item = cv.item AND b.value_sha256 = cv.value_sha256 \
                 WHERE cv.item LIKE '%/ALPHA'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(readable, 0, "and their bytes must be unreachable");
    }

    #[test]
    fn a_begin_that_fails_part_way_leaves_no_orphan_rollback_copy() {
        // `begin` returns Err before any Mutation exists, so there is no
        // commit()/restore() left to clean up after it, and drift reports a
        // leftover only as an advisory PENDING_ROLLBACK — nothing on the host
        // would ever remove it.
        use std::os::unix::fs::MetadataExt;
        let (vault, cfg) = execute_fixture();
        std::fs::write(vault.path().join("secrets.db"), b"db").unwrap();
        let meta = std::fs::metadata(vault.path()).unwrap();
        let transaction = uuid::Uuid::new_v4();

        // Collide the *second* source's rollback path, so the first copy has
        // already been made by the time begin fails.
        let collision = vault
            .path()
            .join(format!(".secretspec.db.rollback.{transaction}"));
        std::fs::write(&collision, b"a previous crash left this").unwrap();

        assert!(
            Mutation::begin(&cfg, transaction, "source-set", meta.uid(), meta.gid()).is_err(),
            "a rollback path collision must abort the mutation"
        );

        let orphan = vault
            .path()
            .join(format!(".secretspec.toml.rollback.{transaction}"));
        assert!(
            !orphan.exists(),
            "the manifest copy made before the failure must not be left behind"
        );
        assert!(
            collision.exists(),
            "the pre-existing file that caused the refusal is not ours to delete"
        );
    }

    #[test]
    fn a_first_mutation_rolls_back_cleanly_instead_of_reporting_unknown() {
        // On a fresh install secrets.db does not exist, so begin has nothing to
        // copy. Treating the absent backup as an unrecoverable pre-state exited
        // 125 / Outcome::Unknown when the pre-state -- "no vault DB" -- was
        // cleanly known, and rolling back means removing what the failed
        // mutation created.
        use std::os::unix::fs::MetadataExt;
        let vault = temp_vault();
        let manifest = vault.path().join("secretspec.toml");
        let dotenv = vault.path().join("secrets.db");
        std::fs::write(&manifest, b"[project]\nname = \"f\"\n").unwrap();
        let transaction = uuid::Uuid::new_v4();
        let mutation = Mutation {
            vault: vault.path().to_path_buf(),
            manifest: manifest.clone(),
            dotenv: dotenv.clone(),
            transaction,
            operation: "source-set".into(),
            service_uid: std::fs::metadata(vault.path()).unwrap().uid(),
            // The manifest was there to back up; secrets.db was not.
            existed: [true, false],
        };
        std::fs::write(mutation.rollback_path("toml"), b"[project]\nname = \"f\"\n").unwrap();
        // What the failed mutation created.
        std::fs::write(&dotenv, b"created by the mutation being undone").unwrap();

        assert!(
            mutation.restore(),
            "a known pre-state of 'absent' is a clean rollback, not an unknown outcome"
        );
        assert!(
            !dotenv.exists(),
            "restoring an absent pre-state means removing what the mutation created"
        );
        assert!(
            manifest.exists(),
            "the manifest must be restored, not removed"
        );
    }
}
