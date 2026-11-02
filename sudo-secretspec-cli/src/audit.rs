//! Fail-closed transactional SQLite audit ledger for sudo-secretspec.
//!
//! Every event is hash-chained. An append writes the event row and updates the
//! singleton `head` row inside a single `BEGIN IMMEDIATE` transaction so a
//! crash cannot leave them out of sync. The ledger stores **no** reason text,
//! command arguments, or secret values — only a SHA-256 digest of the reason.
//!
//! ## Protected metadata
//!
//! Before opening the database the module validates:
//! - the protected directory is mode `0700` and owned by the expected UID,
//! - any existing ledger is a regular file with mode `0600` (not a symlink).
//!
//! After opening, the ledger is reassigned to the vault owner, its ownership is
//! re-checked, and its `(dev, ino)` is compared against the pre-open identity so
//! a file swapped in during the open is rejected.
//!
//! That reassignment is a write, which is why [`verify_read_only`] exists
//! alongside [`verify`]: callers that promise not to mutate state get a
//! connection with no power to normalise, create a schema, or take a write
//! lock. The repairing path stays the broker's, so a ledger left root-owned by
//! an earlier install still recovers.
//!
//! If any check fails the call returns an error before creating or touching a
//! database — **fail-closed**.
//!
//! ## Locking
//!
//! The ledger is a SQLite file in rollback-journal (`DELETE`) mode, so there is
//! one writer at a time and the write lock is the scarce thing. An append keeps
//! its hold on it short and independent of the ledger's size:
//!
//! 1. the whole chain is verified first, in short read statements with no
//!    transaction open, so no lock is held while the hashing runs;
//! 2. only then does it `BEGIN IMMEDIATE`, re-check just the rows that landed
//!    since (usually none) and the `head` row, insert, and commit.
//!
//! Verifying inside the write transaction instead made the hold time grow with
//! the ledger, and under memory pressure one descheduled broker kept every other
//! caller out for as long as it stayed descheduled (issue #4). Nothing else is
//! held across a broker operation: the connection is opened, used and closed
//! inside [`append_event`], never across the secret read or a provider call.
//!
//! Every connection waits for another process's lock for a bounded time
//! ([`WRITE_BUSY_TIMEOUT`] for the broker, [`READ_BUSY_TIMEOUT`] for the
//! read-only checkers) and then fails with [`AuditError::Busy`]. That is still
//! fail-closed — nothing is appended and the caller is told so — but it is
//! reported as contention to retry rather than as damage. `doctor` separately
//! reports a process that keeps the write lock for seconds
//! ([`write_lock_holder`]).
//!
//! [`verify`] (the `audit-verify` command) is the exception: it takes the write
//! lock for its whole scan and integrity check, so it is meant for a quiet
//! system.
//!
//! ## Residual risk
//!
//! The chain detects *modification*: altering or removing any event other than
//! the last leaves a `previous_hash` that no longer matches, and the whole
//! chain fails to verify.
//!
//! It does not detect truncation, and it does not detect deletion of the whole
//! ledger. Both have the same shape, because `head` lives in the same database
//! as the events it points at: delete the last N events, rewrite the singleton
//! `head` to the new tip, and [`verify`] re-verifies cleanly — it only checks
//! that `head` agrees with the rows that are still present. Deleting everything
//! is the same move taken to its limit, and an empty `events` table with no
//! `head` row is indistinguishable from a fresh install.
//!
//! Nothing in the mediated sudoers policy can reach that state; it requires
//! write access to the vault as root or the service user. But tamper-evidence
//! against a principal who can write the ledger cannot be established from
//! inside the ledger — that is arithmetic, not a defect. An external watcher
//! wanting it must pin the tip hash reported by [`verify`] somewhere outside
//! the vault and compare on each run.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::time::Duration;

use rusqlite::{Connection, OptionalExtension};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// The hash used as the genesis previous-hash (i.e. before any event exists).
pub const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// The fixed ledger filename inside the protected directory.
pub const DB_NAME: &str = "broker-audit.sqlite3";

/// Valid secret-name pattern.
pub const NAME_RE: &str = r"^[A-Z][A-Z0-9_]*$";

/// Valid operation pattern.
pub const OP_RE: &str = r"^[a-z][a-z0-9-]*$";

/// Valid client-family pattern.
pub const CLIENT_RE: &str = r"^(?:hermes|claude|codex|opencode|cursor|agy|fixed-consumer|unknown)$";

/// Valid command-basename pattern.
pub const COMMAND_RE: &str = r"^[A-Za-z0-9_.+-]{1,128}$";

/// How long a broker's ledger connection waits for another process's lock
/// before giving up with [`AuditError::Busy`].
///
/// SQLite's busy handler retries with backoff inside this window, so ordinary
/// contention — several broker calls arriving together, each holding the lock
/// for milliseconds — resolves by waiting instead of by failing the caller.
/// rusqlite already installs a 5 s default; this makes the bound an explicit
/// decision, and long enough to ride out the load spikes where a single call can
/// be descheduled for seconds.
pub const WRITE_BUSY_TIMEOUT: Duration = Duration::from_secs(30);

/// The same bound for read-only connections (`doctor`, `drift`). They are
/// interactive, so they keep the 5 s wait they always had.
pub const READ_BUSY_TIMEOUT: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Audit event phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Attempt,
    Success,
    Failure,
    Unknown,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Attempt => "attempt",
            Outcome::Success => "success",
            Outcome::Failure => "failure",
            Outcome::Unknown => "unknown",
        }
    }

    pub fn from_label(s: &str) -> Option<Self> {
        match s {
            "attempt" => Some(Outcome::Attempt),
            "success" => Some(Outcome::Success),
            "failure" => Some(Outcome::Failure),
            "unknown" => Some(Outcome::Unknown),
            _ => None,
        }
    }
}

/// Known client-family label (correlation metadata, NOT an authenticated
/// principal).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientFamily {
    Hermes,
    Claude,
    Codex,
    OpenCode,
    Cursor,
    Agy,
    FixedConsumer,
    Unknown,
}

impl ClientFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            ClientFamily::Hermes => "hermes",
            ClientFamily::Claude => "claude",
            ClientFamily::Codex => "codex",
            ClientFamily::OpenCode => "opencode",
            ClientFamily::Cursor => "cursor",
            ClientFamily::Agy => "agy",
            ClientFamily::FixedConsumer => "fixed-consumer",
            ClientFamily::Unknown => "unknown",
        }
    }

    pub fn from_label(s: &str) -> Option<Self> {
        match s {
            "hermes" => Some(ClientFamily::Hermes),
            "claude" => Some(ClientFamily::Claude),
            "codex" => Some(ClientFamily::Codex),
            "opencode" => Some(ClientFamily::OpenCode),
            "cursor" => Some(ClientFamily::Cursor),
            "agy" => Some(ClientFamily::Agy),
            "fixed-consumer" => Some(ClientFamily::FixedConsumer),
            "unknown" => Some(ClientFamily::Unknown),
            _ => None,
        }
    }
}

/// Request to append an audit event.
#[derive(Debug, Clone)]
pub struct AppendEventRequest {
    pub operation: String,
    pub phase: Outcome,
    pub transaction: uuid::Uuid,
    pub actor: String,
    pub client: ClientFamily,
    pub reason_sha256: Option<String>,
    pub command_basename: Option<String>,
    pub names: Vec<String>,
    pub result_code: Option<u8>,
    pub expected_uid: Option<u32>,
}

/// A successfully appended audit event.
#[derive(Debug, Clone)]
pub struct AuditEvent {
    pub sequence: i64,
    pub timestamp_ns: i64,
    pub transaction: uuid::Uuid,
    pub phase: Outcome,
    pub operation: String,
    pub actor: String,
    pub client: ClientFamily,
    pub reason_sha256: String,
    pub command_basename: Option<String>,
    pub names: Vec<String>,
    pub result_code: Option<u8>,
    pub previous_hash: String,
    pub event_hash: String,
}

/// Result of a successful chain verification.
#[derive(Debug, Clone)]
pub struct VerifyResult {
    pub count: u64,
    pub hash: String,
}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("audit denied: {0}")]
    Denied(String),

    /// Another process held the ledger's lock for longer than the busy timeout.
    ///
    /// Distinct from [`AuditError::Database`] so the message can say what it
    /// is: contention to retry, not damage. The text keeps SQLite's own words
    /// ("database is locked") on purpose: the public client matches them to
    /// choose its hint, and an older broker prints them unwrapped.
    #[error(
        "database is locked: another broker call is holding the ledger and did not release it in time; retry shortly"
    )]
    Busy,

    #[error("database error: {0}")]
    Database(rusqlite::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<rusqlite::Error> for AuditError {
    fn from(error: rusqlite::Error) -> Self {
        if is_busy(&error) {
            AuditError::Busy
        } else {
            AuditError::Database(error)
        }
    }
}

/// True when SQLite gave up waiting for another connection's lock.
pub(crate) fn is_busy(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(failure, _)
            if matches!(
                failure.code,
                rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
            )
    )
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

/// Compute the SHA-256 hex digest of `data`.
pub fn sha256_hex(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}

/// Validate text against limit and forbidden characters.
fn validate_text(label: &str, value: &str, limit: usize) -> Result<(), AuditError> {
    if value.is_empty()
        || value.len() > limit
        || value.contains('\0')
        || value.contains('\r')
        || value.contains('\n')
    {
        return Err(AuditError::Denied(format!("invalid {label}")));
    }
    Ok(())
}

/// Manual validation: operation must be lowercase letter followed by
/// lowercase letters, digits, hyphens.
fn is_valid_operation(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.is_empty() || !bytes[0].is_ascii_lowercase() {
        return false;
    }
    bytes
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
}

/// Manual validation: client must be one of the known labels.
fn is_valid_client(s: &str) -> bool {
    matches!(
        s,
        "hermes"
            | "claude"
            | "codex"
            | "opencode"
            | "cursor"
            | "agy"
            | "fixed-consumer"
            | "unknown"
    )
}

/// Manual validation: 64 hex digits (lowercase).
fn is_valid_sha256_hex(s: &str) -> bool {
    s.len() == 64
        && s.as_bytes()
            .iter()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// Basename the ledger records for a `run` target.
///
/// The counterpart to [`is_valid_command_basename`], and the only supported way
/// to produce a value that satisfies it. The validator forbids separators, so a
/// caller that forwards the invocation verbatim has every absolute path denied
/// -- `run -- /bin/echo hi` failed with `audit denied: invalid command
/// basename`, which is most real invocations.
///
/// A target with no usable final component degrades to `unknown` rather than
/// failing the run. The ledger recording that a command ran and could not be
/// named is worth more than refusing to run it: this value is a label for
/// after-the-fact reading, never an authorization input.
#[must_use]
pub fn command_basename(target: &std::ffi::OsStr) -> String {
    Path::new(target)
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| is_valid_command_basename(name))
        .unwrap_or("unknown")
        .to_string()
}

/// Manual validation: alphanumeric plus `_.+-`, 1-128 chars.
fn is_valid_command_basename(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.is_empty() || bytes.len() > 128 {
        return false;
    }
    bytes
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'+' | b'-'))
}

/// Manual validation: uppercase letter followed by uppercase letters, digits, underscores.
fn is_valid_secret_name(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.is_empty() || !bytes[0].is_ascii_uppercase() {
        return false;
    }
    bytes
        .iter()
        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || *b == b'_')
}

// ---------------------------------------------------------------------------
// Protected metadata checks
// ---------------------------------------------------------------------------

/// Check that `path` is a directory with mode `0700` and the expected owner.
fn check_protected_dir(path: &Path, expected_uid: Option<u32>) -> Result<(), AuditError> {
    let meta = std::fs::symlink_metadata(path)?;

    // Must not be a symlink
    if meta.is_symlink() {
        return Err(AuditError::Denied(
            "protected directory is a symlink".into(),
        ));
    }

    if !meta.is_dir() {
        return Err(AuditError::Denied(
            "protected directory is not a directory".into(),
        ));
    }

    let mode = meta.permissions().mode() & 0o777;
    if mode != 0o700 {
        return Err(AuditError::Denied(
            "protected directory must be mode 0700".into(),
        ));
    }

    if let Some(uid) = expected_uid
        && meta.uid() != uid
    {
        return Err(AuditError::Denied(
            "protected directory owner mismatch".into(),
        ));
    }

    Ok(())
}

/// Check the existing ledger file: must be a regular file (not symlink),
/// mode `0600`, and owned by the expected UID (when given).
fn check_ledger_metadata(path: &Path, expected_uid: Option<u32>) -> Result<(), AuditError> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(AuditError::Io(e)),
    };

    // Reject symlinks
    if meta.is_symlink() {
        return Err(AuditError::Denied("ledger is a symlink".into()));
    }

    if !meta.is_file() {
        return Err(AuditError::Denied(
            "ledger path must be a regular file".into(),
        ));
    }

    let mode = meta.permissions().mode() & 0o777;
    if mode != 0o600 {
        return Err(AuditError::Denied("ledger must be mode 0600".into()));
    }

    if let Some(uid) = expected_uid
        && meta.uid() != uid
    {
        return Err(AuditError::Denied("ledger owner mismatch".into()));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Database connection
// ---------------------------------------------------------------------------

/// Whether opening the ledger may also normalise it.
///
/// `ReadWrite` is the broker's mode: it repairs the ledger's mode and
/// ownership on the way in, which is what lets a ledger left root-owned by an
/// earlier install recover instead of being permanently fatal.
///
/// `ReadOnly` exists because `drift` documents itself as never mutating state,
/// and then reached this function. A non-repairing checker that silently
/// repairs is exactly the surprise this codebase otherwise refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyMode {
    ReadWrite,
    ReadOnly,
}

/// Open a protected database in the vault, with the ledger's own hardening.
///
/// Exposed so [`crate::history`] opens its store through exactly this code
/// rather than a second copy of it. Every guarantee below — directory metadata,
/// pre- and post-open ownership, `0600`, the pragmas, and the dev/ino re-check
/// against a swap during open — is one a second store needs identically, and a
/// duplicated version is one that drifts. `db_name` is the only difference
/// between the two callers.
pub(crate) fn open_protected_db(
    directory: &Path,
    db_name: &str,
    expected_uid: Option<u32>,
    mode: VerifyMode,
) -> Result<Connection, AuditError> {
    open_protected_db_waiting(
        directory,
        db_name,
        expected_uid,
        mode,
        busy_timeout_for(mode),
    )
}

/// [`open_protected_db`] with the busy timeout given rather than taken from
/// `mode`, so a caller (and a test) can choose how long to wait.
pub(crate) fn open_protected_db_waiting(
    directory: &Path,
    db_name: &str,
    expected_uid: Option<u32>,
    mode: VerifyMode,
    busy_timeout: Duration,
) -> Result<Connection, AuditError> {
    open_connection(directory, db_name, expected_uid, mode, busy_timeout)
}

/// How long a connection opened under `mode` waits for another process's lock.
pub(crate) fn busy_timeout_for(mode: VerifyMode) -> Duration {
    match mode {
        VerifyMode::ReadWrite => WRITE_BUSY_TIMEOUT,
        VerifyMode::ReadOnly => READ_BUSY_TIMEOUT,
    }
}

/// Assert the protected directory's metadata without opening anything.
///
/// Exposed for the same reason as [`open_protected_db`]: a store that does not
/// exist yet still has to prove its directory is the real vault before
/// reporting "no entries".
pub(crate) fn require_protected_dir(
    directory: &Path,
    expected_uid: Option<u32>,
) -> Result<(), AuditError> {
    check_protected_dir(directory, expected_uid)
}

fn open_connection(
    directory: &Path,
    db_name: &str,
    expected_uid: Option<u32>,
    mode: VerifyMode,
    busy_timeout: Duration,
) -> Result<Connection, AuditError> {
    // 1. Validate protected directory metadata first (fail-closed).
    check_protected_dir(directory, expected_uid)?;

    // 2. Check any existing ledger metadata before opening. Under `ReadWrite`
    //    ownership is deliberately not asserted yet: step 5 reassigns the ledger
    //    to the vault owner, so a ledger left root-owned by an earlier install
    //    must be repairable rather than permanently fatal, and the post-open
    //    check enforces the final ownership. Under `ReadOnly` there is no such
    //    repair, so the expectation is asserted immediately.
    let db_path = directory.join(db_name);
    let identity_before = std::fs::symlink_metadata(&db_path)
        .ok()
        .map(|m| (m.dev(), m.ino()));
    let pre_open_uid = match mode {
        VerifyMode::ReadWrite => None,
        VerifyMode::ReadOnly => expected_uid,
    };
    check_ledger_metadata(&db_path, pre_open_uid)?;

    // 3. Open. `ReadWrite` masks so a newly created ledger gets 0600;
    //    `ReadOnly` opens an existing ledger without the power to create one.
    let conn = match mode {
        VerifyMode::ReadWrite => {
            let old_mask = unsafe { libc::umask(0o077) };
            let conn_result = Connection::open(&db_path);
            unsafe { libc::umask(old_mask) };
            conn_result?
        }
        VerifyMode::ReadOnly => Connection::open_with_flags(
            &db_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                | rusqlite::OpenFlags::SQLITE_OPEN_URI
                | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?,
    };

    // Bound how long this connection waits on another process's lock. Set before
    // any statement runs: the `journal_mode` pragma below takes a lock too.
    conn.busy_timeout(busy_timeout)?;

    // 4. Set pragmas immediately. `journal_mode` is a property of the database
    //    file rather than the connection, so setting it needs write access and
    //    is skipped under `ReadOnly`; the rest are per-connection.
    if mode == VerifyMode::ReadWrite {
        conn.execute_batch("PRAGMA journal_mode=DELETE;")?;
    }
    // `secure_delete` is defense-in-depth here rather than a fix: both ledgers
    // this helper opens are append-only and hold no secret values, only digests
    // and the declaration manifest. It costs one pragma to keep that true if
    // either ever learns to prune or rotate.
    conn.execute_batch(
        "PRAGMA synchronous=FULL;\
         PRAGMA foreign_keys=ON;\
         PRAGMA secure_delete=ON;\
         PRAGMA trusted_schema=OFF;",
    )?;

    // 5. Ensure ledger is mode 0600 and owned by the vault service identity.
    if mode == VerifyMode::ReadWrite {
        let meta = std::fs::metadata(&db_path)?;
        let mut perms = meta.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&db_path, perms)?;
        // When the broker runs as root, reassign ownership to the vault owner
        // (the dedicated service user) so doctor/drift checks stay consistent.
        if unsafe { libc::geteuid() } == 0 {
            let dir_meta = std::fs::metadata(directory)?;
            let uid = dir_meta.uid();
            let gid = dir_meta.gid();
            let c_path = std::ffi::CString::new(db_path.to_string_lossy().as_bytes())
                .map_err(|_| AuditError::Denied("invalid ledger path".into()))?;
            let rc = unsafe { libc::chown(c_path.as_ptr(), uid, gid) };
            if rc != 0 {
                return Err(AuditError::Denied(format!(
                    "could not chown ledger to vault owner {uid}:{gid}"
                )));
            }
        }
    }

    // 6. Re-verify ledger metadata after open, now including ownership.
    check_ledger_metadata(&db_path, expected_uid)?;

    // 7. The path must still name the same file it did before the open. A
    //    metadata re-check alone would pass happily if the ledger had been
    //    swapped for a different file underneath us.
    if let Some(before) = identity_before {
        let after = std::fs::symlink_metadata(&db_path)?;
        if (after.dev(), after.ino()) != before {
            return Err(AuditError::Denied(
                "ledger was replaced while opening".into(),
            ));
        }
    }

    Ok(conn)
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

fn ensure_schema(conn: &Connection) -> Result<(), AuditError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS events (\
           sequence       INTEGER PRIMARY KEY AUTOINCREMENT,\
           timestamp_ns   INTEGER NOT NULL,\
           transaction_id TEXT    NOT NULL,\
           phase          TEXT    NOT NULL CHECK (phase IN ('attempt','success','failure','unknown')),\
           operation      TEXT    NOT NULL,\
           actor          TEXT    NOT NULL,\
           client         TEXT    NOT NULL,\
           reason_sha256  TEXT    NOT NULL,\
           command_basename TEXT,\
           names_json     TEXT    NOT NULL,\
           result_code    INTEGER,\
           previous_hash  TEXT    NOT NULL,\
           event_hash     TEXT    NOT NULL UNIQUE\
         ) STRICT;\
         CREATE TABLE IF NOT EXISTS head (\
           singleton INTEGER PRIMARY KEY CHECK (singleton = 1),\
           sequence  INTEGER NOT NULL,\
           event_hash TEXT   NOT NULL\
         ) STRICT;",
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Canonical serialisation
// ---------------------------------------------------------------------------

/// Canonical JSON for an event: every field that identifies it, including
/// `sequence` and `timestamp_ns`, and excluding only `event_hash` itself.
///
/// Binding the sequence and the timestamp into the hash is what stops an event
/// being renumbered or back-dated in place. (An earlier version of this comment
/// claimed both were excluded; the code was always the stronger of the two, and
/// changing it to match would invalidate every existing chain.)
fn canonical_event_json(event: &AuditEvent) -> String {
    // Build a BTreeMap for deterministic key ordering.
    let mut map = std::collections::BTreeMap::new();
    map.insert("sequence", serde_json::Value::Number(event.sequence.into()));
    map.insert(
        "timestamp_ns",
        serde_json::Value::Number(event.timestamp_ns.into()),
    );
    map.insert(
        "transaction",
        serde_json::Value::String(event.transaction.to_string()),
    );
    map.insert(
        "phase",
        serde_json::Value::String(event.phase.as_str().into()),
    );
    map.insert(
        "operation",
        serde_json::Value::String(event.operation.clone()),
    );
    map.insert("actor", serde_json::Value::String(event.actor.clone()));
    map.insert(
        "client",
        serde_json::Value::String(event.client.as_str().into()),
    );
    map.insert(
        "reason_sha256",
        serde_json::Value::String(event.reason_sha256.clone()),
    );
    map.insert(
        "command_basename",
        match &event.command_basename {
            Some(s) => serde_json::Value::String(s.clone()),
            None => serde_json::Value::Null,
        },
    );
    map.insert("names", {
        let names: Vec<serde_json::Value> = event
            .names
            .iter()
            .map(|n| serde_json::Value::String(n.clone()))
            .collect();
        serde_json::Value::Array(names)
    });
    map.insert(
        "result_code",
        match event.result_code {
            Some(c) => serde_json::Value::Number(c.into()),
            None => serde_json::Value::Null,
        },
    );
    map.insert(
        "previous_hash",
        serde_json::Value::String(event.previous_hash.clone()),
    );

    serde_json::to_string(&map).unwrap()
}

/// Compute the event hash for a prepared event.
fn compute_event_hash(previous_hash: &str, event: &AuditEvent) -> String {
    let canonical = canonical_event_json(event);
    let input = format!("{previous_hash}\n{canonical}");
    sha256_hex(input.as_bytes())
}

// ---------------------------------------------------------------------------
// Chain verification
// ---------------------------------------------------------------------------

/// Rows fetched per statement while verifying the chain.
const VERIFY_CHUNK_ROWS: usize = 512;

/// One `events` row exactly as stored, before any check has run on it.
type RawEvent = (
    i64,            // sequence
    i64,            // timestamp_ns
    String,         // transaction_id
    String,         // phase
    String,         // operation
    String,         // actor
    String,         // client
    String,         // reason_sha256
    Option<String>, // command_basename
    String,         // names_json
    Option<i64>,    // result_code
    String,         // previous_hash
    String,         // event_hash
);

fn read_raw_event(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawEvent> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
        row.get(10)?,
        row.get(11)?,
        row.get(12)?,
    ))
}

/// Fetch up to `limit` events numbered after `after`, in order, and finish the
/// statement before returning, so the read lock it needed is already released.
fn fetch_events_after(
    conn: &Connection,
    after: i64,
    limit: usize,
) -> rusqlite::Result<Vec<RawEvent>> {
    let mut stmt = conn.prepare(
        "SELECT sequence, timestamp_ns, transaction_id, phase, operation,\
                actor, client, reason_sha256, command_basename, names_json,\
                result_code, previous_hash, event_hash \
         FROM events WHERE sequence > ?1 ORDER BY sequence LIMIT ?2",
    )?;
    let rows: Vec<RawEvent> = stmt
        .query_map(rusqlite::params![after, limit as i64], read_raw_event)?
        .collect::<Result<_, _>>()?;
    Ok(rows)
}

/// Check one event against the hash of the event before it. Returns the event's
/// own hash and sequence, which become the next call's `previous`.
fn check_event(previous: &str, raw: RawEvent) -> Result<(String, i64), AuditError> {
    let (
        sequence,
        timestamp_ns,
        transaction_id,
        phase_str,
        operation,
        actor,
        client_str,
        reason_sha256,
        command_basename,
        names_json,
        result_code_i64,
        stored_previous,
        event_hash,
    ) = raw;

    let transaction = uuid::Uuid::parse_str(&transaction_id)
        .map_err(|e| AuditError::Denied(format!("invalid transaction UUID in ledger: {e}")))?;

    let phase = Outcome::from_label(&phase_str)
        .ok_or_else(|| AuditError::Denied(format!("invalid phase in ledger: {phase_str}")))?;

    let client = ClientFamily::from_label(&client_str)
        .ok_or_else(|| AuditError::Denied(format!("invalid client in ledger: {client_str}")))?;

    let names: Vec<String> = serde_json::from_str(&names_json)
        .map_err(|e| AuditError::Denied(format!("invalid names_json in ledger: {e}")))?;

    let result_code: Option<u8> = result_code_i64.map(|c| c as u8);

    let event = AuditEvent {
        sequence,
        timestamp_ns,
        transaction,
        phase,
        operation,
        actor,
        client,
        reason_sha256,
        command_basename,
        names,
        result_code,
        previous_hash: stored_previous.clone(),
        event_hash: event_hash.clone(),
    };

    // Compute expected hash
    let expected = compute_event_hash(previous, &event);

    // Validate previous hash link
    if stored_previous != previous {
        return Err(AuditError::Denied("ledger chain is invalid".into()));
    }

    // Validate event hash
    if event_hash != expected {
        return Err(AuditError::Denied("ledger chain is invalid".into()));
    }

    Ok((event_hash, sequence))
}

/// [`verify_chain_after`] with the chunk size given, so a test can exercise the
/// chunk boundaries without writing hundreds of events.
fn verify_chain_in_chunks(
    conn: &Connection,
    mut after: i64,
    mut previous: String,
    chunk_rows: usize,
) -> Result<(String, i64), AuditError> {
    // A zero chunk would fetch nothing and never reach the end condition.
    debug_assert!(chunk_rows > 0, "chunk_rows must be positive");
    loop {
        let rows = fetch_events_after(conn, after, chunk_rows)?;
        let fetched = rows.len();
        for raw in rows {
            let (hash, sequence) = check_event(&previous, raw)?;
            previous = hash;
            after = sequence;
        }
        if fetched < chunk_rows {
            return Ok((previous, after));
        }
    }
}

/// Verify every event numbered after `after`, chaining from `previous` (the hash
/// of event `after`, or [`ZERO_HASH`] when `after` is 0). Returns the new tip as
/// `(hash, sequence)`, which is the inputs unchanged when nothing follows.
///
/// Rows are read [`VERIFY_CHUNK_ROWS`] at a time and each statement is finished
/// before its rows are hashed. Called with no transaction open, that means no
/// lock is held while the CPU work runs, and a read lock only for as long as one
/// chunk takes to fetch. Called inside the caller's transaction it behaves the
/// same, and the lock is the transaction's.
fn verify_chain_after(
    conn: &Connection,
    after: i64,
    previous: String,
) -> Result<(String, i64), AuditError> {
    verify_chain_in_chunks(conn, after, previous, VERIFY_CHUNK_ROWS)
}

/// Check that the `head` row names the tip the chain actually ended on (or is
/// absent when there are no events).
fn check_head(conn: &Connection, count: i64, tip_hash: &str) -> Result<(), AuditError> {
    let head: Option<(i64, String)> = conn
        .query_row(
            "SELECT sequence, event_hash FROM head WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;

    let expected_head = if count == 0 {
        None
    } else {
        Some((count, tip_hash.to_string()))
    };

    if head != expected_head {
        return Err(AuditError::Denied("ledger head is invalid".into()));
    }
    Ok(())
}

/// Verify the whole chain and the head inside the caller's transaction.
/// Returns (last_event_hash, row_count) on success.
fn verify_rows(conn: &Connection) -> Result<(String, i64), AuditError> {
    let (previous, count) = verify_chain_after(conn, 0, ZERO_HASH.to_string())?;
    check_head(conn, count, &previous)?;
    Ok((previous, count))
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Verify the full ledger chain and head, returning the current tip hash
/// and total event count. If no ledger exists yet, returns `count=0` with
/// `ZERO_HASH`.
pub fn verify(directory: &Path, expected_uid: Option<u32>) -> Result<VerifyResult, AuditError> {
    verify_with(directory, expected_uid, VerifyMode::ReadWrite)
}

/// Verify the ledger without touching it.
///
/// Same answer as [`verify`], but the ledger is opened read-only and its mode,
/// ownership and schema are left exactly as found. For callers that promise not
/// to mutate state — `drift`, and so `doctor` — where repairing on the read
/// path would be a silent surprise.
///
/// Note that a ledger with a hot journal cannot be replayed read-only, so an
/// interrupted write surfaces here as an error rather than being recovered.
/// That is the intended trade: the caller reports it, the broker repairs it.
pub fn verify_read_only(
    directory: &Path,
    expected_uid: Option<u32>,
) -> Result<VerifyResult, AuditError> {
    verify_with(directory, expected_uid, VerifyMode::ReadOnly)
}

fn verify_with(
    directory: &Path,
    expected_uid: Option<u32>,
    mode: VerifyMode,
) -> Result<VerifyResult, AuditError> {
    // If no ledger exists yet, succeed with count=0. This early return is also
    // what keeps `ReadOnly` from having to open a database that does not exist:
    // it cannot create one, so it would otherwise fail on a fresh install.
    let db_path = directory.join(DB_NAME);
    if !db_path.exists() {
        check_protected_dir(directory, expected_uid)?;
        return Ok(VerifyResult {
            count: 0,
            hash: ZERO_HASH.into(),
        });
    }

    let conn = open_connection(
        directory,
        DB_NAME,
        expected_uid,
        mode,
        busy_timeout_for(mode),
    )?;

    let result = (|| -> Result<VerifyResult, AuditError> {
        // Creating the schema is a write. Under `ReadOnly` a ledger missing its
        // tables is a finding for the caller to report, not something to fix
        // here — and `verify_rows` returns the same "no events" answer either
        // way once the tables exist.
        if mode == VerifyMode::ReadWrite {
            ensure_schema(&conn)?;
        }
        // `BEGIN IMMEDIATE` takes a write lock, which a read-only connection
        // cannot. A deferred `BEGIN` still gives the snapshot the chain check
        // needs.
        conn.execute(
            match mode {
                VerifyMode::ReadWrite => "BEGIN IMMEDIATE",
                VerifyMode::ReadOnly => "BEGIN",
            },
            [],
        )?;
        let (hash, count) = verify_rows(&conn)?;

        // Run integrity check
        let integrity: String = conn.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
        if integrity != "ok" {
            return Err(AuditError::Denied("ledger integrity check failed".into()));
        }

        conn.execute("COMMIT", [])?;
        Ok(VerifyResult {
            count: count as u64,
            hash,
        })
    })();

    match result {
        Ok(r) => Ok(r),
        Err(e) => {
            let _ = conn.execute("ROLLBACK", []);
            Err(e)
        }
    }
}

/// Append a new audit event. Validates all inputs before touching the
/// database (fail-closed). The event and head are committed atomically, and the
/// write lock is held only around that commit: see the module's "Locking"
/// section. Waits up to [`WRITE_BUSY_TIMEOUT`] for another writer, then fails
/// with [`AuditError::Busy`] without appending anything.
pub fn append_event(
    directory: &Path,
    request: AppendEventRequest,
) -> Result<AuditEvent, AuditError> {
    append_event_waiting(directory, request, WRITE_BUSY_TIMEOUT)
}

/// [`append_event`] with the busy timeout given, so a test can show the bound
/// without waiting out the production one.
pub(crate) fn append_event_waiting(
    directory: &Path,
    request: AppendEventRequest,
    busy_timeout: Duration,
) -> Result<AuditEvent, AuditError> {
    // ---- Input validation (fail-closed, before opening the database) ----

    // Operation
    {
        if !is_valid_operation(&request.operation) {
            return Err(AuditError::Denied("invalid operation".into()));
        }
    }

    // Phase rules
    if request.phase.as_str() == "attempt" && request.result_code.is_some() {
        return Err(AuditError::Denied(
            "attempt cannot have a result code".into(),
        ));
    }
    if request.phase.as_str() != "attempt" && request.result_code.is_none() {
        return Err(AuditError::Denied(
            "terminal event requires a result code".into(),
        ));
    }

    // Actor
    validate_text("actor", &request.actor, 128)?;

    // Client
    {
        if !is_valid_client(request.client.as_str()) {
            return Err(AuditError::Denied("invalid client".into()));
        }
    }

    // Reason SHA-256
    let reason_sha256 = match &request.reason_sha256 {
        Some(h) => {
            if !is_valid_sha256_hex(h) {
                return Err(AuditError::Denied("invalid reason hash".into()));
            }
            h.clone()
        }
        None => {
            return Err(AuditError::Denied("reason hash is required".into()));
        }
    };

    // Command basename
    if let Some(ref basename) = request.command_basename
        && !is_valid_command_basename(basename)
    {
        return Err(AuditError::Denied("invalid command basename".into()));
    }

    // Names
    let mut clean_names: Vec<String> = request.names.to_vec();
    clean_names.sort();
    clean_names.dedup();
    {
        for name in &clean_names {
            if !is_valid_secret_name(name) {
                return Err(AuditError::Denied("invalid secret name".into()));
            }
        }
    }

    // ---- Database operations ----

    // Appending is a write by definition; there is no read-only variant here.
    let conn = open_connection(
        directory,
        DB_NAME,
        request.expected_uid,
        VerifyMode::ReadWrite,
        busy_timeout,
    )?;

    let result = (|| -> Result<AuditEvent, AuditError> {
        ensure_schema(&conn)?;

        // Verify the whole chain *before* taking the write lock. This is the
        // O(ledger) part of an append; run inside the write transaction it let
        // one descheduled broker lock every other caller out for as long as it
        // stayed descheduled (issue #4). Done here it holds no lock beyond one
        // chunk fetch at a time, and the rows it covers are append-only, so what
        // it proved is still true once the lock is taken.
        let (verified_hash, verified_sequence) =
            verify_chain_after(&conn, 0, ZERO_HASH.to_string())?;

        conn.execute("BEGIN IMMEDIATE", [])?;

        // Under the lock, check only what landed since: usually nothing, at most
        // the few events other brokers appended while we were verifying. The
        // head row is checked here too, atomically with the insert that moves it.
        let (previous_hash, count) = verify_chain_after(&conn, verified_sequence, verified_hash)?;
        check_head(&conn, count, &previous_hash)?;
        let sequence = count + 1;

        // Get timestamp
        let timestamp_ns = {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| AuditError::Denied(format!("clock error: {e}")))?;
            now.as_nanos() as i64
        };

        let names_json = serde_json::to_string(&clean_names).unwrap();

        // Build event (without event_hash yet)
        let mut event = AuditEvent {
            sequence,
            timestamp_ns,
            transaction: request.transaction,
            phase: request.phase,
            operation: request.operation.clone(),
            actor: request.actor.clone(),
            client: request.client,
            reason_sha256: reason_sha256.clone(),
            command_basename: request.command_basename.clone(),
            names: clean_names.clone(),
            result_code: request.result_code,
            previous_hash: previous_hash.clone(),
            event_hash: String::new(), // placeholder
        };

        // Compute event hash
        event.event_hash = compute_event_hash(&previous_hash, &event);

        // Insert event
        conn.execute(
            "INSERT INTO events (\
                sequence, timestamp_ns, transaction_id, phase, operation,\
                actor, client, reason_sha256, command_basename, names_json,\
                result_code, previous_hash, event_hash\
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            rusqlite::params![
                event.sequence,
                event.timestamp_ns,
                event.transaction.to_string(),
                event.phase.as_str(),
                event.operation,
                event.actor,
                event.client.as_str(),
                event.reason_sha256,
                event.command_basename,
                names_json,
                event.result_code.map(|c| c as i64),
                event.previous_hash,
                event.event_hash,
            ],
        )?;

        // Upsert head
        conn.execute(
            "INSERT INTO head (singleton, sequence, event_hash) VALUES (1, ?1, ?2) \
             ON CONFLICT(singleton) DO UPDATE SET \
             sequence = excluded.sequence, event_hash = excluded.event_hash",
            rusqlite::params![event.sequence, event.event_hash],
        )?;

        conn.execute("COMMIT", [])?;

        Ok(event)
    })();

    match result {
        Ok(event) => Ok(event),
        Err(e) => {
            let _ = conn.execute("ROLLBACK", []);
            Err(e)
        }
    }
}

/// SQLite's unix VFS takes `RESERVED` as a POSIX write lock on the single byte
/// after its `PENDING_BYTE` (`0x40000000`). A writer holds it from `BEGIN
/// IMMEDIATE` until its commit finishes, and every other writer needs it.
const SQLITE_RESERVED_BYTE: i64 = 0x4000_0001;

/// The process holding the ledger's write lock right now, if any.
///
/// This asks the kernel (`fcntl(F_GETLK)`) who holds the lock byte SQLite's
/// `RESERVED` lock lives on, instead of opening the ledger through SQLite. That
/// is the only way to see it without writing: a read-only connection is never
/// blocked by `RESERVED`, which is exactly why a stalled writer could leave
/// `doctor` reporting a healthy ledger while every broker call failed. Nothing
/// is locked, created or changed, and a reader holding only a shared lock is not
/// reported.
///
/// `Ok(None)` also covers a ledger that does not exist and a filesystem that
/// does not honour POSIX locks; both mean there is nothing to report.
///
/// Do not call this from a process that has the ledger open through SQLite:
/// closing the descriptor used here drops that process's own POSIX locks on the
/// file. `doctor` calls it before it opens the ledger.
pub fn write_lock_holder(db_path: &Path) -> std::io::Result<Option<u32>> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;

    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(db_path)
    {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };

    // SAFETY: an all-zero `flock` is a valid value; every field is a plain
    // integer.
    let mut lock: libc::flock = unsafe { std::mem::zeroed() };
    // A read-lock request conflicts only with another process's write lock, so
    // it needs no write access to the file and reports exactly the `RESERVED`
    // holder (SQLite's shared locks are read locks on a different byte range).
    lock.l_type = libc::F_RDLCK as _;
    lock.l_whence = libc::SEEK_SET as _;
    lock.l_start = SQLITE_RESERVED_BYTE as _;
    lock.l_len = 1;
    // SAFETY: `lock` is a valid, initialised `flock` and the descriptor stays
    // open for the call.
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETLK, &mut lock) } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    // `l_type` is a `c_short` where `F_UNLCK` is a `c_int` on Linux, so the
    // constant needs a named type to compare against.
    let unlocked: libc::c_short = libc::F_UNLCK as _;
    if lock.l_type == unlocked {
        return Ok(None);
    }
    Ok(Some(u32::try_from(lock.l_pid).unwrap_or(0)))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Helpers that hold a ledger's lock from outside the code under test.
#[cfg(test)]
pub(crate) mod test_support {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::path::Path;
    use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
    use std::sync::mpsc;
    use std::thread::{self, JoinHandle};
    use std::time::Duration;

    use rusqlite::Connection;

    /// Names the database the process [`ProcessLock`] starts must lock.
    const HOLD_DB: &str = "SUDO_SECRETSPEC_TEST_HOLD_DB";
    /// Whether that process takes the write lock or only a read lock.
    const HOLD_KIND: &str = "SUDO_SECRETSPEC_TEST_HOLD_KIND";
    /// What the child prints once it holds its lock.
    const READY: &str = "lock-holder-ready";

    /// A write lock held by another *connection in this process*, for tests of
    /// how long an append waits. The lock is dropped by [`ThreadLock::release`],
    /// or by dropping the value, so a failing test cannot leave it held.
    pub(crate) struct ThreadLock {
        release: Option<mpsc::Sender<()>>,
        handle: Option<JoinHandle<()>>,
    }

    impl ThreadLock {
        /// Take `BEGIN IMMEDIATE` on `db` and hold it. Returns once it is held.
        pub(crate) fn hold(db: &Path) -> Self {
            let (locked_tx, locked_rx) = mpsc::channel::<()>();
            let (release_tx, release_rx) = mpsc::channel::<()>();
            let db = db.to_path_buf();
            let handle = thread::spawn(move || {
                let conn = Connection::open(db).unwrap();
                conn.execute("BEGIN IMMEDIATE", []).unwrap();
                locked_tx.send(()).unwrap();
                // Ends on `release`, on the sender being dropped, or after a
                // minute if the test is wedged.
                let _ = release_rx.recv_timeout(Duration::from_secs(60));
                let _ = conn.execute("ROLLBACK", []);
            });
            locked_rx
                .recv()
                .expect("the lock holder failed to take the write lock");
            Self {
                release: Some(release_tx),
                handle: Some(handle),
            }
        }

        pub(crate) fn release(mut self) {
            self.shutdown();
        }

        fn shutdown(&mut self) {
            drop(self.release.take());
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }
    }

    impl Drop for ThreadLock {
        fn drop(&mut self) {
            self.shutdown();
        }
    }

    #[derive(Clone, Copy)]
    pub(crate) enum Hold {
        /// `BEGIN IMMEDIATE`: the write (`RESERVED`) lock.
        Write,
        /// A deferred transaction that has read: a shared lock only.
        Read,
    }

    /// A lock held by a *separate process*, which is what `fcntl(F_GETLK)` needs:
    /// POSIX locks never conflict with the process that took them.
    ///
    /// The process is this test binary run again on [`lock_holder_child`]. Its
    /// stdin is the release: it holds the lock until the pipe closes, which also
    /// frees it if the parent test dies.
    pub(crate) struct ProcessLock {
        child: Child,
        stdin: Option<ChildStdin>,
        _stdout: BufReader<ChildStdout>,
    }

    impl ProcessLock {
        pub(crate) fn hold(db: &Path, hold: Hold) -> Self {
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "audit::test_support::lock_holder_child",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(HOLD_DB, db)
                .env(
                    HOLD_KIND,
                    match hold {
                        Hold::Write => "write",
                        Hold::Read => "read",
                    },
                )
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap();
            let stdin = child.stdin.take();
            let mut stdout = BufReader::new(child.stdout.take().unwrap());
            let mut line = String::new();
            loop {
                line.clear();
                let read = stdout.read_line(&mut line).unwrap();
                assert!(read > 0, "the lock holder exited before it took its lock");
                // `contains`, not equality: libtest prints `test <name> ... `
                // on the same line before the test's own output.
                if line.contains(READY) {
                    break;
                }
            }
            Self {
                child,
                stdin,
                _stdout: stdout,
            }
        }

        pub(crate) fn pid(&self) -> u32 {
            self.child.id()
        }

        pub(crate) fn release(mut self) {
            self.shutdown();
        }

        fn shutdown(&mut self) {
            drop(self.stdin.take());
            let _ = self.child.wait();
        }
    }

    impl Drop for ProcessLock {
        fn drop(&mut self) {
            self.shutdown();
        }
    }

    /// Not a test in its own right: the body of the process [`ProcessLock::hold`]
    /// starts. Under a normal run the environment names no database and this
    /// returns at once.
    #[test]
    fn lock_holder_child() {
        let (Some(db), Some(kind)) = (std::env::var_os(HOLD_DB), std::env::var_os(HOLD_KIND))
        else {
            return;
        };
        let conn = Connection::open(db).unwrap();
        if kind == "write" {
            conn.execute("BEGIN IMMEDIATE", []).unwrap();
        } else {
            conn.execute("BEGIN", []).unwrap();
            conn.query_row("SELECT count(*) FROM events", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap();
        }
        println!("{READY}");
        std::io::stdout().flush().unwrap();
        let mut sink = Vec::new();
        let _ = std::io::stdin().read_to_end(&mut sink);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    fn basename_of(target: &str) -> String {
        command_basename(std::ffi::OsStr::new(target))
    }

    #[test]
    fn an_absolute_path_is_reduced_to_its_final_component() {
        // The regression: the whole invocation was forwarded verbatim, and the
        // validator rejects separators, so every absolute path was denied.
        assert_eq!(basename_of("/bin/echo"), "echo");
        assert_eq!(basename_of("/usr/local/bin/my-tool"), "my-tool");
    }

    #[test]
    fn a_bare_command_is_unchanged() {
        assert_eq!(basename_of("sh"), "sh");
        assert_eq!(basename_of("cargo"), "cargo");
    }

    #[test]
    fn every_produced_basename_satisfies_the_validator() {
        // The two must agree by construction; that agreement is the whole point.
        for target in [
            "/bin/echo",
            "sh",
            "./local-tool",
            "../up/tool",
            "/weird/name with spaces",
            "/",
            "..",
            "",
            "/usr/bin/tool.v2+build-1",
        ] {
            let produced = basename_of(target);
            assert!(
                is_valid_command_basename(&produced),
                "{target:?} produced {produced:?}, which the broker would deny"
            );
        }
    }

    #[test]
    fn a_name_the_validator_would_reject_degrades_to_unknown() {
        // A separator-free component can still be invalid (spaces are not in the
        // allowed set). Recording `unknown` beats failing an otherwise fine run.
        assert_eq!(basename_of("/weird/name with spaces"), "unknown");
        assert_eq!(basename_of("/"), "unknown");
        assert_eq!(basename_of(""), "unknown");
    }

    #[test]
    fn a_relative_path_keeps_only_its_final_component() {
        assert_eq!(basename_of("./local-tool"), "local-tool");
        assert_eq!(basename_of("../up/tool"), "tool");
    }

    /// Create a protected directory (mode 0700) inside tmp.
    fn protected_dir(tmp: &Path) -> std::path::PathBuf {
        let dir = tmp.join("protected");
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    // --- read-only verification ------------------------------------------
    //
    // `drift` documents itself as never mutating state and then called into
    // this module, whose read-write path creates the schema and reassigns the
    // ledger's mode and ownership. These cover the mode that keeps that promise.

    #[test]
    fn read_only_verify_agrees_with_the_repairing_path() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = protected_dir(tmp.path());
        let uid = Some(unsafe { libc::getuid() });
        let tx = uuid::Uuid::new_v4();
        attempt(&dir, tx).unwrap();
        terminal(&dir, tx, Outcome::Success, 0).unwrap();

        let rw = verify(&dir, uid).unwrap();
        let ro = verify_read_only(&dir, uid).unwrap();
        assert_eq!((ro.count, &ro.hash), (rw.count, &rw.hash));
        assert_eq!(ro.count, 2);
    }

    #[test]
    fn read_only_verify_does_not_create_a_ledger() {
        // A fresh vault has no ledger. The read-only connection has no power to
        // create one, so the early return is what keeps this from failing.
        let tmp = tempfile::tempdir().unwrap();
        let dir = protected_dir(tmp.path());

        let result = verify_read_only(&dir, Some(unsafe { libc::getuid() })).unwrap();
        assert_eq!(result.count, 0);
        assert_eq!(result.hash, ZERO_HASH);
        assert!(
            !dir.join(DB_NAME).exists(),
            "verifying must not bring a ledger into existence"
        );
    }

    #[test]
    fn read_only_verify_does_not_create_the_schema() {
        // An existing but empty database file. The read-write path would run
        // CREATE TABLE IF NOT EXISTS and report a clean empty ledger; the
        // read-only path must report the problem instead of fixing it.
        let tmp = tempfile::tempdir().unwrap();
        let dir = protected_dir(tmp.path());
        let db = dir.join(DB_NAME);
        Connection::open(&db).unwrap();
        fs::set_permissions(&db, fs::Permissions::from_mode(0o600)).unwrap();
        let uid = Some(unsafe { libc::getuid() });

        assert!(
            verify_read_only(&dir, uid).is_err(),
            "a ledger with no schema must be reported, not repaired"
        );
        // Control: the repairing path does create it, so the assertion above is
        // about the mode and not about the fixture being broken.
        assert_eq!(verify(&dir, uid).unwrap().count, 0);
        // And now that the schema exists, read-only agrees again.
        assert_eq!(verify_read_only(&dir, uid).unwrap().count, 0);
    }

    #[test]
    fn read_only_verify_leaves_the_ledger_file_untouched() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = protected_dir(tmp.path());
        let uid = Some(unsafe { libc::getuid() });
        let tx = uuid::Uuid::new_v4();
        attempt(&dir, tx).unwrap();
        terminal(&dir, tx, Outcome::Success, 0).unwrap();

        let db = dir.join(DB_NAME);
        let before = fs::metadata(&db).unwrap();
        let bytes_before = fs::read(&db).unwrap();

        verify_read_only(&dir, uid).unwrap();

        let after = fs::metadata(&db).unwrap();
        assert_eq!(fs::read(&db).unwrap(), bytes_before, "ledger bytes changed");
        assert_eq!(before.modified().unwrap(), after.modified().unwrap());
        assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
        // No journal or side files left behind either.
        let strays: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n != DB_NAME)
            .collect();
        assert!(strays.is_empty(), "read-only verify left {strays:?}");
    }

    // --- what the chain does and does not prove ---------------------------

    #[test]
    fn removing_an_event_from_the_middle_breaks_the_chain() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = protected_dir(tmp.path());
        let uid = Some(unsafe { libc::getuid() });
        for _ in 0..3 {
            let tx = uuid::Uuid::new_v4();
            attempt(&dir, tx).unwrap();
            terminal(&dir, tx, Outcome::Success, 0).unwrap();
        }
        assert_eq!(verify(&dir, uid).unwrap().count, 6);

        let conn = Connection::open(dir.join(DB_NAME)).unwrap();
        conn.execute("DELETE FROM events WHERE sequence = 3", [])
            .unwrap();
        drop(conn);

        assert!(
            verify(&dir, uid).is_err(),
            "a gap in the chain must fail verification"
        );
    }

    /// Pins the limitation documented in this module's "Residual risk" section.
    ///
    /// This asserts something the ledger *cannot* do, deliberately. The note it
    /// backs previously claimed tail truncation was detected "because every
    /// event commits with the singleton `head` row" — but `head` lives in the
    /// same database, so rewriting it is part of the same edit. If someone
    /// later strengthens the chain so this test fails, the fix is to update the
    /// note, not to delete the test.
    #[test]
    fn truncating_the_tail_and_rewriting_head_is_not_detectable() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = protected_dir(tmp.path());
        let uid = Some(unsafe { libc::getuid() });
        for _ in 0..3 {
            let tx = uuid::Uuid::new_v4();
            attempt(&dir, tx).unwrap();
            terminal(&dir, tx, Outcome::Success, 0).unwrap();
        }
        assert_eq!(verify(&dir, uid).unwrap().count, 6);

        let conn = Connection::open(dir.join(DB_NAME)).unwrap();
        conn.execute("DELETE FROM events WHERE sequence > 4", [])
            .unwrap();
        // Dropping the events alone *is* caught, which is what made the old
        // claim look true.
        drop(conn);
        assert!(
            verify(&dir, uid).is_err(),
            "head must not match a short chain"
        );

        let conn = Connection::open(dir.join(DB_NAME)).unwrap();
        let tip: String = conn
            .query_row(
                "SELECT event_hash FROM events WHERE sequence = 4",
                [],
                |r| r.get(0),
            )
            .unwrap();
        conn.execute(
            "UPDATE head SET sequence = 4, event_hash = ?1 WHERE singleton = 1",
            [&tip],
        )
        .unwrap();
        drop(conn);

        let result = verify(&dir, uid).expect("truncation with a rewritten head verifies cleanly");
        assert_eq!(result.count, 4);
        assert_eq!(result.hash, tip);
    }

    /// Simple sliding-window substring check.
    fn window_contains(needle: &str, haystack: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|w| w == needle.as_bytes())
    }

    fn attempt(dir: &Path, tx: uuid::Uuid) -> Result<AuditEvent, AuditError> {
        append_event(
            dir,
            AppendEventRequest {
                operation: "source-set".into(),
                phase: Outcome::Attempt,
                transaction: tx,
                actor: "djbclark".into(),
                client: ClientFamily::Hermes,
                reason_sha256: Some(sha256_hex(b"rotate integration credential")),
                command_basename: Some("curl".into()),
                names: vec!["EXAMPLE_KEY".into()],
                result_code: None,
                expected_uid: Some(unsafe { libc::getuid() }),
            },
        )
    }

    fn terminal(
        dir: &Path,
        tx: uuid::Uuid,
        phase: Outcome,
        code: u8,
    ) -> Result<AuditEvent, AuditError> {
        append_event(
            dir,
            AppendEventRequest {
                operation: "source-set".into(),
                phase,
                transaction: tx,
                actor: "djbclark".into(),
                client: ClientFamily::Hermes,
                reason_sha256: Some(sha256_hex(b"rotate integration credential")),
                command_basename: Some("curl".into()),
                names: vec!["EXAMPLE_KEY".into()],
                result_code: Some(code),
                expected_uid: Some(unsafe { libc::getuid() }),
            },
        )
    }

    // -----------------------------------------------------------------------
    // 1. attempt + success transactional + value-free
    // -----------------------------------------------------------------------
    #[test]
    fn attempt_and_success_transactional_value_free() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = protected_dir(tmp.path());
        let tx = uuid::Uuid::new_v4();

        let first = attempt(&dir, tx).expect("attempt");
        let second = terminal(&dir, tx, Outcome::Success, 0).expect("success");

        assert_eq!(first.client, ClientFamily::Hermes);
        assert_eq!(second.previous_hash, first.event_hash);

        let raw = fs::read(dir.join(DB_NAME)).unwrap();
        assert!(!window_contains("rotate integration credential", &raw));
        assert!(!window_contains("hermes:topic", &raw));
        assert!(!window_contains("Authorization: ***", &raw));
        assert!(window_contains("EXAMPLE_KEY", &raw));

        let meta = fs::metadata(dir.join(DB_NAME)).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);

        let result = verify(&dir, Some(unsafe { libc::getuid() })).unwrap();
        assert_eq!(result.count, 2);
        assert_eq!(result.hash, second.event_hash);
    }

    // -----------------------------------------------------------------------
    // 2. unknown outcome is a distinct terminal phase
    // -----------------------------------------------------------------------
    #[test]
    fn unknown_outcome_distinct_terminal() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = protected_dir(tmp.path());
        let tx = uuid::Uuid::new_v4();

        attempt(&dir, tx).unwrap();
        let unknown = terminal(&dir, tx, Outcome::Unknown, 125).unwrap();
        assert_eq!(unknown.phase, Outcome::Unknown);
        assert_eq!(unknown.result_code, Some(125));

        let result = verify(&dir, Some(unsafe { libc::getuid() })).unwrap();
        assert_eq!(result.count, 2);
    }

    // -----------------------------------------------------------------------
    // 3. free-form reason & argv never persist
    // -----------------------------------------------------------------------
    #[test]
    fn free_form_reason_never_persists() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = protected_dir(tmp.path());

        let secretish = "Authorization: Bearer ***";
        let hash = sha256_hex(secretish.as_bytes());

        append_event(
            &dir,
            AppendEventRequest {
                operation: "source-set".into(),
                phase: Outcome::Attempt,
                transaction: uuid::Uuid::new_v4(),
                actor: "djbclark".into(),
                client: ClientFamily::Hermes,
                reason_sha256: Some(hash),
                command_basename: Some("curl".into()),
                names: vec!["EXAMPLE_KEY".into()],
                result_code: None,
                expected_uid: Some(unsafe { libc::getuid() }),
            },
        )
        .unwrap();

        let raw = fs::read(dir.join(DB_NAME)).unwrap();
        assert!(!window_contains(secretish, &raw));
        assert!(!window_contains("credential-value", &raw));
        assert!(window_contains("curl", &raw));
    }

    // -----------------------------------------------------------------------
    // 4. interrupted attempt remains visible
    // -----------------------------------------------------------------------
    #[test]
    fn interrupted_attempt_visible() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = protected_dir(tmp.path());

        attempt(&dir, uuid::Uuid::new_v4()).unwrap();
        let result = verify(&dir, Some(unsafe { libc::getuid() })).unwrap();
        assert_eq!(result.count, 1);
    }

    // -----------------------------------------------------------------------
    // 5. bad metadata fails before creating ledger
    // -----------------------------------------------------------------------
    #[test]
    fn bad_metadata_fails_before_creating_ledger() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = protected_dir(tmp.path());

        // Bad secret name
        let r = append_event(
            &dir,
            AppendEventRequest {
                operation: "source-set".into(),
                phase: Outcome::Attempt,
                transaction: uuid::Uuid::new_v4(),
                actor: "djbclark".into(),
                client: ClientFamily::Hermes,
                reason_sha256: Some(sha256_hex(b"test")),
                command_basename: None,
                names: vec!["BAD-NAME".into()],
                result_code: None,
                expected_uid: Some(unsafe { libc::getuid() }),
            },
        );
        assert!(r.is_err());
        assert!(!dir.join(DB_NAME).exists());

        // Bad command basename
        let r = append_event(
            &dir,
            AppendEventRequest {
                operation: "source-set".into(),
                phase: Outcome::Attempt,
                transaction: uuid::Uuid::new_v4(),
                actor: "djbclark".into(),
                client: ClientFamily::Hermes,
                reason_sha256: Some(sha256_hex(b"test")),
                command_basename: Some("bad\ncommand".into()),
                names: vec!["EXAMPLE_KEY".into()],
                result_code: None,
                expected_uid: Some(unsafe { libc::getuid() }),
            },
        );
        assert!(r.is_err());
    }

    // -----------------------------------------------------------------------
    // 6. symlink ledger rejected
    // -----------------------------------------------------------------------
    #[test]
    fn symlink_ledger_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = protected_dir(tmp.path());

        let target = tmp.path().join("target");
        fs::write(&target, "unchanged").unwrap();
        std::os::unix::fs::symlink(&target, dir.join(DB_NAME)).unwrap();

        let r = attempt(&dir, uuid::Uuid::new_v4());
        assert!(r.is_err());
        assert_eq!(fs::read_to_string(&target).unwrap(), "unchanged");
    }

    // -----------------------------------------------------------------------
    // 7. wrong directory / ledger mode rejected
    // -----------------------------------------------------------------------
    #[test]
    fn wrong_directory_mode_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = protected_dir(tmp.path());
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(attempt(&dir, uuid::Uuid::new_v4()).is_err());
    }

    #[test]
    fn wrong_ledger_mode_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = protected_dir(tmp.path());

        let ledger = dir.join(DB_NAME);
        {
            let conn = Connection::open(&ledger).unwrap();
            conn.execute_batch(
                "CREATE TABLE t(x); PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;",
            )
            .unwrap();
        }
        fs::set_permissions(&ledger, fs::Permissions::from_mode(0o644)).unwrap();

        assert!(attempt(&dir, uuid::Uuid::new_v4()).is_err());
    }

    // -----------------------------------------------------------------------
    // 8. terminal event requires result code
    // -----------------------------------------------------------------------
    #[test]
    fn terminal_event_requires_result_code() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = protected_dir(tmp.path());

        // Failure without result code
        let r = append_event(
            &dir,
            AppendEventRequest {
                operation: "source-set".into(),
                phase: Outcome::Failure,
                transaction: uuid::Uuid::new_v4(),
                actor: "djbclark".into(),
                client: ClientFamily::Hermes,
                reason_sha256: Some(sha256_hex(b"test")),
                command_basename: None,
                names: vec!["EXAMPLE_KEY".into()],
                result_code: None,
                expected_uid: Some(unsafe { libc::getuid() }),
            },
        );
        assert!(r.is_err());

        // Attempt with result code
        let r = append_event(
            &dir,
            AppendEventRequest {
                operation: "source-set".into(),
                phase: Outcome::Attempt,
                transaction: uuid::Uuid::new_v4(),
                actor: "djbclark".into(),
                client: ClientFamily::Hermes,
                reason_sha256: Some(sha256_hex(b"test")),
                command_basename: None,
                names: vec!["EXAMPLE_KEY".into()],
                result_code: Some(1),
                expected_uid: Some(unsafe { libc::getuid() }),
            },
        );
        assert!(r.is_err());
    }

    // -----------------------------------------------------------------------
    // 9. chain verification detects tampering
    // -----------------------------------------------------------------------
    #[test]
    fn chain_verification_detects_tampering() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = protected_dir(tmp.path());

        attempt(&dir, uuid::Uuid::new_v4()).unwrap();

        let conn = Connection::open(dir.join(DB_NAME)).unwrap();
        conn.execute(
            "UPDATE events SET operation='source-get' WHERE sequence=1",
            [],
        )
        .unwrap();

        assert!(verify(&dir, Some(unsafe { libc::getuid() })).is_err());
    }

    // -----------------------------------------------------------------------
    // 10. event + head atomic rollback
    // -----------------------------------------------------------------------
    #[test]
    fn event_and_head_rollback_together() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = protected_dir(tmp.path());
        let tx = uuid::Uuid::new_v4();

        attempt(&dir, tx).unwrap();

        // Inject trigger that rejects head updates
        let conn = Connection::open(dir.join(DB_NAME)).unwrap();
        conn.execute_batch(
            "CREATE TRIGGER reject_head BEFORE UPDATE ON head BEGIN SELECT RAISE(ABORT, 'fault injection'); END;",
        ).unwrap();

        let r = terminal(&dir, tx, Outcome::Success, 0);
        assert!(r.is_err());

        let result = verify(&dir, Some(unsafe { libc::getuid() })).unwrap();
        assert_eq!(result.count, 1, "only attempt should remain after rollback");
    }

    // -----------------------------------------------------------------------
    // 11. verify empty/absent ledger
    // -----------------------------------------------------------------------
    #[test]
    fn verify_empty_ledger() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = protected_dir(tmp.path());
        let result = verify(&dir, Some(unsafe { libc::getuid() })).unwrap();
        assert_eq!(result.count, 0);
        assert_eq!(result.hash, ZERO_HASH);
    }

    // -----------------------------------------------------------------------
    // 12. reason SHA-256 validation
    // -----------------------------------------------------------------------
    #[test]
    fn reason_sha256_must_be_valid() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = protected_dir(tmp.path());

        // Invalid hex
        let r = append_event(
            &dir,
            AppendEventRequest {
                operation: "source-set".into(),
                phase: Outcome::Attempt,
                transaction: uuid::Uuid::new_v4(),
                actor: "djbclark".into(),
                client: ClientFamily::Hermes,
                reason_sha256: Some("not-a-valid-sha256-hash".into()),
                command_basename: None,
                names: vec!["EXAMPLE_KEY".into()],
                result_code: None,
                expected_uid: Some(unsafe { libc::getuid() }),
            },
        );
        assert!(r.is_err());

        // Missing reason
        let r = append_event(
            &dir,
            AppendEventRequest {
                operation: "source-set".into(),
                phase: Outcome::Attempt,
                transaction: uuid::Uuid::new_v4(),
                actor: "djbclark".into(),
                client: ClientFamily::Hermes,
                reason_sha256: None,
                command_basename: None,
                names: vec!["EXAMPLE_KEY".into()],
                result_code: None,
                expected_uid: Some(unsafe { libc::getuid() }),
            },
        );
        assert!(r.is_err());
    }

    // -----------------------------------------------------------------------
    // 13. operation validation
    // -----------------------------------------------------------------------
    #[test]
    fn operation_must_match_pattern() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = protected_dir(tmp.path());
        let r = append_event(
            &dir,
            AppendEventRequest {
                operation: "INVALID".into(),
                phase: Outcome::Attempt,
                transaction: uuid::Uuid::new_v4(),
                actor: "djbclark".into(),
                client: ClientFamily::Hermes,
                reason_sha256: Some(sha256_hex(b"test")),
                command_basename: None,
                names: vec!["EXAMPLE_KEY".into()],
                result_code: None,
                expected_uid: Some(unsafe { libc::getuid() }),
            },
        );
        assert!(r.is_err());
    }

    // -----------------------------------------------------------------------
    // 14. nil UUID accepted
    // -----------------------------------------------------------------------
    #[test]
    fn nil_uuid_accepted() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = protected_dir(tmp.path());
        let r = append_event(
            &dir,
            AppendEventRequest {
                operation: "source-set".into(),
                phase: Outcome::Attempt,
                transaction: uuid::Uuid::nil(),
                actor: "djbclark".into(),
                client: ClientFamily::Hermes,
                reason_sha256: Some(sha256_hex(b"test")),
                command_basename: None,
                names: vec!["EXAMPLE_KEY".into()],
                result_code: None,
                expected_uid: Some(unsafe { libc::getuid() }),
            },
        );
        assert!(r.is_ok());
    }

    // -----------------------------------------------------------------------
    // 15. names sorted and validated
    // -----------------------------------------------------------------------
    #[test]
    fn names_sorted_and_validated() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = protected_dir(tmp.path());
        let event = append_event(
            &dir,
            AppendEventRequest {
                operation: "source-set".into(),
                phase: Outcome::Attempt,
                transaction: uuid::Uuid::new_v4(),
                actor: "djbclark".into(),
                client: ClientFamily::Hermes,
                reason_sha256: Some(sha256_hex(b"test")),
                command_basename: None,
                names: vec!["Z_KEY".into(), "A_KEY".into()],
                result_code: None,
                expected_uid: Some(unsafe { libc::getuid() }),
            },
        )
        .unwrap();
        assert_eq!(event.names, vec!["A_KEY", "Z_KEY"]);
    }

    // -----------------------------------------------------------------------
    // 16. owner mismatch rejected on verify
    // -----------------------------------------------------------------------
    #[test]
    fn owner_mismatch_rejected_on_verify() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = protected_dir(tmp.path());

        attempt(&dir, uuid::Uuid::new_v4()).unwrap();

        let wrong_uid = if unsafe { libc::getuid() } == 0 { 1 } else { 0 };
        if unsafe { libc::getuid() } != 0 {
            assert!(verify(&dir, Some(wrong_uid)).is_err());
        }
    }

    // -----------------------------------------------------------------------
    // 17. multiple transactions chain correctly
    // -----------------------------------------------------------------------
    #[test]
    fn multiple_transactions_chain_correctly() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = protected_dir(tmp.path());

        let tx1 = uuid::Uuid::new_v4();
        let e1 = attempt(&dir, tx1).unwrap();
        let e2 = terminal(&dir, tx1, Outcome::Success, 0).unwrap();
        assert_eq!(e2.previous_hash, e1.event_hash);

        let tx2 = uuid::Uuid::new_v4();
        let e3 = attempt(&dir, tx2).unwrap();
        assert_eq!(e3.previous_hash, e2.event_hash);
        let e4 = terminal(&dir, tx2, Outcome::Failure, 1).unwrap();
        assert_eq!(e4.previous_hash, e3.event_hash);

        let tx3 = uuid::Uuid::new_v4();
        let e5 = attempt(&dir, tx3).unwrap();
        assert_eq!(e5.previous_hash, e4.event_hash);
        let e6 = terminal(&dir, tx3, Outcome::Unknown, 127).unwrap();
        assert_eq!(e6.previous_hash, e5.event_hash);

        let result = verify(&dir, Some(unsafe { libc::getuid() })).unwrap();
        assert_eq!(result.count, 6);
        assert_eq!(result.hash, e6.event_hash);
    }

    // -----------------------------------------------------------------------
    // 18. SQLite integrity check passes on verify
    // -----------------------------------------------------------------------
    #[test]
    fn sqlite_integrity_check_passes() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = protected_dir(tmp.path());

        attempt(&dir, uuid::Uuid::new_v4()).unwrap();
        assert!(verify(&dir, Some(unsafe { libc::getuid() })).is_ok());
    }

    // -----------------------------------------------------------------------
    // 19. duplicate names are deduplicated
    // -----------------------------------------------------------------------
    #[test]
    fn duplicate_names_deduplicated() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = protected_dir(tmp.path());

        let event = append_event(
            &dir,
            AppendEventRequest {
                operation: "source-set".into(),
                phase: Outcome::Attempt,
                transaction: uuid::Uuid::new_v4(),
                actor: "djbclark".into(),
                client: ClientFamily::Hermes,
                reason_sha256: Some(sha256_hex(b"test")),
                command_basename: None,
                names: vec!["A_KEY".into(), "A_KEY".into()],
                result_code: None,
                expected_uid: Some(unsafe { libc::getuid() }),
            },
        )
        .unwrap();
        assert_eq!(event.names, vec!["A_KEY"]);
    }

    // -----------------------------------------------------------------------
    // 20. all valid client families accepted
    // -----------------------------------------------------------------------
    #[test]
    fn all_valid_client_families_accepted() {
        let tmp = tempfile::tempdir().unwrap();

        for client_str in &[
            "hermes",
            "claude",
            "codex",
            "opencode",
            "cursor",
            "agy",
            "fixed-consumer",
            "unknown",
        ] {
            let dir = protected_dir(&tmp.path().join(client_str));
            let client = ClientFamily::from_label(client_str).unwrap();
            let r = append_event(
                &dir,
                AppendEventRequest {
                    operation: "source-set".into(),
                    phase: Outcome::Attempt,
                    transaction: uuid::Uuid::new_v4(),
                    actor: "djbclark".into(),
                    client,
                    reason_sha256: Some(sha256_hex(b"test")),
                    command_basename: None,
                    names: vec!["EXAMPLE_KEY".into()],
                    result_code: None,
                    expected_uid: Some(unsafe { libc::getuid() }),
                },
            );
            assert!(r.is_ok(), "client '{client_str}' should be accepted");
        }
    }

    // --- bounded waiting on the write lock (issue #4) ----------------------
    //
    // One broker stalled while it held the ledger's write lock, and every other
    // call failed with "database is locked" while `doctor` said OK. These cover
    // the bound on waiting, the error that comes out of it, and the probe
    // `doctor` uses to see the holder.

    use super::test_support::{Hold, ProcessLock, ThreadLock};
    use std::time::Instant;

    fn attempt_request(tx: uuid::Uuid) -> AppendEventRequest {
        AppendEventRequest {
            operation: "source-get".into(),
            phase: Outcome::Attempt,
            transaction: tx,
            actor: "djbclark".into(),
            client: ClientFamily::Hermes,
            reason_sha256: Some(sha256_hex(b"poll the forgejo api")),
            command_basename: None,
            names: vec!["FORGEJO_TOKEN".into()],
            result_code: None,
            expected_uid: Some(unsafe { libc::getuid() }),
        }
    }

    fn event_count(dir: &Path) -> i64 {
        Connection::open(dir.join(DB_NAME))
            .unwrap()
            .query_row("SELECT count(*) FROM events", [], |row| row.get(0))
            .unwrap()
    }

    #[test]
    fn connections_carry_an_explicit_busy_timeout() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = protected_dir(tmp.path());
        let uid = Some(unsafe { libc::getuid() });
        attempt(&dir, uuid::Uuid::new_v4()).unwrap();

        let busy_ms = |mode| {
            let conn = open_connection(&dir, DB_NAME, uid, mode, busy_timeout_for(mode)).unwrap();
            conn.query_row("PRAGMA busy_timeout", [], |row| row.get::<_, i64>(0))
                .unwrap()
        };
        assert_eq!(busy_ms(VerifyMode::ReadWrite), 30_000, "broker writers");
        assert_eq!(busy_ms(VerifyMode::ReadOnly), 5_000, "doctor and drift");
    }

    #[test]
    fn a_busy_sqlite_error_becomes_the_retry_error() {
        let busy = rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY),
            None,
        );
        assert!(is_busy(&busy));
        let err = AuditError::from(busy);
        assert!(matches!(err, AuditError::Busy));
        let text = err.to_string();
        assert!(text.contains("database is locked"), "{text}");
        assert!(text.contains("retry"), "{text}");

        let other = rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CONSTRAINT),
            None,
        );
        assert!(!is_busy(&other));
        assert!(matches!(AuditError::from(other), AuditError::Database(_)));
    }

    #[test]
    fn an_append_waits_out_a_held_write_lock_and_then_succeeds() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = protected_dir(tmp.path());
        attempt(&dir, uuid::Uuid::new_v4()).unwrap();

        // A second connection takes the write lock and lets go 600 ms later.
        let held = ThreadLock::hold(&dir.join(DB_NAME));
        let releaser = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(600));
            held.release();
        });

        let started = Instant::now();
        let event = append_event_waiting(
            &dir,
            attempt_request(uuid::Uuid::new_v4()),
            Duration::from_secs(30),
        )
        .expect("contention must be waited out, not reported as a failure");
        let waited = started.elapsed();
        releaser.join().unwrap();

        assert!(
            waited >= Duration::from_millis(300),
            "returned after {waited:?}: the append never waited for the lock it was blocked on"
        );
        assert_eq!(event.sequence, 2);
        let result = verify(&dir, Some(unsafe { libc::getuid() })).unwrap();
        assert_eq!(result.count, 2);
        assert_eq!(result.hash, event.event_hash);
    }

    #[test]
    fn an_append_gives_up_after_the_bound_with_a_clear_error_and_writes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = protected_dir(tmp.path());
        attempt(&dir, uuid::Uuid::new_v4()).unwrap();
        let held = ThreadLock::hold(&dir.join(DB_NAME));

        let bound = Duration::from_millis(400);
        let started = Instant::now();
        let err = append_event_waiting(&dir, attempt_request(uuid::Uuid::new_v4()), bound)
            .expect_err("the lock is held for the whole call, so this cannot succeed");
        let waited = started.elapsed();

        assert!(matches!(err, AuditError::Busy), "{err}");
        let text = err.to_string();
        assert!(text.contains("database is locked"), "{text}");
        assert!(text.contains("retry"), "{text}");
        assert!(
            waited >= bound / 2,
            "gave up after {waited:?}, well inside the {bound:?} bound"
        );
        assert!(
            waited < Duration::from_secs(20),
            "took {waited:?} to honour a {bound:?} bound"
        );

        // Fail-closed: nothing was appended, and the chain is untouched.
        held.release();
        assert_eq!(event_count(&dir), 1);
        assert_eq!(
            verify(&dir, Some(unsafe { libc::getuid() })).unwrap().count,
            1
        );

        // And the ledger is usable the moment the holder lets go.
        let event = append_event_waiting(&dir, attempt_request(uuid::Uuid::new_v4()), bound)
            .expect("the lock is free again");
        assert_eq!(event.sequence, 2);
    }

    #[test]
    fn an_append_still_refuses_a_ledger_whose_history_was_altered() {
        // Verification moved out of the write transaction. It must still run,
        // and still stop the append, before anything is written.
        let tmp = tempfile::tempdir().unwrap();
        let dir = protected_dir(tmp.path());
        let tx = uuid::Uuid::new_v4();
        attempt(&dir, tx).unwrap();
        terminal(&dir, tx, Outcome::Success, 0).unwrap();

        let conn = Connection::open(dir.join(DB_NAME)).unwrap();
        conn.execute(
            "UPDATE events SET operation='source-get' WHERE sequence=1",
            [],
        )
        .unwrap();
        drop(conn);

        let err = attempt(&dir, uuid::Uuid::new_v4()).expect_err("must fail closed");
        assert!(matches!(err, AuditError::Denied(_)), "{err}");
        assert_eq!(event_count(&dir), 2, "a refused append must add nothing");
    }

    #[test]
    fn an_append_still_checks_the_head_row_under_the_lock() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = protected_dir(tmp.path());
        attempt(&dir, uuid::Uuid::new_v4()).unwrap();

        let conn = Connection::open(dir.join(DB_NAME)).unwrap();
        conn.execute("UPDATE head SET sequence = 99 WHERE singleton = 1", [])
            .unwrap();
        drop(conn);

        let err = attempt(&dir, uuid::Uuid::new_v4()).expect_err("a wrong head must fail closed");
        assert!(err.to_string().contains("head"), "{err}");
        assert_eq!(event_count(&dir), 1);
    }

    #[test]
    fn chunked_verification_agrees_with_one_pass_at_every_boundary() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = protected_dir(tmp.path());
        let uid = Some(unsafe { libc::getuid() });
        let mut hashes = vec![ZERO_HASH.to_string()];
        for _ in 0..7 {
            hashes.push(attempt(&dir, uuid::Uuid::new_v4()).unwrap().event_hash);
        }
        let conn =
            open_connection(&dir, DB_NAME, uid, VerifyMode::ReadOnly, READ_BUSY_TIMEOUT).unwrap();

        for chunk in [1, 2, 3, 7, 8, 100] {
            let (tip, sequence) =
                verify_chain_in_chunks(&conn, 0, ZERO_HASH.to_string(), chunk).unwrap();
            assert_eq!(
                (tip.as_str(), sequence),
                (hashes[7].as_str(), 7),
                "chunk size {chunk}"
            );
        }

        // Resuming from an already verified point reaches the same tip: this is
        // what an append does under its lock.
        let (tip, sequence) = verify_chain_in_chunks(&conn, 3, hashes[3].clone(), 2).unwrap();
        assert_eq!((tip, sequence), (hashes[7].clone(), 7));

        // With nothing after the starting point the inputs come back unchanged.
        let (tip, sequence) = verify_chain_in_chunks(&conn, 7, hashes[7].clone(), 2).unwrap();
        assert_eq!((tip, sequence), (hashes[7].clone(), 7));

        // A starting hash that does not match what follows is caught, not trusted.
        let err = verify_chain_in_chunks(&conn, 3, ZERO_HASH.to_string(), 2).unwrap_err();
        assert!(matches!(err, AuditError::Denied(_)), "{err}");
    }

    #[test]
    fn concurrent_appenders_all_land_and_the_chain_stays_valid() {
        // Several brokers arriving together: each verifies, then the writes
        // serialise, and whoever lost the race re-checks only what landed since.
        let tmp = tempfile::tempdir().unwrap();
        let dir = protected_dir(tmp.path());
        attempt(&dir, uuid::Uuid::new_v4()).unwrap();

        let workers: Vec<_> = (0..3)
            .map(|_| {
                let dir = dir.clone();
                std::thread::spawn(move || {
                    for _ in 0..4 {
                        append_event(&dir, attempt_request(uuid::Uuid::new_v4()))
                            .expect("an append under contention must wait, not fail");
                    }
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }

        let result = verify(&dir, Some(unsafe { libc::getuid() })).unwrap();
        assert_eq!(result.count, 13);
    }

    #[test]
    fn the_probe_names_the_process_holding_the_write_lock_until_it_lets_go() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = protected_dir(tmp.path());
        attempt(&dir, uuid::Uuid::new_v4()).unwrap();
        let db = dir.join(DB_NAME);

        assert_eq!(write_lock_holder(&db).unwrap(), None, "an idle ledger");

        let holder = ProcessLock::hold(&db, Hold::Write);
        assert_eq!(write_lock_holder(&db).unwrap(), Some(holder.pid()));
        // Probing must not disturb the holder or the ledger.
        assert_eq!(write_lock_holder(&db).unwrap(), Some(holder.pid()));
        holder.release();

        assert_eq!(write_lock_holder(&db).unwrap(), None, "after it let go");
        assert_eq!(event_count(&dir), 1);
    }

    #[test]
    fn a_reader_is_not_a_stuck_writer_though_it_does_block_commits() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = protected_dir(tmp.path());
        attempt(&dir, uuid::Uuid::new_v4()).unwrap();
        let db = dir.join(DB_NAME);

        let reader = ProcessLock::hold(&db, Hold::Read);
        assert_eq!(
            write_lock_holder(&db).unwrap(),
            None,
            "a shared lock is not the write lock"
        );

        // Control: the reader really does hold a lock. In rollback-journal mode
        // that keeps a writer's COMMIT out, so a probe that reported "some lock
        // is held" would flag every doctor run that overlaps a reader.
        let err = append_event_waiting(&dir, attempt_request(uuid::Uuid::new_v4()), Duration::ZERO)
            .expect_err("the commit cannot take its exclusive lock past a reader");
        assert!(matches!(err, AuditError::Busy), "{err}");
        reader.release();
        assert_eq!(event_count(&dir), 1);
    }

    #[test]
    fn the_probe_has_nothing_to_say_about_an_absent_ledger_and_refuses_a_symlink() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = protected_dir(tmp.path());
        let db = dir.join(DB_NAME);
        assert_eq!(write_lock_holder(&db).unwrap(), None);

        attempt(&dir, uuid::Uuid::new_v4()).unwrap();
        let link = dir.join("link.sqlite3");
        std::os::unix::fs::symlink(&db, &link).unwrap();
        assert!(
            write_lock_holder(&link).is_err(),
            "a symlinked ledger must not be followed by a root-run probe"
        );
    }
}
