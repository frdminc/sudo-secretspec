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

    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
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
    open_connection(directory, db_name, expected_uid, mode)
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
// Chain verification (in-transaction)
// ---------------------------------------------------------------------------

/// Verify the chain inside an active read transaction.
/// Returns (last_event_hash, row_count) on success.
fn verify_rows(conn: &Connection) -> Result<(String, i64), AuditError> {
    let mut previous = ZERO_HASH.to_string();
    let mut count: i64 = 0;

    let mut stmt = conn.prepare(
        "SELECT sequence, timestamp_ns, transaction_id, phase, operation,\
                actor, client, reason_sha256, command_basename, names_json,\
                result_code, previous_hash, event_hash \
         FROM events ORDER BY sequence",
    )?;

    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, String>(6)?,
            row.get::<_, String>(7)?,
            row.get::<_, Option<String>>(8)?,
            row.get::<_, String>(9)?,
            row.get::<_, Option<i64>>(10)?,
            row.get::<_, String>(11)?,
            row.get::<_, String>(12)?,
        ))
    })?;

    for row in rows {
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
        ) = row?;

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
        let expected = compute_event_hash(&previous, &event);

        // Validate previous hash link
        if stored_previous != previous {
            return Err(AuditError::Denied("ledger chain is invalid".into()));
        }

        // Validate event hash
        if event_hash != expected {
            return Err(AuditError::Denied("ledger chain is invalid".into()));
        }

        previous = event_hash;
        count = sequence;
    }

    // Check head matches last event (or is absent when no events exist)
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
        Some((count, previous.clone()))
    };

    if head != expected_head {
        return Err(AuditError::Denied("ledger head is invalid".into()));
    }

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

    let conn = open_connection(directory, DB_NAME, expected_uid, mode)?;

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
/// database (fail-closed). The event and head are committed atomically.
pub fn append_event(
    directory: &Path,
    request: AppendEventRequest,
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
    )?;

    let result = (|| -> Result<AuditEvent, AuditError> {
        ensure_schema(&conn)?;
        conn.execute("BEGIN IMMEDIATE", [])?;

        // Verify chain and get previous hash + count
        let (previous_hash, count) = verify_rows(&conn)?;
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

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
}
