//! Infinite secret history for the sudo-secretspec privilege boundary.
//!
//! The boundary snapshots the manifest before every mutating operation.
//! (Dotenv and values are now managed by the provider, not the boundary).
//!
//! ## Chain
//!
//! Entries are hash-chained exactly as [`crate::audit`] chains events.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use rusqlite::{Connection, OptionalExtension};

use crate::audit::{self, AuditError, VerifyMode, ZERO_HASH, sha256_hex};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const DB_NAME: &str = "broker-history.sqlite3";

const MAX_CAPTURE_BYTES: usize = 16 * 1024 * 1024;

/// Rows fetched per statement while verifying. Small, because each row carries
/// a whole captured manifest.
const VERIFY_CHUNK_ROWS: usize = 32;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum HistoryError {
    #[error("history denied: {0}")]
    Denied(String),

    /// Another process held the store's lock for longer than the busy timeout.
    /// See [`AuditError::Busy`]; the wording is shared on purpose.
    #[error(
        "database is locked: another broker call is holding the history store and did not release it in time; retry shortly"
    )]
    Busy,

    #[error("database error: {0}")]
    Database(rusqlite::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<rusqlite::Error> for HistoryError {
    fn from(error: rusqlite::Error) -> Self {
        if audit::is_busy(&error) {
            HistoryError::Busy
        } else {
            HistoryError::Database(error)
        }
    }
}

impl From<AuditError> for HistoryError {
    fn from(error: AuditError) -> Self {
        match error {
            AuditError::Denied(message) => HistoryError::Denied(message),
            AuditError::Busy => HistoryError::Busy,
            AuditError::Database(error) => HistoryError::Database(error),
            AuditError::Io(error) => HistoryError::Io(error),
        }
    }
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct CaptureRequest {
    pub transaction: uuid::Uuid,
    pub operation: String,
    pub manifest: Vec<u8>,
    pub expected_uid: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct Entry {
    pub sequence: i64,
    pub timestamp_ns: i64,
    pub transaction: uuid::Uuid,
    pub operation: String,
    pub manifest_sha256: String,
    pub previous_hash: String,
    pub entry_hash: String,
}

#[derive(Debug, Clone)]
pub struct EntrySummary {
    pub sequence: i64,
    pub timestamp_ns: i64,
    pub transaction: uuid::Uuid,
    pub operation: String,
}

#[derive(Debug, Clone)]
pub struct VerifyResult {
    pub entries: u64,
    pub hash: String,
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

fn ensure_schema(conn: &Connection) -> Result<(), HistoryError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS entries (\
           sequence        INTEGER PRIMARY KEY AUTOINCREMENT,\
           timestamp_ns    INTEGER NOT NULL,\
           transaction_id  TEXT    NOT NULL,\
           operation       TEXT    NOT NULL,\
           manifest_blob   BLOB    NOT NULL,\
           manifest_sha256 TEXT    NOT NULL,\
           previous_hash   TEXT    NOT NULL,\
           entry_hash      TEXT    NOT NULL UNIQUE\
         ) STRICT;\
         CREATE TABLE IF NOT EXISTS head (\
           singleton  INTEGER PRIMARY KEY CHECK (singleton = 1),\
           sequence   INTEGER NOT NULL,\
           entry_hash TEXT    NOT NULL\
         ) STRICT;",
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Canonical serialisation
// ---------------------------------------------------------------------------

fn canonical_entry_json(entry: &Entry) -> String {
    let mut map = BTreeMap::new();
    map.insert("sequence", serde_json::Value::Number(entry.sequence.into()));
    map.insert(
        "timestamp_ns",
        serde_json::Value::Number(entry.timestamp_ns.into()),
    );
    map.insert(
        "transaction",
        serde_json::Value::String(entry.transaction.to_string()),
    );
    map.insert(
        "operation",
        serde_json::Value::String(entry.operation.clone()),
    );
    map.insert(
        "manifest_sha256",
        serde_json::Value::String(entry.manifest_sha256.clone()),
    );
    map.insert(
        "previous_hash",
        serde_json::Value::String(entry.previous_hash.clone()),
    );

    serde_json::to_string(&map).unwrap()
}

fn compute_entry_hash(previous_hash: &str, entry: &Entry) -> String {
    let canonical = canonical_entry_json(entry);
    sha256_hex(format!("{previous_hash}\n{canonical}").as_bytes())
}

// ---------------------------------------------------------------------------
// Chain verification
// ---------------------------------------------------------------------------

/// One `entries` row exactly as stored, before any check has run on it.
type RawEntry = (
    i64,     // sequence
    i64,     // timestamp_ns
    String,  // transaction_id
    String,  // operation
    Vec<u8>, // manifest_blob
    String,  // manifest_sha256
    String,  // previous_hash
    String,  // entry_hash
);

fn read_raw_entry(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawEntry> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
    ))
}

/// Fetch up to `limit` entries numbered after `after`, in order, and finish the
/// statement before returning, so the read lock it needed is already released.
fn fetch_entries_after(
    conn: &Connection,
    after: i64,
    limit: usize,
) -> rusqlite::Result<Vec<RawEntry>> {
    let mut stmt = conn.prepare(
        "SELECT sequence, timestamp_ns, transaction_id, operation,\
                manifest_blob, manifest_sha256, previous_hash, entry_hash \
         FROM entries WHERE sequence > ?1 ORDER BY sequence LIMIT ?2",
    )?;
    let rows: Vec<RawEntry> = stmt
        .query_map(rusqlite::params![after, limit as i64], read_raw_entry)?
        .collect::<Result<_, _>>()?;
    Ok(rows)
}

/// Check one entry against the hash of the entry before it. Returns the entry's
/// own hash and sequence, which become the next call's `previous`.
fn check_entry(previous: &str, raw: RawEntry) -> Result<(String, i64), HistoryError> {
    let (
        sequence,
        timestamp_ns,
        transaction_id,
        operation,
        manifest_blob,
        manifest_sha256,
        stored_previous,
        entry_hash,
    ) = raw;

    if sha256_hex(&manifest_blob) != manifest_sha256 {
        return Err(HistoryError::Denied(
            "history manifest does not match its digest".into(),
        ));
    }

    let transaction = uuid::Uuid::parse_str(&transaction_id)
        .map_err(|e| HistoryError::Denied(format!("invalid transaction UUID in history: {e}")))?;

    let entry = Entry {
        sequence,
        timestamp_ns,
        transaction,
        operation,
        manifest_sha256,
        previous_hash: stored_previous.clone(),
        entry_hash: entry_hash.clone(),
    };

    if stored_previous != previous || entry_hash != compute_entry_hash(previous, &entry) {
        return Err(HistoryError::Denied("history chain is invalid".into()));
    }

    Ok((entry_hash, sequence))
}

/// Verify every entry numbered after `after`, chaining from `previous` (the hash
/// of entry `after`, or [`ZERO_HASH`] when `after` is 0). Returns the new tip as
/// `(hash, sequence)`, which is the inputs unchanged when nothing follows.
///
/// Rows are read [`VERIFY_CHUNK_ROWS`] at a time and each statement is finished
/// before its rows are hashed; see [`audit`]'s "Locking" section for why. Called
/// with no transaction open, no lock is held while the hashing runs.
fn verify_chain_after(
    conn: &Connection,
    mut after: i64,
    mut previous: String,
) -> Result<(String, i64), HistoryError> {
    loop {
        let rows = fetch_entries_after(conn, after, VERIFY_CHUNK_ROWS)?;
        let fetched = rows.len();
        for raw in rows {
            let (hash, sequence) = check_entry(&previous, raw)?;
            previous = hash;
            after = sequence;
        }
        if fetched < VERIFY_CHUNK_ROWS {
            return Ok((previous, after));
        }
    }
}

/// Check that the `head` row names the tip the chain actually ended on (or is
/// absent when there are no entries).
fn check_head(conn: &Connection, count: i64, tip_hash: &str) -> Result<(), HistoryError> {
    let head: Option<(i64, String)> = conn
        .query_row(
            "SELECT sequence, entry_hash FROM head WHERE singleton = 1",
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
        return Err(HistoryError::Denied("history head is invalid".into()));
    }
    Ok(())
}

/// Verify the whole chain and the head inside the caller's transaction.
fn verify_rows(conn: &Connection) -> Result<(String, i64), HistoryError> {
    let (previous, count) = verify_chain_after(conn, 0, ZERO_HASH.to_string())?;
    check_head(conn, count, &previous)?;
    Ok((previous, count))
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

pub fn verify(directory: &Path, expected_uid: Option<u32>) -> Result<VerifyResult, HistoryError> {
    verify_with(directory, expected_uid, VerifyMode::ReadWrite)
}

pub fn verify_read_only(
    directory: &Path,
    expected_uid: Option<u32>,
) -> Result<VerifyResult, HistoryError> {
    verify_with(directory, expected_uid, VerifyMode::ReadOnly)
}

fn verify_with(
    directory: &Path,
    expected_uid: Option<u32>,
    mode: VerifyMode,
) -> Result<VerifyResult, HistoryError> {
    if !directory.join(DB_NAME).exists() {
        audit::require_protected_dir(directory, expected_uid)?;
        return Ok(VerifyResult {
            entries: 0,
            hash: ZERO_HASH.into(),
        });
    }

    let conn = audit::open_protected_db(directory, DB_NAME, expected_uid, mode)?;
    let result = (|| -> Result<VerifyResult, HistoryError> {
        if mode == VerifyMode::ReadWrite {
            ensure_schema(&conn)?;
        }
        conn.execute(
            match mode {
                VerifyMode::ReadWrite => "BEGIN IMMEDIATE",
                VerifyMode::ReadOnly => "BEGIN",
            },
            [],
        )?;
        let (hash, count) = verify_rows(&conn)?;

        let integrity: String = conn.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
        if integrity != "ok" {
            return Err(HistoryError::Denied(
                "history integrity check failed".into(),
            ));
        }

        conn.execute("COMMIT", [])?;
        Ok(VerifyResult {
            entries: count as u64,
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

/// Summarise the captured entries. Never returns a captured manifest, only the
/// metadata identifying it.
///
/// There is deliberately no per-name filter. This store archives the *manifest*
/// — declarations, not values — so it has no name to filter on; names live in
/// the provider's own history inside `secrets.db`. The parameter used to exist
/// and was silently discarded, which is the same shape as every defect this
/// module has already produced: an argument a caller can pass, believing it
/// narrows the result, that does nothing. Removing it makes the absence a
/// compile error instead of a wrong answer.
pub fn list(
    directory: &Path,
    expected_uid: Option<u32>,
) -> Result<Vec<EntrySummary>, HistoryError> {
    if !directory.join(DB_NAME).exists() {
        audit::require_protected_dir(directory, expected_uid)?;
        return Ok(Vec::new());
    }

    let conn = audit::open_protected_db(directory, DB_NAME, expected_uid, VerifyMode::ReadOnly)?;
    let result = (|| -> Result<Vec<EntrySummary>, HistoryError> {
        conn.execute("BEGIN", [])?;
        verify_rows(&conn)?;

        let mut stmt = conn.prepare(
            "SELECT sequence, timestamp_ns, transaction_id, operation \
             FROM entries ORDER BY sequence",
        )?;
        let rows: Vec<(i64, i64, String, String)> = stmt
            .query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })?
            .collect::<Result<_, _>>()?;

        let mut out = Vec::new();
        for (sequence, timestamp_ns, transaction_id, operation) in rows {
            let transaction = uuid::Uuid::parse_str(&transaction_id).map_err(|e| {
                HistoryError::Denied(format!("invalid transaction UUID in history: {e}"))
            })?;
            out.push(EntrySummary {
                sequence,
                timestamp_ns,
                transaction,
                operation,
            });
        }

        conn.execute("COMMIT", [])?;
        Ok(out)
    })();

    match result {
        Ok(entries) => Ok(entries),
        Err(e) => {
            let _ = conn.execute("ROLLBACK", []);
            Err(e)
        }
    }
}

/// Archive one manifest. The write lock is held only around the insert: the
/// chain is verified first with no transaction open (see [`audit`]'s "Locking"
/// section). Waits up to [`audit::WRITE_BUSY_TIMEOUT`] for another writer, then
/// fails with [`HistoryError::Busy`] having stored nothing.
pub fn capture(directory: &Path, request: CaptureRequest) -> Result<Entry, HistoryError> {
    capture_waiting(directory, request, audit::WRITE_BUSY_TIMEOUT)
}

/// [`capture`] with the busy timeout given, so a test can show the bound
/// without waiting out the production one.
pub(crate) fn capture_waiting(
    directory: &Path,
    request: CaptureRequest,
    busy_timeout: Duration,
) -> Result<Entry, HistoryError> {
    if request.manifest.len() > MAX_CAPTURE_BYTES {
        return Err(HistoryError::Denied(
            "captured file exceeds the history size limit".into(),
        ));
    }
    if request.operation.is_empty()
        || !request
            .operation
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(HistoryError::Denied("invalid operation".into()));
    }

    let manifest_sha256 = sha256_hex(&request.manifest);

    let conn = audit::open_protected_db_waiting(
        directory,
        DB_NAME,
        request.expected_uid,
        VerifyMode::ReadWrite,
        busy_timeout,
    )?;

    let result = (|| -> Result<Entry, HistoryError> {
        ensure_schema(&conn)?;

        // Verify before locking, and under the lock check only what landed since.
        let (verified_hash, verified_sequence) =
            verify_chain_after(&conn, 0, ZERO_HASH.to_string())?;

        conn.execute("BEGIN IMMEDIATE", [])?;

        let (previous_hash, count) = verify_chain_after(&conn, verified_sequence, verified_hash)?;
        check_head(&conn, count, &previous_hash)?;
        let sequence = count + 1;

        let timestamp_ns = {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| HistoryError::Denied(format!("clock error: {e}")))?;
            now.as_nanos() as i64
        };

        let mut entry = Entry {
            sequence,
            timestamp_ns,
            transaction: request.transaction,
            operation: request.operation.clone(),
            manifest_sha256,
            previous_hash: previous_hash.clone(),
            entry_hash: String::new(),
        };
        entry.entry_hash = compute_entry_hash(&previous_hash, &entry);

        conn.execute(
            "INSERT INTO entries (\
                sequence, timestamp_ns, transaction_id, operation,\
                manifest_blob, manifest_sha256, previous_hash, entry_hash\
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                entry.sequence,
                entry.timestamp_ns,
                entry.transaction.to_string(),
                entry.operation,
                request.manifest,
                entry.manifest_sha256,
                entry.previous_hash,
                entry.entry_hash,
            ],
        )?;

        conn.execute(
            "INSERT INTO head (singleton, sequence, entry_hash) VALUES (1, ?1, ?2) \
             ON CONFLICT(singleton) DO UPDATE SET \
             sequence = excluded.sequence, entry_hash = excluded.entry_hash",
            rusqlite::params![entry.sequence, entry.entry_hash],
        )?;

        conn.execute("COMMIT", [])?;
        Ok(entry)
    })();

    match result {
        Ok(entry) => Ok(entry),
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

    fn vault() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    const MANIFEST: &[u8] = b"[project]\nname = \"fixture\"\nrevision = \"1.0\"\n";

    fn request(transaction: uuid::Uuid) -> CaptureRequest {
        CaptureRequest {
            transaction,
            operation: "source-set".into(),
            manifest: MANIFEST.to_vec(),
            expected_uid: None,
        }
    }

    #[test]
    fn an_absent_store_verifies_as_empty_rather_than_damaged() {
        let dir = vault();
        let result = verify(dir.path(), None).unwrap();
        assert_eq!(result.entries, 0);
        assert_eq!(result.hash, ZERO_HASH);
    }

    #[test]
    fn a_capture_stores_the_manifest_and_advances_the_chain() {
        let dir = vault();
        let entry = capture(dir.path(), request(uuid::Uuid::new_v4())).unwrap();

        assert_eq!(entry.sequence, 1);
        assert_eq!(entry.manifest_sha256, sha256_hex(MANIFEST));

        let result = verify(dir.path(), None).unwrap();
        assert_eq!(result.entries, 1);
        assert_eq!(result.hash, entry.entry_hash);
    }

    // -----------------------------------------------------------------------
    // Tamper evidence
    // -----------------------------------------------------------------------
    //
    // The chain is the entire reason this store is not a plain table, and none
    // of what follows was covered. `audit.rs` has the analogous tests; this
    // module had two, neither of which altered a row. A hash chain nothing ever
    // tries to break is an assertion, not a guarantee.

    /// Capture `count` entries and return the open connection to the store, so
    /// a test can corrupt exactly one row and re-verify.
    fn captured(dir: &std::path::Path, count: usize) -> Connection {
        for _ in 0..count {
            capture(dir, request(uuid::Uuid::new_v4())).unwrap();
        }
        Connection::open(dir.join(DB_NAME)).unwrap()
    }

    fn denied(result: Result<VerifyResult, HistoryError>) -> String {
        match result {
            Err(HistoryError::Denied(message)) => message,
            other => panic!("expected a denial, got {other:?}"),
        }
    }

    #[test]
    fn an_edited_manifest_is_caught_by_its_own_digest() {
        // The blob and its digest are stored side by side, so rewriting the
        // archived declarations without also rewriting the digest is the
        // cheapest possible tamper. It must not survive.
        let dir = vault();
        let conn = captured(dir.path(), 2);
        conn.execute(
            "UPDATE entries SET manifest_blob = ?1 WHERE sequence = 1",
            rusqlite::params![&b"[project]\nname = \"forged\"\n"[..]],
        )
        .unwrap();
        drop(conn);

        assert_eq!(
            denied(verify(dir.path(), None)),
            "history manifest does not match its digest"
        );
    }

    #[test]
    fn rewriting_a_manifest_and_its_digest_together_still_breaks_the_chain() {
        // The previous test's tamper is defeated by updating both columns — so
        // this is the one that matters. `entry_hash` covers `manifest_sha256`,
        // which is what makes a consistent-looking row still detectable.
        let dir = vault();
        let conn = captured(dir.path(), 2);
        let forged = b"[project]\nname = \"forged\"\n";
        conn.execute(
            "UPDATE entries SET manifest_blob = ?1, manifest_sha256 = ?2 WHERE sequence = 1",
            rusqlite::params![&forged[..], sha256_hex(forged)],
        )
        .unwrap();
        drop(conn);

        assert_eq!(denied(verify(dir.path(), None)), "history chain is invalid");
    }

    #[test]
    fn deleting_an_entry_from_the_middle_breaks_the_chain() {
        // Removal, not alteration: the surviving successor still records the
        // deleted entry's hash as its predecessor, so the chain no longer links
        // up. This is what makes the history append-only in practice rather
        // than by convention.
        let dir = vault();
        let conn = captured(dir.path(), 3);
        conn.execute("DELETE FROM entries WHERE sequence = 2", [])
            .unwrap();
        drop(conn);

        assert_eq!(denied(verify(dir.path(), None)), "history chain is invalid");
    }

    #[test]
    fn truncating_the_newest_entry_is_caught_by_the_head() {
        // Deleting from the *end* leaves a chain that verifies row by row —
        // every remaining entry still links to its predecessor. Only the head
        // pointer, recorded separately, still names the entry that is gone.
        // Without that check, discarding recent history would be undetectable.
        let dir = vault();
        let conn = captured(dir.path(), 3);
        conn.execute("DELETE FROM entries WHERE sequence = 3", [])
            .unwrap();
        drop(conn);

        assert_eq!(denied(verify(dir.path(), None)), "history head is invalid");
    }

    #[test]
    fn moving_the_head_to_hide_a_forged_entry_is_also_caught() {
        // The complement of the previous test: leave the rows alone and rewrite
        // the head instead. Neither half of the pair is sufficient on its own.
        let dir = vault();
        let conn = captured(dir.path(), 2);
        conn.execute(
            "UPDATE head SET sequence = 1, entry_hash = \
             (SELECT entry_hash FROM entries WHERE sequence = 1) WHERE singleton = 1",
            [],
        )
        .unwrap();
        drop(conn);

        assert_eq!(denied(verify(dir.path(), None)), "history head is invalid");
    }

    #[test]
    fn a_tampered_store_refuses_to_list_rather_than_reporting_what_it_holds() {
        // `list` verifies before it reads. A summary of a chain known to be
        // broken would be a report of unproven contents presented as history.
        let dir = vault();
        let conn = captured(dir.path(), 2);
        conn.execute("DELETE FROM entries WHERE sequence = 1", [])
            .unwrap();
        drop(conn);

        assert!(matches!(
            list(dir.path(), None),
            Err(HistoryError::Denied(_))
        ));
    }

    // -----------------------------------------------------------------------
    // Chain continuity and the capture guard
    // -----------------------------------------------------------------------

    #[test]
    fn each_capture_links_to_the_one_before_it() {
        let dir = vault();
        let first = capture(dir.path(), request(uuid::Uuid::new_v4())).unwrap();
        let second = capture(dir.path(), request(uuid::Uuid::new_v4())).unwrap();

        assert_eq!(first.previous_hash, ZERO_HASH);
        assert_eq!(second.previous_hash, first.entry_hash);
        assert_eq!(second.sequence, 2);

        let result = verify(dir.path(), None).unwrap();
        assert_eq!(result.entries, 2);
        assert_eq!(result.hash, second.entry_hash);
    }

    #[test]
    fn list_summarises_every_entry_and_returns_no_captured_bytes() {
        // `EntrySummary` carries no manifest and no digest by construction; this
        // pins that `list` reports the entries in order and identifies each one
        // by the transaction the audit ledger records, which is the only thing
        // joining the two stores.
        let dir = vault();
        let first = uuid::Uuid::new_v4();
        let second = uuid::Uuid::new_v4();
        capture(dir.path(), request(first)).unwrap();
        capture(dir.path(), request(second)).unwrap();

        let entries = list(dir.path(), None).unwrap();

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].sequence, 1);
        assert_eq!(entries[0].transaction, first);
        assert_eq!(entries[1].sequence, 2);
        assert_eq!(entries[1].transaction, second);
        assert!(entries.iter().all(|e| e.operation == "source-set"));
    }

    #[test]
    fn an_absent_store_lists_as_empty_rather_than_failing() {
        assert!(list(vault().path(), None).unwrap().is_empty());
    }

    #[test]
    fn capture_refuses_an_operation_name_it_cannot_vouch_for() {
        // `operation` is written into the canonical JSON the entry hash covers,
        // so it is constrained at the door rather than escaped later.
        let dir = vault();
        for bad in [
            "",
            "source set",
            "SOURCE-SET",
            "source_set",
            "source-set;--",
        ] {
            let mut req = request(uuid::Uuid::new_v4());
            req.operation = bad.into();
            assert!(
                matches!(capture(dir.path(), req), Err(HistoryError::Denied(_))),
                "operation {bad:?} must be refused"
            );
        }
        // Nothing was written by any of the refusals.
        assert_eq!(verify(dir.path(), None).unwrap().entries, 0);
    }

    #[test]
    fn capture_refuses_a_manifest_larger_than_the_limit() {
        let dir = vault();
        let mut req = request(uuid::Uuid::new_v4());
        req.manifest = vec![b'x'; MAX_CAPTURE_BYTES + 1];

        assert!(matches!(
            capture(dir.path(), req),
            Err(HistoryError::Denied(_))
        ));
        assert_eq!(verify(dir.path(), None).unwrap().entries, 0);
    }

    #[test]
    fn read_only_verification_agrees_and_creates_nothing() {
        // `doctor` runs the read-only path. It must not be the thing that brings
        // a store into existence, or a missing history would silently become an
        // empty one the first time anybody looked.
        let dir = vault();
        assert_eq!(verify_read_only(dir.path(), None).unwrap().entries, 0);
        assert!(
            !dir.path().join(DB_NAME).exists(),
            "read-only verification must not create the store"
        );

        let entry = capture(dir.path(), request(uuid::Uuid::new_v4())).unwrap();
        let read_only = verify_read_only(dir.path(), None).unwrap();
        assert_eq!(read_only.entries, 1);
        assert_eq!(read_only.hash, entry.entry_hash);

        let conn = Connection::open(dir.path().join(DB_NAME)).unwrap();
        conn.execute("DELETE FROM entries WHERE sequence = 1", [])
            .unwrap();
        drop(conn);
        assert!(matches!(
            verify_read_only(dir.path(), None),
            Err(HistoryError::Denied(_))
        ));
    }

    #[test]
    fn a_capture_waits_out_a_held_write_lock_and_then_succeeds() {
        use crate::audit::test_support::ThreadLock;

        let dir = vault();
        capture(dir.path(), request(uuid::Uuid::new_v4())).unwrap();

        let held = ThreadLock::hold(&dir.path().join(DB_NAME));
        let releaser = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(600));
            held.release();
        });

        let started = std::time::Instant::now();
        let entry = capture_waiting(
            dir.path(),
            request(uuid::Uuid::new_v4()),
            Duration::from_secs(30),
        )
        .expect("contention must be waited out, not reported as a failure");
        let waited = started.elapsed();
        releaser.join().unwrap();

        assert!(
            waited >= Duration::from_millis(300),
            "returned after {waited:?}: the capture never waited for the lock"
        );
        assert_eq!(entry.sequence, 2);
        let result = verify(dir.path(), None).unwrap();
        assert_eq!(result.entries, 2);
        assert_eq!(result.hash, entry.entry_hash);
    }

    #[test]
    fn a_capture_gives_up_after_the_bound_with_a_clear_error_and_stores_nothing() {
        use crate::audit::test_support::ThreadLock;

        let dir = vault();
        capture(dir.path(), request(uuid::Uuid::new_v4())).unwrap();
        let held = ThreadLock::hold(&dir.path().join(DB_NAME));

        let err = capture_waiting(
            dir.path(),
            request(uuid::Uuid::new_v4()),
            Duration::from_millis(400),
        )
        .expect_err("the lock is held for the whole call, so this cannot succeed");

        assert!(matches!(err, HistoryError::Busy), "{err}");
        let text = err.to_string();
        assert!(text.contains("database is locked"), "{text}");
        assert!(text.contains("retry"), "{text}");

        held.release();
        assert_eq!(verify(dir.path(), None).unwrap().entries, 1);
    }

    #[test]
    fn a_capture_still_refuses_a_store_whose_history_was_altered() {
        // Verification runs before the write lock now. It must still stop the
        // capture before anything is written.
        let dir = vault();
        let conn = captured(dir.path(), 2);
        conn.execute(
            "UPDATE entries SET manifest_blob = ?1 WHERE sequence = 1",
            rusqlite::params![&b"[project]\nname = \"forged\"\n"[..]],
        )
        .unwrap();
        drop(conn);

        let err = capture(dir.path(), request(uuid::Uuid::new_v4()))
            .expect_err("a forged manifest must fail closed");
        assert!(matches!(err, HistoryError::Denied(_)), "{err}");

        let conn = Connection::open(dir.path().join(DB_NAME)).unwrap();
        let rows: i64 = conn
            .query_row("SELECT count(*) FROM entries", [], |row| row.get(0))
            .unwrap();
        assert_eq!(rows, 2, "a refused capture must add nothing");
    }
}
