//! Read-only backup health and the fixed privileged helper contract.
//!
//! Backups are independent of credential operations: findings are advisory and
//! this module never starts a backup, connects to a mirror, or reads a key.
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path};

use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub const HEALTH_PATH: &str = "/usr/local/var/run/sudo-secretspec-backup/status.json";
pub const HELPER_PATH: &str = "/usr/local/libexec/sudo-secretspec-backup/backup.py";
pub const CONFIG_PATH: &str = "/usr/local/etc/sudo-secretspec-backup.json";
const MAX_HEALTH_BYTES: u64 = 16 * 1024;
const MAX_AGE_SECONDS: i64 = 2 * 60 * 60;

#[derive(Debug, Deserialize, Serialize)]
pub struct Health {
    pub format: u32,
    pub updated_at: String,
    pub last_check_at: Option<String>,
    pub last_snapshot_at: Option<String>,
    pub last_mirror_at: Option<String>,
    pub commit: Option<String>,
    pub mirrored_commit: Option<String>,
    pub capture_error: Option<String>,
    pub mirror_error: Option<String>,
    /// Previously interrupted attempts preserved by an explicit recovery anchor.
    /// Omitted by older helper health records; never inferred from an event's age.
    #[serde(default)]
    pub historical_pending_count: u64,
}

#[derive(Debug)]
pub enum HealthError {
    Missing,
    Invalid,
}

/// Open every component with O_NOFOLLOW, retaining directory descriptors while
/// walking. A final-component-only check could follow an attacker-owned parent.
fn open_protected(path: &Path, expected_uid: u32) -> io::Result<File> {
    if !path.is_absolute() {
        return Err(io::Error::other("absolute protected path required"));
    }
    let parts: Vec<_> = path.components().collect();
    let mut directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")?;
    for (index, component) in parts.iter().enumerate().skip(1) {
        let Component::Normal(name) = component else {
            return Err(io::Error::other("non-normal protected path"));
        };
        let name = std::ffi::CString::new(name.as_encoded_bytes())
            .map_err(|_| io::Error::other("invalid protected path"))?;
        let last = index + 1 == parts.len();
        let flags = libc::O_RDONLY
            | libc::O_NOFOLLOW
            | libc::O_CLOEXEC
            | libc::O_NONBLOCK
            | if last { 0 } else { libc::O_DIRECTORY };
        let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let metadata = file.metadata()?;
        // Tests can name an unprivileged owner; deployed callers always use 0.
        if (metadata.uid() != 0 && metadata.uid() != expected_uid)
            || metadata.mode() & 0o022 != 0
            || (last && !metadata.is_file())
        {
            return Err(io::Error::other("unsafe protected metadata"));
        }
        if last {
            return Ok(file);
        }
        directory = file;
    }
    Err(io::Error::other("protected file required"))
}

pub fn validate_helper_installation() -> Result<(), &'static str> {
    open_protected(Path::new(HELPER_PATH), 0).map_err(
        |_| "backup helper is absent or not root-protected; complete explicit backup setup",
    )?;
    open_protected(Path::new(CONFIG_PATH), 0).map_err(
        |_| "backup configuration is absent or not root-protected; complete explicit backup setup",
    )?;
    Ok(())
}

pub fn read_health() -> Result<Health, HealthError> {
    read_health_at(Path::new(HEALTH_PATH), 0)
}

fn read_health_at(path: &Path, expected_uid: u32) -> Result<Health, HealthError> {
    let file = open_protected(path, expected_uid).map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            HealthError::Missing
        } else {
            HealthError::Invalid
        }
    })?;
    let mut bytes = Vec::new();
    file.take(MAX_HEALTH_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| HealthError::Invalid)?;
    if bytes.len() as u64 > MAX_HEALTH_BYTES {
        return Err(HealthError::Invalid);
    }
    let health: Health = serde_json::from_slice(&bytes).map_err(|_| HealthError::Invalid)?;
    if health.format != 1
        || [&health.capture_error, &health.mirror_error]
            .into_iter()
            .flatten()
            .any(|message| message.len() > 160 || message.chars().any(char::is_control))
    {
        return Err(HealthError::Invalid);
    }
    Ok(health)
}

pub fn valid_commit(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn fresh(timestamp: Option<&str>, now: OffsetDateTime) -> bool {
    timestamp
        .and_then(|s| OffsetDateTime::parse(s, &Rfc3339).ok())
        .is_some_and(|stamp| {
            let age = (now - stamp).whole_seconds();
            (0..=MAX_AGE_SECONDS).contains(&age)
        })
}

/// Fixed diagnostic messages: never echo untrusted strings from a health file.
pub fn findings(health: Result<Health, HealthError>, now: OffsetDateTime) -> Vec<crate::Finding> {
    let mut result = Vec::new();
    let mut add = |code: &str, detail: &str| {
        result.push(crate::Finding {
            code: code.into(),
            detail: detail.into(),
            path: Some(HEALTH_PATH.into()),
            advisory: true,
        });
    };
    let health = match health {
        Ok(health) => health,
        Err(HealthError::Missing) => {
            add(
                "BACKUP_NOT_CONFIGURED",
                "no verified backup health record; complete explicit backup setup (0.21.1-sudo.6+)",
            );
            return result;
        }
        Err(HealthError::Invalid) => {
            add(
                "BACKUP_UNHEALTHY",
                "backup health record has unsafe metadata, unsupported format, or invalid JSON",
            );
            return result;
        }
    };
    let commit_ok = health.commit.as_deref().is_some_and(valid_commit);
    if health.capture_error.is_some() || health.mirror_error.is_some() || !commit_ok {
        add(
            "BACKUP_UNHEALTHY",
            "backup reports a capture or replication failure, or has no validated snapshot",
        );
    }
    if !fresh(health.last_check_at.as_deref(), now) || !fresh(Some(&health.updated_at), now) {
        add(
            "BACKUP_STALE",
            "no successful current-vault check within two hours; inspect the backup service",
        );
    }
    if !commit_ok
        || health.commit != health.mirrored_commit
        || !fresh(health.last_mirror_at.as_deref(), now)
    {
        add(
            "BACKUP_REPLICATION_STALE",
            "the mirror has not recently verified the current local backup commit",
        );
    }
    if health.historical_pending_count > 0 {
        add(
            "BACKUP_HISTORICAL_UNRESOLVED",
            "backup preserves explicitly anchored historical audit attempts with unknown outcomes; these do not indicate active transactions or audit corruption",
        );
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn healthy() -> Health {
        Health {
            format: 1,
            updated_at: "2026-11-12T12:00:00+00:00".into(),
            last_check_at: Some("2026-11-12T12:00:00+00:00".into()),
            last_snapshot_at: Some("2026-11-01T12:00:00+00:00".into()),
            last_mirror_at: Some("2026-11-12T12:00:00+00:00".into()),
            commit: Some("a".repeat(40)),
            mirrored_commit: Some("a".repeat(40)),
            capture_error: None,
            mirror_error: None,
            historical_pending_count: 0,
        }
    }
    fn now() -> OffsetDateTime {
        OffsetDateTime::parse("2026-11-12T12:30:00Z", &Rfc3339).unwrap()
    }
    #[test]
    fn missing_backups_are_advisory() {
        let result = findings(Err(HealthError::Missing), now());
        assert_eq!(result[0].code, "BACKUP_NOT_CONFIGURED");
        assert!(result.iter().all(|f| f.advisory));
    }
    #[test]
    fn unchanged_old_snapshot_with_recent_check_is_healthy() {
        assert!(findings(Ok(healthy()), now()).is_empty());
    }
    #[test]
    fn anchored_historical_attempts_are_informational_not_a_backup_failure() {
        let mut health = healthy();
        health.historical_pending_count = 8254;
        let result = findings(Ok(health), now());
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].code, "BACKUP_HISTORICAL_UNRESOLVED");
        assert!(result[0].advisory);
        assert!(result[0].detail.contains("unknown outcomes"));
        assert!(
            result[0]
                .detail
                .contains("do not indicate active transactions")
        );
    }
    #[test]
    fn old_health_records_default_to_no_anchored_historical_attempts() {
        let mut value = serde_json::to_value(healthy()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .remove("historical_pending_count");
        let health: Health = serde_json::from_value(value).unwrap();
        assert_eq!(health.historical_pending_count, 0);
        assert!(findings(Ok(health), now()).is_empty());
    }
    #[test]
    fn stale_checks_and_mismatched_mirror_are_distinct() {
        let mut h = healthy();
        h.last_check_at = Some("2026-11-12T00:00:00Z".into());
        h.mirrored_commit = Some("b".repeat(40));
        let codes: Vec<_> = findings(Ok(h), now()).into_iter().map(|f| f.code).collect();
        assert_eq!(codes, ["BACKUP_STALE", "BACKUP_REPLICATION_STALE"]);
    }
    #[test]
    fn future_or_invalid_timestamps_are_not_fresh() {
        assert!(!fresh(Some("2027-01-01T00:00:00Z"), now()));
        assert!(!fresh(Some("not a time"), now()));
    }
    #[test]
    fn errors_are_not_reflected_in_diagnostics() {
        let mut h = healthy();
        h.capture_error = Some("DO NOT PRINT THIS".into());
        let f = findings(Ok(h), now());
        assert_eq!(f[0].code, "BACKUP_UNHEALTHY");
        assert!(!format!("{f:?}").contains("DO NOT PRINT THIS"));
    }
    #[test]
    fn restore_commit_rejects_git_revision_expressions() {
        assert!(valid_commit(&"f".repeat(40)));
        for bad in ["HEAD", "--help", "main~1", "", "a:b"] {
            assert!(!valid_commit(bad));
        }
    }
    fn protected_fixture_dir() -> tempfile::TempDir {
        // GitHub's Debian container sets HOME=/github/home, which has writable
        // ancestors. Use root's real home there; never weaken the reader's
        // ancestor checks to accommodate the CI environment.
        let home = if cfg!(target_os = "linux") && unsafe { libc::geteuid() } == 0 {
            std::path::PathBuf::from("/root")
        } else {
            std::path::PathBuf::from(std::env::var_os("HOME").unwrap())
        };
        tempfile::tempdir_in(home.canonicalize().unwrap()).unwrap()
    }

    #[test]
    fn protected_reader_rejects_symlinks_and_writable_files() {
        let dir = protected_fixture_dir();
        let uid = unsafe { libc::geteuid() };
        let path = dir.path().join("health.json");
        std::fs::write(&path, serde_json::to_vec(&healthy()).unwrap()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read_health_at(&path, uid).is_ok());
        let alias = dir.path().join("alias");
        symlink(&path, &alias).unwrap();
        assert!(matches!(
            read_health_at(&alias, uid),
            Err(HealthError::Invalid)
        ));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(matches!(
            read_health_at(&path, uid),
            Err(HealthError::Invalid)
        ));
    }
    #[test]
    fn oversized_health_is_rejected() {
        let dir = protected_fixture_dir();
        let path = dir.path().join("health.json");
        std::fs::write(&path, serde_json::to_vec(&healthy()).unwrap()).unwrap();
        assert!(read_health_at(&path, unsafe { libc::geteuid() }).is_ok());
        std::fs::write(&path, vec![b' '; MAX_HEALTH_BYTES as usize + 1]).unwrap();
        assert!(matches!(
            read_health_at(&path, unsafe { libc::geteuid() }),
            Err(HealthError::Invalid)
        ));
    }

    #[test]
    fn health_error_strings_are_bounded_and_cannot_inject_log_lines() {
        let dir = protected_fixture_dir();
        let path = dir.path().join("health.json");
        let mut health = healthy();
        std::fs::write(&path, serde_json::to_vec(&health).unwrap()).unwrap();
        assert!(read_health_at(&path, unsafe { libc::geteuid() }).is_ok());
        for message in ["x".repeat(161), "error\nforged log line".into()] {
            health.capture_error = Some(message);
            std::fs::write(&path, serde_json::to_vec(&health).unwrap()).unwrap();
            assert!(matches!(
                read_health_at(&path, unsafe { libc::geteuid() }),
                Err(HealthError::Invalid)
            ));
        }
    }
}
