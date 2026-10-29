use std::path::{Path, PathBuf};

use crate::platform;

use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid TOML config: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("invalid sudo-secretspec config: {0}")]
    Invalid(&'static str),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub engine: PathBuf,
    pub audit_helper: PathBuf,
    pub vault: PathBuf,
    pub vault_realpath: PathBuf,
    #[serde(default)]
    pub declarations: Option<PathBuf>,
    pub service_user: String,
    pub service_group: String,
    /// Manifest profile the broker resolves secrets from.
    ///
    /// Part of the protected control plane rather than an ambient fallback.
    /// The engine's `resolve_profile_name` falls through to its *user-global*
    /// config when nothing else selects a profile, and inside the root broker
    /// that file belongs to the unprivileged caller — so which secrets resolve
    /// would be the caller's choice. Naming it here puts it in a root-owned,
    /// `0444`, boundary-validated file instead.
    ///
    /// `serde(default)` because `deny_unknown_fields` tolerates a *new* field
    /// but not a *missing* one: a config written by an older installer must
    /// still parse. The inverse — a new config met by an older broker — is
    /// rejected, but the two are installed as a pair and `rollback` restores
    /// them together, so that combination is not reachable.
    #[serde(default = "default_profile")]
    pub profile: String,
    /// Version of the installer that last wrote this file.
    ///
    /// Recorded so an install can report what it replaced and `doctor` can tell
    /// a pending upgrade from a current one. `Option` rather than a defaulted
    /// string because a boundary installed before this field existed has no
    /// honest value to report — `None` means "not recorded", which is different
    /// from any particular version.
    ///
    /// `serde(default)` for the same reason as `profile`: a config written by an
    /// older installer must still parse.
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub adopted_vault: bool,
}

fn default_profile() -> String {
    "default".into()
}

impl Config {
    pub fn parse(input: &str) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(input)?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        let mut managed_paths = vec![&self.engine, &self.audit_helper];
        if let Some(decl) = &self.declarations {
            managed_paths.push(decl);
        }
        for path in managed_paths {
            if !path.is_absolute() {
                return Err(ConfigError::Invalid("managed paths must be absolute"));
            }
            if path.to_string_lossy().contains("..") {
                return Err(ConfigError::Invalid("managed paths must not contain '..'"));
            }
        }
        let vault_name = direct_child(&self.vault, Path::new(platform::VAULT_PARENT))?;
        let real_name = direct_child(&self.vault_realpath, Path::new(platform::VAULT_REAL_PARENT))?;
        if vault_name != real_name {
            return Err(ConfigError::Invalid("vault and resolved vault must match"));
        }
        if !valid_service_identity(
            &self.service_user,
            platform::SERVICE_USER_REQUIRES_UNDERSCORE,
        ) || !valid_service_identity(&self.service_group, false)
        {
            return Err(ConfigError::Invalid("invalid service identity"));
        }
        if !valid_profile_name(&self.profile) {
            return Err(ConfigError::Invalid("invalid profile name"));
        }
        Ok(())
    }

    #[must_use]
    pub fn vault(&self) -> &Path {
        &self.vault
    }

    #[must_use]
    pub fn service_user(&self) -> &str {
        &self.service_user
    }
}

fn direct_child<'a>(path: &'a Path, parent: &Path) -> Result<&'a std::ffi::OsStr, ConfigError> {
    let relative = path
        .strip_prefix(parent)
        .map_err(|_| ConfigError::Invalid("vault is outside protected database root"))?;
    let mut components = relative.components();
    let name = components
        .next()
        .ok_or(ConfigError::Invalid("vault name is missing"))?;
    if components.next().is_some() {
        return Err(ConfigError::Invalid("vault must be one direct child"));
    }
    // A `.` or `..` component slips past the "one direct child" check and would
    // let a config author aim the vault at `/var/lib` itself (`.`) or its
    // parent (`..`); the module's tmpfiles rule would then re-own a system
    // state directory on every activation. Refuse the traversal components.
    if matches!(
        name,
        std::path::Component::CurDir | std::path::Component::ParentDir
    ) {
        return Err(ConfigError::Invalid("vault name must not be '.' or '..'"));
    }
    Ok(name.as_os_str())
}

/// A profile name is a manifest table key, not a path. Constrain it here so a
/// hand-edited config cannot smuggle a traversal or a separator into the value
/// the broker hands the engine.
fn valid_profile_name(value: &str) -> bool {
    if value.is_empty() || value.len() > 64 {
        return false;
    }
    value.bytes().enumerate().all(|(index, byte)| match byte {
        b'a'..=b'z' | b'A'..=b'Z' => true,
        b'0'..=b'9' | b'_' | b'-' => index > 0,
        _ => false,
    })
}

fn valid_service_identity(value: &str, require_underscore: bool) -> bool {
    // The superuser is never a service identity. macOS got this for free from
    // the mandatory underscore; Linux has no such prefix, so say it outright.
    if value == "root"
        || value.is_empty()
        || value.len() > 31
        || (require_underscore && !value.starts_with('_'))
    {
        return false;
    }
    value.bytes().enumerate().all(|(index, byte)| match byte {
        b'a'..=b'z' | b'_' => true,
        b'0'..=b'9' => index > 0,
        b'-' => platform::SERVICE_IDENTITY_ALLOWS_HYPHEN && index > 0,
        _ => false,
    })
}
