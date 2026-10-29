//! Per-platform install layout and service-identity rules.
//!
//! Every path the boundary trusts lives here, in one place, so a reviewer can
//! read the whole platform surface at once. The defaults are chosen by
//! `target_os`; three of them can be replaced **at compile time** through an
//! environment variable read by `option_env!`:
//!
//! | variable                          | replaces        |
//! |-----------------------------------|-----------------|
//! | `SUDO_SECRETSPEC_SUDO`            | [`SUDO`]        |
//! | `SUDO_SECRETSPEC_BROKER_PATH`     | [`BROKER_PATH`] |
//! | `SUDO_SECRETSPEC_CONFIG_PATH`     | [`CONFIG_PATH`] |
//!
//! Compile time, not run time, on purpose. These paths decide which binary the
//! public client hands to `sudo` and which file the root-adjacent broker
//! believes is its configuration; letting the *caller's* environment choose
//! either would hand the unprivileged side control of the boundary. A packager
//! (the NixOS flake does this) bakes them into the binary instead.
//!
//! The other constants are deliberately not overridable. The vault location is
//! validated against [`VAULT_PARENT`] by `config.rs`, so changing one without
//! the other would silently loosen that check; the install prefix, sudoers
//! directory and service identity only matter to the macOS installer, which
//! does not run anywhere else.
//!
//! macOS values are byte-identical to what `main.rs`, `broker.rs`, `install.rs`
//! and `drift.rs` hard-coded before this module existed.

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
compile_error!("sudo-secretspec-cli supports only macOS and Linux");

/// Reject an override that is not an absolute path, at compile time.
///
/// A relative `SUDO` would be resolved through the caller's `PATH` at run time,
/// which is exactly what the absolute default exists to prevent.
const fn pick(override_value: Option<&'static str>, default: &'static str) -> &'static str {
    match override_value {
        Some(value) => {
            let bytes = value.as_bytes();
            assert!(
                !bytes.is_empty() && bytes[0] == b'/',
                "SUDO_SECRETSPEC_* path overrides must be absolute"
            );
            value
        }
        None => default,
    }
}

// ---------------------------------------------------------------------------
// macOS
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
mod os {
    pub const SUDO: &str = "/usr/bin/sudo";
    pub const PREFIX: &str = "/usr/local";
    pub const BROKER_PATH: &str = "/usr/local/libexec/sudo-secretspec";
    pub const CONFIG_PATH: &str = "/usr/local/etc/sudo-secretspec.toml";
    pub const SUDOERS_DIR: &str = "/private/etc/sudoers.d";
    pub const SUDOERS_FILE: &str = "/private/etc/sudoers.d/sudo-secretspec";
    /// `secure_path` for the broker's `Defaults!` line, so `sudo` cannot hand
    /// the privileged process a caller-chosen `PATH`.
    pub const SUDOERS_SECURE_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";
    pub const DEFAULT_VAULT: &str = "/var/db/sudo-secretspec";
    pub const VAULT_PARENT: &str = "/var/db";
    pub const VAULT_REAL_PARENT: &str = "/private/var/db";
    pub const DEFAULT_USER: &str = "_sudo_secretspec";
    pub const DEFAULT_GROUP: &str = "_sudo_secretspec";
    /// Where the installed public client lives, for operator-facing messages.
    pub const CLIENT_PATH: &str = "/usr/local/bin/sudo-secretspec";
    /// macOS service accounts conventionally start with `_`.
    pub const SERVICE_USER_REQUIRES_UNDERSCORE: bool = true;
    pub const SERVICE_IDENTITY_ALLOWS_HYPHEN: bool = false;
}

// ---------------------------------------------------------------------------
// Linux
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod os {
    pub const SUDO: &str = "/usr/bin/sudo";
    pub const PREFIX: &str = "/usr";
    pub const BROKER_PATH: &str = "/usr/libexec/sudo-secretspec";
    pub const CONFIG_PATH: &str = "/etc/sudo-secretspec.toml";
    pub const SUDOERS_DIR: &str = "/etc/sudoers.d";
    pub const SUDOERS_FILE: &str = "/etc/sudoers.d/sudo-secretspec";
    /// NixOS `secure_path`: the setuid `sudo` wrapper and the current system
    /// profile. There is no `/usr/bin` on NixOS.
    pub const SUDOERS_SECURE_PATH: &str = "/run/current-system/sw/bin:/run/wrappers/bin";
    pub const DEFAULT_VAULT: &str = "/var/lib/sudo-secretspec";
    pub const VAULT_PARENT: &str = "/var/lib";
    /// `/var/lib` is a real directory on Linux; there is no `/private` chain.
    pub const VAULT_REAL_PARENT: &str = "/var/lib";
    pub const DEFAULT_USER: &str = "sudo-secretspec";
    pub const DEFAULT_GROUP: &str = "sudo-secretspec";
    /// The public client on NixOS lives in the current system profile; there is
    /// no `/usr/bin`.
    pub const CLIENT_PATH: &str = "/run/current-system/sw/bin/sudo-secretspec";
    /// Linux has no leading-underscore convention for service accounts.
    pub const SERVICE_USER_REQUIRES_UNDERSCORE: bool = false;
    pub const SERVICE_IDENTITY_ALLOWS_HYPHEN: bool = true;
}

/// Absolute path to `sudo`; never resolved through `PATH`.
pub const SUDO: &str = pick(option_env!("SUDO_SECRETSPEC_SUDO"), os::SUDO);

/// Installed path of the privileged broker. The sudoers policy grants NOPASSWD
/// execution of this path.
pub const BROKER_PATH: &str = pick(option_env!("SUDO_SECRETSPEC_BROKER_PATH"), os::BROKER_PATH);

/// Installed protected configuration.
pub const CONFIG_PATH: &str = pick(option_env!("SUDO_SECRETSPEC_CONFIG_PATH"), os::CONFIG_PATH);

pub const PREFIX: &str = os::PREFIX;
pub const SUDOERS_DIR: &str = os::SUDOERS_DIR;
pub const SUDOERS_FILE: &str = os::SUDOERS_FILE;
pub const SUDOERS_SECURE_PATH: &str = os::SUDOERS_SECURE_PATH;
pub const DEFAULT_VAULT: &str = os::DEFAULT_VAULT;
pub const VAULT_PARENT: &str = os::VAULT_PARENT;
pub const VAULT_REAL_PARENT: &str = os::VAULT_REAL_PARENT;
pub const DEFAULT_USER: &str = os::DEFAULT_USER;
pub const DEFAULT_GROUP: &str = os::DEFAULT_GROUP;
pub const CLIENT_PATH: &str = os::CLIENT_PATH;
pub const SERVICE_USER_REQUIRES_UNDERSCORE: bool = os::SERVICE_USER_REQUIRES_UNDERSCORE;
pub const SERVICE_IDENTITY_ALLOWS_HYPHEN: bool = os::SERVICE_IDENTITY_ALLOWS_HYPHEN;

/// True where the imperative installer (`install`, `uninstall`, `rollback`) and
/// the macOS-shaped `doctor` layout checks are supported.
pub const IS_MACOS: bool = cfg!(target_os = "macos");

/// Refusal text for a boundary-lifecycle command on a platform that has no
/// imperative installer. `None` on macOS.
///
/// Linux boundaries are declared, not installed: the NixOS module owns the
/// service account, the broker path, the vault directory, the config file and
/// the sudoers policy, and a rebuild is how any of them change.
#[must_use]
pub fn lifecycle_refusal(command: &str) -> Option<String> {
    if IS_MACOS {
        return None;
    }
    Some(format!(
        "`{command}` is not supported on this platform: the privilege boundary is managed \
         declaratively by the NixOS module (`nixosModules.default` of the sudo-secretspec \
         flake, option `services.sudo-secretspec`), not by an imperative installer. Change \
         the boundary by editing your NixOS configuration and rebuilding."
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_lives_directly_under_its_parent() {
        assert_eq!(
            std::path::Path::new(DEFAULT_VAULT).parent(),
            Some(std::path::Path::new(VAULT_PARENT))
        );
    }
}
