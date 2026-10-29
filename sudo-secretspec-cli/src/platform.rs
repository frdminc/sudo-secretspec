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
    pub const DEFAULT_VAULT: &str = "/var/db/sudo-secretspec";
    pub const VAULT_PARENT: &str = "/var/db";
    pub const VAULT_REAL_PARENT: &str = "/private/var/db";
    pub const DEFAULT_USER: &str = "_sudo_secretspec";
    pub const DEFAULT_GROUP: &str = "_sudo_secretspec";
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
    pub const DEFAULT_VAULT: &str = "/var/lib/sudo-secretspec";
    pub const VAULT_PARENT: &str = "/var/lib";
    /// `/var/lib` is a real directory on Linux; there is no `/private` chain.
    pub const VAULT_REAL_PARENT: &str = "/var/lib";
    pub const DEFAULT_USER: &str = "sudo-secretspec";
    pub const DEFAULT_GROUP: &str = "sudo-secretspec";
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
/// Where the broker lives when it is *not* overridden at compile time: the path
/// the imperative installer writes. A binary whose [`BROKER_PATH`] differs from
/// this was built for a declared layout (the NixOS flake bakes a store path).
pub const DEFAULT_BROKER_PATH: &str = os::BROKER_PATH;
pub const DEFAULT_VAULT: &str = os::DEFAULT_VAULT;
pub const VAULT_PARENT: &str = os::VAULT_PARENT;
pub const VAULT_REAL_PARENT: &str = os::VAULT_REAL_PARENT;
pub const DEFAULT_USER: &str = os::DEFAULT_USER;
pub const DEFAULT_GROUP: &str = os::DEFAULT_GROUP;

// `secure_path` for the broker's `Defaults!` line, so `sudo` cannot hand the
// privileged process a caller-chosen `PATH`, and the installed public client,
// per running system. Not `os` constants: Linux has two answers.

const MACOS_SECURE_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";
const MACOS_CLIENT_PATH: &str = "/usr/local/bin/sudo-secretspec";
/// NixOS: the setuid `sudo` wrapper and the current system profile. There is no
/// `/usr/bin` on NixOS. Used only for the declared (NixOS module) policy.
const NIXOS_SECURE_PATH: &str = "/run/current-system/sw/bin:/run/wrappers/bin";
const NIXOS_CLIENT_PATH: &str = "/run/current-system/sw/bin/sudo-secretspec";
/// Ordinary FHS Linux (Debian's own sudo default): `/usr/bin` for the system
/// tools and the public client. Keep sudo's other standard search directories.
const LINUX_SECURE_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
/// The public client on an ordinary FHS Linux: on the real `PATH`, and a
/// different file from the broker at [`DEFAULT_BROKER_PATH`].
const LINUX_CLIENT_PATH: &str = "/usr/bin/sudo-secretspec";
pub const SERVICE_USER_REQUIRES_UNDERSCORE: bool = os::SERVICE_USER_REQUIRES_UNDERSCORE;
pub const SERVICE_IDENTITY_ALLOWS_HYPHEN: bool = os::SERVICE_IDENTITY_ALLOWS_HYPHEN;

/// Group that owns root-owned installed files on `host` (`root:wheel` on macOS,
/// `root:root` on Linux).
#[must_use]
pub fn root_group(host: Host) -> &'static str {
    match host {
        Host::MacOs => "wheel",
        Host::NixOs | Host::Linux => "root",
    }
}

/// Absolute path of `chown` on `host`; never resolved through `PATH`.
#[must_use]
pub fn chown_path(host: Host) -> &'static str {
    match host {
        Host::MacOs => "/usr/sbin/chown",
        Host::NixOs | Host::Linux => "/bin/chown",
    }
}

/// Absolute path of `visudo` on `host`; never resolved through `PATH`.
#[must_use]
pub fn visudo_path(_host: Host) -> &'static str {
    "/usr/sbin/visudo"
}

/// True when this binary was compiled for macOS.
pub const IS_MACOS: bool = cfg!(target_os = "macos");

/// The system this binary is *running on*, which decides how its boundary is
/// managed. Not the same question as `target_os`: one Linux build may run on
/// Debian or on NixOS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Host {
    /// macOS: imperative installer, Homebrew-shaped layout.
    MacOs,
    /// NixOS: the boundary is declared by `services.sudo-secretspec`
    /// (`nix/module.nix`); there is no imperative installer.
    NixOs,
    /// Any other Linux (Debian and friends): imperative installer, FHS layout.
    Linux,
}

impl Host {
    /// True where `install`, `uninstall`, `rollback` and `doctor` operate on
    /// the boundary directly.
    #[must_use]
    pub fn has_imperative_installer(self) -> bool {
        !matches!(self, Host::NixOs)
    }
}

/// Classify a host from two facts: whether this is a macOS build, and whether a
/// NixOS system profile is present. Pure, so tests can cover every cell without
/// a NixOS machine (a Nix build sandbox has no `/run/current-system`).
#[must_use]
pub fn host_for(macos_build: bool, nixos_running: bool) -> Host {
    if macos_build {
        Host::MacOs
    } else if nixos_running {
        Host::NixOs
    } else {
        Host::Linux
    }
}

/// Root-controlled NixOS markers cover both activated systems and chroots.
/// `symlink_metadata` also recognizes a dangling system-profile link.
#[must_use]
pub fn nixos_running() -> bool {
    nixos_markers_present(
        std::path::Path::new("/run/current-system"),
        std::path::Path::new("/etc/NIXOS"),
    )
}

fn nixos_markers_present(profile: &std::path::Path, marker: &std::path::Path) -> bool {
    std::fs::symlink_metadata(profile).is_ok() || std::fs::symlink_metadata(marker).is_ok()
}

/// The system this process is running on.
#[must_use]
pub fn host() -> Host {
    host_for(IS_MACOS, nixos_running())
}

/// `secure_path` for the broker's `Defaults!` line on `host`.
#[must_use]
pub fn secure_path(host: Host) -> &'static str {
    match host {
        Host::MacOs => MACOS_SECURE_PATH,
        Host::NixOs => NIXOS_SECURE_PATH,
        Host::Linux => LINUX_SECURE_PATH,
    }
}

/// Installed path of the public client on `host`.
#[must_use]
pub fn client_path(host: Host) -> &'static str {
    match host {
        Host::MacOs => MACOS_CLIENT_PATH,
        Host::NixOs => NIXOS_CLIENT_PATH,
        Host::Linux => LINUX_CLIENT_PATH,
    }
}

/// Refusal text for a boundary-lifecycle command that `host` cannot run, or
/// `None` when it can.
///
/// NixOS boundaries are declared, not installed: the NixOS module owns the
/// service account, the broker path, the vault directory, the config file and
/// the sudoers policy, and a rebuild is how any of them change.
///
/// A binary whose broker path was baked at compile time (`broker_path` differs
/// from [`DEFAULT_BROKER_PATH`]) was built for such a declared layout and must
/// not drive the imperative installer on any host: the installer would copy the
/// broker to the default path while the sudoers policy and config named the
/// baked one.
#[must_use]
pub fn lifecycle_refusal_for(host: Host, broker_path: &str, command: &str) -> Option<String> {
    if host == Host::NixOs {
        return Some(format!(
            "`{command}` is not supported on NixOS: the privilege boundary is managed \
             declaratively by the NixOS module (`nixosModules.default` of the sudo-secretspec \
             flake, option `services.sudo-secretspec`), not by an imperative installer. Change \
             the boundary by editing your NixOS configuration and rebuilding."
        ));
    }
    if host == Host::Linux && broker_path != DEFAULT_BROKER_PATH {
        return Some(format!(
            "`{command}` is not supported by this build: its broker path ({broker_path}) was \
             baked in for a declared (NixOS module) layout, not the imperative installer's \
             {DEFAULT_BROKER_PATH}. Use the Linux release artifact built without \
             SUDO_SECRETSPEC_BROKER_PATH."
        ));
    }
    None
}

/// [`lifecycle_refusal_for`] for the running system and this build's broker path.
#[must_use]
pub fn lifecycle_refusal(command: &str) -> Option<String> {
    lifecycle_refusal_for(host(), BROKER_PATH, command)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn either_nixos_marker_selects_the_declarative_host() {
        let tmp = tempfile::tempdir().unwrap();
        let profile = tmp.path().join("current-system");
        let marker = tmp.path().join("NIXOS");
        assert_eq!(
            host_for(false, nixos_markers_present(&profile, &marker)),
            Host::Linux
        );
        std::fs::write(&marker, "").unwrap();
        assert_eq!(
            host_for(false, nixos_markers_present(&profile, &marker)),
            Host::NixOs
        );
        std::fs::remove_file(&marker).unwrap();
        std::os::unix::fs::symlink("/nonexistent", &profile).unwrap();
        assert_eq!(
            host_for(false, nixos_markers_present(&profile, &marker)),
            Host::NixOs
        );
    }

    #[test]
    fn vault_lives_directly_under_its_parent() {
        assert_eq!(
            std::path::Path::new(DEFAULT_VAULT).parent(),
            Some(std::path::Path::new(VAULT_PARENT))
        );
    }

    #[test]
    fn host_follows_the_running_system_not_the_build_target() {
        assert_eq!(host_for(true, false), Host::MacOs);
        assert_eq!(host_for(true, true), Host::MacOs);
        assert_eq!(host_for(false, true), Host::NixOs);
        assert_eq!(host_for(false, false), Host::Linux);
    }

    #[test]
    fn lifecycle_refusal_fires_on_nixos_and_names_the_module() {
        for command in ["install", "uninstall", "rollback", "doctor"] {
            let text = lifecycle_refusal_for(Host::NixOs, DEFAULT_BROKER_PATH, command)
                .unwrap_or_else(|| panic!("{command} must be refused on NixOS"));
            assert!(text.contains("services.sudo-secretspec"), "{text}");
            assert!(text.contains(command), "{text}");
        }
    }

    #[test]
    fn lifecycle_refusal_does_not_fire_on_debian_or_macos() {
        for command in ["install", "uninstall", "rollback", "doctor"] {
            assert_eq!(
                lifecycle_refusal_for(Host::Linux, DEFAULT_BROKER_PATH, command),
                None
            );
            assert_eq!(
                lifecycle_refusal_for(Host::MacOs, DEFAULT_BROKER_PATH, command),
                None
            );
        }
    }

    #[test]
    fn a_baked_broker_path_cannot_drive_the_imperative_installer() {
        let text = lifecycle_refusal_for(
            Host::Linux,
            "/nix/store/x-sudo-secretspec/libexec/b",
            "install",
        )
        .expect("a nix-baked build must not run the imperative installer");
        assert!(text.contains("SUDO_SECRETSPEC_BROKER_PATH"), "{text}");
    }

    #[test]
    fn debian_policy_names_usr_bin_and_the_client_directory() {
        assert_ne!(client_path(Host::Linux), "/usr/libexec/sudo-secretspec");
        assert!(secure_path(Host::Linux).split(':').any(|d| d == "/usr/bin"));
        let client_dir = std::path::Path::new(client_path(Host::Linux))
            .parent()
            .unwrap()
            .to_str()
            .unwrap();
        assert!(secure_path(Host::Linux).split(':').any(|d| d == client_dir));
        // NixOS keeps its own shape: no /usr/bin.
        assert!(!secure_path(Host::NixOs).contains("/usr/bin"));
    }
}
