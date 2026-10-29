use std::ffi::OsString;
use std::io::{self, Write};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use clap::{Parser, Subcommand};

/// Absolute path to sudo. Never resolve this through `PATH`: the caller
/// controls the environment, and a planted `sudo` earlier in `PATH` would
/// silently satisfy every broker call with forged values and no audit event.
const SUDO: &str = "/usr/bin/sudo";

/// Installed path of the privileged broker. The sudoers policy grants
/// NOPASSWD execution of this path, so when the running binary *is* this
/// path it may only serve the operations that policy is meant to expose.
const BROKER_PATH: &str = "/usr/local/libexec/sudo-secretspec";

/// Installed protected configuration, written by `install`.
const CONFIG_PATH: &str = "/usr/local/etc/sudo-secretspec.toml";

#[derive(Debug, Parser)]
#[command(
    name = "sudo-secretspec",
    version,
    about = "Privilege-separated SecretSpec companion"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Declare a new secret in the runtime manifest.
    ///
    /// Creates the declaration only; it assigns no value. Follow with `set`.
    ///
    /// This edits the runtime manifest immediately, so `template-check` will
    /// report drift until you either mirror the declaration into the tracked
    /// declarations file and release it, or undo it with `undeclare`.
    Add {
        name: String,
        /// Human description recorded in the declaration.
        #[arg(long)]
        description: String,
        /// Declare the secret optional, writing `required = false`.
        #[arg(long, conflicts_with = "required")]
        optional: bool,
        /// Declare the secret required, writing `required = true`. Only needed
        /// when the profile's `[defaults]` set `required = false`.
        #[arg(long)]
        required: bool,
        #[arg(long)]
        reason: String,
    },
    Set {
        name: String,
        #[arg(long)]
        reason: String,
    },
    Delete {
        name: String,
        #[arg(long)]
        reason: String,
    },
    /// Remove a declaration this client added at runtime.
    ///
    /// The inverse of `add`. Refuses a name that is in the tracked declaration
    /// template — removing one of those is a review-and-release decision — and
    /// refuses a name that still holds a value, so `delete` comes first.
    Undeclare {
        name: String,
        #[arg(long)]
        reason: String,
    },
    Get {
        name: String,
        #[arg(long)]
        reason: String,
    },
    Check {
        #[arg(long)]
        reason: String,
    },
    Export {
        #[arg(long)]
        reason: String,
    },
    /// Compare the runtime manifest against the tracked declaration template.
    ///
    /// Reports drift between `<vault>/secretspec.toml` (what the broker
    /// actually resolves from) and the `declarations` file recorded in the
    /// root-owned config (what review sees in git). Reads no secret values.
    TemplateCheck {
        #[arg(long)]
        reason: String,
    },
    /// Emit a JSON Schema of the runtime manifest's typed shape.
    ///
    /// Declared names and whether each is required — never values, and not
    /// descriptions either: `codegen`'s emitter writes only the `type` key
    /// per property. The profile is the one recorded in the root-owned
    /// config, not a caller flag: an arbitrary profile would enumerate
    /// shapes the boundary is not configured for.
    Schema {
        #[arg(long)]
        reason: String,
    },
    Run {
        #[arg(long)]
        reason: String,
        #[arg(last = true, required = true)]
        command: Vec<OsString>,
    },
    Restore {
        name: Option<String>,
        #[arg(long)]
        to: String,
        #[arg(long)]
        force: bool,
        #[arg(long)]
        all: bool,
        #[arg(long)]
        reason: String,
    },
    Destroy {
        name: String,
        #[arg(long)]
        reason: String,
    },
    /// Install or adopt the privileged boundary.
    ///
    /// Typical short form:
    ///   sudo-secretspec install
    ///   sudo-secretspec install --adopt-existing
    Install {
        /// Declaration TOML. Optional: auto-detected or prompted.
        #[arg(long)]
        declarations: Option<PathBuf>,
        #[arg(long)]
        dry_run: bool,
        /// Adopt an existing vault/service identity instead of creating one.
        ///
        /// Only needed for a vault found by path scan, including the retired
        /// wrapper's. A vault named by the installed config is adopted without
        /// this flag, since the boundary itself recorded it.
        #[arg(long)]
        adopt_existing: bool,
        #[arg(long)]
        vault: Option<PathBuf>,
        #[arg(long)]
        service_user: Option<String>,
        #[arg(long)]
        service_group: Option<String>,
        #[arg(long)]
        operator: Option<String>,
        /// Manifest profile the broker resolves secrets from.
        ///
        /// Recorded in the root-owned config rather than read from the
        /// environment at operation time, so the profile cannot be chosen by
        /// whoever calls the broker. Defaults to `default`.
        #[arg(long)]
        profile: Option<String>,
        /// Never prompt; fail if required values cannot be defaulted.
        #[arg(long)]
        non_interactive: bool,
    },
    /// Remove the privileged boundary this installer owns.
    ///
    /// Leaves the vault and the service identity alone unless asked; both
    /// outlive any single install.
    ///
    /// Typical short form:
    ///   sudo-secretspec uninstall --dry-run
    ///   sudo-secretspec uninstall
    Uninstall {
        #[arg(long)]
        dry_run: bool,
        /// Also delete the vault directory and every secret in it.
        #[arg(long)]
        purge_vault: bool,
        /// Also delete the service user and group.
        #[arg(long)]
        remove_service_user: bool,
        #[arg(long)]
        config: Option<PathBuf>,
        /// Never prompt; the opt-in flags are taken as the confirmation.
        #[arg(long)]
        non_interactive: bool,
    },
    Doctor {
        #[arg(long)]
        json: bool,
        #[arg(long)]
        config: Option<PathBuf>,
        /// Executable search path of the unprivileged caller.
        ///
        /// Set by the public client when it elevates: `sudo` replaces `PATH`
        /// with the policy's `secure_path`, so the privileged process cannot
        /// otherwise tell which `sudo-secretspec` the operator would run. It
        /// only widens the shadow scan and is not an operator-facing knob.
        #[arg(long, hide = true)]
        caller_path: Option<OsString>,
        /// Path of a package-manager build staged but not installed.
        ///
        /// Set by the public client alongside `--available-version`. Like
        /// `caller_path` this is a fact the privileged process cannot safely
        /// collect for itself, not an operator-facing knob.
        #[arg(long, hide = true)]
        available_path: Option<PathBuf>,
        /// Version that staged build reports.
        #[arg(long, hide = true, requires = "available_path")]
        available_version: Option<String>,
    },
    /// Verify the audit ledger's hash chain and report its tip.
    ///
    /// Reads no secret and takes no reason: its whole job is to prove the
    /// ledger is intact. Record the reported tip hash outside the vault and
    /// compare it on later runs -- that external pin is what gives
    /// tamper-evidence against a principal who can write the ledger.
    AuditVerify,
    Rollback {
        snapshot: PathBuf,
    },
    #[command(hide = true, name = "__broker")]
    Broker {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<OsString>,
    },
}

/// True when this process is the installed privileged broker, i.e. it was
/// reached through the NOPASSWD sudoers rule rather than the public client.
///
/// The two ways of not knowing are **not** the same, and collapsing them is
/// what made this fail open. Keep the asymmetry:
///
/// - `canonicalize(BROKER_PATH)` fails → no broker is installed → this process
///   cannot be it → `false`. This is what lets the Homebrew `libexec`
///   bootstrap run `install` at all, on a machine with no boundary yet.
/// - `current_exe()` fails → we cannot identify ourselves → `true`, refusing
///   boundary lifecycle. The allowlist in `main` is presented as the layer that
///   catches a sudoers mistake, so it has to fail closed when it cannot tell.
fn invoked_as_privileged_broker() -> bool {
    match (std::env::current_exe(), std::fs::canonicalize(BROKER_PATH)) {
        (Ok(me), Ok(broker)) => std::fs::canonicalize(me)
            .map(|me| me == broker)
            .unwrap_or(true),
        (Err(_), _) => true,
        (_, Err(_)) => false,
    }
}

fn main() {
    let cli = Cli::parse();

    // The libexec path is NOPASSWD for the operator. Boundary lifecycle must
    // stay behind an interactive authentication, so refuse anything other than
    // the mediated operations when we were invoked through that path.
    //
    // This is an allowlist, deliberately: `install`, `rollback` and `uninstall`
    // are refused here by not appearing, and any lifecycle command added later
    // inherits the refusal instead of having to remember to ask for it.
    if invoked_as_privileged_broker() && !matches!(cli.cmd, Cmd::Broker { .. } | Cmd::Doctor { .. })
    {
        eprintln!(
            "sudo-secretspec: the privileged broker path serves only __broker and doctor;\n\
             run install/rollback through /usr/local/bin/sudo-secretspec so they require\n\
             interactive authentication"
        );
        std::process::exit(2);
    }

    match cli.cmd {
        Cmd::Add {
            name,
            description,
            optional,
            required,
            reason,
        } => lifecycle_add(&name, &description, optional, required, &reason),
        Cmd::Set { name, reason } => lifecycle("set", &name, &reason),
        Cmd::Delete { name, reason } => lifecycle("delete", &name, &reason),
        Cmd::Undeclare { name, reason } => lifecycle("undeclare", &name, &reason),
        Cmd::Get { name, reason } => lifecycle("get", &name, &reason),
        Cmd::Check { reason } => lifecycle("check", "", &reason),
        Cmd::Export { reason } => lifecycle("export", "", &reason),
        Cmd::TemplateCheck { reason } => lifecycle("template-check", "", &reason),
        Cmd::Schema { reason } => lifecycle("schema", "", &reason),
        Cmd::Restore {
            name,
            to,
            force,
            all,
            reason,
        } => lifecycle_restore(name, &to, force, all, &reason),
        Cmd::Destroy { name, reason } => lifecycle_destroy(&name, &reason),
        Cmd::Run { reason, command } => run_target(&reason, &command),
        Cmd::Install {
            declarations,
            dry_run,
            adopt_existing,
            vault,
            service_user,
            service_group,
            operator,
            profile,
            non_interactive,
        } => run_install(
            declarations,
            dry_run,
            adopt_existing,
            vault,
            service_user,
            service_group,
            operator,
            profile,
            non_interactive,
        ),
        Cmd::Uninstall {
            dry_run,
            purge_vault,
            remove_service_user,
            config,
            non_interactive,
        } => run_uninstall(
            dry_run,
            purge_vault,
            remove_service_user,
            config,
            non_interactive,
        ),
        Cmd::Doctor {
            json,
            config,
            caller_path,
            available_path,
            available_version,
        } => doctor(
            json,
            config,
            caller_path,
            available_path
                .zip(available_version)
                .map(|(path, version)| sudo_secretspec_cli::AvailableBuild { path, version }),
        ),
        Cmd::AuditVerify => audit_verify(),
        Cmd::Rollback { snapshot } => {
            if unsafe { libc::geteuid() } != 0 {
                let status = Command::new(SUDO)
                    .arg(self_exe())
                    .arg("rollback")
                    .arg(&snapshot)
                    .status();
                match status {
                    Ok(s) if s.success() => return,
                    Ok(s) => std::process::exit(s.code().unwrap_or(1)),
                    Err(e) => {
                        eprintln!("cannot elevate rollback: {e}");
                        std::process::exit(2);
                    }
                }
            }
            if let Err(e) = sudo_secretspec_cli::rollback::run(&snapshot) {
                eprintln!("rollback denied: {e}");
                std::process::exit(2);
            }
        }
        Cmd::Broker { args } => {
            if let Err(code) = sudo_secretspec_cli::broker::dispatch(&args) {
                std::process::exit(code);
            }
        }
    }
}

fn self_exe() -> PathBuf {
    std::env::current_exe().unwrap_or_else(|_| PathBuf::from("sudo-secretspec"))
}

fn privileged_broker() -> PathBuf {
    let candidate = PathBuf::from(BROKER_PATH);
    if candidate.is_file() {
        candidate
    } else {
        self_exe()
    }
}

fn is_tty() -> bool {
    unsafe { libc::isatty(libc::STDIN_FILENO) == 1 }
}

fn prompt_line(label: &str, default: Option<&str>) -> Option<String> {
    if !is_tty() {
        return default.map(str::to_string);
    }
    let mut stdout = io::stdout();
    match default {
        Some(d) if !d.is_empty() => {
            let _ = write!(stdout, "{label} [{d}]: ");
        }
        _ => {
            let _ = write!(stdout, "{label}: ");
        }
    }
    let _ = stdout.flush();
    let mut line = String::new();
    if io::stdin().read_line(&mut line).is_err() {
        return default.map(str::to_string);
    }
    let trimmed = line.trim();
    if trimmed.is_empty() {
        default.map(str::to_string)
    } else {
        Some(trimmed.to_string())
    }
}

fn prompt_yes_no(label: &str, default_yes: bool) -> bool {
    if !is_tty() {
        return default_yes;
    }
    let def = if default_yes { "Y/n" } else { "y/N" };
    let mut stdout = io::stdout();
    let _ = write!(stdout, "{label} [{def}]: ");
    let _ = stdout.flush();
    let mut line = String::new();
    if io::stdin().read_line(&mut line).is_err() {
        return default_yes;
    }
    match line.trim().to_ascii_lowercase().as_str() {
        "" => default_yes,
        "y" | "yes" => true,
        "n" | "no" => false,
        _ => default_yes,
    }
}

fn resolve_declarations(
    declarations: Option<PathBuf>,
    non_interactive: bool,
) -> Result<Option<PathBuf>, String> {
    if let Some(p) = declarations {
        if p.is_file() && !p.is_symlink() {
            return Ok(Some(p));
        } else {
            return Err(format!("declarations not found: {}", p.display()));
        }
    }
    if let Ok(p) = std::env::var("SUDO_SECRETSPEC_DECLARATIONS") {
        let p = PathBuf::from(p);
        if p.is_file() && !p.is_symlink() {
            return Ok(Some(p));
        } else {
            return Err(format!("declarations not found: {}", p.display()));
        }
    }
    let pwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    for name in ["secretspec.toml", "secrets.toml"] {
        let cand = pwd.join(name);
        if cand.is_file() && !cand.is_symlink() {
            if !non_interactive && is_tty() {
                if prompt_yes_no(&format!("Use declarations at {}?", cand.display()), true) {
                    return Ok(Some(cand));
                }
            } else {
                return Ok(Some(cand));
            }
        }
    }
    if non_interactive || !is_tty() {
        return Ok(None);
    }
    let typed = prompt_line("Path to declarations TOML (leave blank to skip)", None);
    match typed {
        Some(t) if !t.trim().is_empty() => {
            let path = PathBuf::from(t);
            if path.is_file() && !path.is_symlink() {
                Ok(Some(path))
            } else {
                Err(format!("declarations not found: {}", path.display()))
            }
        }
        _ => Ok(None),
    }
}

fn detect_existing_vault() -> Option<sudo_secretspec_cli::install::ExistingVault> {
    sudo_secretspec_cli::install::detect_existing_vault(Path::new(CONFIG_PATH), |path| {
        path.is_dir() && !path.is_symlink()
    })
}

fn run_install(
    declarations: Option<PathBuf>,
    dry_run: bool,
    adopt_existing: bool,
    vault: Option<PathBuf>,
    service_user: Option<String>,
    service_group: Option<String>,
    operator: Option<String>,
    profile: Option<String>,
    non_interactive: bool,
) {
    // Before anything else, and before elevating: an install that would copy
    // the installed boundary onto itself is refused here rather than after the
    // operator has authenticated. `install::run` repeats this check as root and
    // that copy is the authoritative one; this is purely about not charging a
    // Touch ID prompt for an answer already known.
    if let Err(e) = sudo_secretspec_cli::install::preflight_media(None) {
        eprintln!("install denied: {e}");
        std::process::exit(2);
    }

    let declarations = match resolve_declarations(declarations, non_interactive) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("install denied: {e}");
            std::process::exit(2);
        }
    };

    let mut req = sudo_secretspec_cli::install::InstallRequest::from_cli(
        declarations,
        dry_run,
        adopt_existing,
    );

    if let Some(existing) = detect_existing_vault() {
        if vault.is_none() {
            // Adopting is the default only when the installed root-owned config
            // named this vault -- the boundary vouching for the store it already
            // serves from, which makes a reinstall an upgrade rather than a trust
            // decision. Upgrades are the common case (a fresh install happens once
            // per host), and refusing them taught scripts to "fix" the refusal by
            // deleting the vault.
            //
            // A path-scanned vault keeps demanding the flag. There the vault is a
            // guess, and one of the candidates is the retired wrapper's store that
            // migration deliberately leaves on disk -- silently binding a new
            // boundary to retired secrets is exactly what `detect_existing_vault`
            // exists to prevent. Announce the automatic adoption either way, so an
            // operator who believed they were installing clean finds out here.
            let adopt_by_default =
                sudo_secretspec_cli::install::adopts_without_flag(existing.origin);
            if adopt_existing
                || adopt_by_default
                || (!non_interactive
                    && is_tty()
                    && prompt_yes_no(
                        &format!(
                            "Found existing vault at {}. Adopt it?",
                            existing.vault.display()
                        ),
                        true,
                    ))
            {
                if adopt_by_default && !adopt_existing {
                    eprintln!(
                        "adopting the installed vault at {} (recorded in {}); \
                         pass --vault to install elsewhere",
                        existing.vault.display(),
                        CONFIG_PATH,
                    );
                }
                req.adopt_existing = true;
                req.vault = existing.vault;
                req.service_user = existing.service_user;
                req.service_group = existing.service_group;
            }
        }
    }

    if let Some(v) = vault {
        req.vault = v;
    }
    if let Some(u) = service_user {
        req.service_user = u;
    }
    if let Some(g) = service_group {
        req.service_group = g;
    }
    if let Some(p) = profile {
        req.profile = p;
    }
    if let Some(o) = operator {
        req.operator = o;
    } else if !non_interactive && is_tty() {
        if let Some(o) = prompt_line("Operator username for sudoers", Some(&req.operator)) {
            req.operator = o;
        }
    }

    // Install itself needs interactive sudo/Touch ID, not NOPASSWD -n.
    if unsafe { libc::geteuid() } != 0 {
        let mut cmd = Command::new(SUDO);
        cmd.arg(self_exe()).arg("install");
        if let Some(decl) = &req.declarations {
            cmd.arg("--declarations").arg(decl);
        }
        let status = cmd
            .args(if req.dry_run {
                vec!["--dry-run"]
            } else {
                vec![]
            })
            .args(if req.adopt_existing {
                vec!["--adopt-existing"]
            } else {
                vec![]
            })
            .arg("--vault")
            .arg(&req.vault)
            .arg("--service-user")
            .arg(&req.service_user)
            .arg("--service-group")
            .arg(&req.service_group)
            .arg("--operator")
            .arg(&req.operator)
            .arg("--profile")
            .arg(&req.profile)
            .arg("--non-interactive")
            .status();
        match status {
            Ok(s) if s.success() => return,
            Ok(s) => std::process::exit(s.code().unwrap_or(1)),
            Err(e) => {
                eprintln!("cannot elevate install: {e}");
                std::process::exit(2);
            }
        }
    }
    if let Err(e) = sudo_secretspec_cli::install::run(req) {
        eprintln!("install denied: {e}");
        std::process::exit(2);
    }
}

fn run_uninstall(
    dry_run: bool,
    purge_vault: bool,
    remove_service_user: bool,
    config: Option<PathBuf>,
    non_interactive: bool,
) {
    // Confirm here, while still unprivileged and still attached to the
    // operator's terminal. The elevated re-exec below passes
    // `--non-interactive`, so this is the only place a prompt can happen —
    // and both of these destroy state that outlives the install.
    if !non_interactive && !dry_run && is_tty() {
        if purge_vault
            && !prompt_yes_no(
                "Delete the vault and every secret in it? This cannot be undone.",
                false,
            )
        {
            eprintln!("uninstall aborted");
            std::process::exit(2);
        }
        if remove_service_user
            && !prompt_yes_no(
                "Delete the service user and group? Other tools may still depend on them.",
                false,
            )
        {
            eprintln!("uninstall aborted");
            std::process::exit(2);
        }
    }

    // Uninstall is boundary lifecycle: interactive sudo/Touch ID, never the
    // NOPASSWD broker path.
    if unsafe { libc::geteuid() } != 0 {
        let mut cmd = Command::new(SUDO);
        cmd.arg(self_exe()).arg("uninstall");
        if dry_run {
            cmd.arg("--dry-run");
        }
        if purge_vault {
            cmd.arg("--purge-vault");
        }
        if remove_service_user {
            cmd.arg("--remove-service-user");
        }
        if let Some(cfg) = &config {
            cmd.arg("--config").arg(cfg);
        }
        cmd.arg("--non-interactive");
        match cmd.status() {
            Ok(s) if s.success() => return,
            Ok(s) => std::process::exit(s.code().unwrap_or(1)),
            Err(e) => {
                eprintln!("cannot elevate uninstall: {e}");
                std::process::exit(2);
            }
        }
    }

    let req = sudo_secretspec_cli::uninstall::UninstallRequest {
        dry_run,
        purge_vault,
        remove_service_user,
        config: config.unwrap_or_else(|| PathBuf::from(CONFIG_PATH)),
    };
    if let Err(e) = sudo_secretspec_cli::uninstall::run(req) {
        eprintln!("uninstall denied: {e}");
        std::process::exit(2);
    }
}

/// Hash the operator's reason before it crosses the privilege boundary.
///
/// The reason used to be passed to the broker as plaintext in argv, where
/// `ps` and `KERN_PROCARGS2` expose it to every process running as the same
/// user, and where it also lands in shell history — while the design's stated
/// invariant is that only `SHA-256(reason)` is ever stored. Hashing here keeps
/// the prose inside the unprivileged process that already had it.
///
/// The non-empty check stays on this side: it must not be possible to satisfy
/// the gate by sending `SHA-256("")`, and the broker rejects that digest too.
fn reason_digest_or_exit(reason: &str) -> String {
    sudo_secretspec_cli::broker::reason_sha256(reason).unwrap_or_else(|| {
        eprintln!("sudo-secretspec: --reason must not be empty");
        std::process::exit(2);
    })
}

/// Report a broker exit, adding a hint for the one confusing failure.
fn exit_from_broker(code: i32) -> ! {
    // The client and the broker are installed as a pair, but the Homebrew keg
    // ships a bootstrap binary that can be newer than the installed broker. An
    // older broker rejects `--reason-sha256` with clap's usage exit, which
    // otherwise reads as an unexplained argument error. Deliberately *not* a
    // retry with plaintext: falling back would hand an attacker who can
    // downgrade the broker a way to get the prose back.
    if code == 2 {
        eprintln!(
            "sudo-secretspec: if the broker reported an unexpected '--reason-sha256' argument,\n\
             the installed boundary predates this client; re-run `sudo-secretspec install`"
        );
    }
    std::process::exit(code);
}

fn get_service_user() -> String {
    let config_path = std::path::PathBuf::from(CONFIG_PATH);
    if let Ok(layout) = sudo_secretspec_cli::load_config(&config_path) {
        layout.service_user
    } else {
        // Fallback to the default if config is missing or unparseable.
        // It shouldn't get here because we only call this when installed.
        "_sudo_secretspec".to_string()
    }
}

/// `add` is `lifecycle` plus the declaration's description.
///
/// Kept separate rather than widening `lifecycle` with an `Option`: `add` is
/// the only operation that carries one, and threading a `None` through every
/// other call site is how `add` came to be a silent alias for `set`.
fn lifecycle_add(name: &str, description: &str, optional: bool, required: bool, reason: &str) {
    if description.trim().is_empty() {
        eprintln!("sudo-secretspec: --description cannot be empty");
        std::process::exit(2);
    }
    let mut command = Command::new(SUDO);
    command.arg("-u").arg(get_service_user());
    command
        .arg("-n")
        .arg(privileged_broker())
        .arg("__broker")
        .arg("source-add")
        .arg("--client")
        .arg(detect_client())
        .arg("--reason-sha256")
        .arg(reason_digest_or_exit(reason))
        .arg("--name")
        .arg(name)
        .arg("--description")
        .arg(description);
    if optional {
        command.arg("--optional");
    }
    if required {
        command.arg("--required");
    }
    let status = command.status().unwrap_or_else(|e| {
        eprintln!("cannot invoke broker: {e}");
        std::process::exit(2);
    });
    if !status.success() {
        exit_from_broker(status.code().unwrap_or(1));
    }
}

fn audit_verify() {
    let status = Command::new(SUDO)
        .arg("-u")
        .arg(get_service_user())
        .arg("-n")
        .arg(privileged_broker())
        .arg("__broker")
        .arg("audit-verify")
        .status()
        .unwrap_or_else(|e| {
            eprintln!("cannot invoke broker: {e}");
            std::process::exit(2);
        });
    if !status.success() {
        exit_from_broker(status.code().unwrap_or(1));
    }
}

fn lifecycle(op: &str, name: &str, reason: &str) {
    let mut cmd = Command::new(SUDO);
    cmd.arg("-u")
        .arg(get_service_user())
        .arg("-n")
        .arg(privileged_broker())
        .arg("__broker")
        .arg(format!("source-{op}"))
        .arg("--client")
        .arg(detect_client())
        .arg("--reason-sha256")
        .arg(reason_digest_or_exit(reason));
    if !name.is_empty() {
        cmd.arg("--name").arg(name);
    }
    // `status`, not `output`: `get` streams the secret value straight to the
    // caller's stdout, and capturing it here would put a copy in this process.
    let status = cmd.status().unwrap_or_else(|e| {
        eprintln!("cannot invoke broker: {e}");
        std::process::exit(2);
    });
    if !status.success() {
        exit_from_broker(status.code().unwrap_or(1));
    }
}

/// Which broker verb a restore request must use.
///
/// `source-restore-force` is also the auth-gated verb for `--all`, not just
/// `--force`: the sudoers grant for plain `source-restore` (in
/// `install::sudoers_text`) is a `--*` wildcard, which matches a `--all`
/// invocation just as well as a named one. Routing `--all` through the plain
/// verb would make that NOPASSWD grant, not the `-n`/interactive split below,
/// the real authorization gate -- silently permitting an unattended
/// whole-vault restore. Named and tested on its own rather than inlined,
/// since this exact confusion is what finding 1 of the 2026-08-18 review was.
fn restore_verb(force: bool, all: bool) -> &'static str {
    if force || all {
        "source-restore-force"
    } else {
        "source-restore"
    }
}

fn lifecycle_restore(name: Option<String>, to: &str, force: bool, all: bool, reason: &str) {
    let mut cmd = Command::new(SUDO);
    cmd.arg("-u").arg(get_service_user());

    // Non-forced specific restore is allowed for agents, others require operator sudo
    if !force && !all {
        cmd.arg("-n");
    }

    cmd.arg(privileged_broker())
        .arg("__broker")
        .arg(restore_verb(force, all));

    cmd.arg("--client")
        .arg(detect_client())
        .arg("--reason-sha256")
        .arg(reason_digest_or_exit(reason))
        .arg("--to")
        .arg(to);

    if let Some(n) = name {
        cmd.arg("--name").arg(n);
    }
    if force {
        cmd.arg("--force");
    }
    if all {
        cmd.arg("--all");
    }

    let status = cmd.status().unwrap_or_else(|e| {
        eprintln!("cannot invoke broker: {e}");
        std::process::exit(2);
    });
    if !status.success() {
        exit_from_broker(status.code().unwrap_or(1));
    }
}

fn lifecycle_destroy(name: &str, reason: &str) {
    let mut cmd = Command::new(SUDO);
    // Destroy is operator-only, don't use -n
    cmd.arg("-u").arg(get_service_user());
    cmd.arg(privileged_broker())
        .arg("__broker")
        .arg("source-destroy")
        .arg("--client")
        .arg(detect_client())
        .arg("--reason-sha256")
        .arg(reason_digest_or_exit(reason))
        .arg("--name")
        .arg(name);

    let status = cmd.status().unwrap_or_else(|e| {
        eprintln!("cannot invoke broker: {e}");
        std::process::exit(2);
    });
    if !status.success() {
        exit_from_broker(status.code().unwrap_or(1));
    }
}

fn detect_client() -> &'static str {
    for (key, family) in [
        ("HERMES_SESSION_ID", "hermes"),
        ("CLAUDE_SESSION_ID", "claude"),
        ("CODEX_THREAD_ID", "codex"),
        ("OPENCODE_SESSION_ID", "opencode"),
        ("CURSOR_SESSION_ID", "cursor"),
        ("AGY_SESSION_ID", "agy"),
    ] {
        if std::env::var_os(key).is_some() {
            return family;
        }
    }
    "unknown"
}

fn run_target(reason: &str, command: &[OsString]) {
    // `command` is already exactly the target argv: clap consumed the `--`
    // delimiter via `last = true`. Any further `--` belongs to the target
    // (`cargo test -- --nocapture`) and must be passed through untouched.
    let target = command;
    if target.is_empty() {
        eprintln!("run requires a command after --");
        std::process::exit(2);
    }

    let output = Command::new(SUDO)
        .arg("-u")
        .arg(get_service_user())
        .arg("-n")
        .arg(privileged_broker())
        .arg("__broker")
        .arg("source-export")
        .arg("--client")
        .arg(detect_client())
        .arg("--reason-sha256")
        .arg(reason_digest_or_exit(reason))
        .arg("--command-basename")
        .arg(sudo_secretspec_cli::audit::command_basename(&target[0]))
        .output()
        .unwrap_or_else(|e| {
            eprintln!("cannot invoke broker: {e}");
            std::process::exit(2);
        });

    if !output.status.success() {
        eprint!("{}", String::from_utf8_lossy(&output.stderr));
        exit_from_broker(output.status.code().unwrap_or(1));
    }

    let env: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        eprintln!("broker returned invalid JSON: {e}");
        std::process::exit(2);
    });

    let mut cmd = Command::new(&target[0]);
    cmd.args(&target[1..]);
    // `vars_os`, not `vars`: the latter panics on a non-UTF-8 environment.
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("SECRETSPEC_") {
            cmd.env_remove(&key);
        }
    }
    if let Some(obj) = env.as_object() {
        for (key, value) in obj {
            if let Some(v) = value.as_str() {
                cmd.env(key, v);
            }
        }
    }

    let err = cmd.exec();
    eprintln!("cannot exec target: {err}");
    std::process::exit(127);
}

/// Ask the package manager's staged copy of the boundary what version it is.
///
/// Runs only while unprivileged, and that restriction is the point: the
/// Homebrew prefix is routinely operator-writable, so this is a binary the
/// *operator* may execute but the root broker must not. `doctor` collects the
/// answer here and hands it across the elevation boundary as data.
///
/// A build that cannot be run, or whose output is not a single version word, is
/// simply not reported — this feeds an advisory, and guessing would be worse
/// than staying quiet.
fn probe_available_build(unprivileged: bool) -> Option<sudo_secretspec_cli::AvailableBuild> {
    if !unprivileged {
        return None;
    }
    sudo_secretspec_cli::media_candidates()
        .into_iter()
        .find_map(|path| {
            let out = Command::new(&path).arg("--version").output().ok()?;
            if !out.status.success() {
                return None;
            }
            // `clap` prints "<name> <version>"; take the last word.
            let version = String::from_utf8(out.stdout)
                .ok()?
                .split_whitespace()
                .next_back()?
                .to_string();
            if version.is_empty() {
                return None;
            }
            Some(sudo_secretspec_cli::AvailableBuild { path, version })
        })
}

/// Enforce the privilege boundary on the config the privileged `doctor` reads.
///
/// The installed config is root-owned and read-only (`0444`). A root `doctor`
/// that accepted a caller-chosen `--config` would read whatever file the caller
/// named with root authority, so refuse anything that is not a plain,
/// root-owned, non-group/world-writable regular file. Every message here is a
/// fixed string: the failure must never echo the file's contents.
fn assert_privileged_config(path: &Path) -> Result<(), &'static str> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(_) => return Err("config is missing or unreadable"),
    };
    if meta.file_type().is_symlink() {
        return Err("config is a symlink");
    }
    if !meta.file_type().is_file() {
        return Err("config is not a regular file");
    }
    if meta.uid() != 0 {
        return Err("config is not root-owned");
    }
    if meta.permissions().mode() & 0o022 != 0 {
        return Err("config is group- or world-writable");
    }
    Ok(())
}

fn doctor(
    json: bool,
    config: Option<PathBuf>,
    caller_path: Option<OsString>,
    available_build: Option<sudo_secretspec_cli::AvailableBuild>,
) {
    // `sudo` replaces PATH with the policy's secure_path, so the shadow check
    // has to be told what the caller's PATH was before elevating. Trust the
    // ambient value only while still unprivileged.
    let unprivileged = unsafe { libc::geteuid() } != 0;

    // A privileged `doctor` may only read the installed config. `--config` must
    // never reach root: the unprivileged client no longer forwards it, and a
    // direct `sudo … doctor --config <path>` is refused here unless the path is
    // the installed `CONFIG_PATH` itself. This closes the disclosure where a
    // NOPASSWD root `doctor` echoed an arbitrary file's contents.
    if !unprivileged {
        if let Some(cfg) = &config {
            let is_default = match (
                Path::new(CONFIG_PATH).canonicalize(),
                cfg.canonicalize(),
            ) {
                (Ok(installed), Ok(given)) => installed == given,
                _ => false,
            };
            if !is_default {
                if json {
                    println!(
                        "{}",
                        serde_json::json!({"ok": false, "error": "config invalid"})
                    );
                } else {
                    eprintln!("doctor: refusing a non-default --config while privileged");
                }
                std::process::exit(1);
            }
        }
    }

    let caller_path = caller_path.or_else(|| {
        if unprivileged {
            std::env::var_os("PATH")
        } else {
            None
        }
    });
    let available_build = available_build.or_else(|| probe_available_build(unprivileged));

    // Privileged checks (sudoers/vault) need root. Prefer NOPASSWD libexec.
    if unprivileged {
        let broker = privileged_broker();
        let elevated = |with_hints: bool| {
            let mut cmd = Command::new(SUDO);
            cmd.arg("-n").arg(&broker).arg("doctor");
            if json {
                cmd.arg("--json");
            }
            // `--config` is deliberately not forwarded: the privileged doctor
            // must only ever read the installed `CONFIG_PATH`. See the refusal
            // guard at the top of this function.
            if with_hints {
                if let Some(path) = &caller_path {
                    cmd.arg("--caller-path").arg(path);
                }
                if let Some(build) = &available_build {
                    cmd.arg("--available-path")
                        .arg(&build.path)
                        .arg("--available-version")
                        .arg(&build.version);
                }
            }
            cmd
        };

        // A client from a newer build can meet an older installed broker: brew
        // hands over a new bootstrap binary before `install` replaces the pair.
        // The older broker rejects these hidden flags with clap's usage exit, so
        // capture that attempt rather than letting a bare argument-parsing error
        // stand in for the health check. `doctor` itself exits 0 or 1, so a 2
        // from this path means the broker did not understand the request.
        //
        // All hints are passed and dropped together: retrying flag-by-flag would
        // multiply round trips through `sudo` to recover detail that is
        // advisory either way.
        let mut can_elevate = true;
        if caller_path.is_some() || available_build.is_some() {
            match elevated(true).output() {
                Ok(out) if out.status.code() == Some(2) => {
                    // Retry without the flag; the shadow check then runs against
                    // the fixed search list only.
                }
                Ok(out) => {
                    let _ = io::stdout().write_all(&out.stdout);
                    let _ = io::stderr().write_all(&out.stderr);
                    match out.status.code() {
                        Some(0) => return,
                        code => std::process::exit(code.unwrap_or(1)),
                    }
                }
                Err(e) => {
                    eprintln!("cannot elevate doctor via {}: {e}", broker.display());
                    can_elevate = false;
                }
            }
        }

        if can_elevate {
            match elevated(false).status() {
                Ok(s) if s.success() => return,
                Ok(s) => std::process::exit(s.code().unwrap_or(1)),
                Err(e) => {
                    eprintln!("cannot elevate doctor via {}: {e}", broker.display());
                    // Fall through to unprivileged best-effort.
                }
            }
        }
    }

    let config = config.unwrap_or_else(|| PathBuf::from(CONFIG_PATH));

    // The privileged doctor must not open a config it does not own: reject a
    // non-root-owned, group-writable or world-writable file before reading it.
    // The unprivileged path reads the operator's own file as themselves and
    // needs no such check.
    if !unprivileged {
        if let Err(reason) = assert_privileged_config(&config) {
            if json {
                println!(
                    "{}",
                    serde_json::json!({"ok": false, "error": "config invalid"})
                );
            } else {
                eprintln!("doctor: config invalid ({reason})");
            }
            std::process::exit(1);
        }
    }

    let layout = match sudo_secretspec_cli::load_config(&config) {
        Ok(l) => l,
        Err(e) => {
            if unprivileged {
                // The operator read their own file as themselves; echoing the
                // parse error is safe and useful.
                if json {
                    println!(
                        "{}",
                        serde_json::json!({"ok": false, "error": format!("{e}")})
                    );
                } else {
                    eprintln!("doctor: config error: {e}");
                }
            } else {
                // Privileged: a parse error can quote the file's contents, so
                // never echo it — an arbitrary `--config` must not leak a
                // root-only file through the error path.
                if json {
                    println!(
                        "{}",
                        serde_json::json!({"ok": false, "error": "config invalid"})
                    );
                } else {
                    eprintln!("doctor: config invalid");
                }
            }
            std::process::exit(1);
        }
    };

    let report = sudo_secretspec_cli::inspect(
        &layout,
        &sudo_secretspec_cli::InspectOptions {
            caller_path,
            available_build,
        },
    );
    if json {
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
    } else if report.ok {
        println!("doctor: OK");
        // Advisories never fail the check, but the operator still needs to see
        // them; they are the only findings that can appear alongside OK.
        for finding in report.findings.iter().filter(|f| f.advisory) {
            print_finding("advisory", finding);
        }
    } else {
        eprintln!("doctor: FAILED");
        for finding in &report.findings {
            print_finding(
                if finding.advisory {
                    "advisory"
                } else {
                    "error"
                },
                finding,
            );
        }
        std::process::exit(1);
    }
}

fn print_finding(label: &str, finding: &sudo_secretspec_cli::Finding) {
    match &finding.path {
        Some(path) => eprintln!(
            "- [{label}] {} ({}): {}",
            finding.code, path, finding.detail
        ),
        None => eprintln!("- [{label}] {}: {}", finding.code, finding.detail),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_without_force_still_uses_the_auth_gated_verb() {
        // The defect: only `force` selected `source-restore-force`, so a bare
        // `--all` restore went out over `source-restore`, which sudoers grants
        // NOPASSWD via a `--*` wildcard that also matches `--all`.
        assert_eq!(restore_verb(false, true), "source-restore-force");
    }

    #[test]
    fn force_alone_still_uses_the_auth_gated_verb() {
        assert_eq!(restore_verb(true, false), "source-restore-force");
    }

    #[test]
    fn force_and_all_together_still_use_the_auth_gated_verb() {
        assert_eq!(restore_verb(true, true), "source-restore-force");
    }

    #[test]
    fn a_plain_named_restore_uses_the_nopasswd_verb() {
        // This is the one case agents may run unattended: a single named,
        // non-forced restore that refuses rather than overwrites a live value.
        assert_eq!(restore_verb(false, false), "source-restore");
    }
}
