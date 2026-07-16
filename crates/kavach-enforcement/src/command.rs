//! Secure command enforcement adapter for the KAVACH security runtime.
//!
//! All command execution requires a valid, unexpired, single-use
//! [`ExecutionPermit`] bound to the
//! exact [`ToolRequest`].
//!
//! The adapter enforces:
//! - No shell invocation (cmd /c, sh -c, powershell -Command, etc.)
//! - Executable validation and risk classification
//! - Working-directory containment
//! - Environment variable filtering
//! - Timeout and output limits

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use kavach_core::permit::ExecutionPermit;
use kavach_core::request::{Operation, ToolRequest};
use kavach_core::resource::Resource;

/// Default command execution timeout (seconds).
pub const DEFAULT_COMMAND_TIMEOUT_SECONDS: u64 = 60;
/// Maximum allowed command execution timeout (seconds).
pub const MAX_COMMAND_TIMEOUT_SECONDS: u64 = 3600;
/// Default stdout byte limit (1 MiB).
pub const DEFAULT_STDOUT_LIMIT_BYTES: u64 = 1_048_576;
/// Default stderr byte limit (256 KiB).
pub const DEFAULT_STDERR_LIMIT_BYTES: u64 = 262_144;
/// Maximum number of command arguments.
pub const MAX_ARGUMENT_COUNT: usize = 256;
/// Maximum length of a single argument.
pub const MAX_ARGUMENT_LENGTH: usize = 4096;
/// Maximum number of environment variable entries.
pub const MAX_ENVIRONMENT_ENTRIES: usize = 64;
/// Maximum length of a single environment variable value.
pub const MAX_ENVIRONMENT_VALUE_LENGTH: usize = 4096;

/// Typed command execution input.
#[derive(Debug, Clone, Default)]
pub struct CommandInput {
    /// Working directory (must be under workspace root).
    pub working_directory: Option<PathBuf>,
    /// Environment variables to set (allowlist filtered).
    pub env_vars: Vec<(String, String)>,
    /// Whether to run in dry-run mode (no process spawned).
    pub dry_run: bool,
    /// Override the default timeout.
    pub timeout_seconds: Option<u64>,
}

/// Risk classification for a command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CommandRisk {
    /// Safe, read-only, or inspect-only commands.
    Low,
    /// Commands with elevated impact (network access, moderate mutation).
    Elevated,
    /// Potentially destructive operations requiring explicit approval.
    Destructive,
    /// Commands that must never be executed (shell wrapper, disk format, etc.).
    Forbidden,
}

impl CommandRisk {
    /// Returns a stable reason label for this risk level.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Elevated => "elevated",
            Self::Destructive => "destructive",
            Self::Forbidden => "forbidden",
        }
    }
}

/// Typed outcome of a command execution.
#[derive(Debug, Clone)]
pub struct CommandOutcome {
    /// The executable that was invoked.
    pub executable: String,
    /// Process exit code, or None if killed by timeout.
    pub exit_code: Option<i32>,
    /// Captured stdout bytes (bounded).
    pub stdout: Vec<u8>,
    /// Captured stderr bytes (bounded).
    pub stderr: Vec<u8>,
    /// Wall-clock duration of the command.
    pub duration: Duration,
    /// Risk classification assigned.
    pub risk: CommandRisk,
    /// Whether this was a dry-run.
    pub dry_run: bool,
}

/// Typed errors for command enforcement.
#[derive(Debug, thiserror::Error)]
pub enum CommandError {
    /// The request failed core validation.
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    /// The permit is invalid or does not match the request.
    #[error("invalid permit: {0}")]
    InvalidPermit(String),
    /// The permit has expired.
    #[error("permit expired")]
    PermitExpired,
    /// The permit has already been consumed.
    #[error("permit already consumed")]
    PermitConsumed,
    /// The permit scope does not allow this command.
    #[error("permit scope mismatch: {0}")]
    PermitScopeMismatch(String),
    /// The request operation is not CommandExecute.
    #[error("unsupported operation")]
    UnsupportedOperation,
    /// The request resource is not a Command.
    #[error("wrong resource type")]
    WrongResourceType,
    /// The executable is invalid (empty, control chars, etc.).
    #[error("invalid executable: {0}")]
    InvalidExecutable(String),
    /// Shell execution is not allowed.
    #[error("shell execution rejected: {0}")]
    ShellExecutionRejected(String),
    /// The command is classified as forbidden.
    #[error("forbidden command: {0}")]
    ForbiddenCommand(String),
    /// Destructive commands require special approval scope.
    #[error("destructive command requires approval scope")]
    DestructiveApprovalRequired,
    /// The working directory escapes the workspace.
    #[error("workspace escape: {0}")]
    WorkspaceEscape(String),
    /// The working directory is invalid.
    #[error("invalid working directory: {0}")]
    InvalidWorkingDirectory(String),
    /// The environment configuration is invalid.
    #[error("invalid environment: {0}")]
    InvalidEnvironment(String),
    /// Failed to spawn the process.
    #[error("process spawn failed: {0}")]
    SpawnFailed(String),
    /// The command execution timed out.
    #[error("command timed out after {0}s")]
    Timeout(u64),
    /// The process output exceeded its configured limit.
    #[error("output limit exceeded: {0}")]
    OutputLimitExceeded(String),
    /// The process terminated with an error.
    #[error("process failed: {0}")]
    ProcessFailed(String),
    /// An underlying I/O error occurred.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
}

/// A command enforcement adapter.
pub struct CommandEnforcer {
    workspace_root: PathBuf,
    timeout_seconds: u64,
    stdout_limit: u64,
    stderr_limit: u64,
    /// Optional allowlist of exact executable names or paths.
    #[allow(dead_code)]
    executable_allowlist: Option<BTreeSet<String>>,
    /// Whether to allow PATH lookup for executables without a path separator.
    #[allow(dead_code)]
    allow_path_lookup: bool,
}

impl CommandEnforcer {
    /// Create a new command enforcer with secure defaults.
    pub fn new(workspace_root: impl AsRef<Path>) -> Result<Self, CommandError> {
        let root = dunce::canonicalize(workspace_root.as_ref()).map_err(CommandError::Io)?;
        Ok(Self {
            workspace_root: root,
            timeout_seconds: DEFAULT_COMMAND_TIMEOUT_SECONDS,
            stdout_limit: DEFAULT_STDOUT_LIMIT_BYTES,
            stderr_limit: DEFAULT_STDERR_LIMIT_BYTES,
            executable_allowlist: None,
            allow_path_lookup: false,
        })
    }

    /// Classify a command's risk level by executable name.
    ///
    /// This uses the same logic as the enforcement adapter but without
    /// requiring a full `ToolRequest` or argument inspection.
    pub fn classify(&self, executable: &str) -> CommandRisk {
        classify_risk(executable, &[])
    }

    /// Execute a guarded command.
    pub fn execute(
        &self,
        request: &ToolRequest,
        permit: &mut ExecutionPermit,
        input: &CommandInput,
    ) -> Result<CommandOutcome, CommandError> {
        // 1. Validate request.
        request
            .validate()
            .map_err(|e| CommandError::InvalidRequest(e.to_string()))?;

        // 2. Require CommandExecute + Command resource.
        if !matches!(request.operation, Operation::CommandExecute) {
            return Err(CommandError::UnsupportedOperation);
        }
        let cmd = match &request.resource {
            Resource::Command(c) => c,
            _ => return Err(CommandError::WrongResourceType),
        };

        // 3. Verify and consume permit.
        verify_command_permit(permit, request)?;

        // 4. Validate executable.
        let exe = validate_executable(cmd.executable())?;

        // 5. Validate arguments for shell patterns.
        validate_arguments(cmd.arguments())?;

        // 6. Validate working directory.
        let working_dir =
            resolve_working_directory(&self.workspace_root, input.working_directory.as_deref())?;

        // 7. Classify command risk.
        let risk = classify_risk(cmd.executable(), cmd.arguments());

        match risk {
            CommandRisk::Forbidden => {
                return Err(CommandError::ForbiddenCommand(cmd.executable().to_string()));
            }
            CommandRisk::Destructive => {
                return Err(CommandError::DestructiveApprovalRequired);
            }
            _ => {}
        }

        // 8. Return early for dry-run.
        if input.dry_run {
            return Ok(CommandOutcome {
                executable: exe,
                exit_code: None,
                stdout: Vec::new(),
                stderr: Vec::new(),
                duration: Duration::ZERO,
                risk,
                dry_run: true,
            });
        }

        // 9. Build environment.
        let env = build_environment(&input.env_vars)?;

        // 10. Execute.
        let timeout_secs = input
            .timeout_seconds
            .unwrap_or(self.timeout_seconds)
            .min(MAX_COMMAND_TIMEOUT_SECONDS);
        execute_process(ProcessConfig {
            exe: &exe,
            args: cmd.arguments(),
            working_dir: &working_dir,
            env: &env,
            timeout_secs,
            stdout_limit: self.stdout_limit,
            stderr_limit: self.stderr_limit,
            risk,
        })
    }
}

// ---------------------------------------------------------------------------
// Permit verification
// ---------------------------------------------------------------------------

fn verify_command_permit(
    permit: &mut ExecutionPermit,
    request: &ToolRequest,
) -> Result<(), CommandError> {
    if permit.is_expired() {
        return Err(CommandError::PermitExpired);
    }
    if permit.is_consumed() {
        return Err(CommandError::PermitConsumed);
    }
    let digest = kavach_core::compute_request_digest(request);
    if !permit.verify_request_digest(&digest) {
        return Err(CommandError::InvalidPermit(
            "permit does not match request digest".into(),
        ));
    }
    if !permit.consume() {
        return Err(CommandError::PermitConsumed);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Executable validation
// ---------------------------------------------------------------------------

/// Shell wrapper executables that are rejected or classified as high-risk
/// when paired with shell-evaluation flags.
const SHELL_EXECUTABLES: &[&str] = &[
    "cmd",
    "cmd.exe",
    "powershell",
    "powershell.exe",
    "pwsh",
    "pwsh.exe",
    "sh",
    "bash",
    "zsh",
    "fish",
    "dash",
    "ksh",
];

#[allow(dead_code)]
const SHELL_FLAGS: &[&str] = &[
    "/c",
    "/C",
    "/k",
    "/K",
    "-c",
    "-C",
    "-Command",
    "-command",
    "--command",
    "-EncodedCommand",
    "-Encodedcommand",
    "-encodedcommand",
    "-e",
    "-E",
];

fn is_shell_executable(exe: &str) -> bool {
    // Lower-case the filename portion for comparison.
    let name = std::path::Path::new(exe)
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_else(|| exe.to_lowercase());
    SHELL_EXECUTABLES
        .iter()
        .any(|s| *s == name || format!("{s}.exe") == name)
}

fn validate_executable(exe: &str) -> Result<String, CommandError> {
    if exe.is_empty() {
        return Err(CommandError::InvalidExecutable("empty".into()));
    }
    if exe
        .bytes()
        .any(|b| b == 0 || b.is_ascii_control() && b != b'\t')
    {
        return Err(CommandError::InvalidExecutable(
            "contains null or control characters".into(),
        ));
    }
    if exe.len() > kavach_core::resource::MAX_PATH_LEN {
        return Err(CommandError::InvalidExecutable(
            "exceeds maximum length".into(),
        ));
    }
    // Reject executables that contain shell operators embedded in the name.
    if exe.contains("&&") || exe.contains('|') || exe.contains(';') || exe.contains(' ') {
        return Err(CommandError::InvalidExecutable(
            "contains shell operators or spaces in executable name".into(),
        ));
    }
    // Check against shell executables.
    if is_shell_executable(exe) {
        return Err(CommandError::ShellExecutionRejected(format!(
            "shell executable forbidden: {exe}"
        )));
    }
    Ok(exe.to_string())
}

// ---------------------------------------------------------------------------
// Argument validation
// ---------------------------------------------------------------------------

const SHELL_CHAIN_PATTERNS: &[&str] = &["&&", "||", ";", "|"];

fn validate_arguments(args: &[String]) -> Result<(), CommandError> {
    if args.len() > MAX_ARGUMENT_COUNT {
        return Err(CommandError::InvalidRequest(format!(
            "too many arguments: {} (max {MAX_ARGUMENT_COUNT})",
            args.len()
        )));
    }
    for (i, arg) in args.iter().enumerate() {
        if arg.len() > MAX_ARGUMENT_LENGTH {
            return Err(CommandError::InvalidRequest(format!(
                "argument {i} exceeds {MAX_ARGUMENT_LENGTH} bytes"
            )));
        }
        if arg.is_empty() {
            return Err(CommandError::InvalidRequest(format!(
                "argument {i} is empty"
            )));
        }
        // Reject null bytes.
        if arg.contains('\0') {
            return Err(CommandError::ShellExecutionRejected(format!(
                "argument {i} contains null byte"
            )));
        }
        // Reject control characters except tab.
        if arg
            .bytes()
            .any(|b| b.is_ascii_control() && b != b'\t' && b != b'\r')
        {
            return Err(CommandError::ShellExecutionRejected(format!(
                "argument {i} contains control character"
            )));
        }
        // Reject output redirection operators.
        if arg.contains('>') || arg.contains('<') {
            return Err(CommandError::ShellExecutionRejected(format!(
                "argument {i} contains redirection operator"
            )));
        }
        // Reject shell chaining operators.
        if SHELL_CHAIN_PATTERNS.iter().any(|p| arg.contains(p)) {
            return Err(CommandError::ShellExecutionRejected(format!(
                "argument {i} contains shell chaining operator"
            )));
        }
        // Detect encoded PowerShell.
        if arg.to_lowercase().contains("-encodedcommand")
            || arg.to_lowercase().contains("-enc")
            || arg.to_lowercase().contains("-e ")
        {
            return Err(CommandError::ShellExecutionRejected(format!(
                "argument {i}: encoded PowerShell rejected"
            )));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Risk classification
// ---------------------------------------------------------------------------

/// High-risk exact executable names.
const FORBIDDEN_EXECUTABLES: &[&str] = &["format", "mkfs", "diskpart", "fdisk"];

/// Destructive command patterns (executable + flag combinations).
struct DestructivePattern {
    exe_matches: &'static [&'static str],
    flag_contains: &'static [&'static str],
}

/// Patterns that indicate destructive intent.
static DESTRUCTIVE_PATTERNS: &[DestructivePattern] = &[
    // rm with recursive/force
    DestructivePattern {
        exe_matches: &["rm", "rm.exe"],
        flag_contains: &["-r", "-f", "-rf", "-fr", "--recursive", "--force"],
    },
    // rmdir recursive
    DestructivePattern {
        exe_matches: &["rmdir", "rmdir.exe"],
        flag_contains: &["/s", "/S", "-r", "--recursive"],
    },
    // del destructive
    DestructivePattern {
        exe_matches: &["del", "del.exe"],
        flag_contains: &["/f", "/F", "/s", "/S", "/q", "/Q"],
    },
    // Remove-Item recursive/force
    DestructivePattern {
        exe_matches: &["Remove-Item"],
        flag_contains: &["-Recurse", "-Force", "-recurse", "-force"],
    },
    // dd targeting devices
    DestructivePattern {
        exe_matches: &["dd", "dd.exe"],
        flag_contains: &["of=/dev/", "if=/dev/"],
    },
    // shutdown/reboot
    DestructivePattern {
        exe_matches: &["shutdown", "shutdown.exe", "reboot", "reboot.exe"],
        flag_contains: &[],
    },
    // Dangerous system modifications
    DestructivePattern {
        exe_matches: &["chmod", "chown", "chmod.exe"],
        flag_contains: &["777", "-R", "-r", "--recursive"],
    },
    // Process termination
    DestructivePattern {
        exe_matches: &["kill", "pkill", "taskkill", "taskkill.exe"],
        flag_contains: &["-9", "-KILL", "/f", "/F"],
    },
    // Privilege escalation
    DestructivePattern {
        exe_matches: &["sudo", "su", "runas", "runas.exe"],
        flag_contains: &[],
    },
    // Git destructive operations
    DestructivePattern {
        exe_matches: &["git", "git.exe"],
        flag_contains: &["reset", "checkout", "clean", "branch", "push"],
    },
    // Download + execute patterns
    DestructivePattern {
        exe_matches: &["curl", "curl.exe", "wget", "wget.exe"],
        flag_contains: &["|", "sh", "bash", "cmd"],
    },
    // Invoke-Expression with downloads
    DestructivePattern {
        exe_matches: &["powershell", "powershell.exe", "pwsh", "pwsh.exe"],
        flag_contains: &[
            "Invoke-Expression",
            "iex",
            "Invoke-WebRequest",
            "iwr",
            "DownloadString",
            "DownloadFile",
        ],
    },
    // Firewall modification
    DestructivePattern {
        exe_matches: &["netsh", "netsh.exe", "iptables"],
        flag_contains: &[],
    },
    // Registry modification
    DestructivePattern {
        exe_matches: &["reg", "reg.exe", "regedit", "regedit.exe"],
        flag_contains: &["add", "delete", "/d", "/f"],
    },
    // Service modification
    DestructivePattern {
        exe_matches: &["sc", "sc.exe", "systemctl"],
        flag_contains: &["stop", "disable", "delete"],
    },
];

/// Detailed Git destructive flag detection.
fn is_destructive_git(args: &[String]) -> bool {
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "reset" => {
                if args.get(i + 1).map(|s| s.as_str()) == Some("--hard") {
                    return true;
                }
            }
            "clean" => {
                if args.iter().any(|x| x == "-f" || x == "-fd" || x == "-df") {
                    return true;
                }
            }
            "checkout" => {
                if args.get(i + 1).map(|s| s.as_str()) == Some("--")
                    && args.get(i + 2).map(|s| s.as_str()) == Some(".")
                {
                    return true;
                }
            }
            "push" => {
                if args.iter().any(|x| x == "--force" || x == "-f") {
                    return true;
                }
                return false;
            }
            "branch" if args.iter().any(|x| x == "-D") => return true,
            _ => {}
        }
        i += 1;
    }
    false
}

fn classify_risk(exe: &str, args: &[String]) -> CommandRisk {
    let exe_lower = exe.to_lowercase();
    let name = std::path::Path::new(&exe_lower)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| exe_lower.clone());

    // Check forbidden executables.
    for forbidden in FORBIDDEN_EXECUTABLES {
        if name == *forbidden || format!("{forbidden}.exe") == name {
            return CommandRisk::Forbidden;
        }
    }

    // Check destructive patterns.
    for pat in DESTRUCTIVE_PATTERNS {
        let name_matches = pat
            .exe_matches
            .iter()
            .any(|m| name == *m || format!("{m}.exe") == name);
        if !name_matches {
            continue;
        }
        // If the pattern has no required flags, it's destructive by name alone.
        if pat.flag_contains.is_empty() {
            return CommandRisk::Destructive;
        }
        // Check for flagged arguments.
        for flag in pat.flag_contains {
            if args.iter().any(|a| a.to_lowercase().contains(flag)) {
                // Special handling for git — requires additional checks.
                if name == "git" || name == "git.exe" {
                    if is_destructive_git(args) {
                        return CommandRisk::Destructive;
                    }
                    continue;
                }
                return CommandRisk::Destructive;
            }
        }
    }

    // Elevated: commands with moderate mutation impact.
    if matches!(
        name.as_str(),
        "npm"
            | "npm.exe"
            | "yarn"
            | "pip"
            | "pip3"
            | "docker"
            | "docker.exe"
            | "kubectl"
            | "kubectl.exe"
    ) {
        return CommandRisk::Elevated;
    }

    CommandRisk::Low
}

// ---------------------------------------------------------------------------
// Working directory resolution
// ---------------------------------------------------------------------------

fn resolve_working_directory(
    workspace_root: &Path,
    working_dir: Option<&Path>,
) -> Result<PathBuf, CommandError> {
    let dir = match working_dir {
        Some(d) => {
            if d.is_absolute() {
                return Err(CommandError::WorkspaceEscape(format!(
                    "absolute working directory forbidden: {}",
                    d.display()
                )));
            }
            let full = workspace_root.join(d);
            let canon = dunce::canonicalize(&full).map_err(|e| {
                CommandError::InvalidWorkingDirectory(format!("cannot resolve: {e}"))
            })?;
            if !canon.starts_with(workspace_root) {
                return Err(CommandError::WorkspaceEscape(format!(
                    "working directory outside workspace: {}",
                    canon.display()
                )));
            }
            if !canon.is_dir() {
                return Err(CommandError::InvalidWorkingDirectory(format!(
                    "not a directory: {}",
                    canon.display()
                )));
            }
            canon
        }
        None => workspace_root.to_path_buf(),
    };
    Ok(dir)
}

// ---------------------------------------------------------------------------
// Environment filtering
// ---------------------------------------------------------------------------

/// Variables allowed by default in the child process environment.
const DEFAULT_ALLOWED_VARS: &[&str] = &[
    "PATH",
    "HOME",
    "USERPROFILE",
    "TEMP",
    "TMP",
    "TMPDIR",
    "LANG",
    "LC_ALL",
    "USER",
    "LOGNAME",
    "HOSTNAME",
    "COMPUTERNAME",
    "TERM",
    "COLORTERM",
    "SHELL",
    "PWD",
    "CARGO_HOME",
    "RUSTUP_HOME",
    "RUST_LOG",
    "SYSTEMROOT",
    "SystemRoot",
    "ProgramFiles",
    "ProgramData",
    "PROCESSOR_ARCHITECTURE",
    "NUMBER_OF_PROCESSORS",
    "OS",
    "PATHEXT",
    "COMSPEC",
    "WINDIR",
    "windir",
];

/// Variable prefixes that indicate credentials and must never be inherited.
fn is_dangerous_var(name: &str) -> bool {
    let upper = name.to_uppercase();
    let dangerous = [
        "AWS_",
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "API_KEY",
        "APIKEY_",
        "SECRET",
        "PASSWORD",
        "TOKEN",
        "KEY_",
        "_KEY",
        "CREDENTIAL",
        "PRIVATE",
        "SSH_",
        "DOCKER_PASS",
        "NPM_TOKEN",
        "NUGET_KEY",
        "AZURE_",
        "GCLOUD_",
        "GOOGLE_",
    ];
    dangerous
        .iter()
        .any(|prefix| upper.starts_with(prefix) || upper.contains(prefix))
}

fn build_environment(extra: &[(String, String)]) -> Result<Vec<(String, String)>, CommandError> {
    let mut env: Vec<(String, String)> = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // Copy only allowlisted variables from the parent environment.
    for (key, val) in std::env::vars() {
        if seen.contains(&key) {
            continue;
        }
        if is_dangerous_var(&key) {
            continue;
        }
        // Check against the default allowlist.
        let allowed = DEFAULT_ALLOWED_VARS
            .iter()
            .any(|allowed_key| key.eq_ignore_ascii_case(allowed_key));
        if !allowed {
            continue;
        }
        if key.bytes().any(|b| b == 0) || val.bytes().any(|b| b == 0) {
            continue;
        }
        seen.insert(key.clone());
        env.push((key, val));
    }

    // Add/override user-supplied variables.
    for (key, val) in extra {
        if key.is_empty() {
            return Err(CommandError::InvalidEnvironment(
                "empty variable name".into(),
            ));
        }
        if key
            .bytes()
            .any(|b| b == 0 || b.is_ascii_control() && b != b'\t')
        {
            return Err(CommandError::InvalidEnvironment(format!(
                "invalid variable name: {key}"
            )));
        }
        if val.len() > MAX_ENVIRONMENT_VALUE_LENGTH {
            return Err(CommandError::InvalidEnvironment(format!(
                "variable {key} exceeds max value length"
            )));
        }
        if val.contains('\0') {
            return Err(CommandError::InvalidEnvironment(format!(
                "variable {key} contains null byte"
            )));
        }
        seen.insert(key.clone());
        env.push((key.clone(), val.clone()));
    }

    if env.len() > MAX_ENVIRONMENT_ENTRIES {
        return Err(CommandError::InvalidEnvironment(format!(
            "too many env entries: {} (max {MAX_ENVIRONMENT_ENTRIES})",
            env.len()
        )));
    }

    Ok(env)
}

// ---------------------------------------------------------------------------
// Process execution
// ---------------------------------------------------------------------------

struct ProcessConfig<'a> {
    exe: &'a str,
    args: &'a [String],
    working_dir: &'a Path,
    env: &'a [(String, String)],
    timeout_secs: u64,
    stdout_limit: u64,
    stderr_limit: u64,
    risk: CommandRisk,
}

fn execute_process(config: ProcessConfig<'_>) -> Result<CommandOutcome, CommandError> {
    use std::process::{Command, Stdio};
    use std::time::Instant;

    let mut cmd = Command::new(config.exe);
    cmd.args(config.args);
    cmd.current_dir(config.working_dir);
    cmd.env_clear();
    for (k, v) in config.env {
        cmd.env(k, v);
    }
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let start = Instant::now();
    let mut child = cmd
        .spawn()
        .map_err(|e| CommandError::SpawnFailed(e.to_string()))?;

    let deadline = start + Duration::from_secs(config.timeout_secs);

    let stdout_handle = child.stdout.take();
    let stderr_handle = child.stderr.take();

    let (stdout_read, stderr_read) = std::thread::scope(|s| {
        let stdout_thread = s.spawn(|| read_stream(stdout_handle, config.stdout_limit));
        let stderr_thread = s.spawn(|| read_stream(stderr_handle, config.stderr_limit));
        (stdout_thread.join(), stderr_thread.join())
    });

    let stdout = stdout_read
        .map_err(|_| CommandError::ProcessFailed("stdout reader panicked".into()))?
        .map_err(CommandError::Io)?;
    let stderr = stderr_read
        .map_err(|_| CommandError::ProcessFailed("stderr reader panicked".into()))?
        .map_err(CommandError::Io)?;

    // Wait for child with timeout.
    let remaining = deadline.saturating_duration_since(Instant::now());
    let exit_code = match wait_timeout(&mut child, remaining) {
        Ok(Some(status)) => status.code(),
        Ok(None) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(CommandError::Timeout(config.timeout_secs));
        }
        Err(e) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(CommandError::ProcessFailed(e.to_string()));
        }
    };

    let duration = start.elapsed();

    Ok(CommandOutcome {
        executable: config.exe.to_string(),
        exit_code,
        stdout,
        stderr,
        duration,
        risk: config.risk,
        dry_run: false,
    })
}

/// Read from a stream with a hard byte limit.
fn read_stream(stream: Option<impl std::io::Read>, limit: u64) -> Result<Vec<u8>, std::io::Error> {
    let mut reader = match stream {
        Some(r) => r,
        None => return Ok(Vec::new()),
    };
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                let remaining = limit.saturating_sub(buf.len() as u64);
                if remaining == 0 {
                    break;
                }
                let take = (n as u64).min(remaining) as usize;
                buf.extend_from_slice(&chunk[..take]);
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(buf)
}

/// Wait for a child process with a timeout.
fn wait_timeout(
    child: &mut std::process::Child,
    timeout: Duration,
) -> Result<Option<std::process::ExitStatus>, std::io::Error> {
    if timeout.is_zero() {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(Some(status)),
            Ok(None) => return Ok(None),
            Err(e) => return Err(e),
        }
    }

    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(Some(status)),
            Ok(None) => {
                if start.elapsed() >= timeout {
                    return Ok(None);
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use kavach_core::ids::{AgentId, RequestId, SessionId};
    use kavach_core::permit::PermitScope;
    use kavach_core::request::{AgentSubjectBuilder, RequestContext};
    use std::time::Duration;

    fn make_subject() -> kavach_core::subject::AgentSubject {
        AgentSubjectBuilder::new(
            AgentId::new("agent-1").unwrap(),
            SessionId::new("sess-1").unwrap(),
        )
        .trust_level(kavach_core::subject::TrustLevel::Standard)
        .build()
    }

    fn make_context() -> RequestContext {
        RequestContext::new(None, None, None, None, false).unwrap()
    }

    fn make_permit(request: &ToolRequest) -> ExecutionPermit {
        let digest = kavach_core::compute_request_digest(request);
        ExecutionPermit::new(
            &[1u8; 32],
            request.request_id.clone(),
            PermitScope::CommandLowRisk,
            vec![],
            digest,
            Duration::from_secs(300),
        )
    }

    fn make_expired_permit(request: &ToolRequest) -> ExecutionPermit {
        let digest = kavach_core::compute_request_digest(request);
        ExecutionPermit::new(
            &[2u8; 32],
            request.request_id.clone(),
            PermitScope::CommandLowRisk,
            vec![],
            digest,
            Duration::from_secs(0),
        )
    }

    fn cmd_request(exe: &str, args: &[&str]) -> ToolRequest {
        ToolRequest::new(
            RequestId::new("req-1").unwrap(),
            make_subject(),
            Operation::CommandExecute,
            Resource::Command(
                kavach_core::resource::CommandResource::new(
                    exe,
                    args.iter().map(|s| s.to_string()).collect(),
                )
                .unwrap(),
            ),
            make_context(),
        )
    }

    fn make_enforcer(tmp: &Path) -> CommandEnforcer {
        CommandEnforcer::new(tmp).unwrap()
    }

    fn uuid_simple() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos();
        format!("{nanos:08x}")
    }

    // ----------------------------------------------------------------
    // Risk classification tests
    // ----------------------------------------------------------------

    #[test]
    fn safe_command_low_risk() {
        assert_eq!(classify_risk("ls", &["-la".into()]), CommandRisk::Low);
        assert_eq!(classify_risk("cargo", &["check".into()]), CommandRisk::Low);
        assert_eq!(classify_risk("git", &["status".into()]), CommandRisk::Low);
    }

    #[test]
    fn git_reset_hard_destructive() {
        assert_eq!(
            classify_risk("git", &["reset".into(), "--hard".into()]),
            CommandRisk::Destructive
        );
    }

    #[test]
    fn git_clean_fd_destructive() {
        assert_eq!(
            classify_risk("git", &["clean".into(), "-fd".into()]),
            CommandRisk::Destructive
        );
    }

    #[test]
    fn git_push_force_destructive() {
        assert_eq!(
            classify_risk("git", &["push".into(), "--force".into()]),
            CommandRisk::Destructive
        );
    }

    #[test]
    fn rm_recursive_destructive() {
        assert_eq!(
            classify_risk("rm", &["-rf".into(), "dir".into()]),
            CommandRisk::Destructive
        );
    }

    #[test]
    fn format_command_forbidden() {
        assert_eq!(
            classify_risk("format", &["C:".into()]),
            CommandRisk::Forbidden
        );
    }

    #[test]
    fn shutdown_command_destructive() {
        assert_eq!(
            classify_risk("shutdown", &["-h".into(), "now".into()]),
            CommandRisk::Destructive
        );
    }

    #[test]
    fn curl_pipe_destructive() {
        assert_eq!(
            classify_risk(
                "curl",
                &["-s".into(), "url".into(), "|".into(), "sh".into()]
            ),
            CommandRisk::Destructive
        );
    }

    // ----------------------------------------------------------------
    // Executable validation tests
    // ----------------------------------------------------------------

    #[test]
    fn shell_executables_rejected() {
        assert!(validate_executable("sh").is_err());
        assert!(validate_executable("bash").is_err());
        assert!(validate_executable("cmd").is_err());
        assert!(validate_executable("powershell").is_err());
    }

    #[test]
    fn empty_executable_rejected() {
        assert!(validate_executable("").is_err());
    }

    // ----------------------------------------------------------------
    // Argument validation tests
    // ----------------------------------------------------------------

    #[test]
    fn shell_chaining_rejected() {
        assert!(validate_arguments(&["a&&b".into()]).is_err());
        assert!(validate_arguments(&["a||b".into()]).is_err());
        assert!(validate_arguments(&["a|b".into()]).is_err());
        assert!(validate_arguments(&["a;b".into()]).is_err());
    }

    #[test]
    fn redirection_rejected() {
        assert!(validate_arguments(&[">output".into()]).is_err());
        assert!(validate_arguments(&["<input".into()]).is_err());
    }

    #[test]
    fn null_byte_rejected() {
        assert!(validate_arguments(&["hello\0".into()]).is_err());
    }

    #[test]
    fn encoded_powershell_rejected() {
        assert!(validate_arguments(&["-EncodedCommand".into()]).is_err());
        assert!(validate_arguments(&["-enc".into()]).is_err());
    }

    // ----------------------------------------------------------------
    // Working directory tests
    // ----------------------------------------------------------------

    #[test]
    fn absolute_working_dir_rejected() {
        let tmp = std::env::temp_dir().join(format!("kavach_cmd_wd_{}", uuid_simple()));
        std::fs::create_dir_all(&tmp).unwrap();
        let enforcer = make_enforcer(&tmp);
        // Use a platform-appropriate absolute path outside the workspace.
        #[cfg(unix)]
        let outside = PathBuf::from("/etc");
        #[cfg(windows)]
        let outside = PathBuf::from("C:\\Windows");
        #[cfg(not(any(unix, windows)))]
        let outside = PathBuf::from("/nonexistent");
        let input = CommandInput {
            working_directory: Some(outside),
            ..Default::default()
        };
        let req = cmd_request("echo", &["hello"]);
        let mut permit = make_permit(&req);
        let result = enforcer.execute(&req, &mut permit, &input);
        assert!(matches!(result, Err(CommandError::WorkspaceEscape(_))));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ----------------------------------------------------------------
    // Process execution tests
    // ----------------------------------------------------------------

    #[test]
    fn safe_command_executes_with_permit() {
        let tmp = std::env::temp_dir().join(format!("kavach_cmd_safe_{}", uuid_simple()));
        std::fs::create_dir_all(&tmp).unwrap();
        let enforcer = make_enforcer(&tmp);
        #[cfg(unix)]
        {
            let req = cmd_request("echo", &["hello"]);
            let mut permit = make_permit(&req);
            let outcome = enforcer
                .execute(&req, &mut permit, &CommandInput::default())
                .unwrap();
            assert_eq!(outcome.risk, CommandRisk::Low);
            assert!(!outcome.dry_run);
        }
        #[cfg(windows)]
        {
            // On Windows, cmd/powershell are shells and rejected.
            // Use `hostname` which is a built-in executable.
            let req = cmd_request("hostname", &[]);
            let mut permit = make_permit(&req);
            let outcome = enforcer
                .execute(&req, &mut permit, &CommandInput::default())
                .unwrap();
            assert_eq!(outcome.risk, CommandRisk::Low);
            assert!(!outcome.dry_run);
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn dry_run_never_spawns() {
        let tmp = std::env::temp_dir().join(format!("kavach_cmd_dry_{}", uuid_simple()));
        std::fs::create_dir_all(&tmp).unwrap();
        let enforcer = make_enforcer(&tmp);
        let req = cmd_request("echo", &["hello"]);
        let mut permit = make_permit(&req);
        let input = CommandInput {
            dry_run: true,
            ..Default::default()
        };
        let outcome = enforcer.execute(&req, &mut permit, &input).unwrap();
        assert!(outcome.dry_run);
        assert_eq!(outcome.exit_code, None);
        assert!(outcome.stdout.is_empty());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn expired_permit_rejected() {
        let tmp = std::env::temp_dir().join(format!("kavach_cmd_exp_{}", uuid_simple()));
        std::fs::create_dir_all(&tmp).unwrap();
        let enforcer = make_enforcer(&tmp);
        let req = cmd_request("echo", &["hello"]);
        let mut expired = make_expired_permit(&req);
        let result = enforcer.execute(&req, &mut expired, &CommandInput::default());
        assert!(matches!(result, Err(CommandError::PermitExpired)));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn consumed_permit_rejected() {
        let tmp = std::env::temp_dir().join(format!("kavach_cmd_cons_{}", uuid_simple()));
        std::fs::create_dir_all(&tmp).unwrap();
        let enforcer = make_enforcer(&tmp);
        let req = cmd_request("echo", &["hello"]);
        let mut permit = make_permit(&req);
        permit.consume();
        let result = enforcer.execute(&req, &mut permit, &CommandInput::default());
        assert!(matches!(result, Err(CommandError::PermitConsumed)));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn forged_permit_rejected() {
        let tmp = std::env::temp_dir().join(format!("kavach_cmd_forg_{}", uuid_simple()));
        std::fs::create_dir_all(&tmp).unwrap();
        let enforcer = make_enforcer(&tmp);
        let req_a = cmd_request("echo", &["hello"]);
        let req_b = cmd_request("echo", &["world"]);
        let mut permit_b = make_permit(&req_b);
        let result = enforcer.execute(&req_a, &mut permit_b, &CommandInput::default());
        assert!(matches!(result, Err(CommandError::InvalidPermit(_))));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn failed_spawn_consumes_permit() {
        let tmp = std::env::temp_dir().join(format!("kavach_cmd_failspawn_{}", uuid_simple()));
        std::fs::create_dir_all(&tmp).unwrap();
        let enforcer = make_enforcer(&tmp);
        let req = cmd_request("nonexistent_binary_xyz", &[]);
        let mut permit = make_permit(&req);
        let result = enforcer.execute(&req, &mut permit, &CommandInput::default());
        assert!(matches!(result, Err(CommandError::SpawnFailed(_))));
        assert!(permit.is_consumed());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn forbidden_command_rejected() {
        let tmp = std::env::temp_dir().join(format!("kavach_cmd_forb_{}", uuid_simple()));
        std::fs::create_dir_all(&tmp).unwrap();
        let enforcer = make_enforcer(&tmp);
        let req = cmd_request("format", &["C:"]);
        let mut permit = make_permit(&req);
        let result = enforcer.execute(&req, &mut permit, &CommandInput::default());
        assert!(matches!(result, Err(CommandError::ForbiddenCommand(_))));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn destructive_command_rejected() {
        let tmp = std::env::temp_dir().join(format!("kavach_cmd_destr_{}", uuid_simple()));
        std::fs::create_dir_all(&tmp).unwrap();
        let enforcer = make_enforcer(&tmp);
        let req = cmd_request("rm", &["-rf", "/tmp/foo"]);
        let mut permit = make_permit(&req);
        let result = enforcer.execute(&req, &mut permit, &CommandInput::default());
        assert!(matches!(
            result,
            Err(CommandError::DestructiveApprovalRequired)
        ));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn non_command_resource_rejected() {
        let tmp = std::env::temp_dir().join(format!("kavach_cmd_ncmd_{}", uuid_simple()));
        std::fs::create_dir_all(&tmp).unwrap();
        let enforcer = make_enforcer(&tmp);
        let req = ToolRequest::new(
            RequestId::new("req-1").unwrap(),
            make_subject(),
            Operation::CommandExecute,
            Resource::file("foo.txt").unwrap(),
            make_context(),
        );
        let mut permit = make_permit(&req);
        let result = enforcer.execute(&req, &mut permit, &CommandInput::default());
        // Request validation rejects CommandExecute with non-Command resource.
        assert!(matches!(result, Err(CommandError::InvalidRequest(_))));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn timeout_kills_process() {
        let tmp = std::env::temp_dir().join(format!("kavach_cmd_to_{}", uuid_simple()));
        std::fs::create_dir_all(&tmp).unwrap();
        let enforcer = make_enforcer(&tmp);
        // Create a command that sleeps longer than the timeout.
        let (exe, args): (&str, &[&str]) = if cfg!(windows) {
            ("powershell", &["-Command", "Start-Sleep -Seconds 30"])
        } else {
            ("sleep", &["30"])
        };
        // Skip Windows powershell since it's a shell.
        if cfg!(windows) {
            let _ = std::fs::remove_dir_all(&tmp);
            return;
        }
        let req = cmd_request(exe, args);
        let mut permit = make_permit(&req);
        let input = CommandInput {
            timeout_seconds: Some(1),
            ..Default::default()
        };
        let result = enforcer.execute(&req, &mut permit, &input);
        assert!(matches!(result, Err(CommandError::Timeout(1))));
        assert!(permit.is_consumed());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn argument_count_limit_enforced() {
        let args: Vec<String> = (0..=MAX_ARGUMENT_COUNT)
            .map(|i| format!("arg{i}"))
            .collect();
        let result = validate_arguments(&args);
        assert!(result.is_err());
    }

    #[test]
    fn argument_length_limit_enforced() {
        let long = "a".repeat(MAX_ARGUMENT_LENGTH + 1);
        assert!(validate_arguments(&[long]).is_err());
    }

    #[test]
    fn deterministic_risk_classification() {
        let r1 = classify_risk("git", &["reset".into(), "--hard".into()]);
        let r2 = classify_risk("git", &["reset".into(), "--hard".into()]);
        assert_eq!(r1, r2);
        assert_eq!(r1, CommandRisk::Destructive);
    }
}
