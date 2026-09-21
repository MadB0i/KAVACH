//! KAVACH command-line interface.
//!
//! # Usage
//!
//! ```text
//! kavach [--output <human|json>] <command> [options]
//! ```
//!
//! See `kavach --help` for full usage.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), allow(clippy::print_stdout))]

use std::io::{self, Write};

use clap::{Parser, Subcommand};

mod commands;
mod error;
mod exit;
mod output;

use error::CliError;
use exit::ExitCode;
use output::OutputMode;

#[derive(Parser)]
#[command(name = "kavach", version, about = "KAVACH security runtime CLI")]
struct Cli {
    /// Output format
    #[arg(long, value_enum, default_value_t = OutputMode::Human, global = true)]
    output: OutputMode,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Check the KAVACH environment for common issues
    Doctor,
    /// Validate a config file
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Policy operations
    Policy {
        #[command(subcommand)]
        action: PolicyAction,
    },
    /// Validate a tool request file
    Request {
        #[command(subcommand)]
        action: RequestAction,
    },
    /// Audit log operations
    Audit {
        #[command(subcommand)]
        action: AuditAction,
    },
    /// Approval operations
    Approval {
        /// Path to config file (defaults to kavach.toml in current directory)
        #[arg(long, global = true)]
        config: Option<String>,

        #[command(subcommand)]
        action: ApprovalAction,
    },
    /// Start the KAVACH HTTP gateway
    Serve {
        /// Path to config file
        #[arg(short, long)]
        config: String,
    },
    /// Start the MCP security adapter
    Mcp {
        /// Start the MCP adapter
        #[command(subcommand)]
        action: McpAction,
    },
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Validate a config file
    Validate {
        /// Path to config file
        #[arg(short, long)]
        file: String,
    },
}

#[derive(Subcommand)]
enum PolicyAction {
    /// Validate a policy file
    Validate {
        /// Path to policy file
        #[arg(short, long)]
        file: String,
    },
    /// Check a request against a policy
    Check {
        /// Path to policy file
        #[arg(short, long)]
        policy: String,
        /// Path to request JSON file
        #[arg(short, long)]
        request: String,
        /// Append the decision to a JSONL feed log for the local dashboard
        #[arg(long)]
        feed_log: Option<String>,
    },
    /// Explain policy decision for a request
    Explain {
        /// Path to policy file
        #[arg(short, long)]
        policy: String,
        /// Path to request JSON file
        #[arg(short, long)]
        request: String,
        /// Dump the full AuthorizationDecision (including trace) as JSON
        #[arg(long)]
        json: bool,
        /// Append the decision to a JSONL feed log for the local dashboard
        #[arg(long)]
        feed_log: Option<String>,
    },
    /// Batch-test a policy against expected-outcome scenarios
    Test {
        /// Path to policy file
        #[arg(short, long)]
        policy: String,
        /// Path to scenarios JSON file
        #[arg(short, long)]
        scenarios: String,
    },
}

#[derive(Subcommand)]
enum RequestAction {
    /// Validate a request file
    Validate {
        /// Path to request JSON file
        #[arg(short, long)]
        file: String,
    },
}

#[derive(Subcommand)]
enum AuditAction {
    /// Verify the audit log chain integrity
    Verify {
        /// Path to audit database
        #[arg(short, long)]
        database: String,
    },
    /// List audit events
    List {
        /// Path to audit database
        #[arg(short, long)]
        database: String,
    },
}

#[derive(Subcommand)]
enum McpAction {
    /// Start the MCP security adapter
    Serve {
        /// Path to config file
        #[arg(short, long)]
        config: String,
    },
}

#[derive(Subcommand)]
enum ApprovalAction {
    /// List pending approvals
    List,
    /// Approve a pending approval
    Approve {
        /// Approval ID
        id: String,
    },
    /// Deny a pending approval
    Deny {
        /// Approval ID
        id: String,
    },
}

fn main() {
    let cli = Cli::parse();
    let mode = cli.output;

    let result = match cli.command {
        None => {
            // No subcommand: print version info
            let msg = format!("kavach {}", env!("CARGO_PKG_VERSION"));
            let _ = writeln!(io::stdout().lock(), "{msg}");
            Ok(())
        }
        Some(Commands::Doctor) => commands::doctor::run(mode),
        Some(Commands::Config { action }) => match action {
            ConfigAction::Validate { file } => commands::config_cmd::validate(&file, mode),
        },
        Some(Commands::Policy { action }) => match action {
            PolicyAction::Validate { file } => commands::policy::validate(&file, mode),
            PolicyAction::Check {
                policy,
                request,
                feed_log,
            } => commands::policy::check(&policy, &request, mode, feed_log.as_deref()),
            PolicyAction::Explain {
                policy,
                request,
                json,
                feed_log,
            } => commands::policy::explain(&policy, &request, mode, json, feed_log.as_deref()),
            PolicyAction::Test { policy, scenarios } => {
                commands::policy::test_policy(&policy, &scenarios, mode)
            }
        },
        Some(Commands::Request { action }) => match action {
            RequestAction::Validate { file } => commands::request::validate(&file, mode),
        },
        Some(Commands::Audit { action }) => match action {
            AuditAction::Verify { database } => commands::audit::verify(&database, mode),
            AuditAction::List { database } => commands::audit::list(&database, mode),
        },
        Some(Commands::Approval { config, action }) => match action {
            ApprovalAction::List => commands::approval::list(config.as_deref(), mode),
            ApprovalAction::Approve { id } => {
                commands::approval::approve(&id, config.as_deref(), mode)
            }
            ApprovalAction::Deny { id } => commands::approval::deny(&id, config.as_deref(), mode),
        },
        Some(Commands::Mcp { action }) => match action {
            McpAction::Serve { config } => {
                let rt = tokio::runtime::Runtime::new();
                match rt {
                    Ok(runtime) => runtime.block_on(commands::mcp::run(&config, mode)),
                    Err(e) => Err(CliError::new(
                        ExitCode::InternalError,
                        format!("runtime init failed: {e}"),
                    )),
                }
            }
        },
        Some(Commands::Serve { config }) => {
            let rt = tokio::runtime::Runtime::new();
            match rt {
                Ok(runtime) => runtime.block_on(commands::serve::run(&config, mode)),
                Err(e) => Err(CliError::new(
                    ExitCode::InternalError,
                    format!("runtime init failed: {e}"),
                )),
            }
        }
    };

    if let Err(err) = result {
        err.exit();
    }
}
