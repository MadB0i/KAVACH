//! `kavach setup` — wire the cooperative hook-based agent layer.
//!
//! Detects installed agent CLIs (Claude Code, Codex CLI, OpenCode), stages
//! the hook scripts next to the binary's data dir, and merges hook
//! registrations into each tool's config additively (existing entries are
//! never replaced; conflicts only warn). This installs *cooperative*
//! pre-execution hooks, not system-wide interception: a tool without a hook
//! API, or one run with hooks disabled, is outside this layer.

use std::path::{Path, PathBuf};

use crate::error::CliError;
use crate::exit::ExitCode;
use crate::output::{CliOutput, OutputMode};

// Hook scripts are compiled in so `setup` works from an installed binary
// with no repo checkout present.
const COMMON_MODULE: &str = include_str!("../../../../adapters/kavach-adapter-common.psm1");
const CLAUDE_HOOK: &str = include_str!("../../../../adapters/claude/kavach-claude-hook.ps1");
const CODEX_HOOK: &str = include_str!("../../../../adapters/codex/kavach-codex-hook.ps1");
const OPENCODE_HOOK: &str = include_str!("../../../../adapters/opencode/kavach-hook.mjs");

const CLAUDE_MATCHER: &str = "Bash|PowerShell|Write|Edit|Read|MultiEdit|NotebookEdit";

/// Test hook: when set, all home-relative paths resolve under this root.
fn setup_root() -> Option<PathBuf> {
    std::env::var_os("KAVACH_SETUP_ROOT").map(PathBuf::from)
}

fn home_dir() -> Option<PathBuf> {
    if let Some(root) = setup_root() {
        return Some(root);
    }
    std::env::var_os("USERPROFILE")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(PathBuf::from))
}

fn on_path(name: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    #[cfg(windows)]
    let exts = ["", ".exe", ".cmd", ".bat"];
    #[cfg(not(windows))]
    let exts = [""];
    for dir in std::env::split_paths(&path) {
        for ext in exts {
            if dir.join(format!("{name}{ext}")).is_file() {
                return true;
            }
        }
    }
    false
}

/// One hook registration to merge into a tool config.
#[derive(Debug, Clone)]
pub(crate) struct HookEntry {
    matcher: String,
    command: String,
}

/// Merge `entries` into a Claude/Codex-style hooks document
/// (`{"hooks": {"PreToolUse": [{"matcher", "hooks": [...]}}]}`).
///
/// Returns `(merged_document, warnings)`. Existing matcher groups and hook
/// entries are preserved; an identical command is not duplicated; a matcher
/// group that already holds a *different* command produces a conflict
/// warning and is left untouched.
pub(crate) fn merge_hook_entries(
    mut doc: serde_json::Value,
    entries: &[HookEntry],
) -> (serde_json::Value, Vec<String>) {
    let mut warnings = Vec::new();
    if !doc.is_object() {
        doc = serde_json::json!({});
    }
    let Some(map) = doc.as_object_mut() else {
        return (doc, warnings);
    };
    let hooks = map.entry("hooks").or_insert_with(|| serde_json::json!({}));
    if !hooks.is_object() {
        warnings.push("existing 'hooks' key is not an object; leaving it untouched".into());
        return (doc, warnings);
    }
    let Some(hooks_map) = hooks.as_object_mut() else {
        return (doc, warnings);
    };
    let pre = hooks_map
        .entry("PreToolUse")
        .or_insert_with(|| serde_json::json!([]));
    if !pre.is_array() {
        warnings.push("existing 'hooks.PreToolUse' is not an array; leaving it untouched".into());
        return (doc, warnings);
    }
    let Some(groups) = pre.as_array_mut() else {
        return (doc, warnings);
    };
    for entry in entries {
        let group = groups
            .iter_mut()
            .find(|g| g.get("matcher").and_then(|m| m.as_str()) == Some(entry.matcher.as_str()));
        match group {
            None => {
                groups.push(serde_json::json!({
                    "matcher": entry.matcher,
                    "hooks": [{ "type": "command", "command": entry.command }],
                }));
            }
            Some(g) => {
                let hooks = g.get_mut("hooks").filter(|h| h.is_array());
                match hooks {
                    None => warnings.push(format!(
                        "matcher '{}' has no hooks array; leaving it untouched",
                        entry.matcher
                    )),
                    Some(list) => {
                        let Some(list) = list.as_array_mut() else {
                            warnings.push(format!(
                                "matcher '{}' hooks unreadable; leaving it untouched",
                                entry.matcher
                            ));
                            continue;
                        };
                        let already = list.iter().any(|h| {
                            h.get("command").and_then(|c| c.as_str())
                                == Some(entry.command.as_str())
                        });
                        if already {
                            continue;
                        }
                        let foreign = list.iter().any(|h| {
                            h.get("command")
                                .and_then(|c| c.as_str())
                                .is_some_and(|c| c != entry.command)
                        });
                        if foreign {
                            warnings.push(format!(
                                "conflicting hook already registered on matcher '{}'; Kavach entry not added",
                                entry.matcher
                            ));
                            continue;
                        }
                        list.push(serde_json::json!({
                            "type": "command",
                            "command": entry.command,
                        }));
                    }
                }
            }
        }
    }
    (doc, warnings)
}

/// Merge a plugin path into an OpenCode `opencode.json` document's `plugin`
/// array, additively. Returns `(merged_document, already_present)`.
pub(crate) fn merge_opencode_plugin(
    mut doc: serde_json::Value,
    plugin_path: &str,
) -> (serde_json::Value, bool) {
    if !doc.is_object() {
        doc = serde_json::json!({});
    }
    let Some(map) = doc.as_object_mut() else {
        return (doc, true);
    };
    let plugins = map.entry("plugin").or_insert_with(|| serde_json::json!([]));
    if !plugins.is_array() {
        return (doc, true);
    }
    let Some(list) = plugins.as_array_mut() else {
        return (doc, true);
    };
    if list.iter().any(|p| p.as_str() == Some(plugin_path)) {
        return (doc, true);
    }
    list.push(serde_json::Value::String(plugin_path.to_string()));
    (doc, false)
}

fn read_json_file(path: &Path) -> serde_json::Value {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .filter(|v: &serde_json::Value| v.is_object())
        .unwrap_or_else(|| serde_json::json!({}))
}

fn write_json_file(path: &Path, doc: &serde_json::Value) -> Result<(), CliError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let text = serde_json::to_string_pretty(doc)?;
    std::fs::write(path, text)?;
    Ok(())
}

fn stage_scripts(adapters_dir: &Path) -> Result<StagedScripts, CliError> {
    std::fs::create_dir_all(adapters_dir)?;
    let common = adapters_dir.join("kavach-adapter-common.psm1");
    let claude = adapters_dir.join("kavach-claude-hook.ps1");
    let codex = adapters_dir.join("kavach-codex-hook.ps1");
    // Never overwrite a user's customized hook scripts.
    // (The OpenCode plugin is staged into the opencode config dir itself,
    // next to opencode.json, so it needs no copy here.)
    for (path, contents) in [
        (&common, COMMON_MODULE),
        (&claude, CLAUDE_HOOK),
        (&codex, CODEX_HOOK),
    ] {
        if !path.is_file() {
            std::fs::write(path, contents)?;
        }
    }
    Ok(StagedScripts {
        claude_hook: claude,
        codex_hook: codex,
    })
}

struct StagedScripts {
    claude_hook: PathBuf,
    codex_hook: PathBuf,
}

fn ps_hook_command(script: &Path, policy: &Path, feed: &Path) -> String {
    format!(
        "powershell -NoProfile -ExecutionPolicy Bypass -File \"{}\" -Policy \"{}\" -FeedLog \"{}\"",
        script.display(),
        policy.display(),
        feed.display()
    )
}

struct ToolOutcome {
    tool: &'static str,
    detected: bool,
    wired: bool,
    detail: String,
}

fn setup_claude(home: &Path, scripts: &StagedScripts, policy: &Path, feed: &Path) -> ToolOutcome {
    let settings = home.join(".claude").join("settings.json");
    let detected = settings.is_file() || on_path("claude");
    if !detected {
        return ToolOutcome {
            tool: "Claude Code",
            detected: false,
            wired: false,
            detail: "not found (no ~/.claude/settings.json, no `claude` on PATH)".into(),
        };
    }
    let entry = HookEntry {
        matcher: CLAUDE_MATCHER.into(),
        command: ps_hook_command(&scripts.claude_hook, policy, feed),
    };
    let doc = read_json_file(&settings);
    let (merged, warnings) = merge_hook_entries(doc, &[entry]);
    match write_json_file(&settings, &merged) {
        Ok(()) => ToolOutcome {
            tool: "Claude Code",
            detected: true,
            wired: true,
            detail: if warnings.is_empty() {
                format!("wired {}", settings.display())
            } else {
                format!(
                    "wired {} (warnings: {})",
                    settings.display(),
                    warnings.join("; ")
                )
            },
        },
        Err(e) => ToolOutcome {
            tool: "Claude Code",
            detected: true,
            wired: false,
            detail: format!("failed to write {}: {}", settings.display(), e.message),
        },
    }
}

fn setup_codex(home: &Path, scripts: &StagedScripts, policy: &Path, feed: &Path) -> ToolOutcome {
    let hooks_json = home.join(".codex").join("hooks.json");
    let detected = hooks_json.is_file()
        || home.join(".codex").join("config.toml").is_file()
        || on_path("codex");
    if !detected {
        return ToolOutcome {
            tool: "Codex CLI",
            detected: false,
            wired: false,
            detail: "not found (no ~/.codex config, no `codex` on PATH)".into(),
        };
    }
    // hooks.json merges automatically with inline config.toml [hooks].
    let entries = ["Bash", "apply_patch"]
        .iter()
        .map(|matcher| HookEntry {
            matcher: (*matcher).into(),
            command: ps_hook_command(&scripts.codex_hook, policy, feed),
        })
        .collect::<Vec<_>>();
    let doc = read_json_file(&hooks_json);
    let (merged, warnings) = merge_hook_entries(doc, &entries);
    match write_json_file(&hooks_json, &merged) {
        Ok(()) => ToolOutcome {
            tool: "Codex CLI",
            detected: true,
            wired: true,
            detail: if warnings.is_empty() {
                format!("wired {}", hooks_json.display())
            } else {
                format!(
                    "wired {} (warnings: {})",
                    hooks_json.display(),
                    warnings.join("; ")
                )
            },
        },
        Err(e) => ToolOutcome {
            tool: "Codex CLI",
            detected: true,
            wired: false,
            detail: format!("failed to write {}: {}", hooks_json.display(), e.message),
        },
    }
}

fn setup_opencode(home: &Path) -> ToolOutcome {
    let config = home.join(".config").join("opencode").join("opencode.json");
    let detected = config.is_file() || on_path("opencode");
    if !detected {
        return ToolOutcome {
            tool: "OpenCode",
            detected: false,
            wired: false,
            detail: "not found (no opencode.json, no `opencode` on PATH)".into(),
        };
    }
    let plugin_dest = config.parent().unwrap_or(home).join("kavach-hook.mjs");
    if !plugin_dest.is_file() {
        if let Some(parent) = plugin_dest.parent() {
            if std::fs::create_dir_all(parent).is_err() {
                return ToolOutcome {
                    tool: "OpenCode",
                    detected: true,
                    wired: false,
                    detail: "failed to stage plugin file".into(),
                };
            }
        }
        if std::fs::write(&plugin_dest, OPENCODE_HOOK).is_err() {
            return ToolOutcome {
                tool: "OpenCode",
                detected: true,
                wired: false,
                detail: "failed to stage plugin file".into(),
            };
        }
    }
    let plugin_ref = plugin_dest.to_string_lossy().into_owned();
    let doc = read_json_file(&config);
    let (merged, already) = merge_opencode_plugin(doc, &plugin_ref);
    match write_json_file(&config, &merged) {
        Ok(()) => ToolOutcome {
            tool: "OpenCode",
            detected: true,
            wired: true,
            detail: if already {
                format!("already wired {}", config.display())
            } else {
                format!("wired {} (plugin {})", config.display(), plugin_ref)
            },
        },
        Err(e) => ToolOutcome {
            tool: "OpenCode",
            detected: true,
            wired: false,
            detail: format!("failed to write {}: {}", config.display(), e.message),
        },
    }
}

fn kavach_data_dir(home: &Path) -> PathBuf {
    home.join(".kavach")
}

pub fn run(policy: Option<&str>, start_dashboard: bool, mode: OutputMode) -> Result<(), CliError> {
    let home = home_dir().ok_or_else(|| {
        CliError::new(
            ExitCode::InvalidInput,
            "could not determine home directory (set USERPROFILE/HOME)",
        )
    })?;
    let data_dir = kavach_data_dir(&home);
    let adapters_dir = data_dir.join("adapters");
    let scripts = stage_scripts(&adapters_dir)?;

    // Default policy: privacy starter pack staged on first run only; an
    // existing policy file is never overwritten.
    let default_policy = data_dir.join("policy.toml");
    if !default_policy.is_file() {
        std::fs::create_dir_all(&data_dir)?;
        std::fs::write(&default_policy, privacy_starter_embedded())?;
    }
    let policy_path = policy.map(PathBuf::from).unwrap_or(default_policy);
    let feed_path = data_dir.join("decisions.jsonl");

    let outcomes = [
        setup_claude(&home, &scripts, &policy_path, &feed_path),
        setup_codex(&home, &scripts, &policy_path, &feed_path),
        setup_opencode(&home),
    ];

    let mut dashboard_note = String::new();
    if start_dashboard {
        dashboard_note = try_start_dashboard(&policy_path, &feed_path);
    }

    let rows: Vec<serde_json::Value> = outcomes
        .iter()
        .map(|o| {
            serde_json::json!({
                "tool": o.tool,
                "detected": o.detected,
                "wired": o.wired,
                "detail": o.detail,
            })
        })
        .collect();
    let mut data = serde_json::json!({
        "tools": rows,
        "policy": policy_path.to_string_lossy(),
        "feed": feed_path.to_string_lossy(),
    });
    if !dashboard_note.is_empty() {
        data["dashboard"] = serde_json::Value::String(dashboard_note);
    } else {
        data["dashboard"] = serde_json::Value::String(format!(
            "start it with: kavach-dashboard --feed \"{}\" --policy \"{}\"",
            feed_path.display(),
            policy_path.display()
        ));
    }
    CliOutput::with_data(data).render(mode);
    Ok(())
}

fn try_start_dashboard(policy: &Path, feed: &Path) -> String {
    let exe = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("kavach-dashboard")))
        .filter(|p| p.is_file())
        .or_else(|| {
            #[cfg(windows)]
            let name = "kavach-dashboard.exe";
            #[cfg(not(windows))]
            let name = "kavach-dashboard";
            on_path(name).then(|| PathBuf::from(name))
        });
    match exe {
        None => "dashboard requested but kavach-dashboard binary not found".into(),
        Some(bin) => match std::process::Command::new(&bin)
            .arg("--feed")
            .arg(feed)
            .arg("--policy")
            .arg(policy)
            .spawn()
        {
            Ok(_) => format!(
                "dashboard starting at http://127.0.0.1:3939 ({})",
                bin.display()
            ),
            Err(e) => format!("failed to start dashboard: {e}"),
        },
    }
}

/// Embedded copy of the privacy starter pack (also shipped as a file).
fn privacy_starter_embedded() -> &'static str {
    include_str!("../../../../config/privacy-starter.toml")
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn merge_adds_new_matcher_group() {
        let (doc, warnings) = merge_hook_entries(
            json!({}),
            &[HookEntry {
                matcher: "Bash".into(),
                command: "kavach-hook".into(),
            }],
        );
        assert!(warnings.is_empty());
        assert_eq!(doc["hooks"]["PreToolUse"][0]["matcher"], json!("Bash"));
    }

    #[test]
    fn merge_is_idempotent_for_same_command() {
        let existing = json!({
            "hooks": {"PreToolUse": [
                {"matcher": "Bash", "hooks": [{"type": "command", "command": "kavach-hook"}]}
            ]}
        });
        let (doc, warnings) = merge_hook_entries(
            existing,
            &[HookEntry {
                matcher: "Bash".into(),
                command: "kavach-hook".into(),
            }],
        );
        assert!(warnings.is_empty());
        assert_eq!(
            doc["hooks"]["PreToolUse"][0]["hooks"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn merge_warns_on_conflicting_hook() {
        let existing = json!({
            "hooks": {"PreToolUse": [
                {"matcher": "Bash", "hooks": [{"type": "command", "command": "other-hook"}]}
            ]}
        });
        let (doc, warnings) = merge_hook_entries(
            existing,
            &[HookEntry {
                matcher: "Bash".into(),
                command: "kavach-hook".into(),
            }],
        );
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("conflicting hook"));
        assert_eq!(
            doc["hooks"]["PreToolUse"][0]["hooks"][0]["command"],
            json!("other-hook")
        );
    }

    #[test]
    fn merge_preserves_unrelated_entries() {
        let existing = json!({
            "hooks": {"PreToolUse": [
                {"matcher": "Edit", "hooks": [{"type": "command", "command": "fmt-hook"}]}
            ]},
            "other": true
        });
        let (doc, _) = merge_hook_entries(
            existing,
            &[HookEntry {
                matcher: "Bash".into(),
                command: "kavach-hook".into(),
            }],
        );
        assert_eq!(doc["other"], json!(true));
        assert_eq!(doc["hooks"]["PreToolUse"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn opencode_plugin_merge_is_additive() {
        let (doc, already) = merge_opencode_plugin(json!({}), "/x/kavach-hook.mjs");
        assert!(!already);
        assert_eq!(doc["plugin"], json!(["/x/kavach-hook.mjs"]));
        let (doc2, already2) = merge_opencode_plugin(doc, "/x/kavach-hook.mjs");
        assert!(already2);
        assert_eq!(doc2["plugin"].as_array().unwrap().len(), 1);
    }
}
