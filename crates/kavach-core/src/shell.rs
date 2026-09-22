//! Shared shell-hazard scanner — single source of truth for dangerous
//! shell constructs in argument strings.
//!
//! Both `kavach-policy` (baseline dangerous-invocation check) and
//! `kavach-enforcement` (argument validation) call into this module so that
//! the set of recognized hazards cannot drift between crates.
//!
//! The scanner is purely lexical: it reports constructs that *look*
//! dangerous. Whether a given hazard actually executes depends on the
//! interpreter, which is why policy treats hits as deny/approval signals
//! rather than proof of exploitation.

/// A single dangerous shell construct found in a string.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ShellHazard {
    /// `$(...)` command substitution.
    CommandSubstitution,
    /// Backtick command substitution `` `...` ``.
    Backtick,
    /// `${...}` braced variable expansion.
    EnvVarBraced,
    /// Bare `$NAME` variable expansion (`$` followed by an identifier char).
    EnvVar,
    /// `(` — subshell/group opener.
    SubshellOpen,
    /// `)` — subshell/group closer.
    SubshellClose,
    /// `&&` shell chaining.
    ShellAnd,
    /// `||` shell chaining.
    ShellOr,
    /// `|` pipe.
    Pipe,
    /// `;` command separator.
    Semicolon,
    /// `>` output redirection.
    RedirectOut,
    /// `<` input redirection.
    RedirectIn,
}

impl ShellHazard {
    /// Stable snake_case label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CommandSubstitution => "command_substitution",
            Self::Backtick => "backtick",
            Self::EnvVarBraced => "env_var_braced",
            Self::EnvVar => "env_var",
            Self::SubshellOpen => "subshell_open",
            Self::SubshellClose => "subshell_close",
            Self::ShellAnd => "shell_and",
            Self::ShellOr => "shell_or",
            Self::Pipe => "pipe",
            Self::Semicolon => "semicolon",
            Self::RedirectOut => "redirect_out",
            Self::RedirectIn => "redirect_in",
        }
    }
}

impl std::fmt::Display for ShellHazard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Scan `s` for dangerous shell constructs, in order of appearance.
///
/// Each occurrence is reported (no dedup) so callers can point at every
/// hit; use [`has_dangerous_shell_construct`] for a boolean check.
pub fn scan_dangerous_shell_constructs(s: &str) -> Vec<ShellHazard> {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        match b {
            b'$' => match bytes.get(i + 1) {
                Some(b'(') => {
                    out.push(ShellHazard::CommandSubstitution);
                    i += 2;
                }
                Some(b'{') => {
                    out.push(ShellHazard::EnvVarBraced);
                    i += 2;
                }
                Some(next) if next.is_ascii_alphanumeric() || *next == b'_' => {
                    out.push(ShellHazard::EnvVar);
                    i += 2;
                }
                _ => {
                    i += 1;
                }
            },
            b'`' => {
                out.push(ShellHazard::Backtick);
                i += 1;
            }
            b'(' => {
                out.push(ShellHazard::SubshellOpen);
                i += 1;
            }
            b')' => {
                out.push(ShellHazard::SubshellClose);
                i += 1;
            }
            b'&' => {
                if bytes.get(i + 1) == Some(&b'&') {
                    out.push(ShellHazard::ShellAnd);
                    i += 2;
                } else {
                    // A lone `&` backgrounds a command in POSIX shells.
                    out.push(ShellHazard::ShellAnd);
                    i += 1;
                }
            }
            b'|' => {
                if bytes.get(i + 1) == Some(&b'|') {
                    out.push(ShellHazard::ShellOr);
                    i += 2;
                } else {
                    out.push(ShellHazard::Pipe);
                    i += 1;
                }
            }
            b';' => {
                out.push(ShellHazard::Semicolon);
                i += 1;
            }
            b'>' => {
                out.push(ShellHazard::RedirectOut);
                i += 1;
            }
            b'<' => {
                out.push(ShellHazard::RedirectIn);
                i += 1;
            }
            _ => {
                i += 1;
            }
        }
    }
    out
}

/// Returns `true` when `s` contains any dangerous shell construct.
pub fn has_dangerous_shell_construct(s: &str) -> bool {
    !scan_dangerous_shell_constructs(s).is_empty()
}

/// Returns `true` when `s` contains a substitution/expansion hazard — the
/// subset (`$(`, backtick, `${`, `$VAR`) that the old enforcement blocklist
/// missed entirely and that interpreters evaluate even without a shell
/// metacharacter like `|` or `;` being present.
pub fn has_substitution_hazard(s: &str) -> bool {
    scan_dangerous_shell_constructs(s).iter().any(|h| {
        matches!(
            h,
            ShellHazard::CommandSubstitution
                | ShellHazard::Backtick
                | ShellHazard::EnvVarBraced
                | ShellHazard::EnvVar
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contains(s: &str, hazard: ShellHazard) -> bool {
        scan_dangerous_shell_constructs(s).contains(&hazard)
    }

    #[test]
    fn detects_command_substitution() {
        assert!(contains("echo $(id)", ShellHazard::CommandSubstitution));
    }

    #[test]
    fn detects_backtick() {
        assert!(contains("echo `id`", ShellHazard::Backtick));
    }

    #[test]
    fn detects_braced_env_var() {
        assert!(contains("echo ${HOME}", ShellHazard::EnvVarBraced));
    }

    #[test]
    fn detects_bare_env_var() {
        assert!(contains("echo $HOME", ShellHazard::EnvVar));
    }

    #[test]
    fn detects_bare_parens() {
        assert!(contains("(curl evil)", ShellHazard::SubshellOpen));
        assert!(contains("(curl evil)", ShellHazard::SubshellClose));
    }

    #[test]
    fn detects_legacy_set() {
        assert!(contains("a&&b", ShellHazard::ShellAnd));
        assert!(contains("a||b", ShellHazard::ShellOr));
        assert!(contains("a|b", ShellHazard::Pipe));
        assert!(contains("a;b", ShellHazard::Semicolon));
        assert!(contains("a>b", ShellHazard::RedirectOut));
        assert!(contains("a<b", ShellHazard::RedirectIn));
    }

    #[test]
    fn clean_args_have_no_hazards() {
        for clean in ["hello", "-la", "--hard", "/tmp/foo", "C:", "get", "pods"] {
            assert!(
                scan_dangerous_shell_constructs(clean).is_empty(),
                "clean arg flagged: {clean}"
            );
        }
    }

    #[test]
    fn lone_dollar_is_not_env_var() {
        assert!(scan_dangerous_shell_constructs("price is $").is_empty());
        assert!(scan_dangerous_shell_constructs("a $-b").is_empty());
    }
}
