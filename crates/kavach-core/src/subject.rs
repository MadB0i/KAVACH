//! Capability and trust-level types for AI-agent subjects.
//!
//! Capabilities are deliberately typed rather than free-form strings: a
//! capability only exists if KAVACH understands it, which prevents agents from
//! declaring arbitrary, self-granted permissions.

use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

use crate::error::{DomainError, DomainErrorKind};

/// Maximum number of bytes in a [`Capability`] label.
pub const MAX_CAPABILITY_LEN: usize = 64;

/// A strongly typed capability that an AI agent may declare.
///
/// Capabilities are an input to policy evaluation and **not** an
/// authorization by themselves. Policy rules still decide whether a given
/// capability is trusted.
///
/// The internal label is constrained to `A-Za-z0-9._-`, is non-empty, and is
/// bounded by [`MAX_CAPABILITY_LEN`].
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(try_from = "&str", into = "String")]
pub struct Capability(String);

impl Capability {
    /// Construct a capability from a validated string.
    pub fn new(label: impl AsRef<str> + fmt::Display) -> Result<Self, DomainError> {
        let s = label.as_ref();
        let len = s.chars().count();
        if s.is_empty() {
            return Err(DomainError::new(
                DomainErrorKind::InvalidId,
                "empty capability",
            ));
        }
        if len > MAX_CAPABILITY_LEN {
            return Err(DomainError::new(
                DomainErrorKind::OversizedField,
                "capability exceeds maximum length",
            ));
        }
        if s.chars().any(|c| c.is_control() || !is_capability_char(c)) {
            return Err(DomainError::new(
                DomainErrorKind::InvalidCharacter,
                "capability contains disallowed characters",
            ));
        }
        Ok(Self(s.to_string()))
    }

    /// Returns the capability label.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Returns true if the character is permitted in a [`Capability`] label.
fn is_capability_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-'
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Capability {
    type Err = DomainError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl From<Capability> for String {
    fn from(c: Capability) -> String {
        c.0
    }
}

impl TryFrom<&str> for Capability {
    type Error = DomainError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

/// Ordered trust tier assigned to an AI agent subject.
///
/// Trust level is **policy input, not authorization**. A higher level never
/// grants permissions automatically; it can only be consumed by policy rules
/// that choose to consider it. Representation is a typed enum, not a raw
/// integer, to avoid arithmetic misuse and implicit "higher is better" rules.
///
/// Order is [`PartialOrd`]/[`Ord`] meaningful: `Untrusted < Restricted <
/// Standard < Trusted < System`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum TrustLevel {
    /// No trust assumptions. Treat all requests with maximum suspicion.
    Untrusted,
    /// Narrowly constrained. Useful for exploratory or sandboxed sessions.
    Restricted,
    /// Default trust tier for regular AI agents.
    Standard,
    /// Elevated trust, typically scoped to a trusted workflow.
    Trusted,
    /// Highest tier. Reserved for system-level agents and rarely appropriate.
    System,
}

impl TrustLevel {
    /// Returns the stable string representation matching the serde label.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Untrusted => "untrusted",
            Self::Restricted => "restricted",
            Self::Standard => "standard",
            Self::Trusted => "trusted",
            Self::System => "system",
        }
    }
}

impl fmt::Display for TrustLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for TrustLevel {
    type Err = DomainError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "untrusted" => Ok(Self::Untrusted),
            "restricted" => Ok(Self::Restricted),
            "standard" => Ok(Self::Standard),
            "trusted" => Ok(Self::Trusted),
            "system" => Ok(Self::System),
            other => Err(DomainError::new(
                DomainErrorKind::UnknownVariant,
                format!("unknown trust level: {other}"),
            )),
        }
    }
}

/// A convenience type alias for an ordered set of capabilities.
pub type CapabilitySet = BTreeSet<Capability>;

/// The actor requesting an operation: identified, sessioned, trust-tiered, and
/// carrying an explicit set of capabilities.
///
/// Trust level and capability set are **policy inputs**. They are never used
/// as automatic authorization; a policy rule has to match for any of them
/// to matter. Construction goes through the
/// [`AgentSubjectBuilder`](crate::request::AgentSubjectBuilder) so that all
/// validation happens up front.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AgentSubject {
    /// Stable identifier of the agent making the request.
    pub agent_id: crate::ids::AgentId,
    /// Identifier of the session within which this request was made.
    pub session_id: crate::ids::SessionId,
    /// Optional human-readable display name, never used for authorization.
    pub display_name: Option<String>,
    /// Trust tier assigned to this subject. Input to policy only.
    pub trust_level: TrustLevel,
    /// Capabilities the subject declared it has. Input to policy only.
    pub declared_capabilities: CapabilitySet,
}

impl AgentSubject {
    /// Re-validate every invariant of a possibly-deserialized subject.
    ///
    /// Identifiers and capabilities route through validating serde impls, but
    /// `display_name` is a plain [`Option<String>`] that bypasses length and
    /// control-byte checks when deserialized; this re-checks it so a request
    /// reconstructed from JSON cannot smuggle through an oversized or
    /// control-laden display name.
    pub(crate) fn validate_invariants(&self) -> Result<(), DomainError> {
        crate::ids::validate_id(self.agent_id.as_str())?;
        crate::ids::validate_id(self.session_id.as_str())?;
        if let Some(name) = &self.display_name {
            if name.len() > crate::request::MAX_SHORT_STRING_LEN {
                return Err(DomainError::new(
                    DomainErrorKind::OversizedField,
                    "display name exceeds maximum length",
                ));
            }
            if name
                .bytes()
                .any(|b| b == 0 || b.is_ascii_control() && b != b'\t')
            {
                return Err(DomainError::new(
                    DomainErrorKind::InvalidCharacter,
                    "display name contains control characters",
                ));
            }
        }
        Ok(())
    }
}
