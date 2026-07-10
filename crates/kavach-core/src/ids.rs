//! Validated identifier newtypes used across the KAVACH domain model.
//!
//! All IDs are bounded, non-empty, control-character-free strings. Centralizing
//! the validation here means every request-boundary type can be relied on to
//! never carry an unbounded or control-laden ID.

use std::fmt;
use std::str::FromStr;

use crate::error::{DomainError, DomainErrorKind};

/// Maximum number of bytes allowed in any ID newtype.
pub const MAX_ID_LEN: usize = 256;

/// A central check shared by every ID newtype below.
pub(crate) fn validate_id(value: &str) -> Result<(), DomainError> {
    let len = value.chars().count();
    if value.is_empty() {
        return Err(DomainError::new(DomainErrorKind::InvalidId, "empty id"));
    }
    if len > MAX_ID_LEN {
        return Err(DomainError::new(DomainErrorKind::OversizedField, "id exceeds maximum length"));
    }
    if value.chars().any(|c| c.is_control()) {
        return Err(DomainError::new(DomainErrorKind::InvalidCharacter, "id contains control characters"));
    }
    Ok(())
}

/// Macro generating a domain-validated ID newtype.
macro_rules! id_newtype {
    ($(#[$doc:meta])* $name:ident, $label:expr) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
        #[serde(try_from = "&str", into = "String")]
        pub struct $name(String);

        impl $name {
            /// Construct a validated ID from a string representation.
            pub fn new(value: impl AsRef<str> + fmt::Display) -> Result<Self, DomainError> {
                let s = value.as_ref();
                validate_id(s)?;
                Ok(Self(s.to_string()))
            }

            /// Borrow the underlying string.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = DomainError;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::new(s)
            }
        }

        impl TryFrom<&str> for $name {
            type Error = DomainError;
            fn try_from(s: &str) -> Result<Self, Self::Error> {
                Self::new(s)
            }
        }

        impl From<$crate::ids::$name> for String {
            fn from(value: $crate::ids::$name) -> String {
                value.0
            }
        }

        #[allow(clippy::use_self)]
        impl $crate::ids::$name {
            const LABEL: &'static str = $label;
        }
    };
}

id_newtype!(
    /// Stable identifier for an AI agent subject.
    AgentId,
    "agent id"
);

id_newtype!(
    /// Identifier for an AI agent session.
    SessionId,
    "session id"
);

id_newtype!(
    /// Stable identifier for a single tool request.
    RequestId,
    "request id"
);

id_newtype!(
    /// Stable identifier for a policy rule.
    RuleId,
    "rule id"
);

id_newtype!(
    /// Stable identifier for a policy document.
    PolicyId,
    "policy id"
);

id_newtype!(
    /// Stable identifier for a human-readable approval flow.
    ApprovalId,
    "approval id"
);
