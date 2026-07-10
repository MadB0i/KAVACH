//! Tool-request envelope, operations, and request context.
//!
//! [`Operation`] is a non-exhaustive enum so that future operations can be
//! added without breaking external matching. Each variant deliberately carries
//! only data specific to the action; everything shared (subject, resource,
//! context) lives on [`ToolRequest`].

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;
use std::time::SystemTime;

use crate::error::{DomainError, DomainErrorKind};
use crate::ids::{AgentId, RequestId, SessionId};
use crate::resource::{NormalizedPath, PathError, RequestMetadata};
use crate::subject::{AgentSubject, Capability};

/// Maximum-byte cap for declared-intent and similar short string fields.
pub const MAX_SHORT_STRING_LEN: usize = 1024;

/// Operations an agent may attempt to perform against a protected resource.
///
/// This enum is `#[non_exhaustive]` so new operations can be added in future
/// versions without breaking serialized requests (older consumers are required
/// to fail closed on unknown variants, see [`Operation::from_str`]).
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    /// Read an existing file.
    FileRead {
        /// Limit on the number of bytes the agent intends to read, if known.
        max_bytes: Option<u64>,
    },
    /// Write into an existing file (overwrite/truncate).
    FileWrite,
    /// Create a new file (must not already exist for the create to hold).
    FileCreate,
    /// Delete a file.
    FileDelete,
    /// Move or rename a file. Optional destination path is carried when known.
    FileMove {
        /// Intended destination path, normalized lexically.
        destination: Option<NormalizedPath>,
    },
    /// List the contents of a directory.
    DirectoryList,
    /// Create a new directory.
    DirectoryCreate,
    /// Delete a directory (and optionally its contents).
    DirectoryDelete,
    /// Execute a shell command.
    CommandExecute,
    /// Open an outbound network connection.
    NetworkRequest,
    /// Read or use a stored secret.
    SecretAccess,
    /// Invoke another tool on behalf of the agent.
    ToolInvoke {
        /// Stable identifier of the invoked tool.
        tool_id: String,
    },
}

impl Operation {
    /// Returns the stable, snake_case label for this operation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::FileRead { .. } => "file_read",
            Self::FileWrite => "file_write",
            Self::FileCreate => "file_create",
            Self::FileDelete => "file_delete",
            Self::FileMove { .. } => "file_move",
            Self::DirectoryList => "directory_list",
            Self::DirectoryCreate => "directory_create",
            Self::DirectoryDelete => "directory_delete",
            Self::CommandExecute => "command_execute",
            Self::NetworkRequest => "network_request",
            Self::SecretAccess => "secret_access",
            Self::ToolInvoke { .. } => "tool_invoke",
        }
    }

    /// The simplified operation label used by policy matching. For parameterized
    /// operations (such as [`Self::FileRead`]) the discriminator is returned,
    /// ignoring the variant payload.
    pub fn discriminant(&self) -> &'static str {
        self.as_str()
    }
}

impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Operation {
    /// Parse an operation from its stable snake_case label, failing closed on
    /// any unknown label. Variant payloads default to "no/unknown" values.
    pub fn from_label(label: &str) -> Result<Self, DomainError> {
        match label {
            "file_read" => Ok(Self::FileRead { max_bytes: None }),
            "file_write" => Ok(Self::FileWrite),
            "file_create" => Ok(Self::FileCreate),
            "file_delete" => Ok(Self::FileDelete),
            "file_move" => Ok(Self::FileMove { destination: None }),
            "directory_list" => Ok(Self::DirectoryList),
            "directory_create" => Ok(Self::DirectoryCreate),
            "directory_delete" => Ok(Self::DirectoryDelete),
            "command_execute" => Ok(Self::CommandExecute),
            "network_request" => Ok(Self::NetworkRequest),
            "secret_access" => Ok(Self::SecretAccess),
            "tool_invoke" => Ok(Self::ToolInvoke { tool_id: String::new() }),
            other => Err(DomainError::new(
                DomainErrorKind::UnknownVariant,
                "unknown operation: {other}",
            )),
        }
    }
}

impl FromStr for Operation {
    type Err = DomainError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_label(s)
    }
}

/// Per-request context, bounded and deterministic.
///
/// The metadata map is a [`BTreeMap`]-backed[`RequestMetadata`], so iteration
/// order is independent of hashing and reproducible.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RequestContext {
    /// When the request was constructed.
    pub timestamp: SystemTime,
    /// The working directory the agent reports itself as running within, if any.
    pub working_directory: Option<NormalizedPath>,
    /// Optional declared intent for the request (a short, non-secret string).
    pub declared_intent: Option<String>,
    /// Optional parent request id for chained requests.
    pub parent_request_id: Option<RequestId>,
    /// Sanitized, bounded metadata in stable sorted order.
    pub metadata: RequestMetadata,
    /// Whether this is a dry-run: the engine must still evaluate decision but
    /// cannot trust any actual enforcement to occur.
    pub dry_run: bool,
}

impl RequestContext {
    /// Construct a context, validating the declared-intent length and metadata.
    pub fn new(
        working_directory: Option<&str>,
        declared_intent: Option<&str>,
        parent_request_id: Option<RequestId>,
        metadata: Option<RequestMetadata>,
        dry_run: bool,
    ) -> Result<Self, PathError> {
        let working_directory = match working_directory {
            Some(w) if w.is_empty() => None,
            Some(w) => Some(NormalizedPath::new(w)?),
            None => None,
        };
        let declared_intent = match declared_intent {
            Some(d) if d.is_empty() => None,
            Some(d) => {
                if d.len() > MAX_SHORT_STRING_LEN {
                    return Err(PathError::from_kind(
                        crate::resource::PathErrorKind::Oversized,
                        "declared intent exceeds maximum length",
                    ));
                }
                if d.bytes().any(|b| b == 0) {
                    return Err(PathError::from_kind(
                        crate::resource::PathErrorKind::InvalidCharacter,
                        "declared intent contains null bytes",
                    ));
                }
                Some(d.to_string())
            }
            None => None,
        };
        Ok(Self {
            timestamp: SystemTime::now(),
            working_directory,
            declared_intent,
            parent_request_id,
            metadata: metadata.unwrap_or_default(),
            dry_run,
        })
    }
}

/// A single tool request made by an AI agent.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ToolRequest {
    /// Stable, validated identifier for this request.
    pub request_id: RequestId,
    /// The AI agent subject requesting the operation.
    pub subject: AgentSubject,
    /// The operation the agent wants to perform.
    pub operation: Operation,
    /// The protected resource targeted by the operation.
    pub resource: crate::resource::Resource,
    /// Bounded, deterministic request context.
    pub context: RequestContext,
}

impl ToolRequest {
    /// Construct a request from its components, validating nothing new
    /// (each typed component already performed its own validation).
    pub fn new(
        request_id: RequestId,
        subject: AgentSubject,
        operation: Operation,
        resource: crate::resource::Resource,
        context: RequestContext,
    ) -> Self {
        Self { request_id, subject, operation, resource, context }
    }
}

/// Builder for [`AgentSubject`] to keep construction readable and validated.
#[derive(Debug, Clone)]
pub struct AgentSubjectBuilder {
    agent_id: AgentId,
    session_id: SessionId,
    display_name: Option<String>,
    trust_level: crate::subject::TrustLevel,
    declared_capabilities: std::collections::BTreeSet<Capability>,
}

impl AgentSubjectBuilder {
    /// Begin building a subject with the required identifiers.
    pub fn new(agent_id: AgentId, session_id: SessionId) -> Self {
        Self {
            agent_id,
            session_id,
            display_name: None,
            trust_level: crate::subject::TrustLevel::Untrusted,
            declared_capabilities: Default::default(),
        }
    }

    /// Set an optional human-readable display name.
    pub fn display_name(mut self, name: Option<impl Into<String>>) -> Result<Self, DomainError> {
        let name = match name {
            None => None,
            Some(s) => {
                let s = s.into();
                if s.bytes().any(|b| b == 0 || b.is_ascii_control() && b != b'\t') {
                    return Err(DomainError::new(
                        DomainErrorKind::InvalidCharacter,
                        "display name contains control characters",
                    ));
                }
                if s.len() > MAX_SHORT_STRING_LEN {
                    return Err(DomainError::new(
                        DomainErrorKind::OversizedField,
                        "display name exceeds maximum length",
                    ));
                }
                Some(s)
            }
        };
        self.display_name = name;
        Ok(self)
    }

    /// Set the trust level.
    pub fn trust_level(mut self, level: crate::subject::TrustLevel) -> Self {
        self.trust_level = level;
        self
    }

    /// Add a single capability.
    pub fn capability(mut self, c: Capability) -> Self {
        self.declared_capabilities.insert(c);
        self
    }

    /// Build the subject.
    pub fn build(self) -> AgentSubject {
        AgentSubject {
            agent_id: self.agent_id,
            session_id: self.session_id,
            display_name: self.display_name,
            trust_level: self.trust_level,
            declared_capabilities: self.declared_capabilities,
        }
    }
}

#[cfg(test)]
mod ops_tests {
    use super::*;

    #[test]
    fn operation_label_round_trip() {
        let labels = [
            "file_read",
            "file_write",
            "file_create",
            "file_delete",
            "file_move",
            "directory_list",
            "directory_create",
            "directory_delete",
            "command_execute",
            "network_request",
            "secret_access",
            "tool_invoke",
        ];
        for label in labels {
            let op = Operation::from_label(label).expect("round trip");
            assert_eq!(op.discriminant(), label);
        }
    }

    #[test]
    fn unknown_operation_fails_closed() {
        let r = Operation::from_label("rm_dash_rf");
        assert!(r.is_err());
    }
}
