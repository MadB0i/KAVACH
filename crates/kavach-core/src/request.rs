//! Tool-request envelope, operations, and request context.
//!
//! [`Operation`] is a non-exhaustive enum so that future operations can be
//! added without breaking external matching. Each variant deliberately carries
//! only data specific to the action; everything shared (subject, resource,
//! context) lives on [`ToolRequest`].

use std::fmt;
use std::str::FromStr;
use std::time::SystemTime;

use crate::error::{DomainError, DomainErrorKind, DomainValidationError, FieldPath};
use crate::ids::{AgentId, RequestId, SessionId};
use crate::resource::{NormalizedPath, PathError, RequestMetadata};
use crate::subject::{AgentSubject, Capability};

/// Maximum-byte cap for declared-intent and similar short string fields.
pub const MAX_SHORT_STRING_LEN: usize = 4096;

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

    /// Re-validate every invariant of a possibly-deserialized operation.
    ///
    /// Most variants carry no payload, but [`Self::FileMove`] stores a
    /// destination [`NormalizedPath`] and [`Self::ToolInvoke`] stores a plain
    /// `tool_id: String` whose bounds are only enforced here. A serde
    /// round-trip could otherwise smuggle in an oversized or control-laden
    /// `tool_id`; depth validation rejects it.
    pub(crate) fn validate_invariants(
        &self,
        parent: &FieldPath,
    ) -> Result<(), DomainValidationError> {
        match self {
            Self::ToolInvoke { tool_id } => {
                let field = parent.push("tool_id").map_err(|e| {
                    DomainValidationError::at_field(
                        "operation.tool_id",
                        e.kind(),
                        e.context().to_string(),
                    )
                })?;
                validate_tool_id(tool_id, &field)?;
            }
            Self::FileMove {
                destination: Some(dest),
            } => {
                let field = parent.push("destination").map_err(|e| {
                    DomainValidationError::at_field(
                        "operation.destination",
                        e.kind(),
                        e.context().to_string(),
                    )
                })?;
                dest.validate_invariants()
                    .map_err(|e| DomainValidationError::new(field, DomainError::from(e)))?;
            }
            _ => {}
        }
        Ok(())
    }
}

/// Bounds shared by every operation-carried identifier: non-empty, no null
/// bytes except tab, no control bytes except tab, bounded length.
fn validate_tool_id(tool_id: &str, field: &FieldPath) -> Result<(), DomainValidationError> {
    if tool_id.is_empty() {
        return Err(DomainValidationError::new(
            field.clone(),
            DomainError::new(DomainErrorKind::Missing, "empty tool id"),
        ));
    }
    if tool_id.len() > MAX_SHORT_STRING_LEN {
        return Err(DomainValidationError::new(
            field.clone(),
            DomainError::new(
                DomainErrorKind::OversizedField,
                "tool id exceeds maximum length",
            ),
        ));
    }
    if tool_id
        .bytes()
        .any(|b| b == 0 || b.is_ascii_control() && b != b'\t')
    {
        return Err(DomainValidationError::new(
            field.clone(),
            DomainError::new(
                DomainErrorKind::InvalidCharacter,
                "tool id contains control characters",
            ),
        ));
    }
    Ok(())
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
            "tool_invoke" => Ok(Self::ToolInvoke {
                tool_id: String::new(),
            }),
            other => Err(DomainError::new(
                DomainErrorKind::UnknownVariant,
                format!("unknown operation: {other}"),
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
/// The metadata map is a [`std::collections::BTreeMap`]-backed
/// [`RequestMetadata`], so iteration order is independent of hashing and
/// reproducible.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
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
            None | Some("") => None,
            Some(w) => Some(NormalizedPath::new(w)?),
        };
        let declared_intent = match declared_intent {
            None | Some("") => None,
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

    /// Re-validate every invariant of a possibly-deserialized context.
    ///
    /// Each typed member self-validates on construction, but a context
    /// reconstructed from JSON could carry a working-directory path whose
    /// stored `raw` form disagrees with its `normalized` form, an oversized
    /// declared intent, or a metadata map exceeding the entry cap. Depth
    /// validation rejects those so the request envelope stays fail-closed
    /// after a serde round-trip.
    pub fn validate(&self) -> Result<(), DomainValidationError> {
        if let Some(wd) = &self.working_directory {
            wd.validate_invariants()
                .map_err(|e| path_error_to_validation_error("context.working_directory", e))?;
        }
        if let Some(intent) = &self.declared_intent {
            if intent.len() > MAX_SHORT_STRING_LEN {
                return Err(DomainValidationError::at_field(
                    "context.declared_intent",
                    DomainErrorKind::OversizedField,
                    "declared intent exceeds maximum length",
                ));
            }
            if intent.bytes().any(|b| b == 0) {
                return Err(DomainValidationError::at_field(
                    "context.declared_intent",
                    DomainErrorKind::InvalidCharacter,
                    "declared intent contains null bytes",
                ));
            }
        }
        if let Some(parent) = &self.parent_request_id {
            crate::ids::validate_id(parent.as_str()).map_err(|e| {
                DomainValidationError::at_field(
                    "context.parent_request_id",
                    e.kind(),
                    e.context().to_string(),
                )
            })?;
        }
        self.metadata
            .validate_invariants()
            .map_err(|e| path_error_to_validation_error("context.metadata", e))?;
        Ok(())
    }
}

/// Build a [`DomainValidationError`] from a [`PathError`] anchored at the
/// given field-path literal.
fn path_error_to_validation_error(field: &'static str, e: PathError) -> DomainValidationError {
    let kind = match e.kind() {
        crate::resource::PathErrorKind::InvalidCharacter => DomainErrorKind::InvalidCharacter,
        _ => DomainErrorKind::InvalidValue,
    };
    DomainValidationError::at_field(field, kind, e.context().to_string())
}

/// A single tool request made by an AI agent.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
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
        Self {
            request_id,
            subject,
            operation,
            resource,
            context,
        }
    }

    /// Deep, fail-closed validation of a possibly-deserialized request.
    ///
    /// Construction via [`Self::new`] and the typed constructors perform their
    /// own validation, but a request reconstructed by serde bypasses several of
    /// them (for example plain `String` fields and struct-derived members).
    /// Before any consumer trusts a [`ToolRequest`], it must call this method.
    ///
    /// The check walks every field in a deterministic order, returns the
    /// *first* invariant violation as a [`DomainValidationError`] carrying the
    /// stable offending field path, and additionally enforces
    /// operation/resource compatibility:
    ///
    /// | Operation                              | Required resource kind     |
    /// |----------------------------------------|----------------------------|
    /// | `file_*` / `directory_*`               | `Resource::File` or `Resource::Directory` |
    /// | `Operation::CommandExecute`            | `Resource::Command`         |
    /// | `Operation::NetworkRequest`            | `Resource::NetworkEndpoint` |
    /// | `Operation::SecretAccess`              | `Resource::Secret`          |
    /// | `Operation::ToolInvoke`                | `Resource::ExternalTool`    |
    ///
    /// `Resource::Unknown` is rejected by this check regardless of the
    /// operation, implementing the fail-closed contract for unrecognized
    /// resources at the core layer (the policy engine also denies it by
    /// default).
    pub fn validate(&self) -> Result<(), DomainValidationError> {
        let root = FieldPath::new("request").map_err(|e| {
            DomainValidationError::at_field("request", e.kind(), e.context().to_string())
        })?;

        // request_id: already validated on construction, but re-check for a
        // deser-deserialized value that may have skipped the validating
        // constructor path (the newtype does use try_from, so this is mostly
        // defense-in-depth).
        crate::ids::validate_id(self.request_id.as_str()).map_err(|e| {
            DomainValidationError::at_field("request_id", e.kind(), e.context().to_string())
        })?;

        // subject
        let subject_field = root.push("subject").map_err(|e| {
            DomainValidationError::at_field("subject", e.kind(), e.context().to_string())
        })?;
        self.subject
            .validate_invariants()
            .map_err(|e| DomainValidationError::new(subject_field.clone(), e))?;

        // operation
        let operation_field = root.push("operation").map_err(|e| {
            DomainValidationError::at_field("operation", e.kind(), e.context().to_string())
        })?;
        self.operation.validate_invariants(&operation_field)?;

        // resource
        let resource_field = root.push("resource").map_err(|e| {
            DomainValidationError::at_field("resource", e.kind(), e.context().to_string())
        })?;
        self.resource.validate_invariants().map_err(|e| {
            DomainValidationError::new(resource_field.clone(), DomainError::from(e))
        })?;

        // Fail-closed: reject unrecognized resources outright at the core
        // layer. The policy engine also denies them by default, but rejecting
        // here means a malformed request never reaches evaluation.
        if matches!(self.resource, crate::resource::Resource::Unknown) {
            return Err(DomainValidationError::new(
                resource_field,
                DomainError::new(
                    DomainErrorKind::UnknownVariant,
                    "resource kind is unknown; request fails closed",
                ),
            ));
        }

        // operation / resource compatibility
        check_operation_resource_compatibility(&self.operation, &self.resource, &root)?;

        // context
        let context_field = root.push("context").map_err(|e| {
            DomainValidationError::at_field("context", e.kind(), e.context().to_string())
        })?;
        let ctx_err = self.context.validate();
        if let Err(e) = ctx_err {
            // Re-anchor the context's own path under the request root so
            // callers see a fully-qualified dotted path. The context opts to
            // surface paths already prefixed with `context.` for readability,
            // so we only re-anchor when its root is not yet qualified.
            return Err(merge_context_error(context_field, e));
        }
        Ok(())
    }
}

/// Merge a [`RequestContext`] validation error into the request-level path.
///
/// The context surfaces paths such as `context.working_directory`; the
/// request validator anchors them under `request.` so the final dotted path
/// reads `request.context.working_directory` for unambiguous diagnostics.
fn merge_context_error(
    context_field: FieldPath,
    e: DomainValidationError,
) -> DomainValidationError {
    let child = e.field().as_str();
    // The context always returns paths under "context.", so we re-pin the
    // reported path to "request.context.<rest>" if possible, else fall back
    // to the explicit context field.
    let rest = child.strip_prefix("context.").unwrap_or(child);
    match context_field.push(rest) {
        Ok(path) => DomainValidationError::new(path, e.source_error().clone()),
        Err(_) => DomainValidationError::new(context_field, e.source_error().clone()),
    }
}

/// Enforce that the requested operation matches the supplied resource kind.
///
/// The mapping is strict and one-to-one:
///
/// - Every `file_*` operation requires [`Resource::File`]; a directory is
///   rejected.
/// - Every `directory_*` operation requires [`Resource::Directory`]; a file is
///   rejected.
/// - `CommandExecute` requires [`Resource::Command`].
/// - `NetworkRequest` requires [`Resource::NetworkEndpoint`].
/// - `SecretAccess` requires [`Resource::Secret`].
/// - `ToolInvoke` requires [`Resource::ExternalTool`].
///
/// Any other pairing fails closed. The error message contains only the
/// operation label and resource kind label, never resource contents.
fn check_operation_resource_compatibility(
    operation: &Operation,
    resource: &crate::resource::Resource,
    root: &FieldPath,
) -> Result<(), DomainValidationError> {
    use crate::resource::Resource;

    let compatible = match (operation, resource) {
        // File operations accept ONLY a File resource.
        (
            Operation::FileRead { .. }
            | Operation::FileWrite
            | Operation::FileCreate
            | Operation::FileDelete
            | Operation::FileMove { .. },
            Resource::File { .. },
        ) => true,
        // Directory operations accept ONLY a Directory resource.
        (
            Operation::DirectoryList | Operation::DirectoryCreate | Operation::DirectoryDelete,
            Resource::Directory { .. },
        ) => true,
        // Command execution requires a command resource.
        (Operation::CommandExecute, Resource::Command(_)) => true,
        // Network requests require a network endpoint resource.
        (Operation::NetworkRequest, Resource::NetworkEndpoint(_)) => true,
        // Secret access requires a secret resource.
        (Operation::SecretAccess, Resource::Secret { .. }) => true,
        // Tool invocation requires an external-tool resource.
        (Operation::ToolInvoke { .. }, Resource::ExternalTool { .. }) => true,
        // Every other pairing is incompatible and fails closed.
        _ => false,
    };

    if !compatible {
        let op_field = root.push("operation").map_err(|e| {
            DomainValidationError::at_field("operation", e.kind(), e.context().to_string())
        })?;
        return Err(DomainValidationError::new(
            op_field,
            DomainError::new(
                DomainErrorKind::InvalidValue,
                format!(
                    "operation `{}` is not compatible with resource kind `{}`",
                    operation.discriminant(),
                    resource.kind()
                ),
            ),
        ));
    }
    Ok(())
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
                if s.bytes()
                    .any(|b| b == 0 || b.is_ascii_control() && b != b'\t')
                {
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
            let op = Operation::from_label(label)
                .unwrap_or_else(|e| panic!("round trip parse failed for {label}: {e}"));
            assert_eq!(op.discriminant(), label);
        }
    }

    #[test]
    fn unknown_operation_fails_closed() {
        let r = Operation::from_label("rm_dash_rf");
        assert!(r.is_err());
    }
}

#[cfg(test)]
mod validation_tests {
    use super::*;
    use crate::ids::{AgentId, RequestId, SessionId};
    use crate::resource::{
        CommandResource, NetworkHost, NetworkPort, NetworkResource, NetworkScheme, Resource,
    };
    use crate::subject::TrustLevel;

    /// `Result::unwrap` equivalent that does not trip the `unwrap_used` lint.
    fn must<T, E: std::fmt::Display>(r: Result<T, E>, ctx: &str) -> T {
        match r {
            Ok(v) => v,
            Err(e) => panic!("{ctx}: {e}"),
        }
    }

    /// `Result::unwrap_err` equivalent that does not trip the lint.
    fn must_err<T: std::fmt::Debug, E: std::fmt::Display>(r: Result<T, E>, ctx: &str) -> E {
        match r {
            Ok(v) => panic!("{ctx}: expected Err, got Ok({v:?})"),
            Err(e) => e,
        }
    }

    /// Field path of an `Err` validation result, suitable for assertions.
    fn err_field(r: Result<(), DomainValidationError>) -> String {
        must_err(r, "expected validation failure")
            .field()
            .as_str()
            .to_string()
    }

    fn make_subject() -> AgentSubject {
        AgentSubjectBuilder::new(
            must(AgentId::new("agent-1"), "agent id"),
            must(SessionId::new("session-1"), "session id"),
        )
        .trust_level(TrustLevel::Standard)
        .build()
    }

    fn make_context() -> RequestContext {
        must(
            RequestContext::new(None, None, None, None, false),
            "default context",
        )
    }

    /// Construct a baseline, fully-valid request for file_read on a project file.
    fn valid_request() -> ToolRequest {
        let resource = must(Resource::file("./src/main.rs"), "baseline resource");
        let context = must(
            RequestContext::new(Some("./"), Some("read source"), None, None, false),
            "baseline context",
        );
        ToolRequest::new(
            must(RequestId::new("req-1"), "baseline request id"),
            make_subject(),
            Operation::FileRead { max_bytes: None },
            resource,
            context,
        )
    }

    /// Serialize, JSON-patch, and deserialize a request. The patch is assumed
    /// to keep the document valid JSON.
    fn tamper<F: FnOnce(&str) -> String>(req: &ToolRequest, patch: F) -> ToolRequest {
        let json = must(serde_json::to_string(req), "serialize for tampering");
        let patched = patch(&json);
        serde_json::from_str(&patched)
            .unwrap_or_else(|e| panic!("patched JSON did not deserialize: {e}"))
    }

    /// Whether a tampered request passes `validate`, shrinking the call site.
    fn tamper_validate_is_ok(req: &ToolRequest) -> bool {
        req.validate().is_ok()
    }

    #[test]
    fn valid_request_passes_validation() {
        let req = valid_request();
        assert!(req.validate().is_ok(), "baseline request should validate");
    }

    #[test]
    fn empty_request_id_is_rejected_at_serde_boundary() {
        // RequestId routes through a validating `try_from` serde impl, so an
        // empty id cannot survive deserialization in the first place. We assert
        // that here so a future refactor that removes the verifying serde impl
        // does not silently push validation downstream.
        let req = valid_request();
        let json = must(serde_json::to_string(&req), "serialize");
        let patched = json.replace("\"request_id\":\"req-1\"", "\"request_id\":\"\"");
        let res: Result<ToolRequest, _> = serde_json::from_str(&patched);
        assert!(res.is_err(), "empty request_id must not deserialize");
    }

    #[test]
    fn display_name_with_null_bytes_is_rejected_via_serde() {
        let req = valid_request();
        let tampered = tamper(&req, |j| {
            j.replace(
                "\"display_name\":null",
                "\"display_name\":\"name\\u0000bad\"",
            )
        });
        assert_eq!(err_field(tampered.validate()), "request.subject");
    }

    #[test]
    fn oversized_declared_intent_is_rejected_via_serde() {
        let req = valid_request();
        let big = "x".repeat(MAX_SHORT_STRING_LEN + 1);
        let tampered = tamper(&req, |j| {
            j.replace(
                "\"declared_intent\":\"read source\"",
                &format!("\"declared_intent\":\"{big}\""),
            )
        });
        assert_eq!(
            err_field(tampered.validate()),
            "request.context.declared_intent"
        );
    }

    #[test]
    fn null_byte_in_declared_intent_is_rejected_via_serde() {
        let req = valid_request();
        let tampered = tamper(&req, |j| {
            j.replace(
                "\"declared_intent\":\"read source\"",
                "\"declared_intent\":\"read\\u0000source\"",
            )
        });
        assert_eq!(
            err_field(tampered.validate()),
            "request.context.declared_intent"
        );
    }

    #[test]
    fn oversized_metadata_map_is_rejected_via_serde() {
        let req = valid_request();
        let mut entries = String::new();
        for i in 0..(crate::resource::RequestMetadata::MAX_METADATA_ENTRIES + 1) {
            entries.push_str(&format!("\"k{i}\":\"v\","));
        }
        entries.pop(); // drop trailing comma
        let tampered = tamper(&req, |j| {
            j.replace("\"metadata\":{}", &format!("\"metadata\":{{{entries}}}"))
        });
        assert_eq!(err_field(tampered.validate()), "request.context.metadata");
    }

    #[test]
    fn metadata_value_with_null_bytes_is_rejected_via_serde() {
        let req = valid_request();
        let tampered = tamper(&req, |j| {
            j.replace("\"metadata\":{}", "\"metadata\":{\"k\":\"v\\u0000\"}")
        });
        assert_eq!(err_field(tampered.validate()), "request.context.metadata");
    }

    #[test]
    fn unknown_resource_fails_closed() {
        let req = ToolRequest::new(
            must(RequestId::new("req-1"), "request id"),
            make_subject(),
            Operation::FileRead { max_bytes: None },
            Resource::Unknown,
            make_context(),
        );
        assert_eq!(err_field(req.validate()), "request.resource");
    }

    #[test]
    fn command_operation_requires_command_resource() {
        // Command operation against a *file* resource must be incompatible.
        let bad = ToolRequest::new(
            must(RequestId::new("req-1"), "request id"),
            make_subject(),
            Operation::CommandExecute,
            must(Resource::file("./README.md"), "file resource"),
            make_context(),
        );
        assert_eq!(err_field(bad.validate()), "request.operation");

        // Command operation against a *command* resource validates.
        let cmd = must(
            CommandResource::new("ls", vec!["-la".to_string()]),
            "command",
        );
        let good = ToolRequest::new(
            must(RequestId::new("req-2"), "request id"),
            make_subject(),
            Operation::CommandExecute,
            Resource::Command(cmd),
            make_context(),
        );
        assert!(good.validate().is_ok());
    }

    #[test]
    fn network_operation_requires_network_endpoint_resource() {
        // Network operation against a *directory* is incompatible.
        let bad = ToolRequest::new(
            must(RequestId::new("req-1"), "request id"),
            make_subject(),
            Operation::NetworkRequest,
            must(Resource::directory("./src"), "directory"),
            make_context(),
        );
        assert!(bad.validate().is_err());

        // Network operation against a network endpoint validates.
        let net = must(
            NetworkResource::new(
                must(NetworkScheme::new("https"), "scheme"),
                must(NetworkHost::new("example.com"), "host"),
                Some(NetworkPort::new(443)),
                "/",
            ),
            "endpoint",
        );
        let good = ToolRequest::new(
            must(RequestId::new("req-2"), "request id"),
            make_subject(),
            Operation::NetworkRequest,
            Resource::NetworkEndpoint(net),
            make_context(),
        );
        assert!(good.validate().is_ok());
    }

    #[test]
    fn tool_invoke_requires_external_tool_resource() {
        let bad = ToolRequest::new(
            must(RequestId::new("req-1"), "request id"),
            make_subject(),
            Operation::ToolInvoke {
                tool_id: "calc".to_string(),
            },
            must(Resource::file("./x"), "file"),
            make_context(),
        );
        assert!(bad.validate().is_err());

        let good = ToolRequest::new(
            must(RequestId::new("req-2"), "request id"),
            make_subject(),
            Operation::ToolInvoke {
                tool_id: "calc".to_string(),
            },
            Resource::ExternalTool {
                identifier: "calc".to_string(),
            },
            make_context(),
        );
        assert!(good.validate().is_ok());
    }

    #[test]
    fn tool_invoke_with_empty_tool_id_is_rejected_via_serde() {
        let req = ToolRequest::new(
            must(RequestId::new("req-1"), "request id"),
            make_subject(),
            Operation::ToolInvoke {
                tool_id: "calc".to_string(),
            },
            Resource::ExternalTool {
                identifier: "calc".to_string(),
            },
            make_context(),
        );
        let tampered = tamper(&req, |j| {
            j.replace("\"tool_id\":\"calc\"", "\"tool_id\":\"\"")
        });
        assert_eq!(err_field(tampered.validate()), "request.operation.tool_id");
    }

    #[test]
    fn tool_invoke_with_oversized_tool_id_is_rejected_via_serde() {
        let req = ToolRequest::new(
            must(RequestId::new("req-1"), "request id"),
            make_subject(),
            Operation::ToolInvoke {
                tool_id: "calc".to_string(),
            },
            Resource::ExternalTool {
                identifier: "calc".to_string(),
            },
            make_context(),
        );
        let big = "x".repeat(MAX_SHORT_STRING_LEN + 1);
        let tampered = tamper(&req, |j| {
            j.replace("\"tool_id\":\"calc\"", &format!("\"tool_id\":\"{big}\""))
        });
        assert_eq!(err_field(tampered.validate()), "request.operation.tool_id");
    }

    #[test]
    fn secret_access_requires_secret_resource() {
        let bad = ToolRequest::new(
            must(RequestId::new("req-1"), "request id"),
            make_subject(),
            Operation::SecretAccess,
            must(Resource::file("./x"), "file"),
            make_context(),
        );
        assert!(bad.validate().is_err());

        let good = ToolRequest::new(
            must(RequestId::new("req-2"), "request id"),
            make_subject(),
            Operation::SecretAccess,
            Resource::Secret {
                identifier: "vault/kv/db".to_string(),
            },
            make_context(),
        );
        assert!(good.validate().is_ok());
    }

    #[test]
    fn secret_with_empty_identifier_is_rejected_via_serde() {
        let req = ToolRequest::new(
            must(RequestId::new("req-1"), "request id"),
            make_subject(),
            Operation::SecretAccess,
            Resource::Secret {
                identifier: "vault/kv/db".to_string(),
            },
            make_context(),
        );
        let tampered = tamper(&req, |j| {
            j.replace("\"identifier\":\"vault/kv/db\"", "\"identifier\":\"\"")
        });
        assert_eq!(err_field(tampered.validate()), "request.resource");
    }

    #[test]
    fn serde_round_trip_preserves_valid_request() {
        let req = valid_request();
        let json = must(serde_json::to_string(&req), "serialize");
        let back: ToolRequest =
            serde_json::from_str(&json).unwrap_or_else(|e| panic!("deserialize: {e}"));
        assert_eq!(req, back);
        assert!(back.validate().is_ok());
    }

    #[test]
    fn deterministic_first_violation_order() {
        // The resource is replaced with `Resource::Unknown` (serialized as the
        // verbatim variant tag `"Unknown"`) *and* the operation remains
        // file_read on a now-missing resource. The unknown-resource check
        // runs before the compatibility check, so the unknown-resource error
        // is reported first.
        let req = valid_request();
        let tampered = tamper(&req, |j| {
            j.replace("{\"File\":{\"path\":\"./src/main.rs\"}}", "\"Unknown\"")
        });
        assert_eq!(err_field(tampered.validate()), "request.resource");
    }

    // ---- Metadata boundary tests ----
    //
    // The metadata map is capped at `RequestMetadata::MAX_METADATA_ENTRIES`
    // (currently 32). Keys are capped at 128 bytes; values at `MAX_PATH_LEN`
    // (currently 4096). We test exactly at each cap and one beyond.

    #[test]
    fn metadata_with_exactly_max_entries_passes() {
        let req = valid_request();
        let mut entries = String::new();
        for i in 0..crate::resource::RequestMetadata::MAX_METADATA_ENTRIES {
            entries.push_str(&format!("\"k{i}\":\"v\","));
        }
        entries.pop(); // drop trailing comma
        let tampered = tamper(&req, |j| {
            j.replace("\"metadata\":{}", &format!("\"metadata\":{{{entries}}}"))
        });
        assert!(
            tamper_validate_is_ok(&tampered),
            "exactly MAX_METADATA_ENTRIES should pass"
        );
    }

    #[test]
    fn metadata_with_max_entries_plus_one_fails() {
        let req = valid_request();
        let mut entries = String::new();
        for i in 0..(crate::resource::RequestMetadata::MAX_METADATA_ENTRIES + 1) {
            entries.push_str(&format!("\"k{i}\":\"v\","));
        }
        entries.pop();
        let tampered = tamper(&req, |j| {
            j.replace("\"metadata\":{}", &format!("\"metadata\":{{{entries}}}"))
        });
        assert_eq!(err_field(tampered.validate()), "request.context.metadata");
    }

    #[test]
    fn metadata_with_empty_key_fails() {
        let req = valid_request();
        let tampered = tamper(&req, |j| {
            j.replace("\"metadata\":{}", "\"metadata\":{\"\":\"v\"}")
        });
        assert_eq!(err_field(tampered.validate()), "request.context.metadata");
    }

    #[test]
    fn metadata_key_with_control_character_fails() {
        let req = valid_request();
        // Control byte (U+0001) injected via JSON escape.
        let tampered = tamper(&req, |j| {
            j.replace("\"metadata\":{}", "\"metadata\":{\"k\\u0001\":\"v\"}")
        });
        assert_eq!(err_field(tampered.validate()), "request.context.metadata");
    }

    #[test]
    fn metadata_key_exactly_128_chars_passes() {
        let req = valid_request();
        let key = "k".repeat(128);
        let tampered = tamper(&req, |j| {
            j.replace(
                "\"metadata\":{}",
                &format!("\"metadata\":{{\"{key}\":\"v\"}}"),
            )
        });
        assert!(tamper_validate_is_ok(&tampered), "128-byte key should pass");
    }

    #[test]
    fn metadata_key_longer_than_128_chars_fails() {
        let req = valid_request();
        let key = "k".repeat(129);
        let tampered = tamper(&req, |j| {
            j.replace(
                "\"metadata\":{}",
                &format!("\"metadata\":{{\"{key}\":\"v\"}}"),
            )
        });
        assert_eq!(err_field(tampered.validate()), "request.context.metadata");
    }

    #[test]
    fn metadata_value_exactly_max_path_len_passes() {
        let req = valid_request();
        let val = "v".repeat(crate::resource::MAX_PATH_LEN);
        let tampered = tamper(&req, |j| {
            j.replace(
                "\"metadata\":{}",
                &format!("\"metadata\":{{\"k\":\"{val}\"}}"),
            )
        });
        assert!(
            tamper_validate_is_ok(&tampered),
            "value of exactly MAX_PATH_LEN should pass"
        );
    }

    #[test]
    fn metadata_value_longer_than_max_path_len_fails() {
        let req = valid_request();
        let val = "v".repeat(crate::resource::MAX_PATH_LEN + 1);
        let tampered = tamper(&req, |j| {
            j.replace(
                "\"metadata\":{}",
                &format!("\"metadata\":{{\"k\":\"{val}\"}}"),
            )
        });
        assert_eq!(err_field(tampered.validate()), "request.context.metadata");
    }

    // ---- Declared-intent boundary tests ----
    //
    // Declared intent is capped at `MAX_SHORT_STRING_LEN` (currently 4096).

    #[test]
    fn declared_intent_exactly_max_len_passes() {
        let req = valid_request();
        let intent = "i".repeat(MAX_SHORT_STRING_LEN);
        let tampered = tamper(&req, |j| {
            j.replace(
                "\"declared_intent\":\"read source\"",
                &format!("\"declared_intent\":\"{intent}\""),
            )
        });
        assert!(
            tamper_validate_is_ok(&tampered),
            "intent at cap should pass"
        );
    }

    // declared_intent longer than the cap fails: already covered by
    // `oversized_declared_intent_is_rejected_via_serde`.
    // null byte in declared intent fails: already covered by
    // `null_byte_in_declared_intent_is_rejected_via_serde`.
    // null byte in metadata value fails: already covered by
    // `metadata_value_with_null_bytes_is_rejected_via_serde`.

    // ---- Strict operation/resource compatibility tests ----

    #[test]
    fn file_read_with_directory_resource_fails() {
        let bad = ToolRequest::new(
            must(RequestId::new("req-1"), "request id"),
            make_subject(),
            Operation::FileRead { max_bytes: None },
            must(Resource::directory("./src"), "directory"),
            make_context(),
        );
        assert_eq!(err_field(bad.validate()), "request.operation");
    }

    #[test]
    fn directory_list_with_file_resource_fails() {
        let bad = ToolRequest::new(
            must(RequestId::new("req-1"), "request id"),
            make_subject(),
            Operation::DirectoryList,
            must(Resource::file("./README.md"), "file"),
            make_context(),
        );
        assert_eq!(err_field(bad.validate()), "request.operation");
    }

    // ---- Unknown JSON fields fail closed ----

    #[test]
    fn unknown_field_in_tool_request_fails_deserialize() {
        let req = valid_request();
        let json = must(serde_json::to_string(&req), "serialize");
        // The request object ends as `..."dry_run":false}}` — the first `}`
        // closes the context, the second closes the request. Inject a
        // top-level rogue field between them so it lands in ToolRequest, not
        // RequestContext.
        let patched = json.replace(
            "\"dry_run\":false}}",
            "\"dry_run\":false},\"rogue_field\":42}",
        );
        let res: Result<ToolRequest, _> = serde_json::from_str(&patched);
        assert!(
            res.is_err(),
            "unknown top-level field in ToolRequest must fail deserialization"
        );
    }

    #[test]
    fn unknown_field_in_request_context_fails_deserialize() {
        let req = valid_request();
        let json = must(serde_json::to_string(&req), "serialize");
        // `dry_run` is the last context field; add an unknown sibling inside
        // the context object (before the context's closing brace).
        let patched = json.replace(
            "\"dry_run\":false}}",
            "\"dry_run\":false,\"context_rogue\":true}}",
        );
        let res: Result<ToolRequest, _> = serde_json::from_str(&patched);
        assert!(
            res.is_err(),
            "unknown field in RequestContext must fail deserialization"
        );
    }

    // ---- Determinism ----

    #[test]
    fn repeated_validation_produces_same_result() {
        let req = valid_request();
        let first = req.validate();
        let second = req.validate();
        let third = req.validate();
        assert_eq!(first, second);
        assert_eq!(second, third);

        // Also for an invalid request: the same error path and kind recur.
        let bad = ToolRequest::new(
            must(RequestId::new("req-1"), "request id"),
            make_subject(),
            Operation::FileRead { max_bytes: None },
            must(Resource::directory("./src"), "directory"),
            make_context(),
        );
        let e1 = must_err(bad.validate(), "first bad validate");
        let e2 = must_err(bad.validate(), "second bad validate");
        assert_eq!(e1.field().as_str(), e2.field().as_str());
        assert_eq!(e1.source_error().kind(), e2.source_error().kind());
    }
}
