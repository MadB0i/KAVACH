//! KAVACH core domain contracts.
//!
//! This crate defines the stable, strongly typed, serializable contracts that
//! every other KAVACH crate depends on. The crate performs **no side effects**:
//! no filesystem access, no network access, no I/O, and it installs no tracing
//! subscribers. It exists only to describe, validate, and serialize the
//! security-relevant data that the policy engine evaluates.
//!
//! Crate layout:
//!
//! - [`error`] - Domain validation errors.
//! - [`subject`], [`ids`] - Agent subjects, trust tiers, capabilities, validated IDs.
//! - [`request`], [`operation`] - Tool request envelope and operation taxonomy.
//! - [`resource`] - Normalized paths and protected resources.
//! - [`decision`] - Authorization decision output.
//!
//! [`operation`]: request::Operation

#![forbid(unsafe_code)]

pub mod decision;
/// Request digest computation for permit binding.
pub mod digest;
pub mod error;
pub mod ids;
/// Execution permit types and scope definitions.
pub mod permit;
pub mod request;
pub mod resource;
pub mod shell;
pub mod subject;

pub use decision::{
    ApprovalRequirements, AuthorizationDecision, DecisionEffect, DecisionTrace, ReasonCode,
};
pub use digest::compute_request_digest;
pub use error::{DomainError, DomainErrorKind, DomainValidationError, FieldPath};
pub use ids::{AgentId, ApprovalId, MAX_ID_LEN, PolicyId, RequestId, RuleId, SessionId};
pub use permit::{ExecutionPermit, PermitScope, required_scope};
pub use request::{AgentSubjectBuilder, Operation, RequestContext, ToolRequest};
pub use resource::{
    CommandResource, MAX_IDENTIFIER_LEN, MAX_PATH_LEN, NetworkHost, NetworkPort, NetworkResource,
    NetworkScheme, NormalizedPath, PathError, PathErrorKind, RequestMetadata, Resource,
    ResourceKind,
};
pub use shell::{
    ShellHazard, has_dangerous_shell_construct, has_substitution_hazard,
    scan_dangerous_shell_constructs,
};
pub use subject::{AgentSubject, Capability, CapabilitySet, MAX_CAPABILITY_LEN, TrustLevel};

#[cfg(test)]
mod proptests;
