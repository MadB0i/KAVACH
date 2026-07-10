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
pub mod error;
pub mod ids;
pub mod request;
pub mod resource;
pub mod subject;

pub use decision::{ApprovalRequirements, AuthorizationDecision, DecisionEffect, ReasonCode};
pub use error::{DomainError, DomainErrorKind};
pub use ids::{AgentId, ApprovalId, PolicyId, RequestId, RuleId, SessionId, MAX_ID_LEN};
pub use request::{AgentSubjectBuilder, Operation, RequestContext, ToolRequest};
pub use resource::{
    CommandResource, NetworkHost, NetworkPort, NetworkResource, NetworkScheme, NormalizedPath, PathError,
    PathErrorKind, RequestMetadata, Resource, ResourceKind, MAX_PATH_LEN,
};
pub use subject::{AgentSubject, Capability, CapabilitySet, TrustLevel, MAX_CAPABILITY_LEN};
