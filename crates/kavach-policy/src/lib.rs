//! KAVACH policy model and deterministic in-memory evaluator.
//!
//! # Policy data model
//!
//! A [`Policy`] is a document containing an ordered list of [`Rule`] items.
//! Each rule carries an [`Effect`] (Allow, Deny, or RequireApproval) and a
//! set of [`RuleConditions`] that must all be satisfied for the rule to match.
//!
//! # Evaluation
//!
//! [`PolicyEngine::evaluate`] runs every rule against a
//! [`kavach_core::request::ToolRequest`] and
//! applies deterministic precedence:
//!
//! ```text
//! Explicit Deny > Require Approval > Explicit Allow > Policy Default
//! ```
//!
//! Only rule IDs from the winning precedence group appear in the decision,
//! sorted lexicographically.

/// In-memory policy evaluator with deterministic precedence.
pub mod engine;

/// Policy data model: [`Policy`], [`Rule`], [`Effect`], [`RuleConditions`].
pub mod model;

/// TOML policy document parsing and file loading.
pub mod io;

pub use engine::PolicyEngine;
pub use io::MAX_POLICY_FILE_SIZE;
pub use io::{PolicyLoadError, load_policy_from_file, load_policy_from_str};
pub use model::{DefaultEffect, Effect, Policy, PolicyValidationError, Rule, RuleConditions};
