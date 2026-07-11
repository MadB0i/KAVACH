//! Domain validation errors for KAVACH core contracts.
//!
//! These errors are produced while constructing or validating the strongly
//! typed core domain models. They are intentionally narrow: each variant names
//! exactly what failed validation, so callers can surface actionable messages
//! without inspecting unrelated error state.

use std::fmt;

/// A category of domain validation failure.
///
/// Stable machine-readable category used by [`DomainError`]. Variants are kept
/// narrow so that callers can react to specific failure modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainErrorKind {
    /// An identifier was empty, too long, or contained control characters.
    InvalidId,
    /// A string field exceeded its documented maximum length.
    OversizedField,
    /// Input contained bytes that are not permitted in the target context
    /// (for example null bytes in paths).
    InvalidCharacter,
    /// A strongly typed value could not be constructed from its input.
    InvalidValue,
    /// A map or collection exceeded its documented maximum entry count.
    OversizedCollection,
    /// An enum variant received an unknown or unsupported label.
    UnknownVariant,
    /// A required field was missing.
    Missing,
}

/// Error originating from core domain model validation.
///
/// All public constructors of core newtypes and enums return [`Result`] with
/// this error type instead of panicking or returning a raw string. The error
/// carries a stable kind and a context string; it never carries secret values.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub struct DomainError {
    kind: DomainErrorKind,
    context: String,
}

impl DomainError {
    /// Create a new domain error from a kind and a non-secret context string.
    pub fn new(kind: DomainErrorKind, context: impl fmt::Display) -> Self {
        Self {
            kind,
            context: context.to_string(),
        }
    }

    /// Returns the stable error category.
    pub fn kind(&self) -> DomainErrorKind {
        self.kind
    }

    /// Returns a non-secret, human-readable context string describing what was
    /// being validated when the error occurred.
    pub fn context(&self) -> &str {
        &self.context
    }
}

impl fmt::Display for DomainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.context)
    }
}

/// A dotted path into a [`crate::request::ToolRequest`] that names exactly
/// which field failed validation.
///
/// Paths are stable, machine-readable, and use only a small alphabet so that
/// they are safe to surface in logs and CLI output without ever carrying
/// request *values* (which might contain secrets). For example:
///
/// - `request_id`
/// - `subject.agent_id`
/// - `context.metadata[3].key`
/// - `resource.command.executable`
///
/// Equality and ordering are derived from the underlying string so that
/// unrelated [`DomainValidationError`] values compare deterministically.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(try_from = "&str", into = "String")]
pub struct FieldPath(String);

/// Maximum number of bytes in a [`FieldPath`].
pub const MAX_FIELD_PATH_LEN: usize = 256;

impl FieldPath {
    /// Construct a validated, non-empty field path.
    ///
    /// A path is composed of dot-separated identifiers, each matching
    /// `[a-z0-9_]+`, optionally followed by a bracketed index such as `[3]`.
    /// Empty segments, empty indices, control characters, and overly long
    /// inputs are rejected so the path is always safe to display.
    pub fn new(value: impl AsRef<str> + fmt::Display) -> Result<Self, DomainError> {
        Self::new_inner(value.as_ref())
    }

    fn new_inner(s: &str) -> Result<Self, DomainError> {
        if s.is_empty() {
            return Err(DomainError::new(
                DomainErrorKind::Missing,
                "empty field path",
            ));
        }
        if s.len() > MAX_FIELD_PATH_LEN {
            return Err(DomainError::new(
                DomainErrorKind::OversizedField,
                "field path exceeds maximum length",
            ));
        }
        if s.bytes().any(|b| b.is_ascii_control()) {
            return Err(DomainError::new(
                DomainErrorKind::InvalidCharacter,
                "field path contains control characters",
            ));
        }
        // Each dot-separated segment must be a non-empty identifier or an
        // indexed segment of the form `name[i]`. We walk the segments to keep
        // the allowed alphabet tight and avoid accepting raw request values.
        for segment in s.split('.') {
            if segment.is_empty() {
                return Err(DomainError::new(
                    DomainErrorKind::InvalidValue,
                    "field path contains empty segment",
                ));
            }
            if !Self::segment_is_valid(segment) {
                return Err(DomainError::new(
                    DomainErrorKind::InvalidCharacter,
                    "field path segment is malformed",
                ));
            }
        }
        Ok(Self(s.to_string()))
    }

    fn segment_is_valid(segment: &str) -> bool {
        // `name` or `name[i]` where name matches [a-z0-9_]+ and i is unsigned.
        let bytes = segment.as_bytes();
        let Some(end) = bytes.iter().position(|b| *b == b'[') else {
            return Self::ident_is_valid(segment);
        };
        let ident = &segment[..end];
        let rest = &segment[end..];
        let Some(inner) = rest.strip_prefix('[').and_then(|r| r.strip_suffix(']')) else {
            return false;
        };
        if inner.is_empty() || !inner.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
        Self::ident_is_valid(ident)
    }

    fn ident_is_valid(ident: &str) -> bool {
        !ident.is_empty()
            && ident
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    }

    /// Append a child component, returning a new validated path.
    ///
    /// This keeps nested validation code readable while guaranteeing every
    /// resulting path is itself well-formed.
    pub fn push(&self, child: &str) -> Result<Self, DomainError> {
        let mut s = self.0.clone();
        s.push('.');
        s.push_str(child);
        Self::new_inner(&s)
    }

    /// Append an indexed component such as `metadata[3]`.
    pub fn push_indexed(&self, name: &str, index: usize) -> Result<Self, DomainError> {
        let child = format!("{name}[{index}]");
        self.push(&child)
    }

    /// Borrow the path string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The canonical top-level path used when a trusted field-path literal is
    /// itself malformed (a programming bug). Constructed without re-entering
    /// validation so it cannot itself fail.
    pub fn root() -> Self {
        // SAFETY of *correctness* (not unsafe code): the literal "request"
        // matches the validated alphabet by inspection.
        Self("request".to_string())
    }
}

impl fmt::Display for FieldPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::str::FromStr for FieldPath {
    type Err = DomainError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new_inner(s)
    }
}

impl TryFrom<&str> for FieldPath {
    type Error = DomainError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::new_inner(s)
    }
}

impl From<FieldPath> for String {
    fn from(p: FieldPath) -> String {
        p.0
    }
}

/// Error returned by deep post-construction validation of a
/// [`crate::request::ToolRequest`] (or any of its members).
///
/// A request may arrive in KAVACH by **deserialization**, which bypasses the
/// validating constructors of the strongly typed newtypes/enums. To remain
/// fail-closed under that threat model, consumers call
/// [`crate::request::ToolRequest::validate`] before trusting a request; that
/// method walks every field and returns the *first* invariant violation as a
/// [`DomainValidationError`] carrying:
///
/// - the stable [`FieldPath`] naming exactly which field is bad, and
/// - the underlying [`DomainError`] describing *why* it is bad.
///
/// The path and error never carry request *values* (which might contain
/// secrets), only descriptive context, so they are safe to log.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub struct DomainValidationError {
    field: FieldPath,
    source: DomainError,
}

impl DomainValidationError {
    /// Construct a validation error from a field path and a domain error.
    pub fn new(field: FieldPath, source: DomainError) -> Self {
        Self { field, source }
    }

    /// Construct a validation error, validating the field path inline.
    pub fn at(
        field: &str,
        kind: DomainErrorKind,
        context: impl fmt::Display,
    ) -> Result<Self, DomainError> {
        let field = FieldPath::new(field)?;
        Ok(Self::new(field, DomainError::new(kind, context)))
    }

    /// Construct a validation error from a compile-time field-path literal.
    ///
    /// Used by depth validation to attach a stable field designation without
    /// forcing every call site to handle the (impossible-for-trusted-literals)
    /// path-construction failure. The literal must match the
    /// [`FieldPath`] alphabet; a malformed literal is a programming bug and
    /// falls back to the `request` root path rather than panicking.
    pub fn at_field(
        field: &'static str,
        kind: DomainErrorKind,
        context: impl fmt::Display,
    ) -> Self {
        let path = FieldPath::new(field).unwrap_or_else(|_| FieldPath::root());
        Self::new(path, DomainError::new(kind, context))
    }

    /// Construct a validation error from a nested field path and an underlying
    /// domain error. The parent path is taken verbatim (already validated by
    /// construction), then the child is appended.
    pub fn nested(
        parent: &FieldPath,
        child: &str,
        source: DomainError,
    ) -> Result<Self, DomainError> {
        let field = parent.push(child)?;
        Ok(Self::new(field, source))
    }

    /// The dotted path of the offending field.
    pub fn field(&self) -> &FieldPath {
        &self.field
    }

    /// The underlying domain error describing the violation.
    pub fn source_error(&self) -> &DomainError {
        &self.source
    }
}

impl fmt::Display for DomainValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.field, self.source)
    }
}
