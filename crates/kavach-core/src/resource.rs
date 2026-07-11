//! Typed protected resources and platform-independent path normalization.
//!
//! The defining rule of the core path model: paths are **lexically**
//! normalized only. KAVACH core never touches the filesystem inside the type
//! constructor, never resolves symlinks, and never converts a relative path
//! into an absolute one. State that depends on the filesystem is deferred to
//! the later enforcement layer, by design: keeping core pure lets the policy
//! engine remain a pure function and lets decisions be deterministic and
//! trivially testable.
//!
//! The normalization handles `.`, `..`, repeated separators, Windows drive
//! prefixes (`C:`) and UNC `\\?\` / `\\server\share` prefixes as accurately
//! as platform-independent parsing allows. It preserves whether the supplied
//! path was absolute or relative so that policy can choose to restrict one
//! and not the other.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use crate::error::{DomainError, DomainErrorKind};

/// Maximum number of bytes in the raw input form of a normalized path.
pub const MAX_PATH_LEN: usize = 4096;

/// Maximum number of bytes in a secret or external-tool identifier carried by
/// a [`Resource`]. Identifiers are non-secret, stable references.
pub const MAX_IDENTIFIER_LEN: usize = 1024;

/// Stable category of path validation/normalization failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathErrorKind {
    /// The path was empty.
    Empty,
    /// The path exceeded [`MAX_PATH_LEN`].
    Oversized,
    /// The path contained a null byte or other control character.
    InvalidCharacter,
    /// The path's `..` segments would escape its own root, and core has no
    /// workspace anchor. The policy engine uses an explicit workspace root to
    /// reason about traversal instead.
    Escape,
    /// A stored invariants check failed (typically after deserialization).
    InvalidValue,
    /// A network host or port was malformed.
    InvalidEndpoint,
}

/// Error while constructing a [`NormalizedPath`] or typed resource identifier.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub struct PathError {
    kind: PathErrorKind,
    context: String,
}

impl PathError {
    /// Construct a path error from a stable kind and a non-secret context message.
    pub fn from_kind(kind: PathErrorKind, context: impl fmt::Display) -> Self {
        Self {
            kind,
            context: context.to_string(),
        }
    }

    /// Returns the stable error category.
    pub fn kind(&self) -> PathErrorKind {
        self.kind
    }

    /// Returns a non-secret, human-readable description of what failed.
    pub fn context(&self) -> &str {
        &self.context
    }
}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.context)
    }
}

impl From<PathError> for DomainError {
    fn from(value: PathError) -> Self {
        let kind = match value.kind {
            PathErrorKind::Empty | PathErrorKind::Oversized | PathErrorKind::InvalidEndpoint => {
                DomainErrorKind::InvalidValue
            }
            PathErrorKind::InvalidCharacter => DomainErrorKind::InvalidCharacter,
            PathErrorKind::Escape | PathErrorKind::InvalidValue => DomainErrorKind::InvalidValue,
        };
        DomainError::new(kind, value.context)
    }
}

/// A path normalized lexically, with no filesystem access.
///
/// ## What is preserved
/// - Original drive/UNC prefix on Windows-style paths.
/// - Whether the input was absolute or relative (see [`Self::is_absolute`]).
/// - The exact normalized segments after resolving `.` and `..`.
///
/// ## What is rejected
/// - Null bytes or other control characters.
/// - Inputs that exceed [`MAX_PATH_LEN`].
/// - Paths whose `..` segments would escape their own root. The core layer has
///   no root to anchor against; the policy engine handles workspace-relative
///   traversal explicitly.
///
/// ## Symlink limitation
/// Lexical normalization does **not** protect against symlink traversal. A
/// symlink whose target lies outside the workspace cannot be detected here.
/// Filesystem-aware enforcement is a future layer.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(try_from = "&str", into = "String")]
pub struct NormalizedPath {
    raw: String,
    normalized: String,
    absolute: bool,
}

impl NormalizedPath {
    /// Construct a path from a raw input string, normalizing lexically.
    pub fn new(input: impl AsRef<str> + fmt::Display) -> Result<Self, PathError> {
        let s = input.as_ref();

        if s.is_empty() {
            return Err(PathError::from_kind(PathErrorKind::Empty, "empty path"));
        }
        if s.len() > MAX_PATH_LEN {
            return Err(PathError::from_kind(
                PathErrorKind::Oversized,
                "path exceeds maximum length",
            ));
        }
        if s.bytes()
            .any(|b| b == 0 || b.is_ascii_control() && b != b'\t')
        {
            return Err(PathError::from_kind(
                PathErrorKind::InvalidCharacter,
                "path contains null or control bytes",
            ));
        }

        let absolute = s.starts_with('/') || s.starts_with('\\') || has_drive_prefix(s);
        let normalized = normalize_lexical(s).ok_or_else(|| {
            PathError::from_kind(PathErrorKind::Escape, "path escapes its own root via '..'")
        })?;

        Ok(Self {
            raw: s.to_string(),
            normalized,
            absolute,
        })
    }

    /// The original, unmodified input string.
    pub fn raw(&self) -> &str {
        &self.raw
    }

    /// The lexical normalized form (forward-slash separated on all platforms).
    pub fn normalized(&self) -> &str {
        &self.normalized
    }

    /// Whether the original input was absolute.
    pub fn is_absolute(&self) -> bool {
        self.absolute
    }

    /// Whether the original input was relative.
    pub fn is_relative(&self) -> bool {
        !self.absolute
    }

    /// Returns the individual normalized segments (prefix excluded).
    ///
    /// For `C:/projects/kavach` returns `["projects", "kavach"]`.
    /// For `/usr/local/bin` returns `["usr", "local", "bin"]`.
    pub fn segments(&self) -> Vec<String> {
        let mut s = self.normalized.as_str();
        if let Some((_, rest)) = strip_known_prefix(s) {
            s = rest;
        }
        if let Some(rest) = s.strip_prefix('/') {
            s = rest;
        }
        s.split('/')
            .filter(|seg| !seg.is_empty())
            .map(str::to_string)
            .collect()
    }

    /// Re-validate every invariant of a possibly-deserialized value.
    ///
    /// The [`NormalizedPath`] serde impl routes through [`Self::new`], but
    /// future internal refactors or `#[serde(flatten)]` callers could assemble
    /// one from raw fields. Depth validation keeps the type trustworthy by
    /// re-checking emptiness, length, control bytes, absolute/relative marker
    /// consistency and that the stored normalized form actually corresponds to
    /// the stored raw form.
    pub(crate) fn validate_invariants(&self) -> Result<(), PathError> {
        if self.raw.is_empty() {
            return Err(PathError::from_kind(PathErrorKind::Empty, "empty path"));
        }
        if self.raw.len() > MAX_PATH_LEN {
            return Err(PathError::from_kind(
                PathErrorKind::Oversized,
                "path exceeds maximum length",
            ));
        }
        if self
            .raw
            .bytes()
            .any(|b| b == 0 || b.is_ascii_control() && b != b'\t')
        {
            return Err(PathError::from_kind(
                PathErrorKind::InvalidCharacter,
                "path contains null or control bytes",
            ));
        }
        let expected_absolute =
            self.raw.starts_with('/') || self.raw.starts_with('\\') || has_drive_prefix(&self.raw);
        if expected_absolute != self.absolute {
            return Err(PathError::from_kind(
                PathErrorKind::InvalidCharacter,
                "path absolute marker disagrees with raw form",
            ));
        }
        // The normalized field must be reproducible from raw; if someone has
        // deserialized a mismatched pair, reject it.
        let rederived = normalize_lexical(&self.raw).ok_or_else(|| {
            PathError::from_kind(PathErrorKind::Escape, "path escapes its own root via '..'")
        })?;
        if rederived != self.normalized {
            return Err(PathError::from_kind(
                PathErrorKind::InvalidValue,
                "normalized field does not match raw path",
            ));
        }
        Ok(())
    }
}

impl fmt::Display for NormalizedPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.normalized)
    }
}

impl FromStr for NormalizedPath {
    type Err = PathError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl TryFrom<&str> for NormalizedPath {
    type Error = PathError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl From<NormalizedPath> for String {
    fn from(p: NormalizedPath) -> String {
        p.raw
    }
}

/// Returns true if `s` begins with a Windows drive prefix such as `C:` or `c:/`.
fn has_drive_prefix(s: &str) -> bool {
    let bytes = s.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

/// Strip a recognized prefix (Windows drive, UNC `\\?\` or verbatim) from the
/// normalized path. Returns `(prefix_label, remainder_after_prefix)` so that
/// segmentation can proceed uniformly. The label is borrowed from `s` so the
/// exact drive letter is preserved.
fn strip_known_prefix(s: &str) -> Option<(&str, &str)> {
    let lower = s.to_ascii_lowercase();
    if lower.strip_prefix("\\\\?\\unc\\").is_some() {
        // The unc marker is 7 ASCII bytes: `\\?\UNC\`.
        let (label, rest) = s.split_at(7);
        return Some((label, rest));
    }
    if lower.strip_prefix("\\\\?\\").is_some() {
        // The verbatim marker is 4 ASCII bytes: `\\?\`.
        let (label, rest) = s.split_at(4);
        return Some((label, rest));
    }
    if has_drive_prefix(s) {
        // The drive prefix is exactly 2 ASCII bytes: `X:`.
        let (label, rest) = s.split_at(2);
        return Some((label, rest));
    }
    None
}

/// Lexically normalize a path: resolve `.` and `..`, collapse repeated
/// separators, output forward-slash separated segments. Returns `None` if
/// traversal would escape the path's own root.
pub(crate) fn normalize_lexical(input: &str) -> Option<String> {
    if let Some((label, rest)) = strip_known_prefix(input) {
        let body = normalize_body(rest)?;
        return Some(merge_prefix(label, &body));
    }

    let leading_slash = input.starts_with('/');
    let body = if leading_slash { &input[1..] } else { input };

    let normalized_body = normalize_body(body)?;
    if leading_slash {
        Some(format!("/{normalized_body}"))
    } else {
        Some(normalized_body)
    }
}

/// Normalize the body of a path after a prefix/root has been stripped.
fn normalize_body(body: &str) -> Option<String> {
    let mut segments: Vec<String> = Vec::new();
    for raw_seg in body.split(['/', '\\']) {
        let seg = raw_seg.trim_end_matches('\0');
        match seg {
            "" | "." => {}
            ".." => {
                // Escaping the root within core is not allowed.
                segments.pop()?;
            }
            other => segments.push(other.to_string()),
        }
    }
    Some(segments.join("/"))
}

/// Re-join a preserved prefix label with the normalized body, inserting a
/// forward-slash separator only when both halves need one.
fn merge_prefix(label: &str, body: &str) -> String {
    if body.is_empty() {
        return label.to_string();
    }
    let sep = if body.starts_with('/') || label.ends_with('\\') {
        ""
    } else {
        "/"
    };
    format!("{label}{sep}{body}")
}

/// A network scheme label, validated and lower-cased for stable comparison.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(try_from = "&str", into = "String")]
pub struct NetworkScheme(String);

impl NetworkScheme {
    /// Construct a network scheme, lower-cased and validated.
    pub fn new(value: impl AsRef<str> + fmt::Display) -> Result<Self, PathError> {
        let s = value.as_ref();
        if s.is_empty() {
            return Err(PathError::from_kind(
                PathErrorKind::InvalidEndpoint,
                "empty scheme",
            ));
        }
        if s.len() > 32 {
            return Err(PathError::from_kind(
                PathErrorKind::Oversized,
                "scheme exceeds maximum length",
            ));
        }
        if !s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.')
        {
            return Err(PathError::from_kind(
                PathErrorKind::InvalidCharacter,
                "scheme contains invalid characters",
            ));
        }
        Ok(Self(s.to_lowercase()))
    }

    /// The scheme, lower-cased.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for NetworkScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for NetworkScheme {
    type Err = PathError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl TryFrom<&str> for NetworkScheme {
    type Error = PathError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl From<NetworkScheme> for String {
    fn from(s: NetworkScheme) -> String {
        s.0
    }
}

/// A network host label, validated and lower-cased for stable comparison.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(try_from = "&str", into = "String")]
pub struct NetworkHost(String);

impl NetworkHost {
    /// Construct a network host label, lower-cased and validated.
    pub fn new(value: impl AsRef<str> + fmt::Display) -> Result<Self, PathError> {
        let s = value.as_ref();
        if s.is_empty() {
            return Err(PathError::from_kind(
                PathErrorKind::InvalidEndpoint,
                "empty host",
            ));
        }
        if s.len() > 255 {
            return Err(PathError::from_kind(
                PathErrorKind::Oversized,
                "host exceeds maximum length",
            ));
        }
        if !s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '_' | '[' | ']'))
        {
            return Err(PathError::from_kind(
                PathErrorKind::InvalidCharacter,
                "host contains invalid characters",
            ));
        }
        Ok(Self(s.to_lowercase()))
    }

    /// The host, lower-cased.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for NetworkHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for NetworkHost {
    type Err = PathError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl TryFrom<&str> for NetworkHost {
    type Error = PathError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl From<NetworkHost> for String {
    fn from(h: NetworkHost) -> String {
        h.0
    }
}

/// A validated TCP/UDP port number.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(try_from = "u16")]
pub struct NetworkPort(u16);

impl NetworkPort {
    /// Construct a validated port. `0` is allowed as a placeholder for "any
    /// port"; the policy engine treats it as a wildcard.
    pub fn new(value: u16) -> Self {
        Self(value)
    }

    /// The numeric port.
    pub fn value(&self) -> u16 {
        self.0
    }
}

impl TryFrom<u16> for NetworkPort {
    type Error = PathError;
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Ok(Self::new(value))
    }
}

impl From<NetworkPort> for u16 {
    fn from(p: NetworkPort) -> u16 {
        p.0
    }
}

/// A network endpoint resource: scheme, host, optional port and optional path.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NetworkResource {
    scheme: NetworkScheme,
    host: NetworkHost,
    port: Option<NetworkPort>,
    path: NormalizedPath,
}

impl NetworkResource {
    /// Construct a network endpoint resource from typed components.
    pub fn new(
        scheme: NetworkScheme,
        host: NetworkHost,
        port: Option<NetworkPort>,
        path: &str,
    ) -> Result<Self, PathError> {
        if path.is_empty() {
            return Err(PathError::from_kind(
                PathErrorKind::InvalidEndpoint,
                "empty path",
            ));
        }
        Ok(Self {
            scheme,
            host,
            port,
            path: NormalizedPath::new(path)?,
        })
    }

    /// Network scheme (for example `https`).
    pub fn scheme(&self) -> &NetworkScheme {
        &self.scheme
    }

    /// Network host.
    pub fn host(&self) -> &NetworkHost {
        &self.host
    }

    /// Optional network port.
    pub fn port(&self) -> Option<NetworkPort> {
        self.port
    }

    /// Path component, normalized.
    pub fn path(&self) -> &NormalizedPath {
        &self.path
    }

    /// Re-validate every invariant of a possibly-deserialized endpoint.
    pub(crate) fn validate_invariants(&self) -> Result<(), PathError> {
        // Each typed member already validates on construction; we re-run the
        // stored-form check on the path so that a tampered `raw` field (which
        // does not independently re-validate during serde) is caught here too.
        self.path.validate_invariants()
    }
}

/// A command resource, preserving executable and arguments separately.
///
/// The executable is stored separately from arguments so that policy can match
/// on the program being invoked without trusting a single shell string. A
/// complete shell command is never represented as one trusted string inside
/// KAVACH.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CommandResource {
    executable: String,
    arguments: Vec<String>,
}

impl CommandResource {
    /// Construct a command resource. The executable must be non-empty and not
    /// contain path separators used as a single shell token (the executable is
    /// not split). Arguments are stored verbatim, in order.
    pub fn new(executable: impl Into<String>, arguments: Vec<String>) -> Result<Self, PathError> {
        let exe = executable.into();
        if exe.is_empty() {
            return Err(PathError::from_kind(
                PathErrorKind::InvalidEndpoint,
                "empty executable",
            ));
        }
        if exe.len() > MAX_PATH_LEN {
            return Err(PathError::from_kind(
                PathErrorKind::Oversized,
                "executable exceeds maximum length",
            ));
        }
        if exe
            .bytes()
            .any(|b| b == 0 || b.is_ascii_control() && b != b'\t')
        {
            return Err(PathError::from_kind(
                PathErrorKind::InvalidCharacter,
                "executable contains null or control bytes",
            ));
        }
        for arg in &arguments {
            if arg.len() > MAX_PATH_LEN {
                return Err(PathError::from_kind(
                    PathErrorKind::Oversized,
                    "argument exceeds maximum length",
                ));
            }
            if arg
                .bytes()
                .any(|b| b == 0 || b.is_ascii_control() && b != b'\t')
            {
                return Err(PathError::from_kind(
                    PathErrorKind::InvalidCharacter,
                    "argument contains null or control bytes",
                ));
            }
        }
        Ok(Self {
            executable: exe,
            arguments,
        })
    }

    /// The executable program path or name.
    pub fn executable(&self) -> &str {
        &self.executable
    }

    /// The arguments, in order and verbatim.
    pub fn arguments(&self) -> &[String] {
        &self.arguments
    }

    /// Re-validate every invariant of a possibly-deserialized command.
    pub(crate) fn validate_invariants(&self) -> Result<(), PathError> {
        if self.executable.is_empty() {
            return Err(PathError::from_kind(
                PathErrorKind::InvalidEndpoint,
                "empty executable",
            ));
        }
        if self.executable.len() > MAX_PATH_LEN {
            return Err(PathError::from_kind(
                PathErrorKind::Oversized,
                "executable exceeds maximum length",
            ));
        }
        if self
            .executable
            .bytes()
            .any(|b| b == 0 || b.is_ascii_control() && b != b'\t')
        {
            return Err(PathError::from_kind(
                PathErrorKind::InvalidCharacter,
                "executable contains null or control bytes",
            ));
        }
        for arg in &self.arguments {
            if arg.len() > MAX_PATH_LEN {
                return Err(PathError::from_kind(
                    PathErrorKind::Oversized,
                    "argument exceeds maximum length",
                ));
            }
            if arg
                .bytes()
                .any(|b| b == 0 || b.is_ascii_control() && b != b'\t')
            {
                return Err(PathError::from_kind(
                    PathErrorKind::InvalidCharacter,
                    "argument contains null or control bytes",
                ));
            }
        }
        Ok(())
    }
}

/// A bounded metadata map with deterministic ordering (by key) for use in
/// [`crate::request::RequestContext`].
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct RequestMetadata(BTreeMap<String, String>);

impl RequestMetadata {
    /// Maximum supported number of metadata entries.
    pub const MAX_METADATA_ENTRIES: usize = 32;

    /// Construct an empty metadata map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert an entry, enforcing the maximum entry count and field length.
    pub fn insert(
        &mut self,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<(), PathError> {
        let key = key.into();
        let value = value.into();
        if key.is_empty() || key.len() > 128 {
            return Err(PathError::from_kind(
                PathErrorKind::Oversized,
                "metadata key invalid length",
            ));
        }
        if value.len() > MAX_PATH_LEN {
            return Err(PathError::from_kind(
                PathErrorKind::Oversized,
                "metadata value exceeds maximum length",
            ));
        }
        if !self.0.contains_key(&key) && self.0.len() + 1 > Self::MAX_METADATA_ENTRIES {
            return Err(PathError::from_kind(
                PathErrorKind::Oversized,
                "metadata exceeds maximum entries",
            ));
        }
        self.0.insert(key, value);
        Ok(())
    }

    /// Look up a value by key.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(String::as_str)
    }

    /// Number of stored entries.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the map is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Iterate entries in stable (key-sorted) order.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &String)> {
        self.0.iter()
    }

    /// Re-validate every invariant of a possibly-deserialized map.
    ///
    /// A map built by serde bypasses [`Self::insert`] and therefore the entry
    /// count cap and key/value length limits. Depth validation rejects such
    /// maps so the request envelope can remain fail-closed after a round-trip.
    pub(crate) fn validate_invariants(&self) -> Result<(), PathError> {
        if self.0.len() > Self::MAX_METADATA_ENTRIES {
            return Err(PathError::from_kind(
                PathErrorKind::Oversized,
                "metadata exceeds maximum entries",
            ));
        }
        for (key, value) in &self.0 {
            if key.is_empty() || key.len() > 128 {
                return Err(PathError::from_kind(
                    PathErrorKind::Oversized,
                    "metadata key invalid length",
                ));
            }
            if key.bytes().any(|b| b == 0 || b.is_ascii_control()) {
                return Err(PathError::from_kind(
                    PathErrorKind::InvalidCharacter,
                    "metadata key contains null or control bytes",
                ));
            }
            if value.len() > MAX_PATH_LEN {
                return Err(PathError::from_kind(
                    PathErrorKind::Oversized,
                    "metadata value exceeds maximum length",
                ));
            }
            if value
                .bytes()
                .any(|b| b == 0 || b.is_ascii_control() && b != b'\t')
            {
                return Err(PathError::from_kind(
                    PathErrorKind::InvalidCharacter,
                    "metadata value contains null or control bytes",
                ));
            }
        }
        Ok(())
    }
}

/// Kinds of protected resources considered by the policy engine.
///
/// `Unknown` exists to make "unknown resource" an explicit, fail-closed
/// variant rather than a silent fall-through.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    /// A single file on disk.
    File,
    /// A directory on disk.
    Directory,
    /// An executable command (with separated arguments).
    Command,
    /// A network endpoint reachable over a `scheme://host[:port]/path`.
    NetworkEndpoint,
    /// Reference to a stored secret.
    Secret,
    /// An external, non-KAVACH tool invoked by the agent.
    ExternalTool,
    /// Unrecognized resource type. Always denied by default.
    Unknown,
}

impl fmt::Display for ResourceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::File => "file",
            Self::Directory => "directory",
            Self::Command => "command",
            Self::NetworkEndpoint => "network_endpoint",
            Self::Secret => "secret",
            Self::ExternalTool => "external_tool",
            Self::Unknown => "unknown",
        };
        f.write_str(s)
    }
}

impl FromStr for ResourceKind {
    type Err = DomainError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "file" => Ok(Self::File),
            "directory" => Ok(Self::Directory),
            "command" => Ok(Self::Command),
            "network_endpoint" => Ok(Self::NetworkEndpoint),
            "secret" => Ok(Self::Secret),
            "external_tool" => Ok(Self::ExternalTool),
            "unknown" => Ok(Self::Unknown),
            other => Err(DomainError::new(
                DomainErrorKind::UnknownVariant,
                format!("unknown resource kind: {other}"),
            )),
        }
    }
}

/// The concrete resource targeted by a tool request, with its normalized path
/// data where applicable.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub enum Resource {
    /// A file target.
    File {
        /// Lexically normalized path.
        path: NormalizedPath,
    },
    /// A directory target.
    Directory {
        /// Lexically normalized path.
        path: NormalizedPath,
    },
    /// A command to execute.
    Command(CommandResource),
    /// A network endpoint.
    NetworkEndpoint(NetworkResource),
    /// Reference to a secret, by stable identifier.
    Secret {
        /// Stable non-secret identifier for the secret (never the secret value).
        identifier: String,
    },
    /// An external tool invocation.
    ExternalTool {
        /// Stable identifier for the external tool.
        identifier: String,
    },
    /// An unrecognized resource type. Always fails closed.
    Unknown,
}

impl Resource {
    /// Convenience factory for file resources.
    pub fn file(path: &str) -> Result<Self, PathError> {
        Ok(Self::File {
            path: NormalizedPath::new(path)?,
        })
    }

    /// Convenience factory for directory resources.
    pub fn directory(path: &str) -> Result<Self, PathError> {
        Ok(Self::Directory {
            path: NormalizedPath::new(path)?,
        })
    }

    /// Returns the [`ResourceKind`] discriminant for this resource.
    pub fn kind(&self) -> ResourceKind {
        match self {
            Self::File { .. } => ResourceKind::File,
            Self::Directory { .. } => ResourceKind::Directory,
            Self::Command(_) => ResourceKind::Command,
            Self::NetworkEndpoint(_) => ResourceKind::NetworkEndpoint,
            Self::Secret { .. } => ResourceKind::Secret,
            Self::ExternalTool { .. } => ResourceKind::ExternalTool,
            Self::Unknown => ResourceKind::Unknown,
        }
    }

    /// Returns the normalized path of a file or directory resource, if any.
    pub fn path(&self) -> Option<&NormalizedPath> {
        match self {
            Self::File { path } | Self::Directory { path } => Some(path),
            _ => None,
        }
    }

    /// Re-validate every invariant of a possibly-deserialized resource.
    ///
    /// The secret and external-tool identifiers are stored as plain
    /// [`String`] fields, so a serde round-trip could smuggle in an empty or
    /// control-laden identifier. This check rejects those and re-runs the
    /// stored-form validation for paths and commands.
    pub(crate) fn validate_invariants(&self) -> Result<(), PathError> {
        match self {
            Self::File { path } | Self::Directory { path } => path.validate_invariants(),
            Self::Command(cmd) => cmd.validate_invariants(),
            Self::NetworkEndpoint(net) => net.validate_invariants(),
            Self::Secret { identifier } | Self::ExternalTool { identifier } => {
                validate_secret_or_tool_identifier(identifier)
            }
            // Unknown resources fail closed at the policy layer; the core
            // invariant layer cannot know whether the caller intended them, so
            // it accepts the variant and lets the engine deny by default.
            Self::Unknown => Ok(()),
        }
    }
}

/// Bounds shared by [`Resource::Secret`] and [`Resource::ExternalTool`]
/// identifiers: non-empty, no null bytes, no control bytes, bounded length.
fn validate_secret_or_tool_identifier(identifier: &str) -> Result<(), PathError> {
    if identifier.is_empty() {
        return Err(PathError::from_kind(
            PathErrorKind::InvalidEndpoint,
            "empty identifier",
        ));
    }
    if identifier.len() > MAX_IDENTIFIER_LEN {
        return Err(PathError::from_kind(
            PathErrorKind::Oversized,
            "identifier exceeds maximum length",
        ));
    }
    if identifier
        .bytes()
        .any(|b| b == 0 || b.is_ascii_control() && b != b'\t')
    {
        return Err(PathError::from_kind(
            PathErrorKind::InvalidCharacter,
            "identifier contains null or control bytes",
        ));
    }
    Ok(())
}
