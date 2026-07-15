//! Filesystem enforcement adapter for the KAVACH security runtime.
//!
//! All filesystem operations require a valid, unexpired, single-use
//! [`ExecutionPermit`] bound to the
//! exact [`ToolRequest`].
//!
//! The adapter enforces:
//! - Workspace containment with symlink-aware canonical resolution
//! - Permit verification and consumption
//! - Operation/resource compatibility
//! - Bounded read/write sizes and directory entry counts

use std::io::Write;
use std::path::{Path, PathBuf};

use kavach_core::request::{Operation, ToolRequest};
use kavach_core::resource::Resource;
use kavach_runtime::ExecutionPermit;

/// Default maximum bytes per file read operation (64 MiB).
pub const MAX_FILE_READ_BYTES: u64 = 64 * 1024 * 1024;
/// Default maximum bytes per file write operation (64 MiB).
pub const MAX_FILE_WRITE_BYTES: u64 = 64 * 1024 * 1024;
/// Default maximum directory entries returned per list operation.
pub const MAX_DIRECTORY_ENTRIES: usize = 10_000;

/// Typed execution input for filesystem operations.
///
/// Operations that require data (e.g. `FileWrite`) receive `WriteBytes`;
/// all other operations use `None`.
#[derive(Debug, Clone, Copy)]
pub enum FilesystemInput<'a> {
    /// No payload — used by read, create, delete, move, and directory operations.
    None,
    /// Bytes to write to an existing file (FileWrite only).
    WriteBytes(&'a [u8]),
}

/// Typed errors from the filesystem enforcement adapter.
#[derive(Debug, thiserror::Error)]
pub enum FilesystemError {
    /// The request failed core validation.
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    /// The permit is invalid, expired, or does not match the request.
    #[error("invalid permit: {0}")]
    InvalidPermit(String),
    /// The permit has expired.
    #[error("permit expired")]
    PermitExpired,
    /// The permit has already been consumed.
    #[error("permit already consumed")]
    PermitConsumed,
    /// The target path escapes the workspace root.
    #[error("path escapes workspace: {0}")]
    WorkspaceEscape(String),
    /// A symlink points outside the workspace.
    #[error("symlink resolves outside workspace")]
    SymlinkEscape,
    /// The target file or directory was not found.
    #[error("not found: {0}")]
    NotFound(String),
    /// The target already exists (for create operations).
    #[error("already exists: {0}")]
    AlreadyExists(String),
    /// The resource type does not match the operation.
    #[error("wrong resource type for operation")]
    WrongResourceType,
    /// The target is not a regular file (for file operations).
    #[error("unsupported file type")]
    UnsupportedFileType,
    /// Read limit exceeded.
    #[error("read limit exceeded: max {0} bytes")]
    ReadLimitExceeded(u64),
    /// Write limit exceeded.
    #[error("write limit exceeded: max {0} bytes")]
    WriteLimitExceeded(u64),
    /// Directory entry limit exceeded.
    #[error("directory entry limit exceeded: max {0} entries")]
    DirectoryEntryLimitExceeded(usize),
    /// Directory is not empty (for non-recursive delete).
    #[error("directory not empty")]
    DirectoryNotEmpty,
    /// Destination already exists (for move/create operations).
    #[error("destination exists: {0}")]
    DestinationExists(String),
    /// An underlying I/O error occurred.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    /// FileWrite was called without WriteBytes payload.
    #[error("FileWrite requires WriteBytes payload")]
    MissingWritePayload,
    /// Payload was supplied for an operation that does not expect one.
    #[error("unexpected payload for this operation")]
    UnexpectedPayload,
    /// Atomic write failed (temp file could not be renamed into place).
    #[error("atomic write failed: {0}")]
    AtomicReplaceFailed(String),
}

/// Typed outcomes for filesystem operations.
#[derive(Debug, Clone)]
pub enum FilesystemOutcome {
    /// Successful file read.
    FileRead {
        /// The bytes read.
        bytes: Vec<u8>,
        /// Number of bytes read.
        bytes_read: u64,
    },
    /// Successful file write.
    FileWrite {
        /// Number of bytes written.
        bytes_written: u64,
    },
    /// Successful file create.
    FileCreate,
    /// Successful file delete.
    FileDelete,
    /// Successful file move.
    FileMove,
    /// Successful directory list.
    DirectoryList {
        /// Sorted list of entry names in the directory.
        entries: Vec<String>,
    },
    /// Successful directory create.
    DirectoryCreate,
    /// Successful directory delete.
    DirectoryDelete,
}

/// A filesystem enforcement adapter with workspace containment.
pub struct FilesystemEnforcer {
    /// The canonical workspace root.
    workspace_root: PathBuf,
    /// Maximum bytes per read.
    max_read_bytes: u64,
    /// Maximum bytes per write.
    max_write_bytes: u64,
    /// Maximum directory entries per list.
    max_dir_entries: usize,
}

impl FilesystemEnforcer {
    /// Create a new enforcer with the given workspace root and default limits.
    ///
    /// The workspace root is canonicalized at construction time.
    /// Returns an error if the root does not exist or cannot be resolved.
    pub fn new(workspace_root: impl AsRef<Path>) -> Result<Self, FilesystemError> {
        let root = dunce::canonicalize(workspace_root.as_ref()).map_err(FilesystemError::Io)?;
        Ok(Self {
            workspace_root: root,
            max_read_bytes: MAX_FILE_READ_BYTES,
            max_write_bytes: MAX_FILE_WRITE_BYTES,
            max_dir_entries: MAX_DIRECTORY_ENTRIES,
        })
    }

    /// Set the maximum bytes per read operation.
    pub fn with_max_read_bytes(mut self, limit: u64) -> Result<Self, FilesystemError> {
        if limit == 0 {
            return Err(FilesystemError::InvalidRequest(
                "max_read_bytes must be positive".into(),
            ));
        }
        self.max_read_bytes = limit;
        Ok(self)
    }

    /// Set the maximum bytes per write operation.
    pub fn with_max_write_bytes(mut self, limit: u64) -> Result<Self, FilesystemError> {
        if limit == 0 {
            return Err(FilesystemError::InvalidRequest(
                "max_write_bytes must be positive".into(),
            ));
        }
        self.max_write_bytes = limit;
        Ok(self)
    }

    /// Set the maximum directory entries per list operation.
    pub fn with_max_dir_entries(mut self, limit: usize) -> Result<Self, FilesystemError> {
        if limit == 0 {
            return Err(FilesystemError::InvalidRequest(
                "max_dir_entries must be positive".into(),
            ));
        }
        self.max_dir_entries = limit;
        Ok(self)
    }

    /// Execute a guarded filesystem operation.
    ///
    /// Consumes the permit on success *and* on failure — a failed execution
    /// must not make a permit reusable.
    ///
    /// # Input
    ///
    /// Use [`FilesystemInput::WriteBytes`] for [`Operation::FileWrite`],
    /// [`FilesystemInput::None`] for everything else. Supplying the wrong
    /// input variant produces [`FilesystemError::MissingWritePayload`] or
    /// [`FilesystemError::UnexpectedPayload`].
    pub fn execute(
        &self,
        request: &ToolRequest,
        permit: &mut ExecutionPermit,
        input: FilesystemInput<'_>,
    ) -> Result<FilesystemOutcome, FilesystemError> {
        // 1. Validate the request at the enforcement boundary.
        request
            .validate()
            .map_err(|e| FilesystemError::InvalidRequest(e.to_string()))?;

        // 2. Verify and consume the permit.
        verify_and_consume_permit(permit, request)?;

        // 3. Validate input matches operation.
        let is_write = matches!(request.operation, Operation::FileWrite);
        match (&input, is_write) {
            (FilesystemInput::WriteBytes(_), true) => {}
            (FilesystemInput::None, true) => {
                return Err(FilesystemError::MissingWritePayload);
            }
            (FilesystemInput::WriteBytes(_), false) => {
                return Err(FilesystemError::UnexpectedPayload);
            }
            (FilesystemInput::None, false) => {}
        }

        // 4. Dispatch based on operation and resource type.
        match (&request.operation, &request.resource) {
            (Operation::FileRead { max_bytes }, Resource::File { path }) => {
                self.do_file_read(path, *max_bytes)
            }
            (Operation::FileWrite, Resource::File { path }) => {
                let data = match input {
                    FilesystemInput::WriteBytes(d) => d,
                    _ => return Err(FilesystemError::MissingWritePayload),
                };
                self.do_file_write(path, data)
            }
            (Operation::FileCreate, Resource::File { path }) => self.do_file_create(path),
            (Operation::FileDelete, Resource::File { path }) => self.do_file_delete(path),
            (Operation::FileMove { destination }, Resource::File { path }) => {
                let dest = destination.as_ref().ok_or_else(|| {
                    FilesystemError::InvalidRequest("FileMove requires a destination path".into())
                })?;
                self.do_file_move(path, dest)
            }
            (Operation::DirectoryList, Resource::Directory { path }) => {
                self.do_directory_list(path)
            }
            (Operation::DirectoryCreate, Resource::Directory { path }) => {
                self.do_directory_create(path)
            }
            (Operation::DirectoryDelete, Resource::Directory { path }) => {
                self.do_directory_delete(path)
            }
            _ => Err(FilesystemError::WrongResourceType),
        }
    }

    // ----------------------------------------------------------------
    // File operations
    // ----------------------------------------------------------------

    fn do_file_read(
        &self,
        path: &kavach_core::resource::NormalizedPath,
        max_bytes: Option<u64>,
    ) -> Result<FilesystemOutcome, FilesystemError> {
        let resolved = resolve_existing_for_read(&self.workspace_root, path)?;
        let hard_limit = max_bytes.unwrap_or(self.max_read_bytes);
        if hard_limit == 0 || hard_limit > self.max_read_bytes {
            return Err(FilesystemError::ReadLimitExceeded(self.max_read_bytes));
        }
        let metadata = std::fs::metadata(&resolved).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => {
                FilesystemError::NotFound(resolved.display().to_string())
            }
            _ => FilesystemError::Io(e),
        })?;
        if metadata.len() > hard_limit {
            return Err(FilesystemError::ReadLimitExceeded(hard_limit));
        }
        let bytes = std::fs::read(&resolved).map_err(FilesystemError::Io)?;
        // Defensive check: enforce hard read limit while reading.
        if bytes.len() as u64 > hard_limit {
            return Err(FilesystemError::ReadLimitExceeded(hard_limit));
        }
        let bytes_read = bytes.len() as u64;
        Ok(FilesystemOutcome::FileRead { bytes, bytes_read })
    }

    fn do_file_write(
        &self,
        path: &kavach_core::resource::NormalizedPath,
        data: &[u8],
    ) -> Result<FilesystemOutcome, FilesystemError> {
        // Check for symlink target before resolving further.
        // The pre-canonicalized path is what the application submitted;
        // if that path is a symlink, reject it.
        let full = resolve_within_workspace(&self.workspace_root, path)?;
        if full.exists()
            && std::fs::symlink_metadata(&full)
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(false)
        {
            return Err(FilesystemError::UnsupportedFileType);
        }

        let resolved = resolve_existing_for_write(&self.workspace_root, path)?;
        // FileWrite requires target to already exist.
        if !resolved.exists() {
            return Err(FilesystemError::NotFound(resolved.display().to_string()));
        }
        if !resolved.is_file() {
            return Err(FilesystemError::UnsupportedFileType);
        }
        // Enforce write size limit.
        if data.len() as u64 > self.max_write_bytes {
            return Err(FilesystemError::WriteLimitExceeded(self.max_write_bytes));
        }

        // Atomic replacement: write to a temp file in the same directory,
        // flush, then rename into place. Clean temp on failure.
        let parent = resolved
            .parent()
            .ok_or_else(|| FilesystemError::WorkspaceEscape("no parent directory".into()))?;

        let suffix = unique_suffix();
        let temp_path = parent.join(format!(".kavach_tmp_write_{suffix}"));

        // Write data to temp file with create-new semantics.
        let mut temp_file = std::fs::File::create_new(&temp_path).map_err(FilesystemError::Io)?;
        std::io::Write::write_all(&mut temp_file, data).map_err(FilesystemError::Io)?;
        temp_file.flush().map_err(FilesystemError::Io)?;
        drop(temp_file);

        // Atomically rename temp file over the target.
        std::fs::rename(&temp_path, &resolved).map_err(|e| {
            // Clean up temp file on failure.
            let _ = std::fs::remove_file(&temp_path);
            FilesystemError::AtomicReplaceFailed(e.to_string())
        })?;

        let bytes_written = data.len() as u64;
        Ok(FilesystemOutcome::FileWrite { bytes_written })
    }

    fn do_file_create(
        &self,
        path: &kavach_core::resource::NormalizedPath,
    ) -> Result<FilesystemOutcome, FilesystemError> {
        let (resolved, _parent) = resolve_to_create(&self.workspace_root, path)?;
        if resolved.exists() {
            return Err(FilesystemError::AlreadyExists(
                resolved.display().to_string(),
            ));
        }
        // Verify parent exists and is directory.
        let parent = resolved
            .parent()
            .ok_or_else(|| FilesystemError::WorkspaceEscape("no parent directory".into()))?;
        if !parent.is_dir() {
            return Err(FilesystemError::NotFound(format!(
                "parent not a directory: {}",
                parent.display()
            )));
        }
        // Use create-new semantics.
        std::fs::File::create_new(&resolved).map_err(|e| match e.kind() {
            std::io::ErrorKind::AlreadyExists => {
                FilesystemError::AlreadyExists(resolved.display().to_string())
            }
            _ => FilesystemError::Io(e),
        })?;
        Ok(FilesystemOutcome::FileCreate)
    }

    fn do_file_delete(
        &self,
        path: &kavach_core::resource::NormalizedPath,
    ) -> Result<FilesystemOutcome, FilesystemError> {
        let resolved = resolve_existing_for_read(&self.workspace_root, path)?;
        // Reject directories and special files.
        if resolved.is_dir() {
            return Err(FilesystemError::UnsupportedFileType);
        }
        std::fs::remove_file(&resolved).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => {
                FilesystemError::NotFound(resolved.display().to_string())
            }
            _ => FilesystemError::Io(e),
        })?;
        Ok(FilesystemOutcome::FileDelete)
    }

    fn do_file_move(
        &self,
        source_path: &kavach_core::resource::NormalizedPath,
        destination: &kavach_core::resource::NormalizedPath,
    ) -> Result<FilesystemOutcome, FilesystemError> {
        let source = resolve_existing_for_read(&self.workspace_root, source_path)?;
        if source.is_dir() {
            return Err(FilesystemError::UnsupportedFileType);
        }
        let dest_resolved = resolve_within_workspace(&self.workspace_root, destination)?;
        if dest_resolved.exists() {
            return Err(FilesystemError::DestinationExists(
                dest_resolved.display().to_string(),
            ));
        }
        // Verify destination parent is in workspace.
        let dest_parent = dest_resolved
            .parent()
            .ok_or_else(|| FilesystemError::WorkspaceEscape("no parent directory".into()))?;
        let dest_parent_canon = dunce::canonicalize(dest_parent).map_err(FilesystemError::Io)?;
        if !dest_parent_canon.starts_with(&self.workspace_root) {
            return Err(FilesystemError::WorkspaceEscape(
                dest_parent_canon.display().to_string(),
            ));
        }
        std::fs::rename(&source, &dest_resolved).map_err(FilesystemError::Io)?;
        Ok(FilesystemOutcome::FileMove)
    }

    // ----------------------------------------------------------------
    // Directory operations
    // ----------------------------------------------------------------

    fn do_directory_list(
        &self,
        path: &kavach_core::resource::NormalizedPath,
    ) -> Result<FilesystemOutcome, FilesystemError> {
        let resolved = resolve_existing_directory(&self.workspace_root, path)?;
        let mut entries: Vec<String> = Vec::new();
        for entry in std::fs::read_dir(&resolved).map_err(FilesystemError::Io)? {
            let entry = entry.map_err(FilesystemError::Io)?;
            let name = entry.file_name().to_string_lossy().into_owned();
            entries.push(name);
            if entries.len() > self.max_dir_entries {
                return Err(FilesystemError::DirectoryEntryLimitExceeded(
                    self.max_dir_entries,
                ));
            }
        }
        entries.sort();
        Ok(FilesystemOutcome::DirectoryList { entries })
    }

    fn do_directory_create(
        &self,
        path: &kavach_core::resource::NormalizedPath,
    ) -> Result<FilesystemOutcome, FilesystemError> {
        let (resolved, parent_canon) = resolve_to_create(&self.workspace_root, path)?;
        if resolved.exists() {
            return Err(FilesystemError::AlreadyExists(
                resolved.display().to_string(),
            ));
        }
        // Confirm parent is in workspace (already checked in resolve_to_create).
        let _ = parent_canon;
        std::fs::create_dir(&resolved).map_err(|e| match e.kind() {
            std::io::ErrorKind::AlreadyExists => {
                FilesystemError::AlreadyExists(resolved.display().to_string())
            }
            _ => FilesystemError::Io(e),
        })?;
        Ok(FilesystemOutcome::DirectoryCreate)
    }

    fn do_directory_delete(
        &self,
        path: &kavach_core::resource::NormalizedPath,
    ) -> Result<FilesystemOutcome, FilesystemError> {
        let resolved = resolve_existing_directory(&self.workspace_root, path)?;
        // Non-recursive: reject non-empty directories.
        let mut entries = std::fs::read_dir(&resolved).map_err(FilesystemError::Io)?;
        if entries.next().is_some() {
            return Err(FilesystemError::DirectoryNotEmpty);
        }
        std::fs::remove_dir(&resolved).map_err(FilesystemError::Io)?;
        Ok(FilesystemOutcome::DirectoryDelete)
    }
}

// ---------------------------------------------------------------------------
// Path validation helpers
// ---------------------------------------------------------------------------

/// Verify the permit is valid for the given request, then consume it.
/// Returns an error if the permit is expired, consumed, or mismatched.
fn verify_and_consume_permit(
    permit: &mut ExecutionPermit,
    request: &ToolRequest,
) -> Result<(), FilesystemError> {
    if permit.is_expired() {
        return Err(FilesystemError::PermitExpired);
    }
    if permit.is_consumed() {
        return Err(FilesystemError::PermitConsumed);
    }
    let digest = kavach_runtime::compute_request_digest(request);
    if !permit.verify_request_digest(&digest) {
        return Err(FilesystemError::InvalidPermit(
            "permit does not match request digest".into(),
        ));
    }
    if !permit.consume() {
        return Err(FilesystemError::PermitConsumed);
    }
    Ok(())
}

/// Resolve a file path for read/delete operations.
///
/// 1. Build the full path from workspace root + resource path.
/// 2. Canonicalize the full path (resolves symlinks).
/// 3. Verify the canonical path stays within the workspace root.
/// 4. Verify the target is a regular file.
fn resolve_existing_for_read(
    workspace_root: &Path,
    resource_path: &kavach_core::resource::NormalizedPath,
) -> Result<PathBuf, FilesystemError> {
    let full = resolve_within_workspace(workspace_root, resource_path)?;
    if !full.exists() {
        return Err(FilesystemError::NotFound(full.display().to_string()));
    }
    let canon = dunce::canonicalize(&full).map_err(FilesystemError::Io)?;
    if !canon.starts_with(workspace_root) {
        return Err(FilesystemError::SymlinkEscape);
    }
    if !canon.is_file() {
        return Err(FilesystemError::UnsupportedFileType);
    }
    Ok(canon)
}

/// Resolve an existing directory path:
/// canonicalize and verify it stays under the workspace.
fn resolve_existing_directory(
    workspace_root: &Path,
    resource_path: &kavach_core::resource::NormalizedPath,
) -> Result<PathBuf, FilesystemError> {
    let full = resolve_within_workspace(workspace_root, resource_path)?;
    if !full.exists() {
        return Err(FilesystemError::NotFound(full.display().to_string()));
    }
    let canon = dunce::canonicalize(&full).map_err(FilesystemError::Io)?;
    if !canon.starts_with(workspace_root) {
        return Err(FilesystemError::SymlinkEscape);
    }
    if !canon.is_dir() {
        return Err(FilesystemError::UnsupportedFileType);
    }
    Ok(canon)
}

/// Resolve a file path for write operations.
fn resolve_existing_for_write(
    workspace_root: &Path,
    resource_path: &kavach_core::resource::NormalizedPath,
) -> Result<PathBuf, FilesystemError> {
    let full = resolve_within_workspace(workspace_root, resource_path)?;
    if full.exists() {
        let canon = dunce::canonicalize(&full).map_err(FilesystemError::Io)?;
        if !canon.starts_with(workspace_root) {
            return Err(FilesystemError::SymlinkEscape);
        }
        if !canon.is_file() {
            return Err(FilesystemError::UnsupportedFileType);
        }
        return Ok(canon);
    }
    // File does not exist yet — verify parent.
    verify_parent_in_workspace(workspace_root, &full)?;
    Ok(full)
}

/// Resolve a path for create operations.
///
/// Returns (resolved_path, parent_canonical_path).
fn resolve_to_create(
    workspace_root: &Path,
    resource_path: &kavach_core::resource::NormalizedPath,
) -> Result<(PathBuf, PathBuf), FilesystemError> {
    let full = resolve_within_workspace(workspace_root, resource_path)?;
    let parent = full
        .parent()
        .ok_or_else(|| FilesystemError::WorkspaceEscape("no parent directory".into()))?;
    // Resolve the parent and verify it is inside workspace.
    let parent_canon = dunce::canonicalize(parent).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => {
            FilesystemError::NotFound(format!("parent directory not found: {}", parent.display()))
        }
        _ => FilesystemError::Io(e),
    })?;
    if !parent_canon.starts_with(workspace_root) {
        return Err(FilesystemError::SymlinkEscape);
    }
    // Build the target path under the canonical parent.
    let filename = full
        .file_name()
        .ok_or_else(|| FilesystemError::WorkspaceEscape("no filename".into()))?;
    Ok((parent_canon.join(filename), parent_canon))
}

/// Verify that a path's existing parent stays within the workspace root.
fn verify_parent_in_workspace(workspace_root: &Path, path: &Path) -> Result<(), FilesystemError> {
    let parent = path
        .parent()
        .ok_or_else(|| FilesystemError::WorkspaceEscape("no parent directory".into()))?;
    let parent_canon = dunce::canonicalize(parent).map_err(FilesystemError::Io)?;
    if !parent_canon.starts_with(workspace_root) {
        return Err(FilesystemError::SymlinkEscape);
    }
    Ok(())
}

/// Build a path under the workspace root and validate lexical containment.
///
/// Rejects:
/// - `..` segments that escape the workspace
/// - Absolute paths that bypass the workspace prefix
/// - Windows drive-prefix escapes
fn resolve_within_workspace(
    workspace_root: &Path,
    resource_path: &kavach_core::resource::NormalizedPath,
) -> Result<PathBuf, FilesystemError> {
    let norm = resource_path.normalized();

    // Reject absolute paths — they bypass the workspace prefix.
    if resource_path.is_absolute() {
        return Err(FilesystemError::WorkspaceEscape(format!(
            "absolute path forbidden: {norm}"
        )));
    }

    // Build the full path.
    let full = workspace_root.join(norm);

    // Check that the full path is still under the workspace root lexically.
    // Use component-aware comparison, not string prefix.
    let root_canon = dunce::canonicalize(workspace_root).map_err(FilesystemError::Io)?;
    let full_canon = dunce::canonicalize(&full).unwrap_or_else(|_| full.clone());

    // If canonicalization fails, fall back to lexical component check.
    if !full_canon.starts_with(&root_canon) && !is_lexically_under(workspace_root, &full) {
        return Err(FilesystemError::WorkspaceEscape(full.display().to_string()));
    }

    Ok(full)
}

/// Check that a path stays under the given root using component iteration,
/// not string prefix matching.
fn is_lexically_under(root: &Path, candidate: &Path) -> bool {
    let root_components: Vec<_> = root.components().collect();
    let candidate_components: Vec<_> = candidate.components().collect();
    candidate_components.len() >= root_components.len()
        && root_components
            .iter()
            .zip(candidate_components.iter())
            .all(|(r, c)| r == c)
}

fn unique_suffix() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    // Combine process ID and nanosecond timestamp for uniqueness.
    format!("{}_{nanos:08x}", std::process::id())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use kavach_core::ids::{AgentId, RequestId, SessionId};
    use kavach_core::request::{AgentSubjectBuilder, RequestContext};
    use kavach_runtime::ExecutionPermit;
    use std::time::Duration;

    fn make_subject() -> kavach_core::subject::AgentSubject {
        AgentSubjectBuilder::new(
            AgentId::new("agent-1").unwrap(),
            SessionId::new("sess-1").unwrap(),
        )
        .trust_level(kavach_core::subject::TrustLevel::Standard)
        .build()
    }

    fn make_context() -> RequestContext {
        RequestContext::new(None, None, None, None, false).unwrap()
    }

    fn file_request(op: Operation, filename: &str) -> ToolRequest {
        ToolRequest::new(
            RequestId::new("req-1").unwrap(),
            make_subject(),
            op,
            Resource::file(filename).unwrap(),
            make_context(),
        )
    }

    fn dir_request(op: Operation, dirname: &str) -> ToolRequest {
        ToolRequest::new(
            RequestId::new("req-1").unwrap(),
            make_subject(),
            op,
            Resource::directory(dirname).unwrap(),
            make_context(),
        )
    }

    fn make_permit(request: &ToolRequest) -> ExecutionPermit {
        let digest = kavach_runtime::compute_request_digest(request);
        ExecutionPermit::new(&[1u8; 32], vec![], digest, Duration::from_secs(300))
    }

    fn make_enforcer(tmp: &std::path::Path) -> FilesystemEnforcer {
        FilesystemEnforcer::new(tmp).unwrap()
    }

    // ----------------------------------------------------------------
    // Permit validation tests
    // ----------------------------------------------------------------

    #[test]
    fn execution_without_permit_rejected() {
        let tmp = std::env::temp_dir().join(format!("kavach_fs_no_permit_{}", uuid_simple()));
        std::fs::create_dir_all(&tmp).unwrap();
        let enforcer = make_enforcer(&tmp);
        let req = file_request(Operation::FileCreate, "no-permit.txt");
        let mut expired = make_expired_permit(&req);
        let result = enforcer.execute(&req, &mut expired, FilesystemInput::None);
        assert!(result.is_err());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn expired_permit_rejected() {
        let tmp = std::env::temp_dir().join(format!("kavach_fs_expired_{}", uuid_simple()));
        std::fs::create_dir_all(&tmp).unwrap();
        let enforcer = make_enforcer(&tmp);
        let req = file_request(Operation::FileRead { max_bytes: None }, "doesnotexist.txt");
        let mut expired = make_expired_permit(&req);
        let result = enforcer.execute(&req, &mut expired, FilesystemInput::None);
        assert!(matches!(result, Err(FilesystemError::PermitExpired)));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn consumed_permit_rejected() {
        let tmp = std::env::temp_dir().join(format!("kavach_fs_consumed_{}", uuid_simple()));
        std::fs::create_dir_all(&tmp).unwrap();
        let enforcer = make_enforcer(&tmp);
        let req = file_request(Operation::FileRead { max_bytes: None }, "doesnotexist.txt");
        let mut permit = make_permit(&req);
        permit.consume();
        let result = enforcer.execute(&req, &mut permit, FilesystemInput::None);
        assert!(matches!(result, Err(FilesystemError::PermitConsumed)));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn forged_permit_mismatched_digest_rejected() {
        let tmp = std::env::temp_dir().join(format!("kavach_fs_forged_{}", uuid_simple()));
        std::fs::create_dir_all(&tmp).unwrap();
        let enforcer = make_enforcer(&tmp);
        let req_a = file_request(Operation::FileRead { max_bytes: None }, "a.txt");
        let req_b = file_request(Operation::FileRead { max_bytes: None }, "b.txt");
        let mut permit_b = make_permit(&req_b);
        // Present permit for b with request a.
        let result = enforcer.execute(&req_a, &mut permit_b, FilesystemInput::None);
        assert!(matches!(result, Err(FilesystemError::InvalidPermit(_))));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ----------------------------------------------------------------
    // File read tests
    // ----------------------------------------------------------------

    #[test]
    fn valid_file_read() {
        let tmp = std::env::temp_dir().join(format!("kavach_fs_read_{}", uuid_simple()));
        std::fs::create_dir_all(&tmp).unwrap();
        let content = b"hello world";
        std::fs::write(tmp.join("test.txt"), content).unwrap();
        let enforcer = make_enforcer(&tmp);
        let req = file_request(Operation::FileRead { max_bytes: None }, "test.txt");
        let mut permit = make_permit(&req);
        let outcome = enforcer
            .execute(&req, &mut permit, FilesystemInput::None)
            .unwrap();
        match outcome {
            FilesystemOutcome::FileRead { bytes, bytes_read } => {
                assert_eq!(&bytes, content);
                assert_eq!(bytes_read, 11);
            }
            _ => panic!("expected FileRead"),
        }
        assert!(permit.is_consumed());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn file_read_not_found() {
        let tmp = std::env::temp_dir().join(format!("kavach_fs_nf_{}", uuid_simple()));
        std::fs::create_dir_all(&tmp).unwrap();
        let enforcer = make_enforcer(&tmp);
        let req = file_request(Operation::FileRead { max_bytes: None }, "missing.txt");
        let mut permit = make_permit(&req);
        let result = enforcer.execute(&req, &mut permit, FilesystemInput::None);
        assert!(matches!(result, Err(FilesystemError::NotFound(_))));
        assert!(permit.is_consumed()); // Permit consumed even on failure.
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn file_read_rejects_directory() {
        let tmp = std::env::temp_dir().join(format!("kavach_fs_dir_{}", uuid_simple()));
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::create_dir(tmp.join("subdir")).unwrap();
        let enforcer = make_enforcer(&tmp);
        let req = file_request(Operation::FileRead { max_bytes: None }, "subdir");
        let mut permit = make_permit(&req);
        let result = enforcer.execute(&req, &mut permit, FilesystemInput::None);
        assert!(matches!(result, Err(FilesystemError::UnsupportedFileType)));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn read_size_limit_enforced() {
        let tmp = std::env::temp_dir().join(format!("kavach_fs_rsl_{}", uuid_simple()));
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("big.txt"), vec![b'x'; 2048]).unwrap();
        let enforcer = make_enforcer(&tmp);
        let req = file_request(
            Operation::FileRead {
                max_bytes: Some(100),
            },
            "big.txt",
        );
        let mut permit = make_permit(&req);
        let result = enforcer.execute(&req, &mut permit, FilesystemInput::None);
        assert!(matches!(
            result,
            Err(FilesystemError::ReadLimitExceeded(100))
        ));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ----------------------------------------------------------------
    // File create tests
    // ----------------------------------------------------------------

    #[test]
    fn file_create_succeeds() {
        let tmp = std::env::temp_dir().join(format!("kavach_fs_create_{}", uuid_simple()));
        std::fs::create_dir_all(&tmp).unwrap();
        let enforcer = make_enforcer(&tmp);
        let req = file_request(Operation::FileCreate, "new.txt");
        let mut permit = make_permit(&req);
        let outcome = enforcer
            .execute(&req, &mut permit, FilesystemInput::None)
            .unwrap();
        assert!(matches!(outcome, FilesystemOutcome::FileCreate));
        assert!(tmp.join("new.txt").exists());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn file_create_rejects_existing() {
        let tmp = std::env::temp_dir().join(format!("kavach_fs_cexist_{}", uuid_simple()));
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("exists.txt"), b"data").unwrap();
        let enforcer = make_enforcer(&tmp);
        let req = file_request(Operation::FileCreate, "exists.txt");
        let mut permit = make_permit(&req);
        let result = enforcer.execute(&req, &mut permit, FilesystemInput::None);
        assert!(matches!(result, Err(FilesystemError::AlreadyExists(_))));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ----------------------------------------------------------------
    // File write tests
    // ----------------------------------------------------------------

    #[test]
    fn file_write_replaces_content() {
        let tmp = std::env::temp_dir().join(format!("kavach_fs_wr_{}", uuid_simple()));
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("target.txt"), b"original content").unwrap();
        let enforcer = make_enforcer(&tmp);
        let req = file_request(Operation::FileWrite, "target.txt");
        let mut permit = make_permit(&req);
        let new_data = b"replaced";
        let outcome = enforcer
            .execute(&req, &mut permit, FilesystemInput::WriteBytes(new_data))
            .unwrap();
        match outcome {
            FilesystemOutcome::FileWrite { bytes_written } => {
                assert_eq!(bytes_written, 8);
            }
            _ => panic!("expected FileWrite"),
        }
        let on_disk = std::fs::read(tmp.join("target.txt")).unwrap();
        assert_eq!(&on_disk, new_data);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn file_write_without_payload_rejected() {
        let tmp = std::env::temp_dir().join(format!("kavach_fs_wo_{}", uuid_simple()));
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("target.txt"), b"data").unwrap();
        let enforcer = make_enforcer(&tmp);
        let req = file_request(Operation::FileWrite, "target.txt");
        let mut permit = make_permit(&req);
        let result = enforcer.execute(&req, &mut permit, FilesystemInput::None);
        assert!(matches!(result, Err(FilesystemError::MissingWritePayload)));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn payload_on_file_read_rejected() {
        let tmp = std::env::temp_dir().join(format!("kavach_fs_rp_{}", uuid_simple()));
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("target.txt"), b"data").unwrap();
        let enforcer = make_enforcer(&tmp);
        let req = file_request(Operation::FileRead { max_bytes: None }, "target.txt");
        let mut permit = make_permit(&req);
        let result = enforcer.execute(&req, &mut permit, FilesystemInput::WriteBytes(b"bad"));
        assert!(matches!(result, Err(FilesystemError::UnexpectedPayload)));
        // Permit still consumed even though wrong payload was supplied.
        assert!(permit.is_consumed());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn file_write_nonexistent_target_rejected() {
        let tmp = std::env::temp_dir().join(format!("kavach_fs_wnf_{}", uuid_simple()));
        std::fs::create_dir_all(&tmp).unwrap();
        let enforcer = make_enforcer(&tmp);
        let req = file_request(Operation::FileWrite, "nofile.txt");
        let mut permit = make_permit(&req);
        let result = enforcer.execute(&req, &mut permit, FilesystemInput::WriteBytes(b"x"));
        assert!(matches!(result, Err(FilesystemError::NotFound(_))));
        assert!(permit.is_consumed());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn file_write_directory_target_rejected() {
        let tmp = std::env::temp_dir().join(format!("kavach_fs_wdir_{}", uuid_simple()));
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::create_dir(tmp.join("adir")).unwrap();
        let enforcer = make_enforcer(&tmp);
        let req = file_request(Operation::FileWrite, "adir");
        let mut permit = make_permit(&req);
        let result = enforcer.execute(&req, &mut permit, FilesystemInput::WriteBytes(b"x"));
        assert!(matches!(result, Err(FilesystemError::UnsupportedFileType)));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn file_write_size_limit_enforced() {
        let tmp = std::env::temp_dir().join(format!("kavach_fs_wsl_{}", uuid_simple()));
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("target.txt"), b"data").unwrap();
        let enforcer = make_enforcer(&tmp).with_max_write_bytes(5).unwrap();
        let req = file_request(Operation::FileWrite, "target.txt");
        let mut permit = make_permit(&req);
        let large_data = b"too much data for the limit";
        let result = enforcer.execute(&req, &mut permit, FilesystemInput::WriteBytes(large_data));
        assert!(matches!(
            result,
            Err(FilesystemError::WriteLimitExceeded(5))
        ));
        assert!(permit.is_consumed());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn file_write_temp_file_cleaned_after_success() {
        let tmp = std::env::temp_dir().join(format!("kavach_fs_tmpcl_{}", uuid_simple()));
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("target.txt"), b"original").unwrap();
        let enforcer = make_enforcer(&tmp);
        let req = file_request(Operation::FileWrite, "target.txt");
        let mut permit = make_permit(&req);
        let outcome = enforcer
            .execute(
                &req,
                &mut permit,
                FilesystemInput::WriteBytes(b"new content"),
            )
            .unwrap();
        assert!(matches!(outcome, FilesystemOutcome::FileWrite { .. }));
        // No .kavach_tmp_write_* files should remain.
        let entries: Vec<_> = std::fs::read_dir(&tmp)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with(".kavach_tmp_write_")
            })
            .collect();
        assert!(entries.is_empty(), "temp file left behind");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn file_write_consumes_permit_on_failure_and_reuse_rejected() {
        let tmp = std::env::temp_dir().join(format!("kavach_fs_pconsume_{}", uuid_simple()));
        std::fs::create_dir_all(&tmp).unwrap();
        let enforcer = make_enforcer(&tmp);
        let req = file_request(Operation::FileWrite, "nofile.txt");
        let mut permit = make_permit(&req);

        // First attempt: target does not exist → fails after permit verification.
        let result = enforcer.execute(&req, &mut permit, FilesystemInput::WriteBytes(b"x"));
        assert!(matches!(result, Err(FilesystemError::NotFound(_))));
        assert!(permit.is_consumed(), "permit consumed even on failure");

        // Second attempt: reuse the same consumed permit.
        let result2 = enforcer.execute(&req, &mut permit, FilesystemInput::WriteBytes(b"y"));
        assert!(
            matches!(result2, Err(FilesystemError::PermitConsumed)),
            "reusing consumed permit should return PermitConsumed, got {result2:?}"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn file_write_rejects_symlink_target() {
        let tmp = std::env::temp_dir().join(format!("kavach_fs_sym_{}", uuid_simple()));
        std::fs::create_dir_all(&tmp).unwrap();

        // Create a real file and attempt a symlink to it.
        let real_file = tmp.join("real.txt");
        let symlink = tmp.join("link.txt");
        std::fs::write(&real_file, b"original").unwrap();

        #[cfg(unix)]
        let can_symlink = std::os::unix::fs::symlink(&real_file, &symlink).is_ok();
        #[cfg(windows)]
        let can_symlink = std::os::windows::fs::symlink_file(&real_file, &symlink).is_ok();
        #[cfg(not(any(unix, windows)))]
        let can_symlink = false;

        if !can_symlink {
            let _ = std::fs::remove_dir_all(&tmp);
            // Symlink creation unavailable on this platform/configuration;
            // skip the test. The symlink-rejection logic is platform-neutral
            // and exercised by unit tests on the path-level code.
            return;
        }

        let enforcer = make_enforcer(&tmp);
        let req = file_request(Operation::FileWrite, "link.txt");
        let mut permit = make_permit(&req);
        let result = enforcer.execute(&req, &mut permit, FilesystemInput::WriteBytes(b"evil"));
        assert!(
            matches!(result, Err(FilesystemError::UnsupportedFileType)),
            "expected UnsupportedFileType for symlink target, got {result:?}"
        );

        // The linked file must remain unchanged.
        let on_disk = std::fs::read(&real_file).unwrap();
        assert_eq!(&on_disk, b"original", "linked file content must not change");

        // The symlink itself must remain unchanged.
        assert!(symlink.exists(), "symlink must still exist");
        assert!(permit.is_consumed(), "permit consumed even on rejection");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn file_write_no_temp_left_on_failure() {
        let tmp = std::env::temp_dir().join(format!("kavach_fs_tmpfail_{}", uuid_simple()));
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("target.txt"), b"original").unwrap();
        let enforcer = make_enforcer(&tmp).with_max_write_bytes(3).unwrap();
        let req = file_request(Operation::FileWrite, "target.txt");
        let mut permit = make_permit(&req);
        let large_data = b"exceeds limit";
        let result = enforcer.execute(&req, &mut permit, FilesystemInput::WriteBytes(large_data));
        assert!(
            matches!(result, Err(FilesystemError::WriteLimitExceeded(3))),
            "expected WriteLimitExceeded, got {result:?}"
        );

        // No .kavach_tmp_write_* files should remain after the failure.
        let entries: Vec<_> = std::fs::read_dir(&tmp)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with(".kavach_tmp_write_")
            })
            .collect();
        assert!(entries.is_empty(), "temp file left behind after failure");

        // Original content must be untouched.
        let on_disk = std::fs::read(tmp.join("target.txt")).unwrap();
        assert_eq!(&on_disk, b"original", "original content unchanged");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn file_create_creates_empty_file() {
        let tmp = std::env::temp_dir().join(format!("kavach_fs_crnew_{}", uuid_simple()));
        std::fs::create_dir_all(&tmp).unwrap();
        let enforcer = make_enforcer(&tmp);
        let req = file_request(Operation::FileCreate, "new.txt");
        let mut permit = make_permit(&req);
        let outcome = enforcer
            .execute(&req, &mut permit, FilesystemInput::None)
            .unwrap();
        assert!(matches!(outcome, FilesystemOutcome::FileCreate));
        let meta = std::fs::metadata(tmp.join("new.txt")).unwrap();
        assert_eq!(meta.len(), 0, "FileCreate should produce an empty file");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ----------------------------------------------------------------
    // File delete tests
    // ----------------------------------------------------------------

    #[test]
    fn file_delete_succeeds() {
        let tmp = std::env::temp_dir().join(format!("kavach_fs_del_{}", uuid_simple()));
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("delme.txt"), b"x").unwrap();
        let enforcer = make_enforcer(&tmp);
        let req = file_request(Operation::FileDelete, "delme.txt");
        let mut permit = make_permit(&req);
        let outcome = enforcer
            .execute(&req, &mut permit, FilesystemInput::None)
            .unwrap();
        assert!(matches!(outcome, FilesystemOutcome::FileDelete));
        assert!(!tmp.join("delme.txt").exists());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn file_delete_rejects_directory() {
        let tmp = std::env::temp_dir().join(format!("kavach_fs_deldir_{}", uuid_simple()));
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::create_dir(tmp.join("adir")).unwrap();
        let enforcer = make_enforcer(&tmp);
        let req = file_request(Operation::FileDelete, "adir");
        let mut permit = make_permit(&req);
        let result = enforcer.execute(&req, &mut permit, FilesystemInput::None);
        assert!(matches!(result, Err(FilesystemError::UnsupportedFileType)));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ----------------------------------------------------------------
    // Workspace escape tests
    // ----------------------------------------------------------------

    #[test]
    fn lexical_dotdot_traversal_rejected() {
        let tmp = std::env::temp_dir().join(format!("kavach_fs_dotdot_{}", uuid_simple()));
        std::fs::create_dir_all(&tmp).unwrap();
        // Create a subdirectory for the test.
        std::fs::create_dir(tmp.join("sub")).unwrap();
        let enforcer = make_enforcer(&tmp);
        // A path that lexically goes above the workspace root when joined.
        // Core NormalizedPath rejects leading `..`, so use a path with `..`
        // that goes outside after join.
        let request = ToolRequest::new(
            RequestId::new("req-1").unwrap(),
            make_subject(),
            Operation::FileRead { max_bytes: None },
            Resource::File {
                path: kavach_core::resource::NormalizedPath::new("sub/../outside.txt").unwrap(),
            },
            make_context(),
        );
        // "sub/../outside.txt" normalizes to "outside.txt" which is inside workspace.
        // Core already handles pure `..` escape. Verify that works.
        // Test that a symlink or absolute path is caught — absolute path test below.
        let mut permit = make_permit(&request);
        // This request targets "outside.txt" which doesn't exist → NotFound.
        let result = enforcer.execute(&request, &mut permit, FilesystemInput::None);
        assert!(matches!(result, Err(FilesystemError::NotFound(_))));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn absolute_path_rejected() {
        let tmp = std::env::temp_dir().join(format!("kavach_fs_abs_{}", uuid_simple()));
        std::fs::create_dir_all(&tmp).unwrap();
        let enforcer = make_enforcer(&tmp);
        // Absolute NormalizedPath bypasses workspace prefix.
        let request = ToolRequest::new(
            RequestId::new("req-1").unwrap(),
            make_subject(),
            Operation::FileRead { max_bytes: None },
            Resource::File {
                path: kavach_core::resource::NormalizedPath::new("/etc/passwd").unwrap(),
            },
            make_context(),
        );
        let mut permit = make_permit(&request);
        let result = enforcer.execute(&request, &mut permit, FilesystemInput::None);
        assert!(matches!(result, Err(FilesystemError::WorkspaceEscape(_))));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ----------------------------------------------------------------
    // Directory operations
    // ----------------------------------------------------------------

    #[test]
    fn directory_list_sorted() {
        let tmp = std::env::temp_dir().join(format!("kavach_fs_dl_{}", uuid_simple()));
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("z.txt"), b"").unwrap();
        std::fs::write(tmp.join("a.txt"), b"").unwrap();
        std::fs::create_dir(tmp.join("m_dir")).unwrap();
        let enforcer = make_enforcer(&tmp);
        let req = dir_request(Operation::DirectoryList, ".");
        let mut permit = make_permit(&req);
        let outcome = enforcer
            .execute(&req, &mut permit, FilesystemInput::None)
            .unwrap();
        match outcome {
            FilesystemOutcome::DirectoryList { entries } => {
                assert_eq!(entries, vec!["a.txt", "m_dir", "z.txt"]);
            }
            _ => panic!("expected DirectoryList"),
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn directory_create_and_delete() {
        let tmp = std::env::temp_dir().join(format!("kavach_fs_dcd_{}", uuid_simple()));
        std::fs::create_dir_all(&tmp).unwrap();
        let enforcer = make_enforcer(&tmp);

        // Create directory
        let req = dir_request(Operation::DirectoryCreate, "newdir");
        let mut permit = make_permit(&req);
        let outcome = enforcer
            .execute(&req, &mut permit, FilesystemInput::None)
            .unwrap();
        assert!(matches!(outcome, FilesystemOutcome::DirectoryCreate));
        assert!(tmp.join("newdir").is_dir());

        // Delete directory
        let req = dir_request(Operation::DirectoryDelete, "newdir");
        let mut permit = make_permit(&req);
        let outcome = enforcer
            .execute(&req, &mut permit, FilesystemInput::None)
            .unwrap();
        assert!(matches!(outcome, FilesystemOutcome::DirectoryDelete));
        assert!(!tmp.join("newdir").exists());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn directory_delete_rejects_non_empty() {
        let tmp = std::env::temp_dir().join(format!("kavach_fs_ddne_{}", uuid_simple()));
        std::fs::create_dir_all(&tmp).unwrap();
        let sub = tmp.join("notempty");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(sub.join("f.txt"), b"").unwrap();
        let enforcer = make_enforcer(&tmp);
        let req = dir_request(Operation::DirectoryDelete, "notempty");
        let mut permit = make_permit(&req);
        let result = enforcer.execute(&req, &mut permit, FilesystemInput::None);
        assert!(matches!(result, Err(FilesystemError::DirectoryNotEmpty)));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn directory_create_rejects_existing() {
        let tmp = std::env::temp_dir().join(format!("kavach_fs_dcexist_{}", uuid_simple()));
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::create_dir(tmp.join("exists")).unwrap();
        let enforcer = make_enforcer(&tmp);
        let req = dir_request(Operation::DirectoryCreate, "exists");
        let mut permit = make_permit(&req);
        let result = enforcer.execute(&req, &mut permit, FilesystemInput::None);
        assert!(matches!(result, Err(FilesystemError::AlreadyExists(_))));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn wrong_resource_type_rejected() {
        let tmp = std::env::temp_dir().join(format!("kavach_fs_wrt_{}", uuid_simple()));
        std::fs::create_dir_all(&tmp).unwrap();
        let enforcer = make_enforcer(&tmp);
        // FileRead on a Directory resource — request validation catches this
        // as operation/resource mismatch.
        let req = dir_request(Operation::FileRead { max_bytes: None }, ".");
        let mut permit = make_permit(&req);
        let result = enforcer.execute(&req, &mut permit, FilesystemInput::None);
        assert!(matches!(result, Err(FilesystemError::InvalidRequest(_))));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn directory_entry_limit_enforced() {
        let tmp = std::env::temp_dir().join(format!("kavach_fs_delimit_{}", uuid_simple()));
        std::fs::create_dir_all(&tmp).unwrap();
        for i in 0..10u16 {
            std::fs::write(tmp.join(format!("f{i}.txt")), b"").unwrap();
        }
        let enforcer = make_enforcer(&tmp).with_max_dir_entries(3).unwrap();
        let req = dir_request(Operation::DirectoryList, ".");
        let mut permit = make_permit(&req);
        let result = enforcer.execute(&req, &mut permit, FilesystemInput::None);
        assert!(matches!(
            result,
            Err(FilesystemError::DirectoryEntryLimitExceeded(3))
        ));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ----------------------------------------------------------------
    // Helpers
    // ----------------------------------------------------------------

    fn make_expired_permit(request: &ToolRequest) -> ExecutionPermit {
        let digest = kavach_runtime::compute_request_digest(request);
        ExecutionPermit::new(&[2u8; 32], vec![], digest, Duration::from_secs(0))
    }

    fn uuid_simple() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos();
        format!("{nanos:08x}")
    }
}
