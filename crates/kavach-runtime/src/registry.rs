use std::fmt;
use std::path::PathBuf;

use kavach_core::request::{Operation, ToolRequest};

use crate::error::RuntimeError;

/// Typed registry of enforcement adapters.
///
/// Each declared operation resource kind maps to exactly one adapter.
/// Duplicate registrations are rejected at construction time.
pub struct AdapterRegistry {
    pub(crate) filesystem: kavach_enforcement::FilesystemEnforcer,
    pub(crate) command: kavach_enforcement::command::CommandEnforcer,
    pub(crate) network: kavach_enforcement::network::NetworkEnforcer,
}

impl fmt::Debug for AdapterRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdapterRegistry")
            .field("filesystem", &"<enforcer>")
            .field("command", &"<enforcer>")
            .field("network", &"<enforcer>")
            .finish()
    }
}

impl AdapterRegistry {
    /// Create a new registry with the three built-in adapters, using default
    /// configuration for each.
    pub fn new_test(workspace_root: PathBuf) -> Result<Self, RuntimeError> {
        let fs = kavach_enforcement::FilesystemEnforcer::new(&workspace_root)
            .map_err(|e| RuntimeError::ConfigurationFailure(e.to_string()))?;
        let cmd = kavach_enforcement::command::CommandEnforcer::new(&workspace_root)
            .map_err(|e| RuntimeError::ConfigurationFailure(e.to_string()))?;
        let net = kavach_enforcement::network::NetworkEnforcer::new();
        Ok(Self {
            filesystem: fs,
            command: cmd,
            network: net,
        })
    }

    /// Resolve the required [`Operation`] to a dispatch key.
    ///
    /// Returns an error for operations that have no adapter yet (SecretAccess,
    /// ToolInvoke) or that are unrecognised.
    pub fn resolve_operation(request: &ToolRequest) -> Result<AdapterKind, RuntimeError> {
        match &request.operation {
            Operation::FileRead { .. }
            | Operation::FileWrite
            | Operation::FileCreate
            | Operation::FileDelete
            | Operation::FileMove { .. }
            | Operation::DirectoryList
            | Operation::DirectoryCreate
            | Operation::DirectoryDelete => Ok(AdapterKind::Filesystem),
            Operation::CommandExecute => Ok(AdapterKind::Command),
            Operation::NetworkRequest => Ok(AdapterKind::Network),
            Operation::SecretAccess => Err(RuntimeError::MissingAdapter(
                "SecretAccess adapter is not yet implemented".into(),
            )),
            Operation::ToolInvoke { .. } => Err(RuntimeError::MissingAdapter(
                "ToolInvoke adapter is not yet implemented".into(),
            )),
            _ => Err(RuntimeError::UnsupportedOperation(
                "unknown operation type".into(),
            )),
        }
    }

    /// Classify a command's risk level for scope matching.
    pub fn classify_command_risk(
        &self,
        executable: &str,
    ) -> kavach_enforcement::command::CommandRisk {
        self.command.classify(executable)
    }
}

/// Which adapter handles a given operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdapterKind {
    /// Filesystem adapter (read, write, create, delete, move, list).
    Filesystem,
    /// Command adapter (execute).
    Command,
    /// Network adapter (HTTP/HTTPS request).
    Network,
}
