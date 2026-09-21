use std::process;

/// Stable exit codes for the KAVACH CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum ExitCode {
    Success = 0,
    Deny = 10,
    ApprovalRequired = 11,
    InvalidInput = 20,
    PolicyError = 21,
    AuditError = 22,
    /// One or more `policy test` scenarios failed (usable in CI).
    TestFailures = 23,
    InternalError = 30,
    Unavailable = 40,
}

impl ExitCode {
    pub fn code(self) -> i32 {
        self as i32
    }

    pub fn exit(self) -> ! {
        process::exit(self.code());
    }
}
