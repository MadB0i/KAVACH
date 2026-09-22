# Kavach PreToolUse hook for Claude Code.
#
# Wiring (manual): add adapters/claude/settings.project.snippet.json (or the
# global snippet) to your settings file with the script path filled in, e.g.
#   "command": "powershell -NoProfile -ExecutionPolicy Bypass -File
#     C:\\Kavach\\adapters\\claude\\kavach-claude-hook.ps1
#     -Policy C:\\Kavach\\config\\privacy-starter.toml
#     -FeedLog C:\\Kavach\\decisions.jsonl"
# Environment overrides: KAVACH_BIN, KAVACH_POLICY, KAVACH_FEED_LOG.
# Flags win over environment. Unmapped tools and any check failure deny
# (fail closed). Requires Windows PowerShell 5.1 or PowerShell 7+.
param(
    [string]$Policy = $env:KAVACH_POLICY,
    [string]$FeedLog = $env:KAVACH_FEED_LOG,
    [string]$KavachBin = $env:KAVACH_BIN,
    [int]$TimeoutSec = 25
)

# Fail-closed top level: ANY unhandled error below (missing module, parse
# failure, unexpected exception) exits 2 (deny). Without this, PowerShell
# would exit 1, which agent CLIs treat as NON-blocking (fail-open).
$ErrorActionPreference = 'Stop'
try {
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$adaptersRoot = Split-Path -Parent $here
Import-Module (Join-Path $adaptersRoot 'kavach-adapter-common.psm1') -Force

if ([string]::IsNullOrWhiteSpace($KavachBin)) { $KavachBin = 'kavach' }

$hook = Read-HookInput
if ($null -eq $hook -or [string]::IsNullOrWhiteSpace($Policy)) {
    if ([string]::IsNullOrWhiteSpace($Policy)) {
        [Console]::Error.WriteLine('Kavach: KAVACH_POLICY not set; failing closed (deny)')
    } else {
        [Console]::Error.WriteLine('Kavach: unreadable hook input; failing closed (deny)')
    }
    Write-Output (@{
        hookSpecificOutput = @{
            hookEventName = 'PreToolUse'
            permissionDecision = 'deny'
            permissionDecisionReason = 'Kavach hook misconfigured; failing closed'
        }
    } | ConvertTo-Json -Depth 5 -Compress)
    exit 2
}

$mapped = ConvertTo-ToolRequest -Hook $hook -ToolMap 'Claude'
if ($null -eq $mapped) {
    $name = [string](Get-JsonProp -Object $hook -Name 'tool_name')
    [Console]::Error.WriteLine("Kavach: blocked tool '$name' - not mapped to a Kavach policy subject")
    Write-Output (@{
        hookSpecificOutput = @{
            hookEventName = 'PreToolUse'
            permissionDecision = 'deny'
            permissionDecisionReason = "Blocked because tool '$name' is not mapped to a Kavach policy subject"
        }
    } | ConvertTo-Json -Depth 5 -Compress)
    exit 2
}

$session = [string](Get-JsonProp -Object $hook -Name 'session_id')
if ([string]::IsNullOrWhiteSpace($session)) { $session = 'hook-session' }
$cwd = [string](Get-JsonProp -Object $hook -Name 'cwd')

$result = Invoke-KavachExplain -Mapped $mapped -KavachBin $KavachBin `
    -Policy $Policy -FeedLog $FeedLog -AgentId 'claude-code' `
    -SessionId $session -WorkingDirectory $cwd -TimeoutSec $TimeoutSec
$code = Convert-DecisionToExit -Effect ([string]$result.effect) -Reason ([string]$result.reason)
exit $code
} catch {
    [Console]::Error.WriteLine("Kavach: hook failed ($($_.Exception.Message)); failing closed (deny)")
    Write-Output (@{
        hookSpecificOutput = @{
            hookEventName = 'PreToolUse'
            permissionDecision = 'deny'
            permissionDecisionReason = 'Kavach hook error; failing closed'
        }
    } | ConvertTo-Json -Depth 5 -Compress)
    exit 2
}
