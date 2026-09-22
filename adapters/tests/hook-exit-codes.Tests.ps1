# Pester regression matrix for the Kavach hook adapters (Phase 3b).
#
# Asserts EXACT process exit codes per decision path (Allow / baseline-Deny /
# rule-Deny / RequireApproval-as-Deny) and fail-closed behavior for every
# adapter failure mode. A corrupted exit code turns Deny into Allow, so these
# pin the contract: Allow -> 0, everything else -> 2, never 0-or-1 on failure.
#
# Prerequisites: a debug `kavach` binary at <repo>/target/debug/kavach.exe
# (`cargo build -p kavach-cli`).
# Run: powershell -NoProfile -Command "Invoke-Pester -Script ./adapters/tests/hook-exit-codes.Tests.ps1"
# Pester 3.4 syntax (ships with Windows PowerShell 5.1).

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$KavachBin = Join-Path $RepoRoot 'target\debug\kavach.exe'
$PrivacyPolicy = Join-Path $RepoRoot 'config\privacy-starter.toml'
$ClaudeHook = Join-Path $RepoRoot 'adapters\claude\kavach-claude-hook.ps1'
$CodexHook = Join-Path $RepoRoot 'adapters\codex\kavach-codex-hook.ps1'
$StubDir = Join-Path $PSScriptRoot 'stubs'

if (-not (Test-Path $KavachBin)) {
    throw "kavach binary not found at $KavachBin (run: cargo build -p kavach-cli)"
}

function Write-Utf8NoBom($Path, $Text) {
    $utf8 = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText($Path, $Text, $utf8)
}

function New-ApprovalPolicy {
    $path = Join-Path ([System.IO.Path]::GetTempPath()) (
        "kavach-pester-$([Guid]::NewGuid().ToString('N')).toml")
    Write-Utf8NoBom $path @'
schema_version = 1

[policy]
id = "approval-test"
default_effect = "deny"

[[rules]]
id = "allow-echo"
effect = "allow"

[rules.conditions]
operations = ["command_execute"]
executables = ["echo"]

[[rules]]
id = "needs-approval-write"
effect = "require_approval"

[rules.conditions]
operations = ["file_write"]
resource_kinds = ["file"]
'@
    return $path
}

function Invoke-HookScript {
    # Runs one hook script with $StdinText on stdin. Returns
    # @{ Code = <process exit code>; Out = <stdout>; Err = <stderr> }.
    param($Script, $StdinText, $Policy, $KavachBinOverride, $ExtraArgs)
    if ($null -eq $ExtraArgs) { $ExtraArgs = @() }
    $bin = $KavachBin
    if (-not [string]::IsNullOrWhiteSpace($KavachBinOverride)) { $bin = $KavachBinOverride }
    $invokeArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $Script,
        '-Policy', $Policy, '-KavachBin', $bin) + $ExtraArgs
    $stdinBytes = [System.Text.Encoding]::UTF8.GetBytes([string]$StdinText)
    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo.FileName = 'powershell.exe'
    $proc.StartInfo.Arguments = ($invokeArgs | ForEach-Object { '"{0}"' -f ($_.Replace('"', '\"')) }) -join ' '
    $proc.StartInfo.RedirectStandardInput = $true
    $proc.StartInfo.RedirectStandardOutput = $true
    $proc.StartInfo.RedirectStandardError = $true
    $proc.StartInfo.UseShellExecute = $false
    $proc.StartInfo.CreateNoWindow = $true
    [void]$proc.Start()
    $proc.StandardInput.BaseStream.Write($stdinBytes, 0, $stdinBytes.Length)
    $proc.StandardInput.Close()
    $out = $proc.StandardOutput.ReadToEnd()
    $err = $proc.StandardError.ReadToEnd()
    $proc.WaitForExit()
    return @{ Code = $proc.ExitCode; Out = $out.Trim(); Err = $err.Trim() }
}

function ClaudePayload($Tool, $ToolInput) {
    (@{ session_id = 's1'; cwd = 'C:/work/proj'; hook_event_name = 'PreToolUse';
        tool_name = $Tool; tool_input = $ToolInput } | ConvertTo-Json -Depth 5 -Compress)
}

function CodexPayload($Tool, $ToolInput) {
    (@{ session_id = 's1'; cwd = 'C:/work/proj'; hook_event_name = 'PreToolUse';
        turn_id = 't1'; tool_name = $Tool; tool_use_id = 'u1';
        tool_input = $ToolInput } | ConvertTo-Json -Depth 5 -Compress)
}

Describe 'Claude adapter exit codes' {
    It 'Allow exits 0 with allow JSON' {
        $r = Invoke-HookScript -Script $ClaudeHook `
            -StdinText (ClaudePayload 'Bash' @{ command = 'ls' }) `
            -Policy $PrivacyPolicy
        $r.Code | Should Be 0
        $r.Out | Should Match '"permissionDecision":"allow"'
    }

    It 'baseline-Deny (echo redirect) exits 2' {
        $r = Invoke-HookScript -Script $ClaudeHook `
            -StdinText (ClaudePayload 'Bash' @{ command = 'echo x > f.txt' }) `
            -Policy $PrivacyPolicy
        $r.Code | Should Be 2
        $r.Out | Should Match '"permissionDecision":"deny"'
        $r.Err | Should Match 'baseline'
    }

    It 'rule-Deny (.env read) exits 2' {
        $r = Invoke-HookScript -Script $ClaudeHook `
            -StdinText (ClaudePayload 'Read' @{ file_path = 'C:/work/proj/.env' }) `
            -Policy $PrivacyPolicy
        $r.Code | Should Be 2
        $r.Out | Should Match '"permissionDecision":"deny"'
        $r.Err | Should Match 'deny-credential-files'
    }

    It 'RequireApproval exits 2 as Deny (no interactive path in v1)' {
        $policy = New-ApprovalPolicy
        try {
            $r = Invoke-HookScript -Script $ClaudeHook `
                -StdinText (ClaudePayload 'Edit' @{ file_path = 'C:/work/proj/a.txt' }) `
                -Policy $policy
            $r.Code | Should Be 2
            $r.Err | Should Match 'RequireApproval treated as Deny'
        } finally {
            Remove-Item -LiteralPath $policy -ErrorAction SilentlyContinue
        }
    }

    It 'missing kavach binary exits 2 (never 0)' {
        $r = Invoke-HookScript -Script $ClaudeHook `
            -StdinText (ClaudePayload 'Bash' @{ command = 'ls' }) `
            -Policy $PrivacyPolicy `
            -KavachBinOverride 'C:\nonexistent\kavach-nope.exe'
        $r.Code | Should Be 2
        $r.Code | Should Not Be 0
    }

    It 'empty stdin exits 2' {
        $r = Invoke-HookScript -Script $ClaudeHook `
            -StdinText '' -Policy $PrivacyPolicy
        $r.Code | Should Be 2
    }

    It 'malformed stdin exits 2' {
        $r = Invoke-HookScript -Script $ClaudeHook `
            -StdinText '{not json' -Policy $PrivacyPolicy
        $r.Code | Should Be 2
    }

    It 'unparseable kavach output exits 2' {
        $r = Invoke-HookScript -Script $ClaudeHook `
            -StdinText (ClaudePayload 'Bash' @{ command = 'ls' }) `
            -Policy $PrivacyPolicy `
            -KavachBinOverride (Join-Path $StubDir 'garbage-stub.cmd')
        $r.Code | Should Be 2
    }

    It 'silent kavach failure exits 2' {
        $r = Invoke-HookScript -Script $ClaudeHook `
            -StdinText (ClaudePayload 'Bash' @{ command = 'ls' }) `
            -Policy $PrivacyPolicy `
            -KavachBinOverride (Join-Path $StubDir 'silent-fail-stub.cmd')
        $r.Code | Should Be 2
    }

    It 'hung kavach call times out to exit 2' {
        $r = Invoke-HookScript -Script $ClaudeHook `
            -StdinText (ClaudePayload 'Bash' @{ command = 'ls' }) `
            -Policy $PrivacyPolicy `
            -KavachBinOverride (Join-Path $StubDir 'timeout-stub.cmd') `
            -ExtraArgs @('-TimeoutSec', '2')
        $r.Code | Should Be 2
        $r.Err | Should Match 'timed out'
    }
}

Describe 'Codex adapter exit codes' {
    It 'Allow exits 0 with allow JSON' {
        $r = Invoke-HookScript -Script $CodexHook `
            -StdinText (CodexPayload 'Bash' @{ command = 'ls' }) `
            -Policy $PrivacyPolicy
        $r.Code | Should Be 0
        $r.Out | Should Match '"permissionDecision":"allow"'
    }

    It 'baseline-Deny (echo redirect) exits 2' {
        $r = Invoke-HookScript -Script $CodexHook `
            -StdinText (CodexPayload 'Bash' @{ command = 'echo x > f.txt' }) `
            -Policy $PrivacyPolicy
        $r.Code | Should Be 2
        $r.Out | Should Match '"permissionDecision":"deny"'
        $r.Err | Should Match 'baseline'
    }

    It 'rule-Deny (apply_patch on .env) exits 2' {
        $patch = "*** Begin Patch`n*** Update File: C:/work/proj/.env`n@@`n+x=1`n*** End Patch"
        $r = Invoke-HookScript -Script $CodexHook `
            -StdinText (CodexPayload 'apply_patch' @{ command = $patch }) `
            -Policy $PrivacyPolicy
        $r.Code | Should Be 2
        $r.Out | Should Match '"permissionDecision":"deny"'
        $r.Err | Should Match 'deny-credential-files'
    }

    It 'RequireApproval exits 2 as Deny (no interactive path in v1)' {
        $policy = New-ApprovalPolicy
        try {
            $patch = "*** Begin Patch`n*** Update File: C:/work/proj/a.txt`n@@`n+x=1`n*** End Patch"
            $r = Invoke-HookScript -Script $CodexHook `
                -StdinText (CodexPayload 'apply_patch' @{ command = $patch }) `
                -Policy $policy
            $r.Code | Should Be 2
            $r.Err | Should Match 'RequireApproval treated as Deny'
        } finally {
            Remove-Item -LiteralPath $policy -ErrorAction SilentlyContinue
        }
    }

    It 'missing kavach binary exits 2 (never 0)' {
        $r = Invoke-HookScript -Script $CodexHook `
            -StdinText (CodexPayload 'Bash' @{ command = 'ls' }) `
            -Policy $PrivacyPolicy `
            -KavachBinOverride 'C:\nonexistent\kavach-nope.exe'
        $r.Code | Should Be 2
        $r.Code | Should Not Be 0
    }

    It 'empty stdin exits 2' {
        $r = Invoke-HookScript -Script $CodexHook `
            -StdinText '' -Policy $PrivacyPolicy
        $r.Code | Should Be 2
    }

    It 'malformed stdin exits 2' {
        $r = Invoke-HookScript -Script $CodexHook `
            -StdinText '{not json' -Policy $PrivacyPolicy
        $r.Code | Should Be 2
    }

    It 'unparseable kavach output exits 2' {
        $r = Invoke-HookScript -Script $CodexHook `
            -StdinText (CodexPayload 'Bash' @{ command = 'ls' }) `
            -Policy $PrivacyPolicy `
            -KavachBinOverride (Join-Path $StubDir 'garbage-stub.cmd')
        $r.Code | Should Be 2
    }

    It 'silent kavach failure exits 2' {
        $r = Invoke-HookScript -Script $CodexHook `
            -StdinText (CodexPayload 'Bash' @{ command = 'ls' }) `
            -Policy $PrivacyPolicy `
            -KavachBinOverride (Join-Path $StubDir 'silent-fail-stub.cmd')
        $r.Code | Should Be 2
    }

    It 'hung kavach call times out to exit 2' {
        $r = Invoke-HookScript -Script $CodexHook `
            -StdinText (CodexPayload 'Bash' @{ command = 'ls' }) `
            -Policy $PrivacyPolicy `
            -KavachBinOverride (Join-Path $StubDir 'timeout-stub.cmd') `
            -ExtraArgs @('-TimeoutSec', '2')
        $r.Code | Should Be 2
        $r.Err | Should Match 'timed out'
    }
}
