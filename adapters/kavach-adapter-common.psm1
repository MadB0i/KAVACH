# Kavach adapter common module (cooperative hook-based enforcement layer).
#
# Shared contract for every per-tool hook adapter (Claude Code, Codex CLI,
# OpenCode). A hook adapter is a thin translator, not a decision maker:
#   raw hook JSON (stdin) -> Kavach ToolRequest -> `kavach policy explain`
#   -> exit code + hook-output JSON.
#
# Decisions are NEVER re-derived here; `policy explain --json` is the single
# source of truth and every decision is appended to the shared dashboard
# feed via --feed-log. Requires Windows PowerShell 5.1 or PowerShell 7+.

Set-StrictMode -Version 2.0

# Tool names that execute shell commands, per agent CLI.
$script:BashTools = @('Bash', 'PowerShell', 'bash')
# Tool names that create/overwrite files.
$script:WriteTools = @('Write', 'MultiEdit', 'NotebookEdit', 'write')
# Tool names that mutate an existing file.
$script:EditTools = @('Edit', 'edit')
# Tool names that read files.
$script:ReadTools = @('Read', 'read', 'glob', 'grep')

function Get-JsonProp {
    # StrictMode-safe optional property read: returns $null when $Object
    # is $null or lacks the property (direct member access would throw
    # under Set-StrictMode). Use for every optional hook/decision field.
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    $prop = $Object.PSObject.Properties[$Name]
    if ($null -eq $prop) { return $null }
    return $prop.Value
}

function Read-HookInput {
    # Reads the full stdin hook payload and parses it as JSON. Returns $null
    # when stdin is not JSON. NOTE: no -Depth flag: ConvertFrom-Json has no
    # -Depth parameter on Windows PowerShell 5.1 (it errors); the default
    # depth-2 parse covers everything this adapter reads (tool_name and
    # tool_input.* are within depth 2).
    $raw = [Console]::In.ReadToEnd()
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
    try {
        return $raw | ConvertFrom-Json
    } catch {
        return $null
    }
}

function Split-ShellCommand {
    # Minimal shlex-like split: respects single/double quotes and backslash
    # escapes. Returns @(executable, @(arguments)).
    param([string]$Command)
    $parts = New-Object System.Collections.ArrayList
    $current = New-Object System.Text.StringBuilder
    $inSingle = $false
    $inDouble = $false
    $escaped = $false
    foreach ($ch in $Command.ToCharArray()) {
        if ($escaped) { [void]$current.Append($ch); $escaped = $false; continue }
        if ($ch -eq '\') { $escaped = $true; continue }
        if (($ch -eq "'") -and (-not $inDouble)) { $inSingle = -not $inSingle; continue }
        if (($ch -eq '"') -and (-not $inSingle)) { $inDouble = -not $inDouble; continue }
        if (($ch -eq ' ') -and (-not $inSingle) -and (-not $inDouble)) {
            if ($current.Length -gt 0) {
                [void]$parts.Add($current.ToString()); $current.Clear() | Out-Null
            }
            continue
        }
        [void]$current.Append($ch)
    }
    if ($current.Length -gt 0) { [void]$parts.Add($current.ToString()) }
    $exe = ''
    $args = @()
    if ($parts.Count -gt 0) {
        $exe = $parts[0]
        if ($parts.Count -gt 1) { $args = @($parts.GetRange(1, $parts.Count - 1)) }
    }
    return @($exe, $args)
}

function ConvertTo-NormalizedPath {
    # Forward slashes only: kavach's JSON parser rejects backslash escapes.
    param($Path)
    if ([string]::IsNullOrEmpty($Path)) { return $null }
    return ([string]$Path).Replace('\', '/')
}

function ConvertTo-ToolRequest {
    # Maps one hook payload to a Kavach (operation, resource) pair plus the
    # working directory. Returns $null for unmapped tools (caller must fail
    # closed). $ToolMap selects per-agent tool names; 'Claude' is default.
    param($Hook, [string]$ToolMap = 'Claude')
    $toolName = [string](Get-JsonProp -Object $Hook -Name 'tool_name')
    $input = Get-JsonProp -Object $Hook -Name 'tool_input'
    if ([string]::IsNullOrWhiteSpace($toolName)) { return $null }

    $bashTools = $script:BashTools
    $writeTools = $script:WriteTools
    $editTools = $script:EditTools
    $readTools = $script:ReadTools
    if ($ToolMap -eq 'Codex') {
        # Codex apply_patch carries file edits; Bash carries shell commands.
        # apply_patch input is handled separately (patch-marker scan).
        $bashTools = @('Bash')
        $writeTools = @()
        $editTools = @()
        $readTools = @()
    }

    if ($bashTools -contains $toolName) {
        $command = [string](Get-JsonProp -Object $input -Name 'command')
        if ([string]::IsNullOrWhiteSpace($command)) { return $null }
        $split = Split-ShellCommand -Command $command
        return @{
            operation = @{ command_execute = $null }
            resource = @{ Command = @{ executable = $split[0]; arguments = @($split[1]) } }
        }
    }

    if ($ToolMap -eq 'Codex' -and $toolName -eq 'apply_patch') {
        return ConvertFrom-CodexPatch -Hook $Hook
    }

    $path = [string](Get-JsonProp -Object $input -Name 'file_path')
    if ([string]::IsNullOrWhiteSpace($path)) {
        $path = [string](Get-JsonProp -Object $input -Name 'path')
    }
    if ([string]::IsNullOrWhiteSpace($path)) { return $null }
    $norm = ConvertTo-NormalizedPath -Path $path
    if ($writeTools -contains $toolName) {
        return @{ operation = @{ file_create = $null }; resource = @{ File = @{ path = $norm } } }
    }
    if ($editTools -contains $toolName) {
        return @{ operation = @{ file_write = $null }; resource = @{ File = @{ path = $norm } } }
    }
    if ($readTools -contains $toolName) {
        return @{ operation = @{ file_read = @{} }; resource = @{ File = @{ path = $norm } } }
    }
    return $null
}

function ConvertFrom-CodexPatch {
    # Best-effort mapping for Codex apply_patch payloads: scans the patch
    # text for file markers (*** Add File: / *** Update File: /
    # *** Delete File:) and returns a file_write check for each path.
    # Returns $null when no marker is found (caller fails closed).
    # Multiple paths are joined with '|' in File.path — the policy engine
    # treats an unmatched literal as default-deny, which is the safe
    # direction; adapters never grant access this path cannot describe.
    param($Hook)
    $toolInput = Get-JsonProp -Object $Hook -Name 'tool_input'
    $text = [string](Get-JsonProp -Object $toolInput -Name 'command')
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    $paths = New-Object System.Collections.ArrayList
    foreach ($line in $text -split "`r?`n") {
        if ($line -match '^\*\*\*\s+(Add File|Update File|Delete File):\s*(.+?)\s*$') {
            $p = ConvertTo-NormalizedPath -Path $Matches[2].Trim()
            if (-not [string]::IsNullOrWhiteSpace($p)) { [void]$paths.Add($p) }
        }
    }
    if ($paths.Count -eq 0) { return $null }
    return @{
        operation = @{ file_write = $null }
        resource = @{ File = @{ path = ($paths -join '|') } }
    }
}

function Invoke-KavachExplain {
    # Runs `kavach policy explain --json --feed-log` on one mapped request.
    # Returns @{ effect = 'Allow'|'Deny'|'RequireApproval'|$null; reason = str }.
    # A $null effect means the check itself failed -> caller fails closed.
    # The kavach call runs in a background job bounded by TimeoutSec: a hung
    # binary must surface as a failed check (deny), never as a hung hook,
    # because a tool-side hook timeout fails OPEN on some agent CLIs.
    param(
        [hashtable]$Mapped,
        [string]$KavachBin,
        [string]$Policy,
        [string]$FeedLog,
        [string]$AgentId,
        [string]$SessionId,
        [string]$WorkingDirectory,
        [string]$Intent = 'Agent tool call (Kavach hook)',
        [int]$TimeoutSec = 25
    )
    $request = @{
        request_id = "kavach-hook-$([Math]::Abs($Mapped.GetHashCode()))"
        subject = @{
            agent_id = $AgentId
            session_id = $SessionId
            display_name = "$AgentId (Kavach hook)"
            trust_level = 'standard'
            declared_capabilities = @()
        }
        operation = $Mapped.operation
        resource = $Mapped.resource
        context = @{
            timestamp = @{ secs_since_epoch = 0; nanos_since_epoch = 0 }
            working_directory = ConvertTo-NormalizedPath -Path $WorkingDirectory
            declared_intent = $Intent
            parent_request_id = $null
            metadata = @{}
            dry_run = $false
        }
    }
    $tmp = [System.IO.Path]::Combine(
        [System.IO.Path]::GetTempPath(),
        "kavach-req-$([Guid]::NewGuid().ToString('N')).json")
    try {
        # BOM-less UTF-8: plain Out-File -Encoding utf8 writes a BOM that
        # strict JSON parsers may reject.
        $utf8NoBom = New-Object System.Text.UTF8Encoding $false
        [System.IO.File]::WriteAllText(
            $tmp, ($request | ConvertTo-Json -Depth 10), $utf8NoBom)
        $cliArgs = @('policy', 'explain', '--policy', $Policy,
                  '--request', $tmp, '--json')
        if (-not [string]::IsNullOrWhiteSpace($FeedLog)) {
            $cliArgs += @('--feed-log', $FeedLog)
        }
        $job = Start-Job -ScriptBlock {
            param($Bin, $ArgList)
            $stdout = & $Bin @ArgList 2>$null
            $code = $LASTEXITCODE
            if ($null -eq $stdout) { $stdout = @() }
            [pscustomobject]@{ Out = ($stdout | Out-String); Code = $code }
        } -ArgumentList $KavachBin, $cliArgs
        $finished = Wait-Job -Job $job -Timeout $TimeoutSec
        if ($null -eq $finished) {
            Stop-Job -Job $job | Out-Null
            Remove-Job -Job $job -Force | Out-Null
            return @{ effect = $null; reason = "kavach call timed out after ${TimeoutSec}s" }
        }
        if ($job.State -ne 'Completed') {
            Remove-Job -Job $job -Force | Out-Null
            return @{ effect = $null; reason = 'kavach job did not complete' }
        }
        $result = Receive-Job -Job $job
        Remove-Job -Job $job | Out-Null
        $out = [string](Get-JsonProp -Object $result -Name 'Out')
        $code = Get-JsonProp -Object $result -Name 'Code'
        if ($code -ne 0 -and [string]::IsNullOrWhiteSpace($out)) {
            return @{ effect = $null; reason = "kavach binary failed (exit ${code})" }
        }
        # --json prints the full AuthorizationDecision.
        $decision = ($out | Out-String) | ConvertFrom-Json
        $effect = [string](Get-JsonProp -Object $decision -Name 'effect')
        $reason = [string](Get-JsonProp -Object $decision -Name 'explanation')
        if ([string]::IsNullOrWhiteSpace($reason)) {
            $reason = [string](Get-JsonProp -Object $decision -Name 'reason')
        }
        $trace = Get-JsonProp -Object $decision -Name 'trace'
        $baseline = [string](Get-JsonProp -Object $trace -Name 'baseline_triggered')
        if (-not [string]::IsNullOrWhiteSpace($baseline)) {
            $reason = "baseline: ${baseline} -- ${reason}"
        }
        return @{ effect = $effect; reason = $reason }
    } catch {
        return @{ effect = $null; reason = "kavach invocation failed: $($_.Exception.Message)" }
    } finally {
        Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue
    }
}

function Convert-DecisionToExit {
    # Maps a Kavach effect to the hook exit contract shared by Claude Code
    # and Codex CLI PreToolUse: Allow -> exit 0 (+ allow JSON on stdout);
    # Deny -> exit 2 (+ deny JSON on stdout, reason on stderr);
    # RequireApproval -> exit 2 as Deny (no interactive channel in v1).
    # Emits the hookSpecificOutput JSON to stdout and returns the exit code
    # (does NOT exit itself, so wrappers stay testable).
    param([string]$Effect, [string]$Reason)
    # NOTE: the hook JSON is written with [Console]::Out, not Write-Output:
    # Write-Output inside a function merges into the return value, which
    # would corrupt the exit code at the call site (`exit $code`).
    $norm = ''
    if (-not [string]::IsNullOrWhiteSpace($Effect)) { $norm = $Effect.Trim().ToLowerInvariant() }
    if ($norm -eq 'allow') {
        [Console]::Out.WriteLine((@{
            hookSpecificOutput = @{
                hookEventName = 'PreToolUse'
                permissionDecision = 'allow'
                permissionDecisionReason = 'Allowed by Kavach policy'
            }
        } | ConvertTo-Json -Depth 5 -Compress))
        return 0
    }
    if ($norm -eq 'requireapproval' -or $norm -eq 'require_approval' -or $norm -eq 'ask') {
        $msg = 'RequireApproval treated as Deny (no interactive path in v1)'
        if (-not [string]::IsNullOrWhiteSpace($Reason)) { $msg = "${msg}: ${Reason}" }
        [Console]::Error.WriteLine($msg)
        [Console]::Out.WriteLine((@{
            hookSpecificOutput = @{
                hookEventName = 'PreToolUse'
                permissionDecision = 'deny'
                permissionDecisionReason = $msg
            }
        } | ConvertTo-Json -Depth 5 -Compress))
        return 2
    }
    $msg = 'Blocked by Kavach policy'
    if (-not [string]::IsNullOrWhiteSpace($Reason)) { $msg = "Blocked by Kavach policy: ${Reason}" }
    [Console]::Error.WriteLine($msg)
    [Console]::Out.WriteLine((@{
        hookSpecificOutput = @{
            hookEventName = 'PreToolUse'
            permissionDecision = 'deny'
            permissionDecisionReason = $msg
        }
    } | ConvertTo-Json -Depth 5 -Compress))
    return 2
}

Export-ModuleMember -Function @(
    'Get-JsonProp', 'Read-HookInput',
    'Split-ShellCommand', 'ConvertTo-NormalizedPath',
    'ConvertTo-ToolRequest', 'ConvertFrom-CodexPatch',
    'Invoke-KavachExplain', 'Convert-DecisionToExit'
)
