<#
.SYNOPSIS
    KAVACH End-to-End Demo — Phase 15
.DESCRIPTION
    Orchestrates all KAVACH working examples:
      1. Allowed project-file read
      2. Denied .env read
      3. Approval-required file deletion
      4. Allowed harmless command
      5. Denied dangerous command
      6. Allowed local HTTP request
      7. Blocked SSRF destination
      8. Response secret redaction
      9. Single-use approval replay rejection
     10. Audit-chain verification
.NOTES
    Requires: cargo, rustc 1.85+
    No public internet, no destructive commands, no fake output.
#>

$ErrorActionPreference = "Stop"
$rootDir = Split-Path -Parent $PSScriptRoot | Split-Path -Parent
$startTime = Get-Date

Write-Host "╔══════════════════════════════════════════════════════════════╗"
Write-Host "║        KAVACH End-to-End Demo                              ║"
Write-Host "║        Phase 15: Working Examples                           ║"
Write-Host "╚══════════════════════════════════════════════════════════════╝"
Write-Host ""

# ── 1. Build examples ────────────────────────────────────────────────────

Write-Host "─── Step 1: Building examples ──────────────────────────────"
$buildOutput = & cargo build --package kavach-examples --bins 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "  BUILD FAILED"
    Write-Host $buildOutput
    exit 1
}
Write-Host "  Build OK" -ForegroundColor Green
Write-Host ""

# ── 2. Run basic-policy ──────────────────────────────────────────────────

Write-Host "─── Step 2: basic-policy ───────────────────────────────────"
$output = & cargo run --package kavach-examples --bin basic-policy 2>&1
$exitCode = $LASTEXITCODE
Write-Host $output
if ($exitCode -eq 0) {
    Write-Host "  basic-policy PASSED" -ForegroundColor Green
} else {
    Write-Host "  basic-policy FAILED (exit=$exitCode)" -ForegroundColor Red
}
Write-Host ""

# ── 3. Run guarded-filesystem ────────────────────────────────────────────

Write-Host "─── Step 3: guarded-filesystem ──────────────────────────────"
$output = & cargo run --package kavach-examples --bin guarded-filesystem 2>&1
$exitCode = $LASTEXITCODE
Write-Host $output
if ($exitCode -eq 0) {
    Write-Host "  guarded-filesystem PASSED" -ForegroundColor Green
} else {
    Write-Host "  guarded-filesystem FAILED (exit=$exitCode)" -ForegroundColor Red
}
Write-Host ""

# ── 4. Run guarded-command ───────────────────────────────────────────────

Write-Host "─── Step 4: guarded-command ─────────────────────────────────"
$output = & cargo run --package kavach-examples --bin guarded-command 2>&1
$exitCode = $LASTEXITCODE
Write-Host $output
if ($exitCode -eq 0) {
    Write-Host "  guarded-command PASSED" -ForegroundColor Green
} else {
    Write-Host "  guarded-command FAILED (exit=$exitCode)" -ForegroundColor Red
}
Write-Host ""

# ── 5. Run guarded-network ───────────────────────────────────────────────

Write-Host "─── Step 5: guarded-network ─────────────────────────────────"
$output = & cargo run --package kavach-examples --bin guarded-network 2>&1
$exitCode = $LASTEXITCODE
Write-Host $output
if ($exitCode -eq 0) {
    Write-Host "  guarded-network PASSED" -ForegroundColor Green
} else {
    Write-Host "  guarded-network FAILED (exit=$exitCode)" -ForegroundColor Red
}
Write-Host ""

# ── 6. Run approval-flow ─────────────────────────────────────────────────

Write-Host "─── Step 6: approval-flow ───────────────────────────────────"
$output = & cargo run --package kavach-examples --bin approval-flow 2>&1
$exitCode = $LASTEXITCODE
Write-Host $output
if ($exitCode -eq 0) {
    Write-Host "  approval-flow PASSED" -ForegroundColor Green
} else {
    Write-Host "  approval-flow FAILED (exit=$exitCode)" -ForegroundColor Red
}
Write-Host ""

# ── 7. Run demo-agent ────────────────────────────────────────────────────

Write-Host "─── Step 7: demo-agent ──────────────────────────────────────"
$output = & cargo run --package kavach-examples --bin demo-agent 2>&1
$exitCode = $LASTEXITCODE
Write-Host $output
if ($exitCode -eq 0) {
    Write-Host "  demo-agent PASSED" -ForegroundColor Green
} else {
    Write-Host "  demo-agent FAILED (exit=$exitCode)" -ForegroundColor Red
}
Write-Host ""

# ── Summary ──────────────────────────────────────────────────────────────

$duration = (Get-Date) - $startTime
$totalSeconds = [math]::Round($duration.TotalSeconds, 1)

Write-Host "╔══════════════════════════════════════════════════════════════╗"
Write-Host "║        Demo Complete                                        ║"
Write-Host "║        Duration: $totalSeconds seconds                         ║"
Write-Host "╚══════════════════════════════════════════════════════════════╝"
