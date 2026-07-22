[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet("cwd-probe", "archive-regression", "managed-grant")]
    [string]$Mode,

    [string]$Repo,
    [string]$SessionId,
    [string]$SessionPath,
    [string]$CodexJs,
    [string]$PromptFile,
    [string[]]$ExpectedPath = @("invoices.html", "src/invoices.js", "styles/main.css"),
    [string]$Python,
    [string]$ResultPath,
    [switch]$Grant,
    [switch]$KeepFixture
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$ProjectRoot = Split-Path -Parent $PSScriptRoot
if (-not $Python) {
    $Python = (Get-Command python.exe -ErrorAction Stop).Source
}
$env:PYTHONPATH = Join-Path $ProjectRoot "src"

function Assert-LastExitCode {
    param([string]$Operation)
    if ($LASTEXITCODE -ne 0) {
        throw "$Operation failed with exit code $LASTEXITCODE"
    }
}

function Invoke-NoTugJson {
    param([string[]]$Arguments)
    $raw = & $Python -m notug_protocol @Arguments
    Assert-LastExitCode "notug $($Arguments -join ' ')"
    return ($raw | ConvertFrom-Json)
}

function Invoke-GitText {
    param([string]$WorkingTree, [string[]]$Arguments)
    $raw = & git.exe -C $WorkingTree @Arguments
    Assert-LastExitCode "git $($Arguments -join ' ')"
    return (($raw | Out-String).Trim())
}

function Get-ProtectedEvidence {
    param([string]$Repository)
    return [ordered]@{
        head = Invoke-GitText $Repository @("rev-parse", "HEAD")
        tree = Invoke-GitText $Repository @("rev-parse", "HEAD^{tree}")
        status = Invoke-GitText $Repository @("status", "--short", "--branch")
        worktree_count = @(
            (& git.exe -C $Repository worktree list --porcelain) |
                Where-Object { $_ -like "worktree *" }
        ).Count
    }
}

function Assert-ProtectedUnchanged {
    param($Before, $After)
    foreach ($field in @("head", "tree", "status")) {
        if ($Before[$field] -ne $After[$field]) {
            throw "Protected repository $field changed during the smoke mode"
        }
    }
}

function Write-Result {
    param([System.Collections.IDictionary]$Result)
    $json = $Result | ConvertTo-Json -Depth 12
    if ($ResultPath) {
        $destination = [IO.Path]::GetFullPath($ResultPath)
        $parent = Split-Path -Parent $destination
        if ($parent) {
            New-Item -ItemType Directory -Force -Path $parent | Out-Null
        }
        [IO.File]::WriteAllText($destination, $json + [Environment]::NewLine)
    }
    $json
}

function Require-PathValue {
    param([string]$Name, [string]$Value)
    if (-not $Value) {
        throw "$Name is required for mode $Mode"
    }
    return [IO.Path]::GetFullPath($Value)
}

if ($Mode -eq "cwd-probe") {
    $Repo = Require-PathValue "-Repo" $Repo
    $SessionPath = Require-PathValue "-SessionPath" $SessionPath
    if (-not $SessionId) {
        throw "-SessionId is required for mode cwd-probe"
    }
    $before = Get-ProtectedEvidence $Repo
    $probe = & $Python -m notug_protocol run $SessionId -- powershell.exe -NoProfile -Command `
        'Get-Location; $PWD.Path; git rev-parse --show-toplevel; git status --short --branch'
    Assert-LastExitCode "NoTUG CWD probe"
    $after = Get-ProtectedEvidence $Repo
    Assert-ProtectedUnchanged $before $after
    $normalizedProbe = (($probe | Out-String) -replace "\\", "/")
    $normalizedSession = ($SessionPath -replace "\\", "/")
    if (-not $normalizedProbe.Contains($normalizedSession)) {
        throw "CWD probe did not report the exact managed session path"
    }
    Write-Result ([ordered]@{
        mode = $Mode
        ok = $true
        session_id = $SessionId
        child_worktree_exact = $true
        protected_checkout_unchanged = $true
        mutation_lock = "active"
    })
    exit 0
}

if ($Mode -eq "archive-regression") {
    $fixture = Join-Path ([IO.Path]::GetTempPath()) ("notug-archive-smoke-" + [guid]::NewGuid())
    $fixtureRepo = Join-Path $fixture "repository"
    $previousHome = $env:NOTUG_HOME
    try {
        New-Item -ItemType Directory -Path $fixtureRepo | Out-Null
        $env:NOTUG_HOME = Join-Path $fixture "vault"
        & git.exe -C $fixtureRepo init --initial-branch=main | Out-Null
        Assert-LastExitCode "git init"
        & git.exe -C $fixtureRepo config user.name "NoTUG Smoke Test"
        & git.exe -C $fixtureRepo config user.email "notug-smoke@localhost.invalid"
        [IO.File]::WriteAllText((Join-Path $fixtureRepo "proposal.txt"), "baseline`n")
        & git.exe -C $fixtureRepo add --all
        & git.exe -C $fixtureRepo commit -m "Synthetic archive baseline" | Out-Null
        Assert-LastExitCode "git baseline commit"

        Invoke-NoTugJson @("init", $fixtureRepo, "--json") | Out-Null
        $session = Invoke-NoTugJson @(
            "session", "start", $fixtureRepo, "--name", "archive-regression", "--json"
        )
        [IO.File]::WriteAllText((Join-Path $session.workspace "proposal.txt"), "reviewed`n")
        $tug = Invoke-NoTugJson @("tug", $session.session_id, "--json")
        Invoke-NoTugJson @("deny", $tug.tug.tug_id, "--json") | Out-Null
        $before = Invoke-NoTugJson @("verify", $fixtureRepo, "--json")
        $archive = Invoke-NoTugJson @("session", "archive", $session.session_id, "--json")
        $after = Invoke-NoTugJson @("verify", $fixtureRepo, "--json")

        $duplicateRaw = & $Python -m notug_protocol session archive $session.session_id --json
        $duplicateExit = $LASTEXITCODE
        $duplicate = $duplicateRaw | ConvertFrom-Json
        $final = Invoke-NoTugJson @("verify", $fixtureRepo, "--json")
        if ($duplicateExit -eq 0 -or $duplicate.error.code -ne "SESSION_ALREADY_ARCHIVED") {
            throw "Duplicate archive did not fail precisely as SESSION_ALREADY_ARCHIVED"
        }
        if ($after.checks.receipt_chain.event_count -ne $final.checks.receipt_chain.event_count) {
            throw "Duplicate archive changed the receipt count"
        }
        Write-Result ([ordered]@{
            mode = $Mode
            ok = $true
            first_archive_success = [bool]$archive.archived
            duplicate_error = $duplicate.error.code
            receipt_events_before = $before.checks.receipt_chain.event_count
            receipt_events_after = $after.checks.receipt_chain.event_count
            duplicate_changed_receipts = $false
            protected_checkout_unchanged = $true
            mutation_lock = "active"
        })
    }
    finally {
        $env:NOTUG_HOME = $previousHome
        if (-not $KeepFixture -and (Test-Path -LiteralPath $fixture)) {
            Remove-Item -LiteralPath $fixture -Recurse -Force
        }
    }
    exit 0
}

$Repo = Require-PathValue "-Repo" $Repo
$CodexJs = Require-PathValue "-CodexJs" $CodexJs
$PromptFile = Require-PathValue "-PromptFile" $PromptFile
$before = Get-ProtectedEvidence $Repo
$session = Invoke-NoTugJson @(
    "session", "start", $Repo, "--name", "managed-grant-smoke", "--json"
)
$prompt = [IO.File]::ReadAllText($PromptFile)
& $Python -m notug_protocol run $session.session_id -- node.exe $CodexJs exec --ephemeral `
    --sandbox workspace-write $prompt
Assert-LastExitCode "managed Codex run"
$changed = @(& git.exe -C $session.workspace status --short | ForEach-Object {
    if ($_.Length -lt 4) { throw "Unexpected Git status record: $_" }
    $_.Substring(3).Replace("\\", "/")
}) | Sort-Object -Unique
$expected = @($ExpectedPath | ForEach-Object { $_.Replace("\\", "/") }) | Sort-Object -Unique
if (($changed -join "`n") -ne ($expected -join "`n")) {
    throw "Managed Codex changed paths outside the expected boundary"
}
$tug = Invoke-NoTugJson @("tug", $session.session_id, "--json")
& $Python -m notug_protocol review $tug.tug.tug_id --diff
Assert-LastExitCode "Tug review"
$grantPayload = $null
$archivePayload = $null
if ($Grant) {
    $grantRaw = & $Python -m notug_protocol grant $tug.tug.tug_id --json
    Assert-LastExitCode "interactive exact-hash grant"
    $grantPayload = $grantRaw | ConvertFrom-Json
    $archivePayload = Invoke-NoTugJson @(
        "session", "archive", $session.session_id, "--json"
    )
}
$after = Get-ProtectedEvidence $Repo
Assert-ProtectedUnchanged $before $after
$verification = Invoke-NoTugJson @("verify", $Repo, "--json")
Write-Result ([ordered]@{
    mode = $Mode
    ok = $true
    session_id = $session.session_id
    tug_id = $tug.tug.tug_id
    tug_hash = $tug.tug.tug_hash
    changed_paths = $changed
    grant = if ($Grant) { "completed" } else { "awaiting_explicit_human_ceremony" }
    grant_id = if ($Grant) { $grantPayload.grant.grant_id } else { $null }
    integration_branch = if ($Grant) { $grantPayload.grant.branch } else { $null }
    archived = if ($Grant) { [bool]$archivePayload.archived } else { $false }
    verification_ok = [bool]$verification.ok
    receipt_event_count = $verification.checks.receipt_chain.event_count
    protected_checkout_unchanged = $true
    mutation_lock = "active"
})
