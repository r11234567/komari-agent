# ==============================================================================
# Komari Agent Host Elevation & Demotion Script (Windows PowerShell)
#
# Wakes up privilege elevation or demotion under strict guard conditions:
# 1. Verifies that a signed privileged configuration was actually dispatched by
#    the control plane (checks pending revision, nonce, and expiry in privileged.json).
# 2. Enforces operator confirmation and Windows authentication (admin credentials,
#    leaving audit event log).
# 3. Verifies calling parameters (promote/demote, revision, nonce).
# 4. Updates service definition (ObjectName=LocalSystem or LocalService) and restarts daemon.
# ==============================================================================

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet("promote", "demote")]
    [string]$Action,

    [Parameter(Mandatory = $false)]
    [string]$Revision,

    [Parameter(Mandatory = $false)]
    [string]$Nonce,

    [Parameter(Mandatory = $false)]
    [string]$InstallDir = (Join-Path $env:ProgramFiles "Komari"),

    [Parameter(Mandatory = $false)]
    [string]$ServiceName = "komari-agent"
)

$ErrorActionPreference = "Stop"

function Log-Info { param([string]$Message) Write-Host "[INFO] $Message" -ForegroundColor Cyan }
function Log-Success { param([string]$Message) Write-Host "[SUCCESS] $Message" -ForegroundColor Green }
function Log-Error { param([string]$Message) Write-Host "[SECURITY ERROR] $Message" -ForegroundColor Red }

$IsAdministrator = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltinRole]::Administrator
)

$PrivFile = Join-Path $InstallDir "privileged.json"
$NssmPath = Join-Path $InstallDir "nssm.exe"

# ==============================================================================
# DEMOTE ACTION: Downgrade to unprivileged LocalService account
# ==============================================================================
if ($Action -eq "demote") {
    if (-not $IsAdministrator) {
        Log-Info "Elevating to Administrator to update service configuration..."
        Start-Process powershell -Verb RunAs -Wait -ArgumentList @(
            "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$PSCommandPath`"",
            "demote", "-InstallDir", "`"$InstallDir`"", "-ServiceName", "`"$ServiceName`""
        )
        exit 0
    }

    if (Test-Path $NssmPath) {
        & $NssmPath set $ServiceName ObjectName "LocalService" | Out-Null
    }

    if (Test-Path $PrivFile) {
        $json = Get-Content $PrivFile -Raw | ConvertFrom-Json
        if ($json.active) {
            $json.active.remote_control_enabled = $false
            $json.active.web_ssh_enabled = $false
            $json.active.execution_enabled = $false
        }
        $json | ConvertTo-Json -Depth 6 | Set-Content $PrivFile -Encoding UTF8
    }

    Restart-Service -Name $ServiceName -ErrorAction SilentlyContinue
    Log-Success "Komari Agent demoted to non-privileged LocalService. Remote control disabled."
    exit 0
}

# ==============================================================================
# PROMOTE ACTION: Elevate to LocalSystem service
# ==============================================================================

if ([string]::IsNullOrWhiteSpace($Revision) -or [string]::IsNullOrWhiteSpace($Nonce)) {
    Log-Error "Elevation requires explicit -Revision and -Nonce parameters."
    exit 1
}

if (-not (Test-Path $PrivFile)) {
    Log-Error "Privileged state file not found at: $PrivFile"
    Log-Error "Elevation script cannot be awakened without prior privileged configuration dispatch."
    exit 1
}

# Precondition Check: Validate pending state in privileged.json
$jsonContent = Get-Content $PrivFile -Raw | ConvertFrom-Json
if (-not $jsonContent.pending) {
    Log-Error "No pending configuration waiting in $PrivFile."
    exit 1
}

if ($jsonContent.pending_revision.ToString() -ne $Revision.ToString()) {
    Log-Error "Revision mismatch: expected $Revision, pending is $($jsonContent.pending_revision)."
    exit 1
}

if ($jsonContent.pending_nonce -ne $Nonce) {
    Log-Error "Nonce mismatch: dispatch proof does not match."
    exit 1
}

# UAC Elevation check
if (-not $IsAdministrator) {
    Log-Info "Requesting Windows Administrator authorization via UAC..."
    Start-Process powershell -Verb RunAs -Wait -ArgumentList @(
        "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$PSCommandPath`"",
        "promote", "-Revision", "`"$Revision`"", "-Nonce", "`"$Nonce`"",
        "-InstallDir", "`"$InstallDir`"", "-ServiceName", "`"$ServiceName`""
    )
    exit 0
}

# Operator interactive credential confirmation
Write-Host ""
Write-Host "=================================================================" -ForegroundColor Yellow
Write-Host " [Komari Security Gateway] Windows Privilege Elevation Request   " -ForegroundColor Yellow
Write-Host "=================================================================" -ForegroundColor Yellow
Write-Host "  Target Service:  $ServiceName"
Write-Host "  Target Revision: $Revision"
Write-Host "  Target Nonce:    $Nonce"
Write-Host "  Operator:        $env:USERNAME"
Write-Host "=================================================================" -ForegroundColor Yellow
Write-Host ""

# Mandatory password prompt to bypass saved sessions
$credential = $host.ui.PromptForCredential(
    "Komari Kernel Authorization",
    "Enter Windows Administrator credentials to authorize daemon elevation to LocalSystem:",
    "$env:USERDOMAIN\$env:USERNAME",
    ""
)

if (-not $credential) {
    Log-Error "Operator cancelled authentication prompt. Elevation aborted."
    exit 1
}

# Record audit event in Windows Event Log
try {
    if (-not [System.Diagnostics.EventLog]::SourceExists("KomariElevate")) {
        [System.Diagnostics.EventLog]::CreateEventSource("KomariElevate", "Application")
    }
    [System.Diagnostics.EventLog]::WriteEntry(
        "KomariElevate",
        "Privileged daemon elevation authorized to LocalSystem: Operator=$($credential.UserName), Revision=$Revision, Nonce=$Nonce",
        [System.Diagnostics.EventLogEntryType]::Information,
        4672
    )
}
catch {
    Log-Info "Note: could not write to Windows Event Log: $_"
}

# Update service ObjectName to LocalSystem
if (Test-Path $NssmPath) {
    Log-Info "Configuring $ServiceName to run as LocalSystem..."
    & $NssmPath set $ServiceName ObjectName "LocalSystem" | Out-Null
}

# Promote in privileged.json
$jsonContent.active = $jsonContent.pending
$jsonContent.applied_revision = [uint64]$Revision
$jsonContent.pending = $null
$jsonContent.pending_nonce = ""
$jsonContent.pending_revision = 0
$jsonContent | ConvertTo-Json -Depth 6 | Set-Content $PrivFile -Encoding UTF8

Restart-Service -Name $ServiceName -ErrorAction Stop
Log-Success "Komari Agent successfully elevated to LocalSystem! Revision: $Revision"
Log-Success "Remote control and WebSSH capabilities are now active."
