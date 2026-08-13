# Windows PowerShell installation script for Komari Agent.

$ErrorActionPreference = "Stop"

function Log-Info { param([string]$Message) Write-Host $Message -ForegroundColor Cyan }
function Log-Success { param([string]$Message) Write-Host $Message -ForegroundColor Green }
function Log-Error { param([string]$Message) Write-Host "[ERROR] $Message" -ForegroundColor Red }

$ServiceName = "komari-agent"
$GitHubProxy = ""
$InstallVersion = ""
$ReleaseRepository = "r11234567/komari-agent"
$RuntimeIdentity = "service-account"
$UninstallOnly = $false
$InstallRescue = $false
$InstallRescueFirewall = $false
$InstallDir = ""
$KomariArgs = @()
$AgentEndpoint = ""
$AgentToken = ""
$IgnoreUnsafeCert = $false
$RemoteControlDisabled = $false

for ($i = 0; $i -lt $args.Count; $i++) {
    switch ($args[$i]) {
        "--install-dir" { $InstallDir = $args[++$i]; continue }
        "--install-service-name" { $ServiceName = $args[++$i]; continue }
        "--install-ghproxy" { $GitHubProxy = $args[++$i]; continue }
        "--install-version" { $InstallVersion = $args[++$i]; continue }
        "--install-runtime-identity" { $RuntimeIdentity = $args[++$i]; continue }
        "--uninstall" { $UninstallOnly = $true; continue }
        "--install-rescue" { $InstallRescue = $true; continue }
        "--install-rescue-firewall" { $InstallRescueFirewall = $true; continue }
        { $_ -in @("-e", "--endpoint") } {
            $AgentEndpoint = $args[$i + 1]
            $KomariArgs += $args[$i]
            $KomariArgs += $args[++$i]
            continue
        }
        { $_ -in @("-t", "--token") } {
            $AgentToken = $args[$i + 1]
            $KomariArgs += $args[$i]
            $KomariArgs += $args[++$i]
            continue
        }
        { $_ -in @("-u", "--ignore-unsafe-cert") } {
            $IgnoreUnsafeCert = $true
            $KomariArgs += $args[$i]
            continue
        }
        { $_ -in @("--disable-remote-control", "--disable-web-ssh") } {
            $RemoteControlDisabled = $true
            $KomariArgs += $args[$i]
            continue
        }
        Default { $KomariArgs += $args[$i] }
    }
}

$IsAdministrator = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltinRole]::Administrator
)
if ($RuntimeIdentity -eq "current-user") { $RuntimeIdentity = "service-account" }
if ($RuntimeIdentity -notin @("root-or-administrator", "service-account")) {
    Log-Error "--install-runtime-identity must be root-or-administrator or service-account"
    exit 1
}
if (-not $IsAdministrator) {
    Log-Error "Administrator privileges are required to install or uninstall the Agent service."
    exit 1
}
if ($RuntimeIdentity -eq "service-account" -and -not $RemoteControlDisabled) {
    $RemoteControlDisabled = $true
    $KomariArgs += "--disable-remote-control"
}
if ($InstallRescueFirewall -and -not $InstallRescue) {
    Log-Error "--install-rescue-firewall requires --install-rescue."
    exit 1
}
if ($InstallRescue) {
    if (-not $IsAdministrator) {
        Log-Error "Administrator privileges are required to install the independent rescue helper."
        exit 1
    }
    if (-not $RemoteControlDisabled) {
        Log-Error "The rescue helper is available only when normal remote control is disabled."
        exit 1
    }
    if ([string]::IsNullOrWhiteSpace($AgentEndpoint) -or [string]::IsNullOrWhiteSpace($AgentToken)) {
        Log-Error "The rescue helper requires explicit --endpoint and --token Agent arguments."
        exit 1
    }
}

if ([string]::IsNullOrWhiteSpace($InstallDir)) {
    $InstallDir = Join-Path $env:ProgramFiles "Komari"
}

switch ($env:PROCESSOR_ARCHITECTURE) {
    "AMD64" { $Arch = "amd64" }
    "ARM64" { $Arch = "arm64" }
    "x86" { $Arch = "386" }
    Default { Log-Error "Unsupported architecture: $env:PROCESSOR_ARCHITECTURE"; exit 1 }
}

function Get-ReleaseVersion {
    if (-not [string]::IsNullOrWhiteSpace($InstallVersion)) { return $InstallVersion }
    return (Invoke-RestMethod -Uri "https://api.github.com/repos/$ReleaseRepository/releases/latest" -UseBasicParsing).tag_name
}

function Get-ReleaseUrl([string]$Version, [string]$FileName) {
    $Url = "https://github.com/$ReleaseRepository/releases/download/$Version/$FileName"
    if (-not [string]::IsNullOrWhiteSpace($GitHubProxy)) {
        return "$($GitHubProxy.TrimEnd('/'))/$Url"
    }
    return $Url
}

function Quote-Argument([string]$Value) {
    if ($Value -notmatch '[\s"]') { return $Value }
    return '"' + ($Value -replace '(\\*)"', '$1$1\"' -replace '(\\+)$', '$1$1') + '"'
}

function Join-Arguments([string[]]$Values) {
    return (($Values | ForEach-Object { Quote-Argument $_ }) -join ' ')
}

function Assert-NativeCommand([string]$Description) {
    if ($LASTEXITCODE -ne 0) {
        throw "$Description failed with exit code $LASTEXITCODE"
    }
}

function Start-ServiceAndWait([string]$Name) {
    $InstalledService = Get-Service -Name $Name -ErrorAction Stop
    $InstalledService.Refresh()
    if ($InstalledService.Status -eq [System.ServiceProcess.ServiceControllerStatus]::StopPending) {
        $InstalledService.WaitForStatus(
            [System.ServiceProcess.ServiceControllerStatus]::Stopped,
            [TimeSpan]::FromSeconds(30)
        )
        $InstalledService.Refresh()
    }
    if ($InstalledService.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Paused) {
        Resume-Service -Name $Name -ErrorAction Stop
    }
    elseif ($InstalledService.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
        Start-Service -Name $Name -ErrorAction Stop
    }
    $InstalledService.WaitForStatus(
        [System.ServiceProcess.ServiceControllerStatus]::Running,
        [TimeSpan]::FromSeconds(30)
    )
    $InstalledService.Refresh()
    if ($InstalledService.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running) {
        throw "Service $Name did not reach the Running state (status: $($InstalledService.Status))"
    }
}

function Get-ServiceFailureDetails([string]$Name, [string]$ErrorLogPath) {
    $details = @()
    if (Test-Path $ErrorLogPath) {
        $details += (Get-Content $ErrorLogPath -Raw -ErrorAction SilentlyContinue)
    }
    try {
        $details += (Get-WinEvent -FilterHashtable @{ LogName = "System"; ProviderName = "Service Control Manager" } -MaxEvents 30 -ErrorAction Stop |
            Where-Object { $_.Message -like "*$Name*" } |
            Select-Object -First 1 -ExpandProperty Message)
    }
    catch {
        # Event log access is optional; the NSSM stderr file remains the primary diagnostic.
    }
    return (($details | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join [Environment]::NewLine).Trim()
}

if ($UninstallOnly) {
    foreach ($Name in @($ServiceName, "$ServiceName-rescue")) {
        Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue
        & sc.exe delete $Name | Out-Null
    }
    Unregister-ScheduledTask -TaskName "$ServiceName-CurrentUser" -Confirm:$false -ErrorAction SilentlyContinue
    Get-NetFirewallRule -DisplayName "Komari Rescue Helper" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    Remove-Item $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item (Join-Path $env:ProgramData "Komari\Rescue\$ServiceName-rescue") -Recurse -Force -ErrorAction SilentlyContinue
    Log-Success "Komari Agent uninstalled."
    exit 0
}

function Ensure-Nssm {
    $Existing = Get-Command nssm.exe -ErrorAction SilentlyContinue
    if ($Existing) { return $Existing.Source }
    $NssmPath = Join-Path $InstallDir "nssm.exe"
    if (Test-Path $NssmPath) { return $NssmPath }
    $ZipPath = Join-Path $env:TEMP "komari-nssm.zip"
    $ExtractPath = Join-Path $env:TEMP "komari-nssm"
    Invoke-WebRequest -Uri "https://nssm.cc/release/nssm-2.24.zip" -OutFile $ZipPath -UseBasicParsing
    Remove-Item $ExtractPath -Recurse -Force -ErrorAction SilentlyContinue
    Expand-Archive -Path $ZipPath -DestinationPath $ExtractPath -Force
    $Source = Get-ChildItem -Path $ExtractPath -Recurse -Filter nssm.exe |
        Where-Object { $_.FullName -match '\\win(32|64)\\nssm.exe$' } |
        Select-Object -First 1
    if (-not $Source) { throw "nssm.exe was not found in the downloaded archive" }
    Copy-Item $Source.FullName $NssmPath -Force
    Remove-Item $ZipPath -Force -ErrorAction SilentlyContinue
    Remove-Item $ExtractPath -Recurse -Force -ErrorAction SilentlyContinue
    return $NssmPath
}

$Version = Get-ReleaseVersion
$AgentPath = Join-Path $InstallDir "komari-agent.exe"
$RuntimeStatePath = Join-Path $InstallDir "runtime-config.json"
$LogDir = Join-Path $InstallDir "logs"
$AgentOutputLog = Join-Path $LogDir "agent-stdout.log"
$AgentErrorLog = Join-Path $LogDir "agent-stderr.log"
$UserTaskName = "$ServiceName-CurrentUser"
$RescueServiceName = "$ServiceName-rescue"
$ServiceAccount = "NT AUTHORITY\LocalService"
$ServiceAccountSid = "*S-1-5-19"
New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null

$ExistingTask = Get-ScheduledTask -TaskName $UserTaskName -ErrorAction SilentlyContinue
if ($ExistingTask) { Unregister-ScheduledTask -TaskName $UserTaskName -Confirm:$false }
if ($IsAdministrator) {
    foreach ($Name in @($ServiceName, $RescueServiceName)) {
        $ExistingService = Get-Service -Name $Name -ErrorAction SilentlyContinue
        if ($ExistingService) {
            Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue
            & (Ensure-Nssm) remove $Name confirm | Out-Null
        }
    }
    Get-NetFirewallRule -DisplayName "Komari Rescue Helper" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    $PreviousRescueDir = Join-Path $env:ProgramData "Komari\Rescue\$RescueServiceName"
    Remove-Item $PreviousRescueDir -Recurse -Force -ErrorAction SilentlyContinue
}

$AgentFile = "komari-agent-windows-$Arch.exe"
Invoke-WebRequest -Uri (Get-ReleaseUrl $Version $AgentFile) -OutFile $AgentPath -UseBasicParsing
if ($KomariArgs -notcontains "--runtime-state-file") {
    $KomariArgs += "--runtime-state-file"
    $KomariArgs += $RuntimeStatePath
}
$AgentArgumentLine = Join-Arguments $KomariArgs

$Nssm = Ensure-Nssm
& $Nssm install $ServiceName $AgentPath $AgentArgumentLine | Out-Null
Assert-NativeCommand "Installing service $ServiceName"
& $Nssm set $ServiceName AppDirectory $InstallDir | Out-Null
Assert-NativeCommand "Configuring the working directory for $ServiceName"
& $Nssm set $ServiceName AppStdout $AgentOutputLog | Out-Null
Assert-NativeCommand "Configuring stdout logging for $ServiceName"
& $Nssm set $ServiceName AppStderr $AgentErrorLog | Out-Null
Assert-NativeCommand "Configuring stderr logging for $ServiceName"
& $Nssm set $ServiceName AppRotateFiles 1 | Out-Null
Assert-NativeCommand "Configuring log rotation for $ServiceName"
if ($RuntimeIdentity -eq "service-account") {
    & $Nssm set $ServiceName ObjectName LocalService | Out-Null
    Assert-NativeCommand "Configuring the $ServiceAccount service identity"
    & icacls.exe $InstallDir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "${ServiceAccountSid}:(OI)(CI)M" | Out-Null
    Assert-NativeCommand "Granting the service account access to $InstallDir"
    Log-Success "Ordinary Agent installed as the non-login $ServiceAccount service account."
}
else {
    & $Nssm set $ServiceName ObjectName LocalSystem | Out-Null
    Assert-NativeCommand "Configuring the LocalSystem service identity"
    Log-Success "Ordinary Agent installed as a LocalSystem service."
}
& $Nssm set $ServiceName Start SERVICE_AUTO_START | Out-Null
Assert-NativeCommand "Configuring automatic startup for $ServiceName"
& $Nssm set $ServiceName AppExit Default Restart | Out-Null
Assert-NativeCommand "Configuring restart behavior for $ServiceName"
try {
    Start-ServiceAndWait $ServiceName
}
catch {
    $failureDetails = Get-ServiceFailureDetails $ServiceName $AgentErrorLog
    if ($failureDetails) {
        throw "Starting service $ServiceName failed: $failureDetails"
    }
    throw
}

if ($InstallRescue) {
    $Nssm = Ensure-Nssm
    $RescueDir = Join-Path $env:ProgramData "Komari\Rescue\$RescueServiceName"
    New-Item -ItemType Directory -Path $RescueDir -Force | Out-Null
    $RescuePath = Join-Path $RescueDir "komari-agent-rescue.exe"
    $RescueConfigPath = Join-Path $RescueDir "rescue-helper.json"
    $FirewallMarker = Join-Path $RescueDir "rescue-firewall-managed"
    $RescueFile = "komari-agent-rescue-windows-$Arch.exe"
    Invoke-WebRequest -Uri (Get-ReleaseUrl $Version $RescueFile) -OutFile $RescuePath -UseBasicParsing
    $RescueConfig = @{
        Endpoint = $AgentEndpoint
        Token = $AgentToken
        IgnoreUnsafeCert = $IgnoreUnsafeCert
        FirewallConfigured = $InstallRescueFirewall
        InstanceIDPath = (Join-Path $RescueDir "rescue-instance")
        Action = @{
            AgentPath = $AgentPath
            RuntimeStatePath = $RuntimeStatePath
            ServiceName = $ServiceName
            RuntimeIdentity = $RuntimeIdentity
            RuntimeUser = $(if ($RuntimeIdentity -eq "service-account") { $ServiceAccount } else { "LocalSystem" })
            FirewallMarker = $FirewallMarker
        }
    }
    [IO.File]::WriteAllText($RescueConfigPath, ($RescueConfig | ConvertTo-Json -Depth 4), (New-Object Text.UTF8Encoding($false)))
    & icacls.exe $RescueDir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null
    Assert-NativeCommand "Restricting access to $RescueDir"
    if ($InstallRescueFirewall) {
        Get-NetFirewallRule -DisplayName "Komari Rescue Helper" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
        New-NetFirewallRule -DisplayName "Komari Rescue Helper" -Direction Outbound -Action Allow -Program $RescuePath -Protocol TCP -RemotePort 443 | Out-Null
        New-Item -ItemType File -Path $FirewallMarker -Force | Out-Null
    }
    $RescueArguments = Join-Arguments @("--config", $RescueConfigPath)
    & $Nssm install $RescueServiceName $RescuePath $RescueArguments | Out-Null
    Assert-NativeCommand "Installing service $RescueServiceName"
    & $Nssm set $RescueServiceName ObjectName LocalSystem | Out-Null
    Assert-NativeCommand "Configuring the rescue service identity"
    & $Nssm set $RescueServiceName Start SERVICE_AUTO_START | Out-Null
    Assert-NativeCommand "Configuring automatic startup for $RescueServiceName"
    & $Nssm set $RescueServiceName AppExit Default Restart | Out-Null
    Assert-NativeCommand "Configuring restart behavior for $RescueServiceName"
    Start-ServiceAndWait $RescueServiceName
    Log-Success "Independent rescue helper installed as a LocalSystem service."
}

Log-Success "Komari Agent $Version installation completed."
Log-Info "Runtime identity: $RuntimeIdentity"
Log-Info "Install directory: $InstallDir"
