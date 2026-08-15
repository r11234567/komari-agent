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
    # GitHub's latest/download redirect does not consume the unauthenticated
    # REST API quota shared by every machine behind the same public address.
    return "latest"
}

function Get-ReleaseUrl([string]$Version, [string]$FileName) {
    if ($Version -eq "latest") {
        $Url = "https://github.com/$ReleaseRepository/releases/latest/download/$FileName"
    }
    else {
        $Url = "https://github.com/$ReleaseRepository/releases/download/$Version/$FileName"
    }
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

function Set-ServiceAccount([string]$Name, [string]$Account, [string]$NssmPath) {
    & $NssmPath set $Name ObjectName $Account | Out-Null
    Assert-NativeCommand "Configuring the $Account service identity"
    $service = Get-CimInstance Win32_Service -Filter "Name='$Name'" -ErrorAction Stop
    if ($service.StartName -ne $Account -and
        -not ($Account -eq "LocalService" -and $service.StartName -eq "NT AUTHORITY\LocalService") -and
        -not ($Account -eq "LocalSystem" -and $service.StartName -eq "LocalSystem")) {
        throw "Service $Name account is $($service.StartName), expected $Account"
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

function Wait-ServiceAbsent([string]$Name) {
    $deadline = (Get-Date).AddSeconds(30)
    do {
        if (-not (Get-Service -Name $Name -ErrorAction SilentlyContinue)) { return }
        Start-Sleep -Milliseconds 250
    } while ((Get-Date) -lt $deadline)
    throw "Service $Name could not be removed before reinstalling it"
}

function Restore-KomariNetworkIsolation([string]$RescueDirectory) {
    $StatePath = Join-Path $RescueDirectory "network-isolation.json"
    $State = $null
    if (Test-Path $StatePath) {
        try {
            $State = Get-Content $StatePath -Raw | ConvertFrom-Json
        }
        catch {
            throw "Cannot restore active Komari network isolation because $StatePath is invalid"
        }
    }
    Get-NetFirewallRule -Group "Komari Rescue Isolation" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    if ($State) {
        foreach ($Profile in @($State.profiles)) {
            if ($Profile.Name -notin @("Domain", "Private", "Public") -or
                $Profile.DefaultInboundAction -notin @("Allow", "Block", "NotConfigured") -or
                $Profile.DefaultOutboundAction -notin @("Allow", "Block", "NotConfigured")) {
                throw "Cannot restore active Komari network isolation because its firewall profile state is invalid"
            }
            Set-NetFirewallProfile -Profile $Profile.Name `
                -DefaultInboundAction $Profile.DefaultInboundAction `
                -DefaultOutboundAction $Profile.DefaultOutboundAction
        }
        foreach ($RuleName in @($State.disabled_rules)) {
            Get-NetFirewallRule -Name $RuleName -ErrorAction SilentlyContinue | Enable-NetFirewallRule
        }
        Remove-Item $StatePath -Force
    }
}

if ($UninstallOnly) {
	$RescueDirectory = Join-Path $env:ProgramData "Komari\Rescue\$ServiceName-rescue"
    foreach ($Name in @($ServiceName, "$ServiceName-rescue")) {
        Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue
        & sc.exe delete $Name | Out-Null
    }
    Unregister-ScheduledTask -TaskName "$ServiceName-CurrentUser" -Confirm:$false -ErrorAction SilentlyContinue
	Restore-KomariNetworkIsolation $RescueDirectory
    Get-NetFirewallRule -DisplayName "Komari Rescue Helper" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    Remove-Item $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
	Remove-Item $RescueDirectory -Recurse -Force -ErrorAction SilentlyContinue
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
$RuntimeStateDir = Join-Path $env:ProgramData "Komari"
$RuntimeStatePath = Join-Path $RuntimeStateDir "runtime-config.json"
$LegacyRuntimeStatePath = Join-Path $InstallDir "runtime-config.json"
$LogDir = Join-Path $InstallDir "logs"
$AgentOutputLog = Join-Path $LogDir "agent-stdout.log"
$AgentErrorLog = Join-Path $LogDir "agent-stderr.log"
$UserTaskName = "$ServiceName-CurrentUser"
$RescueServiceName = "$ServiceName-rescue"
$ServiceAccount = "NT AUTHORITY\LocalService"
$ServiceAccountSid = "*S-1-5-19"
New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
New-Item -ItemType Directory -Path $RuntimeStateDir -Force | Out-Null
if (-not (Test-Path $RuntimeStatePath) -and (Test-Path $LegacyRuntimeStatePath)) {
    Copy-Item $LegacyRuntimeStatePath $RuntimeStatePath -Force
}

$ExistingTask = Get-ScheduledTask -TaskName $UserTaskName -ErrorAction SilentlyContinue
if ($ExistingTask) { Unregister-ScheduledTask -TaskName $UserTaskName -Confirm:$false }
if ($IsAdministrator) {
    foreach ($Name in @($ServiceName, $RescueServiceName)) {
        $ExistingService = Get-Service -Name $Name -ErrorAction SilentlyContinue
        if ($ExistingService) {
            Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue
            & (Ensure-Nssm) remove $Name confirm | Out-Null
            Wait-ServiceAbsent $Name
        }
    }
    Get-NetFirewallRule -DisplayName "Komari Rescue Helper" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    $PreviousRescueDir = Join-Path $env:ProgramData "Komari\Rescue\$RescueServiceName"
	Restore-KomariNetworkIsolation $PreviousRescueDir
    Remove-Item $PreviousRescueDir -Recurse -Force -ErrorAction SilentlyContinue
}

Remove-Item $AgentOutputLog, $AgentErrorLog -Force -ErrorAction SilentlyContinue

$AgentFile = "komari-agent-windows-$Arch.exe"
Invoke-WebRequest -Uri (Get-ReleaseUrl $Version $AgentFile) -OutFile $AgentPath -UseBasicParsing
$AgentArgumentLine = Join-Arguments $KomariArgs
$RuntimeStateEnvironment = "AGENT_RUNTIME_STATE_FILE=$RuntimeStatePath"

$Nssm = Ensure-Nssm
& $Nssm install $ServiceName $AgentPath | Out-Null
Assert-NativeCommand "Installing service $ServiceName"
& $Nssm set $ServiceName AppParameters $AgentArgumentLine | Out-Null
Assert-NativeCommand "Configuring Agent arguments"
& $Nssm set $ServiceName AppEnvironmentExtra $RuntimeStateEnvironment | Out-Null
Assert-NativeCommand "Configuring the Agent runtime state environment"
& $Nssm set $ServiceName AppDirectory $InstallDir | Out-Null
Assert-NativeCommand "Configuring the working directory for $ServiceName"
& $Nssm set $ServiceName AppStdout $AgentOutputLog | Out-Null
Assert-NativeCommand "Configuring stdout logging for $ServiceName"
& $Nssm set $ServiceName AppStderr $AgentErrorLog | Out-Null
Assert-NativeCommand "Configuring stderr logging for $ServiceName"
& $Nssm set $ServiceName AppRotateFiles 1 | Out-Null
Assert-NativeCommand "Configuring log rotation for $ServiceName"
if ($RuntimeIdentity -eq "service-account") {
    Set-ServiceAccount $ServiceName "LocalService" $Nssm
    & icacls.exe $InstallDir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "${ServiceAccountSid}:(OI)(CI)M" | Out-Null
    Assert-NativeCommand "Granting the service account access to $InstallDir"
    & icacls.exe $RuntimeStateDir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "${ServiceAccountSid}:(OI)(CI)M" | Out-Null
    Assert-NativeCommand "Granting the service account access to $RuntimeStateDir"
    Log-Success "Ordinary Agent installed as the non-login $ServiceAccount service account."
}
else {
    Set-ServiceAccount $ServiceName "LocalSystem" $Nssm
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
    $RescueFile = "komari-agent-rescue-windows-$Arch.exe"
    Invoke-WebRequest -Uri (Get-ReleaseUrl $Version $RescueFile) -OutFile $RescuePath -UseBasicParsing
    $RescueConfig = @{
        Endpoint = $AgentEndpoint
        Token = $AgentToken
        IgnoreUnsafeCert = $IgnoreUnsafeCert
        InstanceIDPath = (Join-Path $RescueDir "rescue-instance")
        Action = @{
            AgentPath = $AgentPath
            RuntimeStatePath = $RuntimeStatePath
            ServiceName = $ServiceName
            RuntimeIdentity = $RuntimeIdentity
            RuntimeUser = $(if ($RuntimeIdentity -eq "service-account") { $ServiceAccount } else { "LocalSystem" })
            ControlPlaneURL = $AgentEndpoint
            IsolationStatePath = (Join-Path $RescueDir "network-isolation.json")
        }
    }
    [IO.File]::WriteAllText($RescueConfigPath, ($RescueConfig | ConvertTo-Json -Depth 4), (New-Object Text.UTF8Encoding($false)))
    & icacls.exe $RescueDir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null
    Assert-NativeCommand "Restricting access to $RescueDir"
    $RescueArguments = Join-Arguments @("--config", $RescueConfigPath)
    & $Nssm install $RescueServiceName $RescuePath | Out-Null
    Assert-NativeCommand "Installing service $RescueServiceName"
    & $Nssm set $RescueServiceName AppParameters $RescueArguments | Out-Null
    Assert-NativeCommand "Configuring rescue helper arguments"
    Set-ServiceAccount $RescueServiceName "LocalSystem" $Nssm
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
