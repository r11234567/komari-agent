# Windows PowerShell installation script for Komari Agent.

function Log-Info { param([string]$Message) Write-Host $Message -ForegroundColor Cyan }
function Log-Success { param([string]$Message) Write-Host $Message -ForegroundColor Green }
function Log-Error { param([string]$Message) Write-Host "[ERROR] $Message" -ForegroundColor Red }

$ServiceName = "komari-agent"
$GitHubProxy = ""
$InstallVersion = ""
$ReleaseRepository = "r11234567/komari-agent"
$RuntimeIdentity = "root-or-administrator"
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
if ($RuntimeIdentity -notin @("root-or-administrator", "current-user")) {
    Log-Error "--install-runtime-identity must be root-or-administrator or current-user"
    exit 1
}
if ($RuntimeIdentity -eq "root-or-administrator" -and -not $IsAdministrator) {
    Log-Error "Administrator privileges are required for root-or-administrator runtime."
    exit 1
}
if ($RuntimeIdentity -eq "current-user" -and -not $RemoteControlDisabled) {
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
    if ($RuntimeIdentity -eq "current-user") {
        $InstallDir = Join-Path $env:LOCALAPPDATA "Komari"
    }
    else {
        $InstallDir = Join-Path $env:ProgramFiles "Komari"
    }
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
$UserTaskName = "$ServiceName-CurrentUser"
$RescueServiceName = "$ServiceName-rescue"
New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null

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

if ($RuntimeIdentity -eq "current-user") {
    $Action = New-ScheduledTaskAction -Execute $AgentPath -Argument $AgentArgumentLine -WorkingDirectory $InstallDir
    $Trigger = New-ScheduledTaskTrigger -AtLogOn -User ([Security.Principal.WindowsIdentity]::GetCurrent().Name)
    $Principal = New-ScheduledTaskPrincipal -UserId ([Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType Interactive -RunLevel Limited
    $Settings = New-ScheduledTaskSettingsSet -RestartCount 99 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero)
    Register-ScheduledTask -TaskName $UserTaskName -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings | Out-Null
    Start-ScheduledTask -TaskName $UserTaskName
    Log-Success "Ordinary Agent installed for the current non-administrator user."
}
else {
    $Nssm = Ensure-Nssm
    & $Nssm install $ServiceName $AgentPath $AgentArgumentLine | Out-Null
    & $Nssm set $ServiceName ObjectName LocalSystem | Out-Null
    & $Nssm set $ServiceName Start SERVICE_AUTO_START | Out-Null
    & $Nssm set $ServiceName AppExit Default Restart | Out-Null
    & $Nssm start $ServiceName | Out-Null
    Log-Success "Ordinary Agent installed as a LocalSystem service."
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
            ServiceName = $(if ($RuntimeIdentity -eq "current-user") { $UserTaskName } else { $ServiceName })
            RuntimeIdentity = $RuntimeIdentity
            RuntimeUser = ([Security.Principal.WindowsIdentity]::GetCurrent().Name)
            FirewallMarker = $FirewallMarker
        }
    }
    [IO.File]::WriteAllText($RescueConfigPath, ($RescueConfig | ConvertTo-Json -Depth 4), (New-Object Text.UTF8Encoding($false)))
    & icacls.exe $RescueDir /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" | Out-Null
    if ($InstallRescueFirewall) {
        Get-NetFirewallRule -DisplayName "Komari Rescue Helper" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
        New-NetFirewallRule -DisplayName "Komari Rescue Helper" -Direction Outbound -Action Allow -Program $RescuePath -Protocol TCP -RemotePort 443 | Out-Null
        New-Item -ItemType File -Path $FirewallMarker -Force | Out-Null
    }
    $RescueArguments = Join-Arguments @("--config", $RescueConfigPath)
    & $Nssm install $RescueServiceName $RescuePath $RescueArguments | Out-Null
    & $Nssm set $RescueServiceName ObjectName LocalSystem | Out-Null
    & $Nssm set $RescueServiceName Start SERVICE_AUTO_START | Out-Null
    & $Nssm set $RescueServiceName AppExit Default Restart | Out-Null
    & $Nssm start $RescueServiceName | Out-Null
    Log-Success "Independent rescue helper installed as a LocalSystem service."
}

Log-Success "Komari Agent $Version installation completed."
Log-Info "Runtime identity: $RuntimeIdentity"
Log-Info "Install directory: $InstallDir"
