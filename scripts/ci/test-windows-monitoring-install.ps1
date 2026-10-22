$ErrorActionPreference = 'Stop'
$ServiceName = "komari-monitor-ci-$env:GITHUB_RUN_ID"
if (-not $env:GITHUB_RUN_ID) { $ServiceName = "komari-monitor-ci-$PID" }
$InstallDir = Join-Path $env:ProgramFiles "Komari CI\$ServiceName"
$StateDir = Join-Path $env:ProgramData "Komari\$ServiceName"
$ArtifactDir = Join-Path (Get-Location) 'ci-artifacts'
New-Item -ItemType Directory -Force $ArtifactDir | Out-Null
Start-Transcript -Path (Join-Path $ArtifactDir 'windows-installer.log') -Force

function Assert-Condition($Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

try {
    # Exercise the same in-memory invocation as irm | scriptblock users. Use
    # the released Agent: fixing this installer must not require a new binary.
    $Installer = [scriptblock]::Create((Get-Content ./install.ps1 -Raw))
    $Options = @('--install-dir', $InstallDir, '--install-service-name', $ServiceName,
        '--install-version', '1.2.89', '-e', 'http://127.0.0.1:9')
    & $Installer @Options
    Assert-Condition ((Get-Service $ServiceName).Status -eq 'Stopped') 'Unenrolled service must wait for login'
    $AgentPath = Join-Path $InstallDir 'komari-agent.exe'
    & $AgentPath login --help
    Assert-Condition ($LASTEXITCODE -eq 0) 'Installed login command failed'
    $Manifest = Get-Content (Join-Path $InstallDir 'service-config.json') -Raw | ConvertFrom-Json
    Assert-Condition ($Manifest.service_user -eq 'NT AUTHORITY\LocalService') 'Unexpected service identity'
    Assert-Condition ($Manifest.privileged_state_file -eq (Join-Path $StateDir 'privileged.json')) 'Privileged state must be daemon writable'
    Assert-Condition (-not (Test-Path (Join-Path $InstallDir 'elevate.ps1'))) 'Monitoring must not install elevation scripts'

    # Preserve shared state over a repeat install; a dummy token only keeps the
    # daemon reconnecting to a closed local port. No external panel is contacted.
    $CredentialPath = $Manifest.credentials_file
    [IO.File]::WriteAllText($CredentialPath, '{}')
    & $Installer @Options -t 'ci-monitoring-placeholder'
    Start-Sleep -Seconds 8
    $Service = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
    Assert-Condition ($Service.State -eq 'Running') 'NSSM service did not stay running'
    Assert-Condition ($Service.StartName -in @('LocalService', 'NT AUTHORITY\LocalService')) 'Daemon must run without administrator privileges'
    $Agent = @(Get-CimInstance Win32_Process -Filter "Name='komari-agent.exe'" |
        Where-Object { $_.ExecutablePath -eq $AgentPath })
    Assert-Condition ($Agent.Count -eq 1) 'Expected one live Agent child, not just a running NSSM wrapper'
    Assert-Condition ($Agent[0].CommandLine -like '*--disable-remote-control*') 'Daemon remote control is not locally disabled'
    Assert-Condition ((Get-Content $CredentialPath -Raw) -eq '{}') 'Reinstall changed existing credentials'
    Assert-Condition (-not (Get-Service "$ServiceName-rescue" -ErrorAction SilentlyContinue)) 'Monitoring installed a rescue service'
    $Logs = Get-Content (Join-Path $InstallDir 'logs\agent-stderr.log') -Raw
    Assert-Condition ($Logs -like '*Monitoring Interfaces:*') 'Agent did not reach collectors'
    Assert-Condition ($Logs -notmatch 'Access is denied|permission denied|failed to initialize runtime config|load privileged state:') 'Daemon cannot access its state'
    # Do not query config while its independent disk readers race initialization.
    & $AgentPath config show | Out-File (Join-Path $ArtifactDir 'windows-config.json')
    Assert-Condition ($LASTEXITCODE -eq 0) 'Installed CLI cannot read service state'
    $Config = Get-Content (Join-Path $ArtifactDir 'windows-config.json') -Raw | ConvertFrom-Json
    Assert-Condition (-not $Config.effective_config_from_disk.runtime.remote_control_enabled) 'Effective remote control is enabled'
    Assert-Condition (-not $Config.effective_config_from_disk.privileged.rescue_helper_enabled) 'Effective rescue is enabled'
    Write-Host 'PASS: in-memory install, enrollment paths, LocalService daemon, monitoring, reinstall and local deny'
}
finally {
    # Capture diagnostics before cleanup, even when installation/startup fails.
    try {
        if (Test-Path (Join-Path $InstallDir 'logs')) {
            Copy-Item (Join-Path $InstallDir 'logs') (Join-Path $ArtifactDir 'windows-service-logs') -Recurse -Force
        }
        Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" | Format-List * |
            Out-File (Join-Path $ArtifactDir 'windows-service.txt')
        Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Service Control Manager'} -MaxEvents 60 -ErrorAction SilentlyContinue |
            Format-List TimeCreated, Id, Message | Out-File (Join-Path $ArtifactDir 'windows-scm.log')
    }
    finally {
        Stop-Service $ServiceName -Force -ErrorAction SilentlyContinue
        & sc.exe delete $ServiceName | Out-Null
        Remove-Item $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item $StateDir -Recurse -Force -ErrorAction SilentlyContinue
        Stop-Transcript
    }
}
