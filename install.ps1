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
    if ($args[$i] -match '^(--(interval|memory-include-cache|include-nics|exclude-nics|include-mountpoint|month-rotate|get-ip-addr-from-nic|enable-gpu|gpu|detailed-gpu|max-retries|disable-compression)(=|$)|-[ir]([0-9]|$))') {
        throw "Removed agent option: $($args[$i]); use panel configuration or administrator migration"
    }
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
        "--disable-remote-control" {
            $RemoteControlDisabled = $true
            $KomariArgs += $args[$i]
            continue
        }
        Default { $KomariArgs += $args[$i] }
    }
}

if (-not $UninstallOnly) {
    # Monitoring does not need the Linux-only trusted host protocol. Retain the
    # legacy shared-path manifest, without claiming v2 administrative support.
    if ($InstallRescue) {
        throw 'Windows monitoring installation does not support --install-rescue.'
    }
    if ($RuntimeIdentity -notin @('service-account', 'current-user')) {
        throw 'Windows monitoring installation requires --install-runtime-identity service-account; LocalSystem installation is not supported.'
    }
    $RemoteControlDisabled = $true
    $KomariArgs += '--disable-remote-control'
}

$IsAdministrator = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltinRole]::Administrator
)
if ($RuntimeIdentity -eq "current-user") { $RuntimeIdentity = "service-account" }
if ($RuntimeIdentity -notin @("root-or-administrator", "service-account")) {
    Log-Error "--install-runtime-identity must be root-or-administrator or service-account"
    exit 1
}
if ($ServiceName -notmatch '^[a-zA-Z0-9][a-zA-Z0-9_.-]*$') {
    throw "Invalid service name: $ServiceName"
}
if (-not $IsAdministrator) {
    Log-Error "Administrator privileges are required to install or uninstall the Agent service."
    exit 1
}
if ([string]::IsNullOrWhiteSpace($InstallDir)) {
    $InstallDir = Join-Path $env:ProgramFiles "Komari"
}
$InstallDir = [IO.Path]::GetFullPath($InstallDir)

switch ($env:PROCESSOR_ARCHITECTURE) {
    "AMD64" { $Arch = "amd64" }
    "ARM64" { $Arch = "arm64" }
    "x86" { $Arch = "386" }
    Default { Log-Error "Unsupported architecture: $env:PROCESSOR_ARCHITECTURE"; exit 1 }
}

function Get-ReleaseVersion {
    $Version = $InstallVersion
    if ([string]::IsNullOrWhiteSpace($Version)) {
        $Releases = Invoke-RestMethod -Uri "https://api.github.com/repos/$ReleaseRepository/releases?per_page=10" -TimeoutSec 30
        $Manifest = "komari-agent-windows-$Arch.exe.release.json"
        $Candidates = @($Releases | Where-Object { -not $_.draft -and $_.assets.name -contains $Manifest })
        $Version = $Candidates | Where-Object { -not $_.prerelease } | Select-Object -First 1 -ExpandProperty tag_name
        if (-not $Version) {
            $Version = $Candidates | Where-Object { $_.prerelease -and $_.tag_name -cmatch '^Snapshot-[0-9]{10}$' } |
                Select-Object -ExpandProperty tag_name | Sort-Object -Descending | Select-Object -First 1
        }
        if (-not $Version) { throw "No signed Windows release found. Specify a signed tag with --install-version." }
    }
    if ($Version -notmatch '^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$' -or $Version -eq "latest") {
        throw "A concrete release tag is required."
    }
    return $Version
}

function Get-ReleaseUrl([string]$Version, [string]$FileName) {
    $Url = "https://github.com/$ReleaseRepository/releases/download/$Version/$FileName"
    if (-not [string]::IsNullOrWhiteSpace($GitHubProxy)) {
        return "$($GitHubProxy.TrimEnd('/'))/$Url"
    }
    return $Url
}

function Quote-Argument([string]$Value) {
    if ($Value -eq "") { return '""' }
    if ($Value -notmatch '[\s"]') { return $Value }
    return '"' + ($Value -replace '(\\*)"', '$1$1\"' -replace '(\\+)$', '$1$1') + '"'
}

function Join-Arguments([string[]]$Values) {
    return (($Values | ForEach-Object { Quote-Argument $_ }) -join ' ')
}

function Get-AgentOption([string]$Name, [string]$Default) {
    $Value = $Default
    for ($Index = 0; $Index -lt $KomariArgs.Count; $Index++) {
        if ($KomariArgs[$Index] -eq $Name) {
            $Value = $KomariArgs[++$Index]
        }
        elseif ($KomariArgs[$Index].StartsWith("${Name}=")) {
            $Value = $KomariArgs[$Index].Substring($Name.Length + 1)
        }
    }
    if (-not [IO.Path]::IsPathRooted($Value)) { $Value = Join-Path $InstallDir $Value }
    return [IO.Path]::GetFullPath($Value)
}

function Assert-NativeCommand([string]$Description) {
    if ($LASTEXITCODE -ne 0) {
        throw "$Description failed with exit code $LASTEXITCODE"
    }
}

function Assert-NoReparsePoint([string]$Path) {
    $Item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    if ($Item -and ($Item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Installation path is a reparse point: $Path"
    }
}

function Initialize-ProtectedInstallDirectory([string]$Path, [string]$ServiceSid) {
    $SystemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $AdminSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $TrustedInstaller = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
    $Trusted = @($SystemSid.Value, $AdminSid.Value, $TrustedInstaller,
        [Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
    $Ancestors = [Collections.Generic.Stack[string]]::new()
    for ($Parent = [IO.DirectoryInfo]::new($Path); $Parent; $Parent = $Parent.Parent) {
        $Ancestors.Push($Parent.FullName)
    }
    if ($Ancestors.Count -lt 2 -or $Path.StartsWith('\\')) { throw "Choose a local installation directory below the volume root." }
    while ($Ancestors.Count -gt 0) {
        $Directory = $Ancestors.Pop()
        Assert-NoReparsePoint $Directory
        [IO.Directory]::CreateDirectory($Directory) | Out-Null
        $Acl = Get-Acl -LiteralPath $Directory
        if ($Acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $Trusted) {
            throw "Installation directory has an untrusted owner: $Directory"
        }
        if ($Ancestors.Count -eq 0) { break }
        $WriteRights = [Security.AccessControl.FileSystemRights]'Write, Delete, DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership'
        if ($Directory -eq [IO.Path]::GetPathRoot($Path)) {
            # The default system volume allows users to create directories at
            # its root. The next path component is checked independently.
            $WriteRights = [Security.AccessControl.FileSystemRights]'Delete, DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership'
        }
        foreach ($Rule in $Acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
            if ($Rule.AccessControlType -eq 'Allow' -and $Rule.IdentityReference.Value -notin $Trusted -and
                -not ($Rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -and
                ($Rule.FileSystemRights -band $WriteRights)) {
                throw "Installation directory has a writable parent: $Directory"
            }
        }
    }

    $ProtectedAcl = [Security.AccessControl.DirectorySecurity]::new()
    $ProtectedAcl.SetOwner($AdminSid)
    $ProtectedAcl.SetAccessRuleProtection($true, $false)
    $ReadSid = [Security.Principal.SecurityIdentifier]::new($ServiceSid)
    foreach ($Sid in @($SystemSid, $AdminSid, $ReadSid)) {
        $Rights = if ($Sid -eq $ReadSid) { 'ReadAndExecute' } else { 'FullControl' }
        $Rule = [Security.AccessControl.FileSystemAccessRule]::new($Sid, $Rights,
            'ContainerInherit, ObjectInherit', 'None', 'Allow')
        $ProtectedAcl.AddAccessRule($Rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $ProtectedAcl
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
    # NSSM can enter Running before its application immediately exits. Give
    # startup errors time to reach the configured restart delay/Paused state.
    Start-Sleep -Seconds 2
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

function Assert-AgentRelease([string]$Binary, [string]$Manifest, [string]$Version, [string]$Stage) {
    $GitRoots = @($env:ProgramW6432, $env:ProgramFiles, ${env:ProgramFiles(x86)}) |
        Where-Object { $_ } | Select-Object -Unique
    $OpenSSL = $GitRoots | ForEach-Object { Join-Path $_ 'Git\usr\bin\openssl.exe' } |
        Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
    if (-not $OpenSSL) { throw "Install Git for Windows (system installation) to verify Agent release signatures." }
    Assert-NoReparsePoint (Split-Path -Parent $OpenSSL)
    Assert-NoReparsePoint $OpenSSL
    if ((Get-Item -LiteralPath $Manifest).Length -gt 16384) { throw "Agent release manifest exceeds 16 KiB." }
    $Signed = Get-Content -LiteralPath $Manifest -Raw | ConvertFrom-Json
    if ($Signed.key_id -cne 'komari-release-8372cfc532b8f1bf') { throw "Unexpected Agent release publisher key." }
    $Payload = [Convert]::FromBase64String($Signed.payload)
    $Signature = [Convert]::FromBase64String($Signed.signature)
    if ($Signature.Length -ne 64) { throw "Invalid Agent release signature length." }
    $KeyFile = Join-Path $Stage 'publisher.der'
    $PayloadFile = Join-Path $Stage 'release.payload'
    $SignatureFile = Join-Path $Stage 'release.signature'
    [IO.File]::WriteAllBytes($KeyFile, [Convert]::FromBase64String('MCowBQYDK2VwAyEABii7plda32t+iJAWXT2zBoy3uOiUuLqZa8dLqwmBQ6o='))
    [IO.File]::WriteAllBytes($PayloadFile, $Payload)
    [IO.File]::WriteAllBytes($SignatureFile, $Signature)
    & $OpenSSL pkeyutl -verify -pubin -keyform DER -inkey $KeyFile -rawin -in $PayloadFile -sigfile $SignatureFile | Out-Null
    Assert-NativeCommand "Verifying the Agent publisher signature"
    $Release = [Text.Encoding]::UTF8.GetString($Payload) | ConvertFrom-Json
    $Digest = (Get-FileHash -LiteralPath $Binary -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($Release.schema -cne 'komari.release.v1' -or $Release.component -cne 'komari-agent' -or
        $Release.version -cne $Version -or $Release.os -cne 'windows' -or $Release.arch -cne $Arch -or
        $Release.sha256 -cne $Digest) {
        throw "Agent release component, version, platform or SHA-256 does not match."
    }
}

function Get-VerifiedNssm([string]$Stage) {
    $NssmVersion = '2.24-101-g897c7ad'
    $ZipPath = Join-Path $Stage 'nssm.zip'
    $ExtractPath = Join-Path $Stage 'nssm'
    for ($Attempt = 1; $Attempt -le 3; $Attempt++) {
        try {
            Invoke-WebRequest -Uri "https://nssm.cc/ci/nssm-$NssmVersion.zip" -OutFile $ZipPath -UseBasicParsing -TimeoutSec 45 -ErrorAction Stop
            break
        } catch {
            $Response = $_.Exception.Response
            $StatusCode = if ($null -ne $Response) { [int]$Response.StatusCode } else { 0 }
            $Transient = $StatusCode -eq 0 -or $StatusCode -in @(408, 429) -or $StatusCode -ge 500
            if (-not $Transient -or $Attempt -eq 3) { throw }
            Write-Warning "NSSM download attempt $Attempt failed. Retrying."
            Start-Sleep -Seconds (2 * $Attempt)
        }
    }
    $Digest = (Get-FileHash -LiteralPath $ZipPath -Algorithm SHA256).Hash
    # Exact archive SHA-256 of the publisher ZIP, also pinned by WinGet.
    if ($Digest -ne '99F5045FFFBFFB745D67FE3A065A953C4A3D9C253B868892D9B685B0EE7D07B8') {
        throw "NSSM archive SHA-256 does not match."
    }
    Expand-Archive -LiteralPath $ZipPath -DestinationPath $ExtractPath
    $NssmArch = if ($Arch -eq '386') { 'win32' } else { 'win64' }
    $Binary = Join-Path $ExtractPath "nssm-$NssmVersion\$NssmArch\nssm.exe"
    if (-not (Test-Path -LiteralPath $Binary -PathType Leaf)) { throw "NSSM archive is missing the platform executable." }
    return $Binary
}

$Version = Get-ReleaseVersion
$AgentPath = Join-Path $InstallDir "komari-agent.exe"
$RuntimeStateDir = Join-Path $env:ProgramData "Komari"
if ($ServiceName -ne "komari-agent") { $RuntimeStateDir = Join-Path $RuntimeStateDir $ServiceName }
$RuntimeStatePath = Get-AgentOption "--runtime-state-file" (Join-Path $RuntimeStateDir "runtime-config.json")
$CredentialsPath = Get-AgentOption "--credentials-file" (Join-Path $RuntimeStateDir "credentials.json")
$PrivilegedStatePath = Get-AgentOption "--privileged-state-file" (Join-Path $RuntimeStateDir "privileged.json")
$ReplayStatePath = Get-AgentOption "--replay-state-file" (Join-Path $RuntimeStateDir "nonces.json")
$ServiceConfigPath = Join-Path $InstallDir "service-config.json"
$LegacyRuntimeStatePath = Join-Path $InstallDir "runtime-config.json"
$LogDir = Join-Path $InstallDir "logs"
$AgentOutputLog = Join-Path $LogDir "agent-stdout.log"
$AgentErrorLog = Join-Path $LogDir "agent-stderr.log"
$UserTaskName = "$ServiceName-CurrentUser"
$RescueServiceName = "$ServiceName-rescue"
$ServiceAccount = "NT AUTHORITY\LocalService"
$ServiceAccountSid = "*S-1-5-19"
# Fail before stopping an existing service or replacing its executable. A root
# rescue installation must not be silently removed by a monitoring update.
if (Get-Service -Name $RescueServiceName -ErrorAction SilentlyContinue) {
    throw "Existing rescue service $RescueServiceName requires explicit removal before installing monitoring-only mode."
}

$Nssm = Join-Path $InstallDir 'nssm.exe'
$AgentFile = "komari-agent-windows-$Arch.exe"
Initialize-ProtectedInstallDirectory $InstallDir 'S-1-5-19'
foreach ($Path in @($AgentPath, $Nssm, $ServiceConfigPath, $LogDir, $LegacyRuntimeStatePath,
    (Join-Path $InstallDir 'privileged.json'))) {
    Assert-NoReparsePoint $Path
}
$Stage = Join-Path $InstallDir ".staging-$([Guid]::NewGuid().ToString('N'))"
$LockPath = Join-Path $InstallDir '.installer.lock'
Assert-NoReparsePoint $LockPath
$InstallLock = [IO.File]::Open($LockPath, 'OpenOrCreate', 'ReadWrite', 'None')
$StagedAgentPath = Join-Path $Stage $AgentFile
$ManifestPath = Join-Path $Stage 'agent.release.json'
$Reg = "$env:SystemRoot\System32\reg.exe"
$Sc = "$env:SystemRoot\System32\sc.exe"
$ParametersKey = "HKLM\SYSTEM\CurrentControlSet\Services\$ServiceName\Parameters"
$PreviousParameters = Join-Path $Stage 'previous-service.reg'
$PreviousService = $null
$InstalledService = $false
$Replacing = $false
$KeepStage = $false
$Backups = @{}
try {
    New-Item -ItemType Directory -Path $Stage | Out-Null
    Invoke-WebRequest -Uri (Get-ReleaseUrl $Version $AgentFile) -OutFile $StagedAgentPath -UseBasicParsing
    Invoke-WebRequest -Uri (Get-ReleaseUrl $Version "$AgentFile.release.json") -OutFile $ManifestPath -UseBasicParsing
    Assert-AgentRelease $StagedAgentPath $ManifestPath $Version $Stage
    $StagedNssm = Get-VerifiedNssm $Stage

    $PreviousService = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
    if ($PreviousService) {
        if ($PreviousService.PathName.Trim('"') -ne $Nssm -or
            $PreviousService.StartName -notin @('LocalService', $ServiceAccount)) {
            throw "Existing service $ServiceName uses a different executable or identity. Migrate it before upgrading."
        }
        & $Reg export $ParametersKey $PreviousParameters /y | Out-Null
        Assert-NativeCommand "Saving the previous service parameters"
    }
    foreach ($Path in @($AgentPath, $Nssm, $ServiceConfigPath)) {
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            $Backup = Join-Path $Stage ("previous-" + [IO.Path]::GetFileName($Path))
            Copy-Item -LiteralPath $Path -Destination $Backup
            $Backups[$Path] = $Backup
        }
        elseif (Test-Path -LiteralPath $Path) { throw "Expected a file at $Path" }
    }

    foreach ($Directory in @($RuntimeStateDir, $LogDir)) {
        Assert-NoReparsePoint $Directory
        New-Item -ItemType Directory -Path $Directory -Force | Out-Null
        & "$env:SystemRoot\System32\icacls.exe" $Directory /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "${ServiceAccountSid}:(OI)(CI)M" | Out-Null
        Assert-NativeCommand "Restricting access to $Directory"
    }
    $LegacyPrivilegedStatePath = Join-Path $InstallDir 'privileged.json'
    foreach ($Migration in @(@($RuntimeStatePath, $LegacyRuntimeStatePath), @($PrivilegedStatePath, $LegacyPrivilegedStatePath))) {
        $Target, $Legacy = $Migration
        Assert-NoReparsePoint $Target
        if (-not (Test-Path -LiteralPath $Target) -and (Test-Path -LiteralPath $Legacy -PathType Leaf)) {
            Copy-Item -LiteralPath $Legacy -Destination $Target
        }
    }
    if ($PreviousService -and $PreviousService.State -ne 'Stopped') {
        Stop-Service -Name $ServiceName -Force
    }
    $Replacing = $true
    Move-Item -LiteralPath $StagedAgentPath -Destination $AgentPath -Force
    Move-Item -LiteralPath $StagedNssm -Destination $Nssm -Force
    # Record the same state paths for the daemon and the enrolling CLI.
    $KomariArgs += @('--runtime-state-file', $RuntimeStatePath, '--credentials-file', $CredentialsPath,
        '--privileged-state-file', $PrivilegedStatePath, '--replay-state-file', $ReplayStatePath)
    $ServiceConfig = @{
        service_name = $ServiceName
        service_user = $ServiceAccount
        init_system = 'windows'
        credentials_file = $CredentialsPath
        runtime_state_file = $RuntimeStatePath
        privileged_state_file = $PrivilegedStatePath
        replay_state_file = $ReplayStatePath
    }
    $StagedConfig = Join-Path $Stage 'service-config.json'
    [IO.File]::WriteAllText($StagedConfig, ($ServiceConfig | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $StagedConfig -Destination $ServiceConfigPath -Force
    if (-not $PreviousService) {
        & $Nssm install $ServiceName $AgentPath | Out-Null
        Assert-NativeCommand "Installing service $ServiceName"
        $InstalledService = $true
        Set-ServiceAccount $ServiceName 'LocalService' $Nssm
        & $Nssm set $ServiceName Start SERVICE_AUTO_START | Out-Null
        Assert-NativeCommand "Configuring automatic startup for $ServiceName"
    }
    $Parameters = [ordered]@{
        Application = $AgentPath
        AppParameters = (Join-Arguments $KomariArgs)
        AppDirectory = $InstallDir
        AppStdout = $AgentOutputLog
        AppStderr = $AgentErrorLog
        AppRotateFiles = '1'
        AppRestartDelay = '5000'
    }
    foreach ($Parameter in $Parameters.Keys) {
        & $Nssm set $ServiceName $Parameter $Parameters[$Parameter] | Out-Null
        Assert-NativeCommand "Configuring $Parameter for $ServiceName"
    }
    & $Nssm set $ServiceName AppExit Default Restart | Out-Null
    Assert-NativeCommand "Configuring restart behavior for $ServiceName"

    $AgentReady = (Test-Path -LiteralPath $CredentialsPath) -or -not [string]::IsNullOrWhiteSpace($AgentToken) -or
        (@($KomariArgs | Where-Object { $_ -eq '--auto-discovery' -or $_ -like '--auto-discovery=?*' -or $_ -like '--token=?*' -or
            $_ -like '-t=?*' -or $_ -eq '--config' -or $_ -like '--config=?*' }).Count -gt 0)
    if ($AgentReady) {
        try { Start-ServiceAndWait $ServiceName }
        catch {
            $Details = Get-ServiceFailureDetails $ServiceName $AgentErrorLog
            if ($Details) { throw "Starting service $ServiceName failed: $Details" }
            throw
        }
    }
    else { Log-Info 'Agent service configured for automatic startup; waiting for enrollment before starting.' }
    if (Get-ScheduledTask -TaskName $UserTaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $UserTaskName -Confirm:$false
    }
}
catch {
    $Failure = $_
    if ($Replacing) {
        try {
            if ($PreviousService -or $InstalledService) { Stop-Service -Name $ServiceName -Force }
            if ($InstalledService) {
                & $Sc delete $ServiceName | Out-Null
                Assert-NativeCommand "Removing the incomplete service"
                Wait-ServiceAbsent $ServiceName
            }
            foreach ($Path in @($AgentPath, $Nssm, $ServiceConfigPath)) {
                if ($Backups.ContainsKey($Path)) { Copy-Item -LiteralPath $Backups[$Path] -Destination $Path -Force }
                elseif (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Force }
            }
            if ($PreviousService) {
                & $Reg delete $ParametersKey /f | Out-Null
                Assert-NativeCommand "Clearing incomplete service parameters"
                & $Reg import $PreviousParameters | Out-Null
                Assert-NativeCommand "Restoring the previous service parameters"
                if ($PreviousService.State -eq 'Running') { Start-ServiceAndWait $ServiceName }
            }
        }
        catch {
            $KeepStage = $true
            throw "Install failed: $Failure. Recovery failed: $_. Saved files: $Stage"
        }
    }
    throw $Failure
}
finally {
    if (-not $KeepStage) { Remove-Item -LiteralPath $Stage -Recurse -Force -ErrorAction SilentlyContinue }
    $InstallLock.Dispose()
}

Log-Success "Monitoring Agent installed as the non-login $ServiceAccount service account."
Log-Success "Komari Agent $Version installation completed."
Log-Info "Monitoring only: remote control, WebSSH, remote execution and rescue are disabled. Windows privileged configuration is not supported."
Log-Info "Runtime identity: $RuntimeIdentity"
Log-Info "Install directory: $InstallDir"
Log-Info "Credentials file: $CredentialsPath"
if (-not $AgentReady) {
    $LoginEndpoint = if ($AgentEndpoint) { $AgentEndpoint } else { "https://panel.example.com" }
    Log-Info "Enroll in Administrator PowerShell:"
    Log-Info ("  & '" + $AgentPath.Replace("'", "''") + "' login --endpoint '" + $LoginEndpoint.Replace("'", "''") + "'")
    Log-Info "Then start the service: Restart-Service -Name '$ServiceName'"
}
