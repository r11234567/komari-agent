"""Exercise installer code with temporary files and mocked service managers.

No downloads, accounts, or real services are created. Run with Python 3; Bash
is required, and PowerShell tests run when pwsh/powershell is available.
"""

import json
import os
from pathlib import Path
import plistlib
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SH = (ROOT / "install.sh").read_text(encoding="utf-8")
PS = (ROOT / "install.ps1").read_text(encoding="utf-8")
BASH = (r"C:\Program Files\Git\bin\bash.exe" if os.name == "nt" else shutil.which("bash"))
POWERSHELL = shutil.which("pwsh") or shutil.which("powershell")


def between(source, start, end):
    return source.split(start, 1)[1].split(end, 1)[0]


def ps_function(name):
    return "function " + name + between(PS, "function " + name, "\nfunction ")


class UnixInstallerTests(unittest.TestCase):
    def test_release_resolution_uses_one_signed_release_for_required_components(self):
        resolver = "resolve_release_version() {" + between(SH, "resolve_release_version() {", "# Default values")
        manifest = "komari-agent-linux-amd64.release.json"
        host = "komari-host-linux-amd64.release.json"
        releases = [
            {"tag_name": "1.2.91", "prerelease": False, "draft": False, "assets": [{"name": manifest}]},
            {"tag_name": "Snapshot-2611250102", "prerelease": True, "draft": False, "assets": [{"name": manifest}]},
            {"tag_name": "Snapshot-2611250101", "prerelease": True, "draft": False, "assets": [{"name": manifest}, {"name": host}]},
        ]
        interpreter = shlex.quote(Path(sys.executable).as_posix())
        script = (f'python3() {{ {interpreter} "$@"; }}; '
                  'curl() { cat; }; log_error() { echo "$1" >&2; }; ' + resolver +
                  '\nresolve_release_version linux amd64 "$1" "$2"')
        for requested, host_required, expected in [
            ("", "true", "Snapshot-2611250101"),
            ("", "false", "1.2.91"),
            ("1.2.89", "true", "1.2.89"),
        ]:
            result = subprocess.run([BASH, "-c", script, "resolver", requested, host_required],
                                    input=json.dumps(releases), text=True, capture_output=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), expected)

    def render(self, manager, extra=(), enrolled=False, running=True):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        directory = Path(temporary.name)
        # Forward slashes also work with Git Bash; cygpath avoids MSYS argument
        # conversion when reading files back from Python on Windows.
        root_path = directory.as_posix()
        setup = f"""
test_root={shlex.quote(root_path)}
test_root=$(cd "$test_root" && pwd)
target_dir="$test_root/install space & 'quote%"
mkdir -p "$target_dir" "$test_root/LaunchDaemons"
service_name=komari-test
service_user=root
runtime_identity=root-or-administrator
init_system={shlex.quote(manager)}
rescue_token=''
rescue_endpoint=''
auto_discovery_key=''
log_info() {{ :; }}
log_success() {{ :; }}
log_error() {{ echo "$*" >&2; }}
chown() {{ :; }}
sleep() {{ :; }}
plutil() {{ :; }}
systemctl() {{
    echo "$*" >> "$test_root/commands"
    if [ "$1" = is-active ]; then return {0 if running else 1}; fi
}}
journalctl() {{ echo diagnostics >> "$test_root/commands"; }}
launchctl() {{
    echo "$*" >> "$test_root/commands"
    if [ "$1" = print ]; then echo 'state = {"running" if running else "exited"}'; fi
}}
"""
        parser = "# Parse install-specific arguments" + between(SH, "# Parse install-specific arguments", '\nif { [ -n "$cf_access_client_id"')
        # Select the legacy renderer's standalone validation block. The trusted
        # Linux installer has its own earlier, nested validation; selecting it
        # accidentally executes a real installer instead of rendering fixtures.
        paths = 'if [[ ! "$service_name"' + SH.rsplit('if [[ ! "$service_name"', 1)[1].split('\necho -e "${WHITE}===', 1)[0]
        serializer = 'komari_argv+=("--runtime-state-file"' + between(SH, 'komari_argv+=("--runtime-state-file"', "# Detect init system and configure service")
        manifest = "# Share the exact state paths" + between(SH, "# Share the exact state paths", "# Handle each init system")
        if manager == "systemd":
            renderer = between(SH, 'elif [ "$init_system" = "systemd" ]; then', 'elif [ "$init_system" = "procd" ]; then')
            renderer = renderer.replace('service_file="/etc/systemd/system/${service_name}.service"', 'service_file="$test_root/generated.service"')
        else:
            renderer = between(SH, 'elif [ "$init_system" = "launchd" ]; then', 'elif [ "$init_system" = "upstart" ]; then')
            renderer = renderer.replace('plist_dir="/Library/LaunchDaemons"', 'plist_dir="$test_root/LaunchDaemons"').replace('log_dir="/var/log"', 'log_dir="$test_root"')
        seed = '\nprintf "{}" > "$credentials_path"\n' if enrolled else ""
        script = setup + parser + paths + serializer + seed + manifest + renderer
        # Save the exact raw argv to verify service serialization independently.
        script += '\nprintf "%s\\0" "${komari_argv[@]}" > "$test_root/argv"\n'
        script_path = directory / "render.sh"
        script_path.write_text(script, encoding="utf-8", newline="\n")
        result = subprocess.run([BASH, script_path.as_posix(), *extra], capture_output=True, text=True, timeout=30)
        return directory, result

    def test_systemd_waits_for_enrollment_and_shares_paths(self):
        directory, result = self.render("systemd", ["--credentials-file=custom credentials.json"])
        self.assertEqual(result.returncode, 0, result.stderr)
        commands = (directory / "commands").read_text()
        self.assertIn("enable komari-test.service", commands)
        self.assertNotIn("\nstart ", commands)
        manifest = next(directory.glob("install*/service-config.json"))
        config = json.loads(manifest.read_text())
        self.assertTrue(config["credentials_file"].endswith("/custom credentials.json"))
        unit = (directory / "generated.service").read_text()
        self.assertIn("RestartSec=5", unit)
        self.assertIn('"--credentials-file"', unit)
        # systemd expands %% to % and $$ to $ after parsing ExecStart.
        line = next(line for line in unit.splitlines() if line.startswith("ExecStart="))
        actual = [arg.replace("%%", "%").replace("$$", "$") for arg in shlex.split(line.split("=", 1)[1])][1:]
        expected = (directory / "argv").read_bytes().decode().rstrip("\0").split("\0")
        self.assertEqual(actual, expected)

    def test_systemd_reports_failed_child(self):
        directory, result = self.render("systemd", ["--token", "test-token"], running=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("failed to stay running", result.stderr)
        self.assertIn("diagnostics", (directory / "commands").read_text())

    def test_systemd_starts_existing_enrollment(self):
        directory, result = self.render("systemd", enrolled=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("\nstart komari-test.service", (directory / "commands").read_text())

    def test_systemd_starts_when_auth_is_supplied_through_config(self):
        directory, result = self.render("systemd", ["--config", "agent.json"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("\nstart komari-test.service", (directory / "commands").read_text())

    def test_launchd_escapes_xml_and_preserves_arguments(self):
        directory, result = self.render("launchd", ["--endpoint", "https://panel.test/?a=1&b=2", "--server-name", "node 'one' & <two>", "--token", "test-token"])
        self.assertEqual(result.returncode, 0, result.stderr)
        config = plistlib.loads(next((directory / "LaunchDaemons").glob("*.plist")).read_bytes())
        expected = (directory / "argv").read_bytes().decode().rstrip("\0").split("\0")
        self.assertEqual(config["ProgramArguments"][1:], expected)
        self.assertIn("space & 'quote%", config["WorkingDirectory"])
        self.assertIn("print system/com.komari.komari-test", (directory / "commands").read_text())

    def test_launchd_does_not_equate_bootstrap_with_healthy_child(self):
        _, result = self.render("launchd", ["--token", "test-token"], running=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("failed to stay running", result.stderr)


@unittest.skipUnless(POWERSHELL, "PowerShell unavailable")
class WindowsInstallerTests(unittest.TestCase):
    def run_ps(self, script):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "test.ps1"
            path.write_text(script, encoding="utf-8-sig")
            result = subprocess.run([POWERSHELL, "-NoProfile", "-File", str(path)], capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            return result.stdout

    def test_monitoring_install_is_allowed_without_host_actions(self):
        # Execute the actual parser/gate, before the Windows administrator API.
        # This also covers irm + scriptblock invocation (no script file path).
        preflight = PS.split('$IsAdministrator =', 1)[0]
        script = "$ErrorActionPreference = 'Stop'\n" + r"""
function Check-Install([string[]]$Options, [bool]$ShouldFail) {
    try {
        $result = & ([scriptblock]::Create($Source + [Environment]::NewLine + '$KomariArgs -join "|"')) @Options
        if ($ShouldFail) { throw 'unexpectedly allowed installation' }
        if ($result -notlike '*--disable-remote-control*') { throw 'missing local remote-control deny' }
    }
    catch {
        if (-not $ShouldFail -or $_.Exception.Message -eq 'unexpectedly allowed installation') { throw }
    }
}
"""
        # A here-string avoids interpreting PowerShell quotes/variables twice.
        script += "\n$Source = @'\n" + preflight + "\n'@\n"
        script += r"""
Check-Install @('-e', 'https://panel.test') $false
Check-Install @('--install-runtime-identity', 'current-user') $false
Check-Install @('--install-rescue') $true
Check-Install @('--install-runtime-identity', 'root-or-administrator') $true
Write-Output 'monitoring allowed, administrative installs rejected'
"""
        self.assertIn('monitoring allowed', self.run_ps(script))

    def test_windows_cli_and_nssm_share_all_state_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            escaped_tmp = tmp.replace("'", "''")
            setup = f"""
$ErrorActionPreference = 'Stop'
$InstallDir = Join-Path '{escaped_tmp}' 'install space'
$env:ProgramData = Join-Path '{escaped_tmp}' 'program data'
$ServiceName = 'komari-test'
$RuntimeIdentity = 'service-account'
$KomariArgs = @('--credentials-file=custom credentials.json')
$Stage = Join-Path '{escaped_tmp}' 'staging'
New-Item -ItemType Directory -Path $Stage, $InstallDir | Out-Null
function Get-ReleaseVersion {{ 'test' }}
"""
            functions = "\n".join(ps_function(name) for name in ["Quote-Argument", "Join-Arguments", "Get-AgentOption"])
            layout = "$Version = Get-ReleaseVersion" + between(PS, "$Version = Get-ReleaseVersion", "# Fail before stopping")
            manifest = "# Record the same state paths" + between(PS, "# Record the same state paths", "    if (-not $PreviousService)")
            output = self.run_ps(setup + functions + layout + manifest + '\nGet-Content $ServiceConfigPath -Raw\n')
            config = json.loads(output)
            # Windows PowerShell expands 8.3 temp-directory aliases (RUNNER~1)
            # while Python can retain them. Compare the actual canonical paths.
            self.assertEqual(Path(config["credentials_file"]).resolve(), (Path(tmp) / "install space" / "custom credentials.json").resolve())
            self.assertEqual(Path(config["runtime_state_file"]).resolve(), (Path(tmp) / "program data" / "Komari" / "komari-test" / "runtime-config.json").resolve())
            self.assertTrue(config["privileged_state_file"].endswith("privileged.json"))
            self.assertTrue(config["replay_state_file"].endswith("nonces.json"))

    def test_windows_release_discovery_skips_unsigned_stable_and_drafts(self):
        script = ps_function("Get-ReleaseVersion") + r"""
$Arch = 'amd64'
$InstallVersion = ''
$ReleaseRepository = 'komari/test'
function Invoke-RestMethod {
    param($Uri, $TimeoutSec)
    $present = @(@{ name = 'komari-agent-windows-amd64.exe.release.json' })
    @(
        [PSCustomObject]@{tag_name='1.2.91'; prerelease=$false; draft=$false; assets=@()},
        [PSCustomObject]@{tag_name='Snapshot-2611250103'; prerelease=$true; draft=$true; assets=$present},
        [PSCustomObject]@{tag_name='Snapshot-2611250101'; prerelease=$true; draft=$false; assets=$present},
        [PSCustomObject]@{tag_name='Snapshot-2611250102'; prerelease=$true; draft=$false; assets=$present}
    )
}
Get-ReleaseVersion
$InstallVersion = '1.2.89'
Get-ReleaseVersion
"""
        self.assertEqual(self.run_ps(script).splitlines(), ["Snapshot-2611250102", "1.2.89"])

    def test_nssm_running_with_failed_child_is_rejected(self):
        function = ps_function("Start-ServiceAndWait")
        script = r"""
$ErrorActionPreference = 'Stop'
$script:service = [PSCustomObject]@{Status = [System.ServiceProcess.ServiceControllerStatus]::Stopped}
$script:service | Add-Member ScriptMethod Refresh {}
$script:service | Add-Member ScriptMethod WaitForStatus {param($Status, $Timeout)}
function Get-Service { $script:service }
function Start-Service { $script:service.Status = [System.ServiceProcess.ServiceControllerStatus]::Running }
function Start-Sleep { $script:service.Status = [System.ServiceProcess.ServiceControllerStatus]::Paused }
""" + function + r"""
try { Start-ServiceAndWait 'komari-test'; throw 'accepted failed child' }
catch {
    if ($_.Exception.Message -eq 'accepted failed child') { throw }
    if ($_.Exception.Message -notlike '*Paused*') { throw }
    Write-Output 'rejected failed child'
}
"""
        self.assertIn("rejected failed child", self.run_ps(script))

    def test_nssm_download_retries_then_verifies_archive(self):
        function = "function Get-VerifiedNssm" + between(PS, "function Get-VerifiedNssm", "\n$Version = Get-ReleaseVersion")
        script = function + r"""
$ErrorActionPreference = 'Stop'
$Arch = 'amd64'
$script:attempts = 0
$script:sleeps = @()
$script:expanded = 0
$script:invalid = $false
function Invoke-WebRequest {
    [CmdletBinding()] param($Uri, $OutFile, [switch]$UseBasicParsing, $TimeoutSec)
    if ($TimeoutSec -ne 45 -or $Uri -notlike 'https://nssm.cc/ci/nssm-*') { throw 'unexpected download request' }
    $script:attempts++
    if ($script:attempts -lt 3) {
        $failure = [System.Exception]::new('upstream gateway timeout')
        $failure | Add-Member -NotePropertyName Response -NotePropertyValue @{StatusCode = 504}
        throw $failure
    }
    [IO.File]::WriteAllText($OutFile, 'fixture archive')
}
function Start-Sleep { param($Seconds); $script:sleeps += $Seconds }
function Get-FileHash {
    param($LiteralPath, $Algorithm)
    if (-not (Test-Path $LiteralPath) -or $Algorithm -ne 'SHA256') { throw 'missing archive hash check' }
    $hash = if ($script:invalid) { 'incorrect digest' } else { '99F5045FFFBFFB745D67FE3A065A953C4A3D9C253B868892D9B685B0EE7D07B8' }
    @{Hash = $hash}
}
function Expand-Archive {
    param($LiteralPath, $DestinationPath)
    $script:expanded++
    $dir = Join-Path $DestinationPath 'nssm-2.24-101-g897c7ad/win64'
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    [IO.File]::WriteAllText((Join-Path $dir 'nssm.exe'), 'fixture binary')
}
$stage = Join-Path $PSScriptRoot 'staging'
New-Item -ItemType Directory -Path $stage | Out-Null
$binary = Get-VerifiedNssm $stage
if ((Get-Content $binary) -ne 'fixture binary' -or $script:attempts -ne 3 -or ($script:sleeps -join ',') -ne '2,4') {
    throw 'NSSM download did not recover after two transient errors'
}
$script:invalid = $true
try { Get-VerifiedNssm $stage; throw 'accepted invalid archive' }
catch { if ($_.Exception.Message -notlike '*SHA-256*') { throw } }
if ($script:expanded -ne 1 -or $script:attempts -ne 4) { throw 'retried or extracted an invalid archive' }
Write-Output 'retried NSSM download and verified archive'
"""
        self.assertIn("retried NSSM download and verified archive", self.run_ps(script))


if __name__ == "__main__":
    unittest.main(verbosity=2)
