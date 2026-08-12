param(
  [ValidateSet("version", "verify", "diagnostics", "show-config", "rollback-config")]
  [string]$Action = "diagnostics",
  [string]$AgentBin = $env:KOMARI_AGENT_BIN,
  [Parameter(ValueFromRemainingArguments = $true)]
  [string[]]$Arguments
)

$ErrorActionPreference = "Stop"
if ([string]::IsNullOrWhiteSpace($AgentBin)) { $AgentBin = "komari-agent.exe" }
if ($env:KOMARI_AGENT_SHA256) {
  $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $AgentBin).Hash.ToLowerInvariant()
  if ($actual -ne $env:KOMARI_AGENT_SHA256.ToLowerInvariant()) { throw "agent checksum verification failed" }
}

$timeoutSeconds = 30
if ($env:KOMARI_RECOVER_TIMEOUT) { $timeoutSeconds = [int]$env:KOMARI_RECOVER_TIMEOUT }
$process = Start-Process -FilePath $AgentBin -ArgumentList @("recover", $Action) + $Arguments -NoNewWindow -PassThru
if (-not $process.WaitForExit($timeoutSeconds * 1000)) {
  $process.Kill()
  throw "recovery action timed out"
}
exit $process.ExitCode
