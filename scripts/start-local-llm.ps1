<# Start the authenticated bridge and temporary Cloudflare tunnel on Windows.
   Prerequisites: repository .venv, running Ollama, and cloudflared.exe.
   Credentials stay in the current user's LocalAppData directory. #>
[CmdletBinding()]
param([string]$Model = 'qwen2.5-coder:1.5b')
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
$pythonPath = Join-Path $repoRoot '.venv\Scripts\python.exe'
$bridgeHome = Join-Path $env:LOCALAPPDATA 'AIGuardian'
$tunnelPath = Join-Path $bridgeHome 'bin\cloudflared.exe'
if (-not (Test-Path -LiteralPath $pythonPath)) { throw 'Install the repository Python virtual environment first.' }
if (-not (Test-Path -LiteralPath $tunnelPath)) { throw "Download official cloudflared-windows-amd64.exe to $tunnelPath first." }
$models = Invoke-RestMethod 'http://127.0.0.1:11434/api/tags' -TimeoutSec 5
if ($Model -notin $models.models.name) { throw "Run ollama pull $Model before starting the bridge." }
New-Item -ItemType Directory -Force -Path $bridgeHome | Out-Null
$tokenFile = Join-Path $bridgeHome 'ollama-bridge.secret'
if (-not (Test-Path -LiteralPath $tokenFile)) {
    $randomBytes = New-Object byte[] 48
    $generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $generator.GetBytes($randomBytes) } finally { $generator.Dispose() }
    [System.IO.File]::WriteAllText($tokenFile, [Convert]::ToBase64String($randomBytes))
}
& icacls.exe $tokenFile /inheritance:r /grant:r "$($env:USERDOMAIN)\$($env:USERNAME):(R,W)" | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Unable to restrict bridge credential permissions.' }
if (Get-NetTCPConnection -LocalPort 11435 -State Listen -ErrorAction SilentlyContinue) {
    throw 'Port 11435 is already listening. Stop the previous bridge before restarting.'
}
$env:OLLAMA_BRIDGE_TOKEN = [System.IO.File]::ReadAllText($tokenFile).Trim()
$env:OLLAMA_BRIDGE_MODEL = $Model
try {
    $bridgeProcess = Start-Process -FilePath $pythonPath -ArgumentList '-m uvicorn scanner.ollama_bridge:create_bridge --factory --host 127.0.0.1 --port 11435 --no-access-log' -WorkingDirectory $repoRoot -WindowStyle Hidden -RedirectStandardOutput (Join-Path $bridgeHome 'bridge.out.log') -RedirectStandardError (Join-Path $bridgeHome 'bridge.err.log') -PassThru
} finally { Remove-Item Env:OLLAMA_BRIDGE_TOKEN }
$bridgeProcess.Id | Set-Content (Join-Path $bridgeHome 'bridge.pid')
try {
    $tunnelProcess = Start-Process -FilePath $tunnelPath -ArgumentList 'tunnel --url http://127.0.0.1:11435 --no-autoupdate' -WindowStyle Hidden -RedirectStandardOutput (Join-Path $bridgeHome 'tunnel.out.log') -RedirectStandardError (Join-Path $bridgeHome 'tunnel.err.log') -PassThru
    $tunnelProcess.Id | Set-Content (Join-Path $bridgeHome 'tunnel.pid')
} catch {
    Stop-Process -Id $bridgeProcess.Id -ErrorAction SilentlyContinue
    throw
}
Write-Output "Bridge PID: $($bridgeProcess.Id); tunnel PID: $($tunnelProcess.Id)"
Write-Output "Read the temporary HTTPS hostname from $bridgeHome\tunnel.err.log."
Write-Output "Copy the credential directly from $tokenFile into Render OLLAMA_API_KEY; never paste it into chat."
