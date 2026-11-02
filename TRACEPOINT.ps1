# TRACEPOINT - TRACEPOINT.ps1  (primary launcher)
# Verifies the environment, auto-installs on first run, prevents duplicate instances,
# then launches the interactive terminal application.
#Requires -Version 5.1
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $Root

function Info($m){ Write-Host "[*] $m" -ForegroundColor Cyan }
function Ok($m){ Write-Host "[+] $m" -ForegroundColor Green }
function Warn($m){ Write-Host "[!] $m" -ForegroundColor Yellow }
function Die($m){ Write-Host "[x] $m" -ForegroundColor Red; exit 1 }
function Get-OllamaUrl {
    $u = "http://127.0.0.1:11434"
    $f = Join-Path $Root "config\.env"
    if (Test-Path $f) {
        $line = Get-Content $f -ErrorAction SilentlyContinue | Where-Object { $_ -match '^\s*OLLAMA_URL\s*=' } | Select-Object -Last 1
        if ($line) {
            $v = ($line -split '=', 2)[1].Trim().Trim('"').Trim("'")
            if ($v) { $u = $v }
        }
    }
    if ($env:OLLAMA_URL) { $u = $env:OLLAMA_URL }
    return $u.TrimEnd('/')
}

$vpy = Join-Path $Root ".venv\Scripts\python.exe"
$lock = Join-Path $Root "data\tracepoint.lock"

# --- single instance ------------------------------------------------------
if (Test-Path $lock) {
    $pidText = (Get-Content $lock -ErrorAction SilentlyContinue | Select-Object -First 1)
    $running = $false
    if ($pidText -match '^\d+$') {
        $proc = Get-Process -Id ([int]$pidText) -ErrorAction SilentlyContinue
        if ($proc -and $proc.ProcessName -like "python*") {
            $cl = $null
            try { $cl = (Get-CimInstance Win32_Process -Filter "ProcessId=$pidText" -ErrorAction SilentlyContinue).CommandLine } catch {}
            # Trust the process name if the command line cannot be read; if it can, require main.py.
            if (-not $cl -or $cl -match "main\.py") { $running = $true }
        }
    }
    if ($running) { Die "TRACEPOINT already appears to be running (PID $pidText). Use .\STOP.ps1 first." }
    else { Remove-Item $lock -ErrorAction SilentlyContinue }  # stale lock
}

# --- ensure installed -----------------------------------------------------
if (-not (Test-Path $vpy)) {
    Warn "Virtual environment not found - running first-time install..."
    & (Join-Path $Root "INSTALL.ps1")
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $vpy)) { Die "Install did not complete." }
}

# verify deps quickly; reinstall if a module is missing
# (Windows PowerShell 5.1 turns native stderr into a terminating error under "Stop", so relax it for this probe.)
$prevEap = $ErrorActionPreference; $ErrorActionPreference = "Continue"
& $vpy -c "import rich, requests, dns, phonenumbers" 2>&1 | Out-Null
$depsExit = $LASTEXITCODE
$ErrorActionPreference = $prevEap
if ($depsExit -ne 0) {
    Warn "Dependencies missing or broken - reinstalling..."
    & $vpy -m pip install -r (Join-Path $Root "requirements.txt") --quiet
    if ($LASTEXITCODE -ne 0) { Die "Dependency reinstall failed." }
}

# --- DB init --------------------------------------------------------------
& $vpy -c "import core.database as d; d.get_db(); print('[+] database ready (schema v'+str(d.get_db().schema_version())+')')"
if ($LASTEXITCODE -ne 0) { Die "Database initialization failed." }

# --- Ollama status (informational) ---------------------------------------
$ollama = Get-OllamaUrl
try {
    $r = Invoke-WebRequest -Uri "$ollama/api/tags" -TimeoutSec 2 -UseBasicParsing -ErrorAction Stop
    Ok "Ollama detected - AI analysis available."
} catch { Warn "Ollama not detected - AI analysis optional, app runs without it." }

# --- launch ---------------------------------------------------------------
# Ensure Unicode banners/prompts work on Windows consoles that default to a legacy code page.
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"
# Launch Python as a child process so the lock records the application PID (not this
# PowerShell host PID). STOP.ps1 can then verify and stop exactly the right process.
try {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $vpy
    $psi.Arguments = '"main.py"'
    $psi.WorkingDirectory = $Root
    $psi.UseShellExecute = $false
    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $psi
    if (-not $proc.Start()) { throw "Process.Start() returned false" }
} catch {
    Die "Could not start TRACEPOINT: $($_.Exception.Message)"
}
$proc.Id | Set-Content -Encoding ASCII $lock
Ok "Starting TRACEPOINT (PID $($proc.Id))..."
try {
    $proc.WaitForExit()
    if ($proc.ExitCode -ne 0) { Warn "TRACEPOINT exited with code $($proc.ExitCode)." }
} finally {
    $proc.Dispose()
    Remove-Item $lock -ErrorAction SilentlyContinue
    Write-Host "[*] TRACEPOINT stopped." -ForegroundColor Cyan
}
