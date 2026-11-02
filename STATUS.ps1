# TRACEPOINT - STATUS.ps1
# Reports application, dependency, database and Ollama status.
#Requires -Version 5.1
$Root = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $Root
$vpy = Join-Path $Root ".venv\Scripts\python.exe"
$lock = Join-Path $Root "data\tracepoint.lock"

function Line($label,$value,$color){ Write-Host ("  {0,-22}" -f $label) -NoNewline; Write-Host $value -ForegroundColor $color }

Write-Host "==== TRACEPOINT status ====" -ForegroundColor Cyan

# Application
$appState = "stopped"; $appColor = "DarkGray"
if (Test-Path $lock) {
    $pidText = (Get-Content $lock -ErrorAction SilentlyContinue | Select-Object -First 1)
    if ($pidText -match '^\d+$' -and (Get-Process -Id ([int]$pidText) -ErrorAction SilentlyContinue)) {
        $cl = $null
        try { $cl = (Get-CimInstance Win32_Process -Filter "ProcessId=$pidText" -ErrorAction SilentlyContinue).CommandLine } catch {}
        if (-not $cl -or $cl -match "main\.py") {
            $appState = "running (PID $pidText)"; $appColor = "Green"
        } else {
            $appState = "stale lock (PID $pidText is another program)"; $appColor = "Yellow"
        }
    } else { $appState = "stale lock (not running)"; $appColor = "Yellow" }
}
Line "Application:" $appState $appColor

# Virtual environment / dependencies
if (Test-Path $vpy) {
    Line "Virtual env:" "present" "Green"
    & $vpy -c "import rich,requests,dns,phonenumbers" 2>$null
    if ($LASTEXITCODE -eq 0) { Line "Dependencies:" "installed" "Green" }
    else { Line "Dependencies:" "MISSING - run .\INSTALL.ps1" "Red" }
} else {
    Line "Virtual env:" "missing - run .\INSTALL.ps1" "Red"
    Line "Dependencies:" "n/a" "DarkGray"
}

# Database
$db = Join-Path $Root "data\tracepoint.db"
if (Test-Path $db) {
    $size = [math]::Round((Get-Item $db).Length/1KB,1)
    if (Test-Path $vpy) {
        $stats = & $vpy -c "import core.database as d; s=d.get_db().stats(); print('%d investigations, %d findings, %d entities' % (s['investigations'], s['findings'], s['entities']))" 2>$null
        Line "Database:" "$size KB - $stats" "Green"
    } else { Line "Database:" "$size KB" "Green" }
} else { Line "Database:" "not initialized" "Yellow" }

# Ollama
$ollama = "http://127.0.0.1:11434"
$envFile = Join-Path $Root "config\.env"
if (Test-Path $envFile) {
    $line = Get-Content $envFile -ErrorAction SilentlyContinue | Where-Object { $_ -match '^\s*OLLAMA_URL\s*=' } | Select-Object -Last 1
    if ($line) {
        $v = ($line -split '=', 2)[1].Trim().Trim('"').Trim("'")
        if ($v) { $ollama = $v }
    }
}
if ($env:OLLAMA_URL) { $ollama = $env:OLLAMA_URL }
$ollama = $ollama.TrimEnd('/')
try {
    $r = Invoke-WebRequest -Uri "$ollama/api/tags" -TimeoutSec 2 -UseBasicParsing -ErrorAction Stop
    $models = ($r.Content | ConvertFrom-Json).models
    if ($models) { Line "Ollama (AI):" ("online - " + (($models | ForEach-Object { $_.name }) -join ", ")) "Green" }
    else { Line "Ollama (AI):" "online - no models installed" "Yellow" }
} catch { Line "Ollama (AI):" "offline (optional)" "DarkGray" }

Write-Host ""
