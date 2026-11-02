# TRACEPOINT - INSTALL.ps1
# Checks prerequisites, creates a virtual environment, installs dependencies,
# initializes the SQLite database, and verifies the install.
#Requires -Version 5.1
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $Root

function Info($m){ Write-Host "[*] $m" -ForegroundColor Cyan }
function Ok($m){ Write-Host "[+] $m" -ForegroundColor Green }
function Warn($m){ Write-Host "[!] $m" -ForegroundColor Yellow }
function Die($m){ Write-Host "[x] $m" -ForegroundColor Red; exit 1 }

Write-Host "==== TRACEPOINT installer ====" -ForegroundColor Cyan

# --- Python ---------------------------------------------------------------
$python = $null
foreach ($cmd in @("python","py -3","python3")) {
    try {
        $v = & cmd /c "$cmd --version" 2>&1
        if ($LASTEXITCODE -eq 0 -and $v -match "Python 3\.(\d+)") {
            if ([int]$Matches[1] -ge 10) { $python = $cmd; Ok "Found $v ($cmd)"; break }
            else { Warn "$v is too old (need 3.10+)" }
        }
    } catch {}
}
if (-not $python) { Die "Python 3.10+ not found. Install from https://www.python.org/downloads/ and re-run." }

# --- venv -----------------------------------------------------------------
$venv = Join-Path $Root ".venv"
if (-not (Test-Path $venv)) {
    Info "Creating virtual environment (.venv)..."
    & cmd /c "$python -m venv `"$venv`""
    if ($LASTEXITCODE -ne 0) { Die "Failed to create virtual environment." }
    Ok "Virtual environment created."
} else { Ok "Virtual environment already present." }

$vpy = Join-Path $venv "Scripts\python.exe"
if (-not (Test-Path $vpy)) { Die "venv python not found at $vpy" }

# --- dependencies ---------------------------------------------------------
Info "Upgrading pip..."
& $vpy -m pip install --upgrade pip --quiet
Info "Installing dependencies from requirements.txt..."
& $vpy -m pip install -r (Join-Path $Root "requirements.txt") --quiet
if ($LASTEXITCODE -ne 0) { Die "Dependency installation failed." }
Ok "Dependencies installed."

# --- folders & env --------------------------------------------------------
foreach ($d in @("data","reports","logs","config","data\backups")) {
    $p = Join-Path $Root $d
    if (-not (Test-Path $p)) { New-Item -ItemType Directory -Path $p | Out-Null }
}
$envFile = Join-Path $Root "config\.env"
if (-not (Test-Path $envFile)) {
@"
# TRACEPOINT local configuration (non-secret). API keys are stored encrypted in the database,
# set them from the app: menu -> API Configuration.
OLLAMA_URL=http://127.0.0.1:11434
"@ | Set-Content -Encoding UTF8 $envFile
    Ok "Created config\.env"
}

# --- initialize DB & verify ----------------------------------------------
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"
Info "Initializing database and verifying modules..."
& $vpy -c "import core.database, core.investigation, main; d=core.database.get_db(); print('schema v'+str(d.schema_version())); print('modules:', ', '.join(core.investigation.SPECS))"
if ($LASTEXITCODE -ne 0) { Die "Verification failed - see output above." }

Ok "Installation complete."
Write-Host ""
Write-Host "Launch with:  .\TRACEPOINT.ps1" -ForegroundColor Cyan
Write-Host "Optional AI:  install Ollama (https://ollama.com), then 'ollama pull qwen2.5-coder:7b'" -ForegroundColor DarkGray
