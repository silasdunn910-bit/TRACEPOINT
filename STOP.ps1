# TRACEPOINT - STOP.ps1
# Stops ONLY the TRACEPOINT process recorded in the lock file. Does not touch other
# Python processes.
#Requires -Version 5.1
$Root = Split-Path -Parent $MyInvocation.MyCommand.Definition
$lock = Join-Path $Root "data\tracepoint.lock"

if (-not (Test-Path $lock)) { Write-Host "[*] No TRACEPOINT lock file; nothing to stop." -ForegroundColor Cyan; exit 0 }

$pidText = (Get-Content $lock -ErrorAction SilentlyContinue | Select-Object -First 1)
$clearLock = $true
if ($pidText -match '^\d+$') {
    $proc = Get-Process -Id ([int]$pidText) -ErrorAction SilentlyContinue
    if ($proc -and $proc.ProcessName -like "python*") {
        # Only kill if this python is actually running our main.py. If the command line
        # cannot be verified, leave the process alone (never kill an unrelated Python).
        $isOurs = $false
        $verified = $false
        try {
            $cl = (Get-CimInstance Win32_Process -Filter "ProcessId=$pidText" -ErrorAction SilentlyContinue).CommandLine
            if ($cl) { $verified = $true; $isOurs = $cl -match "main\.py" }
        } catch {}
        if ($verified -and $isOurs) {
            Stop-Process -Id ([int]$pidText) -Force
            Write-Host "[+] Stopped TRACEPOINT (PID $pidText)." -ForegroundColor Green
        } elseif (-not $verified) {
            $clearLock = $false
            Write-Host "[!] Could not verify PID $pidText belongs to TRACEPOINT; leaving it alone." -ForegroundColor Yellow
            Write-Host "[!] Lock kept so STATUS.ps1 still reports the running process." -ForegroundColor Yellow
            Write-Host "[!] Stop it manually only if you are sure it is TRACEPOINT." -ForegroundColor Yellow
        } else {
            Write-Host "[!] PID $pidText is not a TRACEPOINT process; leaving it alone." -ForegroundColor Yellow
        }
    } else {
        Write-Host "[*] Recorded process is not running (stale lock)." -ForegroundColor Cyan
    }
} else {
    Write-Host "[!] Lock file did not contain a valid PID." -ForegroundColor Yellow
}
if ($clearLock) {
    Remove-Item $lock -ErrorAction SilentlyContinue
    Write-Host "[*] Lock cleared." -ForegroundColor Cyan
}
