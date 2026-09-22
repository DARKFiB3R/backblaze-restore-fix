# bz_watch_and_hook.ps1
#
# Watches for bzrestore.exe (re)launching and automatically attaches
# bz_unavailable_patch.js to every new instance, so the fix stays active
# across app restarts without manually re-running the Frida attach
# command every time.
#
# Must run from an ELEVATED PowerShell (Frida process attach needs
# SeDebugPrivilege, even for same-user processes). Leave this window
# running (minimize it) for as long as you want the fix active.
#
# Requires: frida-tools installed (pip install frida-tools) with frida.exe
# reachable - either on PATH, or edit $fridaExe below to point at it
# (e.g. inside a venv's Scripts\ folder).
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File bz_watch_and_hook.ps1

$ErrorActionPreference = 'Stop'
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$patchScript = Join-Path $scriptDir 'bz_unavailable_patch.js'

# Edit this if frida.exe isn't on your PATH (e.g. a venv install):
# $fridaExe = "C:\path\to\venv\Scripts\frida.exe"
$fridaExe = (Get-Command frida.exe -ErrorAction SilentlyContinue).Source
if (-not $fridaExe) { throw "frida.exe not found on PATH - install frida-tools (pip install frida-tools) or set `$fridaExe manually in this script." }
if (-not (Test-Path $patchScript)) { throw "patch script not found at $patchScript" }

$lastPid = -1

Write-Host "[watcher] Started. Watching for bzrestore.exe launches..."
Write-Host "[watcher] Will run: $fridaExe -p <pid> -l $patchScript"

while ($true) {
    $proc = Get-Process bzrestore -ErrorAction SilentlyContinue
    if ($proc -and $proc.Id -ne $lastPid) {
        $targetPid = $proc.Id
        Write-Host "[watcher] $(Get-Date -Format 'HH:mm:ss') New bzrestore.exe PID $targetPid detected - attaching hook..."
        Start-Process powershell -ArgumentList @(
            '-NoProfile',
            '-Command',
            "& '$fridaExe' -p $targetPid -l '$patchScript'"
        ) -WindowStyle Minimized
        $lastPid = $targetPid
    }
    elseif (-not $proc -and $lastPid -ne -1) {
        Write-Host "[watcher] $(Get-Date -Format 'HH:mm:ss') bzrestore.exe (PID $lastPid) exited - will re-attach on next launch."
        $lastPid = -1
    }
    Start-Sleep -Seconds 2
}
