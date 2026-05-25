#Requires -Version 5.1
# Shai-Hulud Guard -- Windows Installer
# Protects against ALL known Shai-Hulud / Mini Shai-Hulud npm supply chain attacks
#
# Usage:
#   cd shai-hulud-guard
#   powershell -ExecutionPolicy Bypass -File install.ps1

$ErrorActionPreference = 'Stop'

$InstallDir = Join-Path $env:USERPROFILE '.shai-hulud-guard'
$BlocklistDir = Join-Path $InstallDir 'blocklist'
$BinDir = Join-Path $InstallDir 'bin'
$LogDir = Join-Path $InstallDir 'log'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host ''
Write-Host '  +=============================================+' -ForegroundColor Cyan
Write-Host '  |       SHAI-HULUD GUARD INSTALLER            |' -ForegroundColor Cyan
Write-Host '  |   npm supply chain attack protection        |' -ForegroundColor Cyan
Write-Host '  |              (Windows)                      |' -ForegroundColor Cyan
Write-Host '  +=============================================+' -ForegroundColor Cyan
Write-Host ''

New-Item -ItemType Directory -Path $BlocklistDir, $BinDir, $LogDir -Force | Out-Null

# Step 1: Install blocklist
Write-Host '[1/4] Installing compromised package blocklist...' -ForegroundColor Yellow
$BlocklistSource = Join-Path $ScriptDir 'blocklist\shai-hulud-blocked-packages.txt'
if (Test-Path $BlocklistSource) {
    Copy-Item $BlocklistSource -Destination $BlocklistDir -Force
} else {
    Write-Host 'Error: blocklist\shai-hulud-blocked-packages.txt not found' -ForegroundColor Red
    Write-Host 'Make sure you are running this from the shai-hulud-guard repo directory'
    exit 1
}
$BlockedCount = (Get-Content (Join-Path $BlocklistDir 'shai-hulud-blocked-packages.txt') |
    Where-Object { $_ -and $_ -notmatch '^\s*#' }).Count
Write-Host "  Installed $BlockedCount blocked package versions" -ForegroundColor Green

# Step 2: Install scripts
Write-Host '[2/4] Installing scanner and guard scripts...' -ForegroundColor Yellow
Copy-Item (Join-Path $ScriptDir 'bin\shai-hulud-scan.ps1') -Destination $BinDir -Force
Copy-Item (Join-Path $ScriptDir 'bin\shai-hulud-monitor.ps1') -Destination $BinDir -Force
Write-Host "  Scanner installed at $BinDir" -ForegroundColor Green

# Step 3: Install scheduled task
Write-Host '[3/4] Installing background monitor (Task Scheduler)...' -ForegroundColor Yellow

$TaskName = 'ShaiHuludGuardMonitor'
$MonitorScript = Join-Path $BinDir 'shai-hulud-monitor.ps1'

Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue

$VbsWrapper = Join-Path $BinDir 'run-monitor.vbs'
Set-Content -Path $VbsWrapper -Value @"
Set objShell = CreateObject("WScript.Shell")
objShell.Run "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File ""$MonitorScript""", 0, True
"@

$Action = New-ScheduledTaskAction -Execute 'wscript.exe' `
    -Argument "`"$VbsWrapper`""

$Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) `
    -RepetitionInterval (New-TimeSpan -Minutes 5)

$Settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 2)

Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger `
    -Settings $Settings -Description 'Shai-Hulud Guard: npm supply chain attack monitor' | Out-Null

Write-Host '  Task Scheduler job installed (runs every 5 minutes)' -ForegroundColor Green

# Step 4: Install PowerShell profile functions
Write-Host '[4/4] Installing safe install aliases...' -ForegroundColor Yellow

$ProfilePath = $PROFILE.CurrentUserCurrentHost
$ProfileDir = Split-Path $ProfilePath -Parent
if (-not (Test-Path $ProfileDir)) {
    New-Item -ItemType Directory -Path $ProfileDir -Force | Out-Null
}
if (-not (Test-Path $ProfilePath)) {
    New-Item -ItemType File -Path $ProfilePath -Force | Out-Null
}

$existingProfile = Get-Content $ProfilePath -Raw -ErrorAction SilentlyContinue
if ($existingProfile -and $existingProfile -match 'shai-hulud-guard') {
    Write-Host "  PowerShell profile functions already installed in $ProfilePath" -ForegroundColor Green
} else {
    $profileBlock = @'

# === Shai-Hulud Guard: npm supply chain protection ===
# Forces --ignore-scripts on install commands and scans for compromised packages after
function safe-npm {
    $npmExe = (Get-Command npm.cmd -ErrorAction SilentlyContinue).Source
    if (-not $npmExe) { $npmExe = 'npm.cmd' }
    if ($args.Count -gt 0 -and $args[0] -in 'install','i','ci','add') {
        Write-Host "[shai-hulud-guard] Running npm $($args -join ' ') --ignore-scripts"
        & $npmExe @args --ignore-scripts
        Write-Host "[shai-hulud-guard] Scanning for compromised packages..."
        & "$env:USERPROFILE\.shai-hulud-guard\bin\shai-hulud-scan.ps1" -Path .
    } else {
        & $npmExe @args
    }
}
function safe-pnpm {
    $pnpmExe = (Get-Command pnpm.cmd -ErrorAction SilentlyContinue).Source
    if (-not $pnpmExe) { $pnpmExe = 'pnpm.cmd' }
    if ($args.Count -gt 0 -and $args[0] -in 'install','i','add') {
        Write-Host "[shai-hulud-guard] Running pnpm $($args -join ' ') --ignore-scripts"
        & $pnpmExe @args --ignore-scripts
        Write-Host "[shai-hulud-guard] Scanning for compromised packages..."
        & "$env:USERPROFILE\.shai-hulud-guard\bin\shai-hulud-scan.ps1" -Path .
    } else {
        & $pnpmExe @args
    }
}
function safe-yarn {
    $yarnExe = (Get-Command yarn.cmd -ErrorAction SilentlyContinue).Source
    if (-not $yarnExe) { $yarnExe = 'yarn.cmd' }
    if ($args.Count -gt 0 -and $args[0] -in 'install','add') {
        Write-Host "[shai-hulud-guard] Running yarn $($args -join ' ') --ignore-scripts"
        & $yarnExe @args --ignore-scripts
        Write-Host "[shai-hulud-guard] Scanning for compromised packages..."
        & "$env:USERPROFILE\.shai-hulud-guard\bin\shai-hulud-scan.ps1" -Path .
    } else {
        & $yarnExe @args
    }
}
Set-Alias -Name npm -Value safe-npm -Scope Global -Option AllScope
Set-Alias -Name pnpm -Value safe-pnpm -Scope Global -Option AllScope
Set-Alias -Name yarn -Value safe-yarn -Scope Global -Option AllScope
function shai-hulud-scan { & "$env:USERPROFILE\.shai-hulud-guard\bin\shai-hulud-scan.ps1" -Path ($args[0] ?? '.') }
# === End Shai-Hulud Guard ===
'@
    Add-Content -Path $ProfilePath -Value $profileBlock
    Write-Host "  PowerShell profile functions added to $ProfilePath" -ForegroundColor Green
}

Write-Host ''
Write-Host 'Installation complete!' -ForegroundColor Green
Write-Host ''
Write-Host '  What''s protected:'
Write-Host "    - npm install / pnpm install / yarn install now run with --ignore-scripts"
Write-Host "    - Every install auto-scans for $BlockedCount known compromised package versions"
Write-Host '    - Background monitor checks your projects every 5 minutes for IOC files'
Write-Host '    - Detects router_init.js, tanstack_runner.js, setup_bun.js, Dune-themed git refs'
Write-Host '    - Monitors for webhook.site exfiltration via DNS cache'
Write-Host ''
Write-Host '  Commands:'
Write-Host '    shai-hulud-scan [dir]    Scan a directory for compromised packages'
Write-Host '    npm install              Now safe by default (--ignore-scripts + scan)'
Write-Host ''
Write-Host "  Restart PowerShell or run '. $ProfilePath' to activate aliases." -ForegroundColor Yellow
Write-Host ''
Write-Host '  Uninstall:'
Write-Host "    Unregister-ScheduledTask -TaskName 'ShaiHuludGuardMonitor' -Confirm:`$false"
Write-Host "    Remove-Item -Recurse -Force '$InstallDir'"
Write-Host '    Remove the "Shai-Hulud Guard" block from your PowerShell profile'
Write-Host ''
