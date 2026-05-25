#Requires -Version 5.1
# Shai-Hulud Guard -- Scanner (Windows)
# Scans directories for compromised npm packages, IOC files, and exfiltration indicators
#
# Usage:
#   shai-hulud-scan.ps1 [-Path <directory>]

[CmdletBinding()]
param(
    [string]$Path = '.'
)

$ErrorActionPreference = 'Stop'

$GuardHome = if ($env:SHAI_HULUD_GUARD_HOME) { $env:SHAI_HULUD_GUARD_HOME } else { Join-Path $env:USERPROFILE '.shai-hulud-guard' }
$Blocklist = Join-Path $GuardHome 'blocklist\shai-hulud-blocked-packages.txt'

$IOC_ROUTER_INIT_SHA256 = 'ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c'
$IOC_TANSTACK_RUNNER_SHA256 = '2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96'

$DUNE_BRANCHES = 'atreides|cogitor|fedaykin|fremen|futar|gesserit|ghola|harkonnen|heighliner|kanly|kralizec|lasgun|laza|melange|mentat|navigator|ornithopter|phibian|powindah|prana|prescient|sandworm|sardaukar|sayyadina|sietch|siridar|slig|stillsuit|thumper|tleilaxu'

function Scan-Lockfiles {
    param([string]$Dir)
    $found = $false

    Write-Host '[shai-hulud-guard] Scanning lockfiles...' -ForegroundColor Yellow

    $lockfiles = Get-ChildItem -Path $Dir -Recurse -Depth 8 -Include 'package-lock.json','yarn.lock','pnpm-lock.yaml' -File -ErrorAction SilentlyContinue

    foreach ($lockfile in $lockfiles) {
        $content = Get-Content $lockfile.FullName -Raw -ErrorAction SilentlyContinue
        if (-not $content) { continue }

        if ($content -match 'github:tanstack/router#') {
            Write-Host "[CRITICAL] IOC: github:tanstack/router# reference in $($lockfile.FullName)" -ForegroundColor Red
            $found = $true
        }

        if (Test-Path $Blocklist) {
            foreach ($line in Get-Content $Blocklist) {
                if ($line -match '^\s*#' -or [string]::IsNullOrWhiteSpace($line)) { continue }
                if ($content.Contains("`"$line`"")) {
                    Write-Host "[BLOCKED] Compromised package in $($lockfile.FullName): $line" -ForegroundColor Red
                    $found = $true
                }
            }
        }
    }

    return $found
}

function Scan-NodeModules {
    param([string]$Dir)
    $found = $false

    Write-Host '[shai-hulud-guard] Scanning node_modules for IOC files...' -ForegroundColor Yellow

    # router_init.js (primary Mini Shai-Hulud IOC)
    $routerFiles = Get-ChildItem -Path $Dir -Recurse -Depth 8 -Filter 'router_init.js' -File -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match 'node_modules' }

    foreach ($f in $routerFiles) {
        $hash = (Get-FileHash -Path $f.FullName -Algorithm SHA256).Hash.ToLower()
        if ($hash -eq $IOC_ROUTER_INIT_SHA256) {
            Write-Host "[CRITICAL] MALWARE CONFIRMED: $($f.FullName) (hash match)" -ForegroundColor Red
            $found = $true
        } else {
            Write-Host "[SUSPICIOUS] router_init.js at $($f.FullName) (hash: $hash)" -ForegroundColor Yellow
        }
    }

    # tanstack_runner.js
    $runnerFiles = Get-ChildItem -Path $Dir -Recurse -Depth 8 -Filter 'tanstack_runner.js' -File -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match 'node_modules' }

    foreach ($f in $runnerFiles) {
        Write-Host "[CRITICAL] IOC file: $($f.FullName)" -ForegroundColor Red
        $found = $true
    }

    # Shai-Hulud 2.0 IOCs
    $bunFiles = Get-ChildItem -Path $Dir -Recurse -Depth 8 -Include 'setup_bun.js','bun_environment.js' -File -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match 'node_modules' }

    foreach ($f in $bunFiles) {
        Write-Host "[WARNING] Shai-Hulud 2.0 IOC candidate: $($f.FullName)" -ForegroundColor Red
        $found = $true
    }

    # Dune-themed git references in package.json
    $pkgFiles = Get-ChildItem -Path $Dir -Recurse -Depth 8 -Filter 'package.json' -File -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match 'node_modules' } |
        Select-Object -First 500

    foreach ($f in $pkgFiles) {
        $content = Get-Content $f.FullName -Raw -ErrorAction SilentlyContinue
        if ($content -and $content -match "github:.*#.*($DUNE_BRANCHES)") {
            Write-Host "[CRITICAL] Dead-drop git reference in $($f.FullName)" -ForegroundColor Red
            $found = $true
        }
    }

    return $found
}

$resolvedPath = Resolve-Path $Path -ErrorAction Stop

Write-Host ''
Write-Host '========================================' -ForegroundColor Yellow
Write-Host '  SHAI-HULUD GUARD SCANNER' -ForegroundColor Yellow
Write-Host '========================================' -ForegroundColor Yellow
Write-Host "  Scanning: $resolvedPath"
Write-Host ''

$issues = $false

$lockResult = Scan-Lockfiles -Dir $resolvedPath
if ($lockResult) { $issues = $true }
Write-Host ''

$nodeResult = Scan-NodeModules -Dir $resolvedPath
if ($nodeResult) { $issues = $true }
Write-Host ''

if (-not $issues) {
    Write-Host '[OK] No Shai-Hulud indicators found' -ForegroundColor Green
} else {
    Write-Host '[ALERT] Shai-Hulud indicators detected! See above.' -ForegroundColor Red
    Write-Host '  1. Do NOT run any build scripts' -ForegroundColor Red
    Write-Host '  2. Delete node_modules and lockfile' -ForegroundColor Red
    Write-Host '  3. Rotate any npm/GitHub tokens on this machine' -ForegroundColor Red
    Write-Host '  4. Reinstall from clean package versions' -ForegroundColor Red
}

Write-Host ''
if ($issues) { exit 1 }
