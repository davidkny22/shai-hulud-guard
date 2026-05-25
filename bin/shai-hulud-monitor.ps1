#Requires -Version 5.1
# Shai-Hulud Guard -- Background Monitor (Windows)
# Runs every 5 minutes via Task Scheduler
# Checks all JS/TS projects under common dev directories for IOC indicators

$ErrorActionPreference = 'SilentlyContinue'

$GuardHome = if ($env:SHAI_HULUD_GUARD_HOME) { $env:SHAI_HULUD_GUARD_HOME } else { Join-Path $env:USERPROFILE '.shai-hulud-guard' }
$Blocklist = Join-Path $GuardHome 'blocklist\shai-hulud-blocked-packages.txt'
$LogFile = Join-Path $GuardHome 'log\monitor.log'
$LogDir = Split-Path $LogFile -Parent
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

$IOC_ROUTER_INIT_SHA256 = 'ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c'
$DUNE_BRANCHES = 'atreides|cogitor|fedaykin|fremen|futar|gesserit|ghola|harkonnen|heighliner|kanly|kralizec|lasgun|laza|melange|mentat|navigator|ornithopter|phibian|powindah|prana|prescient|sandworm|sardaukar|sayyadina|sietch|siridar|slig|stillsuit|thumper|tleilaxu'

$WatchDirs = @(
    (Join-Path $env:USERPROFILE 'Documents\GitHub'),
    (Join-Path $env:USERPROFILE 'Projects'),
    (Join-Path $env:USERPROFILE 'dev'),
    (Join-Path $env:USERPROFILE 'code'),
    (Join-Path $env:USERPROFILE 'src'),
    (Join-Path $env:USERPROFILE 'workspace')
)

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Add-Content -Path $LogFile -Value "[$timestamp] $Message"
}

function Send-GuardNotification {
    param([string]$Title, [string]$Message)
    try {
        [void][Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
        [void][Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime]
        $template = @"
<toast>
    <visual>
        <binding template="ToastGeneric">
            <text>$([System.Security.SecurityElement]::Escape($Title))</text>
            <text>$([System.Security.SecurityElement]::Escape($Message))</text>
        </binding>
    </visual>
</toast>
"@
        $xml = New-Object Windows.Data.Xml.Dom.XmlDocument
        $xml.LoadXml($template)
        $toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
        [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('Shai-Hulud Guard').Show($toast)
    } catch {
        # Toast unavailable (older Windows, running as SYSTEM, etc.) -- log-only is fine
    }
}

function Invoke-Check {
    $found = $false

    # -- Process checks --

    # Check for processes with api.github.com/user in command line (credential exfiltration)
    $procs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -and $_.CommandLine -match 'api\.github\.com/user' -and $_.CommandLine -notmatch 'shai-hulud' }
    if ($procs) {
        foreach ($p in $procs) {
            Write-Log "ALERT: Process polling api.github.com/user: PID=$($p.ProcessId) CMD=$($p.CommandLine)"
            Send-GuardNotification 'Shai-Hulud Guard' 'Suspicious GitHub API polling detected!'
        }
        $found = $true
    }

    # Check for webhook.site in DNS cache (exfiltration endpoint)
    $dnsHits = Get-DnsClientCache -ErrorAction SilentlyContinue | Where-Object { $_.Entry -match 'webhook\.site' }
    if ($dnsHits) {
        Write-Log "CRITICAL: webhook.site found in DNS cache"
        Send-GuardNotification 'Shai-Hulud Guard EMERGENCY' 'webhook.site DNS resolution detected!'
        $found = $true
    }

    # Check for active connections to webhook.site IPs
    $tcpConns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
    if ($tcpConns) {
        foreach ($conn in $tcpConns) {
            try {
                $hostname = [System.Net.Dns]::GetHostEntry($conn.RemoteAddress).HostName
                if ($hostname -match 'webhook\.site') {
                    Write-Log "CRITICAL: Active connection to webhook.site: $($conn.RemoteAddress):$($conn.RemotePort)"
                    Send-GuardNotification 'Shai-Hulud Guard EMERGENCY' 'Active webhook.site connection!'
                    $found = $true
                }
            } catch {}
        }
    }

    # -- File system checks --

    foreach ($watchDir in $WatchDirs) {
        if (-not (Test-Path $watchDir)) { continue }

        # IOC: router_init.js in node_modules
        $routerFiles = Get-ChildItem -Path $watchDir -Recurse -Depth 6 -Filter 'router_init.js' -File -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match 'node_modules' } |
            Select-Object -First 5

        foreach ($f in $routerFiles) {
            $hash = (Get-FileHash -Path $f.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
            if ($hash) { $hash = $hash.ToLower() }
            if ($hash -eq $IOC_ROUTER_INIT_SHA256) {
                Write-Log "CRITICAL: MALWARE CONFIRMED: $($f.FullName)"
                Send-GuardNotification 'Shai-Hulud Guard EMERGENCY' 'Shai-Hulud malware found!'
                $found = $true
            }
        }

        # IOC: tanstack_runner.js
        $runner = Get-ChildItem -Path $watchDir -Recurse -Depth 6 -Filter 'tanstack_runner.js' -File -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match 'node_modules' } |
            Select-Object -First 1

        if ($runner) {
            Write-Log "CRITICAL: tanstack_runner.js found: $($runner.FullName)"
            Send-GuardNotification 'Shai-Hulud Guard EMERGENCY' 'tanstack_runner.js found!'
            $found = $true
        }

        # IOC: Shai-Hulud 2.0 files
        $bunIOC = Get-ChildItem -Path $watchDir -Recurse -Depth 6 -Include 'setup_bun.js','bun_environment.js' -File -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match 'node_modules' } |
            Select-Object -First 1

        if ($bunIOC) {
            Write-Log "WARNING: Shai-Hulud 2.0 IOC: $($bunIOC.FullName)"
            Send-GuardNotification 'Shai-Hulud Guard' 'Shai-Hulud 2.0 IOC detected!'
            $found = $true
        }

        # Check recently modified lockfiles against blocklist
        if (Test-Path $Blocklist) {
            $cutoff = (Get-Date).AddMinutes(-10)
            $recentLocks = Get-ChildItem -Path $watchDir -Recurse -Depth 6 -Filter 'package-lock.json' -File -ErrorAction SilentlyContinue |
                Where-Object { $_.FullName -notmatch 'node_modules' -and $_.LastWriteTime -gt $cutoff } |
                Select-Object -First 10

            $blockedEntries = Get-Content $Blocklist | Where-Object { $_ -and $_ -notmatch '^\s*#' }

            foreach ($lockfile in $recentLocks) {
                $content = Get-Content $lockfile.FullName -Raw -ErrorAction SilentlyContinue
                if (-not $content) { continue }
                foreach ($blocked in $blockedEntries) {
                    if ($content.Contains("`"$blocked`"")) {
                        Write-Log "CRITICAL: BLOCKED PACKAGE in $($lockfile.FullName): $blocked"
                        Send-GuardNotification 'Shai-Hulud Guard EMERGENCY' "Blocked: compromised package in lockfile!"
                        $found = $true
                        break
                    }
                }
            }
        }

        # Dune-themed git refs in recently modified package.json
        $cutoff = (Get-Date).AddMinutes(-10)
        $recentPkgs = Get-ChildItem -Path $watchDir -Recurse -Depth 6 -Filter 'package.json' -File -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -notmatch 'node_modules' -and $_.LastWriteTime -gt $cutoff } |
            Select-Object -First 10

        foreach ($pkg in $recentPkgs) {
            $content = Get-Content $pkg.FullName -Raw -ErrorAction SilentlyContinue
            if ($content -and $content -match "github:.*#.*($DUNE_BRANCHES)") {
                Write-Log "CRITICAL: Dead-drop git reference in $($pkg.FullName)"
                Send-GuardNotification 'Shai-Hulud Guard EMERGENCY' 'Shai-Hulud dead-drop reference!'
                $found = $true
            }
        }
    }

    # -- Persistence checks (Windows-specific) --

    # Check for recently created scheduled tasks (suspicious persistence)
    $cutoff = (Get-Date).AddMinutes(-10)
    $newTasks = Get-ScheduledTask -ErrorAction SilentlyContinue |
        Where-Object {
            $_.TaskName -notmatch 'ShaiHuludGuard|Microsoft|Google|Adobe|OneDrive|MicrosoftEdge|Dropbox|Teams' -and
            $_.Date -and
            ([datetime]$_.Date) -gt $cutoff
        }

    if ($newTasks) {
        foreach ($task in $newTasks) {
            Write-Log "ALERT: New scheduled task: $($task.TaskName)"
            Send-GuardNotification 'Shai-Hulud Guard' "New scheduled task detected: $($task.TaskName)"
        }
        $found = $true
    }

    # Check Startup folder for recent additions
    $startupDir = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup'
    if (Test-Path $startupDir) {
        $newStartup = Get-ChildItem -Path $startupDir -File -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -gt $cutoff }
        if ($newStartup) {
            foreach ($item in $newStartup) {
                Write-Log "ALERT: New startup item: $($item.FullName)"
                Send-GuardNotification 'Shai-Hulud Guard' "New startup item: $($item.Name)"
            }
            $found = $true
        }
    }

    if (-not $found) {
        Write-Log 'OK'
    }
}

Invoke-Check
