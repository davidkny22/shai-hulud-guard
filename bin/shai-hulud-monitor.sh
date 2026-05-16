#!/usr/bin/env bash
# Shai-Hulud Guard -- Background Monitor
# Runs every 5 minutes via LaunchAgent (macOS) or cron (Linux)
# Checks all JS/TS projects under common dev directories for IOC indicators

set -euo pipefail

GUARD_HOME="${SHAI_HULUD_GUARD_HOME:-$HOME/.shai-hulud-guard}"
BLOCKLIST="$GUARD_HOME/blocklist/shai-hulud-blocked-packages.txt"
LOG="$GUARD_HOME/log/monitor.log"
mkdir -p "$(dirname "$LOG")"

IOC_ROUTER_INIT_SHA256="ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c"
DUNE_BRANCHES="atreides|cogitor|fedaykin|fremen|futar|gesserit|ghola|harkonnen|heighliner|kanly|kralizec|lasgun|laza|melange|mentat|navigator|ornithopter|phibian|powindah|prana|prescient|sandworm|sardaukar|sayyadina|sietch|siridar|slig|stillsuit|thumper|tleilaxu"

# Directories to monitor -- add your own dev directories here
WATCH_DIRS=(
  "$HOME/Documents/GitHub"
  "$HOME/Projects"
  "$HOME/dev"
  "$HOME/code"
  "$HOME/src"
  "$HOME/workspace"
)

check() {
  local found=0
  local timestamp=$(date '+%Y-%m-%d %H:%M:%S')

  # Check for processes polling github API (credential exfiltration)
  local github_poll=$(ps aux | grep -i "api.github.com/user" | grep -v grep | grep -v "shai-hulud")
  if [ -n "$github_poll" ]; then
    echo "[$timestamp] ALERT: Process polling api.github.com/user: $github_poll" >> "$LOG"
    if command -v osascript &>/dev/null; then
      osascript -e "display notification \"Suspicious GitHub API polling detected!\" with title \"Shai-Hulud Guard\"" 2>/dev/null
    fi
    found=1
  fi

  # Check for rm -rf (destructive payload)
  local rmrf=$(ps aux | grep "rm -rf" | grep -v grep | grep -v "shai-hulud")
  if [ -n "$rmrf" ]; then
    echo "[$timestamp] CRITICAL: rm -rf process detected: $rmrf" >> "$LOG"
    if command -v osascript &>/dev/null; then
      osascript -e "display notification \"CRITICAL: rm -rf detected!\" with title \"Shai-Hulud Guard EMERGENCY\"" 2>/dev/null
    fi
    found=1
  fi

  # Check for webhook.site connections (exfiltration)
  if command -v lsof &>/dev/null; then
    local webhook_conns=$(lsof -i -nP 2>/dev/null | grep -i "webhook.site" | head -3)
    if [ -n "$webhook_conns" ]; then
      echo "[$timestamp] CRITICAL: webhook.site connection: $webhook_conns" >> "$LOG"
      if command -v osascript &>/dev/null; then
        osascript -e "display notification \"CRITICAL: webhook.site connection!\" with title \"Shai-Hulud Guard EMERGENCY\"" 2>/dev/null
      fi
      found=1
    fi
  fi

  # Scan watch directories for IOC files and recently modified lockfiles
  for watch_dir in "${WATCH_DIRS[@]}"; do
    [ ! -d "$watch_dir" ] && continue

    # IOC: router_init.js in node_modules
    for f in $(find "$watch_dir" -maxdepth 6 -name "router_init.js" -path "*/node_modules/*" 2>/dev/null | head -5); do
      local hash
      if command -v shasum &>/dev/null; then
        hash=$(shasum -a 256 "$f" 2>/dev/null | awk '{print $1}')
      elif command -v sha256sum &>/dev/null; then
        hash=$(sha256sum "$f" 2>/dev/null | awk '{print $1}')
      else
        hash="unknown"
      fi
      if [ "$hash" = "$IOC_ROUTER_INIT_SHA256" ]; then
        echo "[$timestamp] CRITICAL: MALWARE CONFIRMED: $f" >> "$LOG"
        if command -v osascript &>/dev/null; then
          osascript -e "display notification \"CRITICAL: Shai-Hulud malware found!\" with title \"Shai-Hulud Guard EMERGENCY\"" 2>/dev/null
        fi
        found=1
      fi
    done

    # IOC: tanstack_runner.js
    local runner=$(find "$watch_dir" -maxdepth 6 -name "tanstack_runner.js" -path "*/node_modules/*" 2>/dev/null | head -1)
    if [ -n "$runner" ]; then
      echo "[$timestamp] CRITICAL: tanstack_runner.js found: $runner" >> "$LOG"
      if command -v osascript &>/dev/null; then
        osascript -e "display notification \"CRITICAL: tanstack_runner.js found!\" with title \"Shai-Hulud Guard EMERGENCY\"" 2>/dev/null
      fi
      found=1
    fi

    # IOC: Shai-Hulud 2.0 files
    local bun_ioc=$(find "$watch_dir" -maxdepth 6 \( -name "setup_bun.js" -o -name "bun_environment.js" \) -path "*/node_modules/*" 2>/dev/null | head -1)
    if [ -n "$bun_ioc" ]; then
      echo "[$timestamp] WARNING: Shai-Hulud 2.0 IOC: $bun_ioc" >> "$LOG"
      if command -v osascript &>/dev/null; then
        osascript -e "display notification \"Shai-Hulud 2.0 IOC detected!\" with title \"Shai-Hulud Guard\"" 2>/dev/null
      fi
      found=1
    fi

    # Check recently modified lockfiles against blocklist
    if [ -f "$BLOCKLIST" ]; then
      for lockfile in $(find "$watch_dir" -maxdepth 6 -name "package-lock.json" -mmin -10 -not -path "*/node_modules/*" 2>/dev/null | head -10); do
        while IFS= read -r blocked; do
          [[ "$blocked" =~ ^#.*$ || -z "$blocked" ]] && continue
          if grep -qF "\"$blocked\"" "$lockfile" 2>/dev/null; then
            echo "[$timestamp] CRITICAL: BLOCKED PACKAGE in $lockfile: $blocked" >> "$LOG"
            if command -v osascript &>/dev/null; then
              osascript -e "display notification \"BLOCKED: Compromised package in lockfile!\" with title \"Shai-Hulud Guard EMERGENCY\"" 2>/dev/null
            fi
            found=1
            break
          fi
        done < "$BLOCKLIST"
      done
    fi

    # Dune-themed git refs in recently modified package.json
    for pkg in $(find "$watch_dir" -maxdepth 6 -name "package.json" -mmin -10 -not -path "*/node_modules/*" 2>/dev/null | head -10); do
      if grep -qE "github:.*#.*(${DUNE_BRANCHES})" "$pkg" 2>/dev/null; then
        echo "[$timestamp] CRITICAL: Dead-drop git reference in $pkg" >> "$LOG"
        if command -v osascript &>/dev/null; then
          osascript -e "display notification \"CRITICAL: Shai-Hulud dead-drop reference!\" with title \"Shai-Hulud Guard EMERGENCY\"" 2>/dev/null
        fi
        found=1
      fi
    done
  done

  # Check for new LaunchAgents (macOS)
  if [ -d "$HOME/Library/LaunchAgents" ]; then
    local new_agents=$(find "$HOME/Library/LaunchAgents" -mmin -10 -type f 2>/dev/null | \
      grep -v -e "com.google" -e "com.apple" -e "com.setapp" -e "homebrew" -e "shai-hulud-guard" -e "malware-watcher")
    if [ -n "$new_agents" ]; then
      echo "[$timestamp] ALERT: New LaunchAgent: $new_agents" >> "$LOG"
      if command -v osascript &>/dev/null; then
        osascript -e "display notification \"New LaunchAgent detected!\" with title \"Shai-Hulud Guard\"" 2>/dev/null
      fi
      found=1
    fi
  fi

  if [ $found -eq 0 ]; then
    echo "[$timestamp] OK" >> "$LOG"
  fi
}

check
