#!/usr/bin/env bash
# Shai-Hulud Guard -- Scanner
# Scans directories for compromised npm packages, IOC files, and exfiltration indicators
#
# Usage:
#   shai-hulud-scan.sh scan [directory]

set -euo pipefail

GUARD_HOME="${SHAI_HULUD_GUARD_HOME:-$HOME/.shai-hulud-guard}"
BLOCKLIST="$GUARD_HOME/blocklist/shai-hulud-blocked-packages.txt"

# IOC file hashes
IOC_ROUTER_INIT_SHA256="ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c"
IOC_TANSTACK_RUNNER_SHA256="2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96"

# Dune-themed dead-drop branch names used by the worm
DUNE_BRANCHES="atreides|cogitor|fedaykin|fremen|futar|gesserit|ghola|harkonnen|heighliner|kanly|kralizec|lasgun|laza|melange|mentat|navigator|ornithopter|phibian|powindah|prana|prescient|sandworm|sardaukar|sayyadina|sietch|siridar|slig|stillsuit|thumper|tleilaxu"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

scan_lockfiles() {
  local dir="$1"
  local found=0

  echo -e "${YELLOW}[shai-hulud-guard] Scanning lockfiles...${NC}"

  for lockfile in $(find "$dir" -maxdepth 8 -name "package-lock.json" -o -name "yarn.lock" -o -name "pnpm-lock.yaml" 2>/dev/null); do
    # Check for github:tanstack/router# references (direct IOC)
    if grep -q "github:tanstack/router#" "$lockfile" 2>/dev/null; then
      echo -e "${RED}[CRITICAL] IOC: github:tanstack/router# reference in $lockfile${NC}"
      found=1
    fi

    # Check against full blocklist
    if [ -f "$BLOCKLIST" ]; then
      while IFS= read -r line; do
        [[ "$line" =~ ^#.*$ || -z "$line" ]] && continue
        if grep -qF "\"$line\"" "$lockfile" 2>/dev/null; then
          echo -e "${RED}[BLOCKED] Compromised package in $lockfile: $line${NC}"
          found=1
        fi
      done < "$BLOCKLIST"
    fi
  done

  return $found
}

scan_node_modules() {
  local dir="$1"
  local found=0

  echo -e "${YELLOW}[shai-hulud-guard] Scanning node_modules for IOC files...${NC}"

  # router_init.js (primary Mini Shai-Hulud IOC)
  for f in $(find "$dir" -maxdepth 8 -name "router_init.js" -path "*/node_modules/*" 2>/dev/null); do
    local hash
    if command -v shasum &>/dev/null; then
      hash=$(shasum -a 256 "$f" 2>/dev/null | awk '{print $1}')
    elif command -v sha256sum &>/dev/null; then
      hash=$(sha256sum "$f" 2>/dev/null | awk '{print $1}')
    else
      hash="unknown"
    fi
    if [ "$hash" = "$IOC_ROUTER_INIT_SHA256" ]; then
      echo -e "${RED}[CRITICAL] MALWARE CONFIRMED: $f (hash match)${NC}"
      found=1
    else
      echo -e "${YELLOW}[SUSPICIOUS] router_init.js at $f (hash: $hash)${NC}"
    fi
  done

  # tanstack_runner.js
  for f in $(find "$dir" -maxdepth 8 -name "tanstack_runner.js" -path "*/node_modules/*" 2>/dev/null); do
    echo -e "${RED}[CRITICAL] IOC file: $f${NC}"
    found=1
  done

  # Shai-Hulud 2.0 IOCs
  for f in $(find "$dir" -maxdepth 8 \( -name "setup_bun.js" -o -name "bun_environment.js" \) -path "*/node_modules/*" 2>/dev/null); do
    echo -e "${RED}[WARNING] Shai-Hulud 2.0 IOC candidate: $f${NC}"
    found=1
  done

  # Dune-themed git references in package.json
  for f in $(find "$dir" -maxdepth 8 -name "package.json" -path "*/node_modules/*" 2>/dev/null | head -500); do
    if grep -qE "github:.*#.*(${DUNE_BRANCHES})" "$f" 2>/dev/null; then
      echo -e "${RED}[CRITICAL] Dead-drop git reference in $f${NC}"
      found=1
    fi
  done

  return $found
}

scan_full() {
  local dir="${1:-.}"
  local issues=0

  echo ""
  echo -e "${YELLOW}========================================${NC}"
  echo -e "${YELLOW}  SHAI-HULUD GUARD SCANNER${NC}"
  echo -e "${YELLOW}========================================${NC}"
  echo -e "  Scanning: $dir"
  echo ""

  scan_lockfiles "$dir" || issues=1
  echo ""
  scan_node_modules "$dir" || issues=1
  echo ""

  if [ $issues -eq 0 ]; then
    echo -e "${GREEN}[OK] No Shai-Hulud indicators found${NC}"
  else
    echo -e "${RED}[ALERT] Shai-Hulud indicators detected! See above.${NC}"
    echo -e "${RED}  1. Do NOT run any build scripts${NC}"
    echo -e "${RED}  2. Delete node_modules and lockfile${NC}"
    echo -e "${RED}  3. Rotate any npm/GitHub tokens on this machine${NC}"
    echo -e "${RED}  4. Reinstall from clean package versions${NC}"
  fi

  echo ""
  return $issues
}

case "${1:-help}" in
  scan)
    scan_full "${2:-.}"
    ;;
  *)
    echo "Shai-Hulud Guard Scanner"
    echo ""
    echo "Usage:"
    echo "  shai-hulud-scan.sh scan [directory]    Scan for compromised packages"
    echo ""
    echo "Blocklist: $BLOCKLIST"
    echo "Blocked versions: $(grep -v '^#' "$BLOCKLIST" 2>/dev/null | grep -v '^$' | wc -l | tr -d ' ')"
    ;;
esac
