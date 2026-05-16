#!/usr/bin/env bash
# Shai-Hulud Guard -- one-command installer
# Protects against ALL known Shai-Hulud / Mini Shai-Hulud npm supply chain attacks
#
# What it does:
#   1. Installs a blocklist of every known compromised package@version
#   2. Installs a scanner that checks lockfiles and node_modules for IOC files
#   3. Installs a background monitor (macOS LaunchAgent or Linux cron) that scans every 5 minutes
#   4. Adds shell aliases so npm/pnpm/yarn install always runs with --ignore-scripts and auto-scans after
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/YOUR_USERNAME/shai-hulud-guard/main/install.sh | bash
#   -- or --
#   git clone https://github.com/YOUR_USERNAME/shai-hulud-guard && cd shai-hulud-guard && bash install.sh

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

INSTALL_DIR="$HOME/.shai-hulud-guard"
BLOCKLIST_DIR="$INSTALL_DIR/blocklist"
BIN_DIR="$INSTALL_DIR/bin"
LOG_DIR="$INSTALL_DIR/log"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo -e "${BOLD}"
echo "  ╔═══════════════════════════════════════════╗"
echo "  ║       SHAI-HULUD GUARD INSTALLER          ║"
echo "  ║   npm supply chain attack protection      ║"
echo "  ╚═══════════════════════════════════════════╝"
echo -e "${NC}"
echo ""

# Create directories
mkdir -p "$BLOCKLIST_DIR" "$BIN_DIR" "$LOG_DIR"

# Step 1: Install blocklist
echo -e "${YELLOW}[1/4] Installing compromised package blocklist...${NC}"
if [ -f "$SCRIPT_DIR/blocklist/shai-hulud-blocked-packages.txt" ]; then
  cp "$SCRIPT_DIR/blocklist/shai-hulud-blocked-packages.txt" "$BLOCKLIST_DIR/"
else
  echo -e "${RED}Error: blocklist/shai-hulud-blocked-packages.txt not found${NC}"
  echo "Make sure you're running this from the shai-hulud-guard repo directory"
  exit 1
fi
BLOCKED_COUNT=$(grep -v "^#" "$BLOCKLIST_DIR/shai-hulud-blocked-packages.txt" | grep -v "^$" | wc -l | tr -d ' ')
echo -e "${GREEN}  Installed $BLOCKED_COUNT blocked package versions${NC}"

# Step 2: Install scanner
echo -e "${YELLOW}[2/4] Installing scanner and guard scripts...${NC}"
cp "$SCRIPT_DIR/bin/shai-hulud-scan.sh" "$BIN_DIR/"
cp "$SCRIPT_DIR/bin/shai-hulud-monitor.sh" "$BIN_DIR/"
chmod +x "$BIN_DIR/shai-hulud-scan.sh"
chmod +x "$BIN_DIR/shai-hulud-monitor.sh"
echo -e "${GREEN}  Scanner installed at $BIN_DIR/${NC}"

# Step 3: Install background monitor
echo -e "${YELLOW}[3/4] Installing background monitor...${NC}"

if [[ "$OSTYPE" == "darwin"* ]]; then
  # macOS: LaunchAgent
  PLIST_DIR="$HOME/Library/LaunchAgents"
  PLIST_FILE="$PLIST_DIR/com.shai-hulud-guard.monitor.plist"
  mkdir -p "$PLIST_DIR"

  cat > "$PLIST_FILE" << PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.shai-hulud-guard.monitor</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>${BIN_DIR}/shai-hulud-monitor.sh</string>
    </array>
    <key>StartInterval</key>
    <integer>300</integer>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardOutPath</key>
    <string>${LOG_DIR}/monitor.log</string>
    <key>StandardErrorPath</key>
    <string>${LOG_DIR}/monitor-error.log</string>
</dict>
</plist>
PLIST

  launchctl unload "$PLIST_FILE" 2>/dev/null || true
  launchctl load "$PLIST_FILE"
  echo -e "${GREEN}  macOS LaunchAgent installed (runs every 5 minutes)${NC}"

elif [[ "$OSTYPE" == "linux"* ]]; then
  # Linux: cron
  CRON_CMD="*/5 * * * * $BIN_DIR/shai-hulud-monitor.sh >> $LOG_DIR/monitor.log 2>&1"
  (crontab -l 2>/dev/null | grep -v "shai-hulud-monitor"; echo "$CRON_CMD") | crontab -
  echo -e "${GREEN}  Linux cron job installed (runs every 5 minutes)${NC}"

else
  echo -e "${YELLOW}  Unknown OS. Skipping background monitor. Run manually:${NC}"
  echo "  $BIN_DIR/shai-hulud-monitor.sh"
fi

# Step 4: Install shell aliases
echo -e "${YELLOW}[4/4] Installing safe install aliases...${NC}"

SHELL_RC=""
if [ -f "$HOME/.zshrc" ]; then
  SHELL_RC="$HOME/.zshrc"
elif [ -f "$HOME/.bashrc" ]; then
  SHELL_RC="$HOME/.bashrc"
elif [ -f "$HOME/.bash_profile" ]; then
  SHELL_RC="$HOME/.bash_profile"
fi

if [ -n "$SHELL_RC" ]; then
  # Check if already installed
  if grep -q "shai-hulud-guard" "$SHELL_RC" 2>/dev/null; then
    echo -e "${GREEN}  Shell aliases already installed in $SHELL_RC${NC}"
  else
    cat >> "$SHELL_RC" << 'ALIASES'

# === Shai-Hulud Guard: npm supply chain protection ===
# Forces --ignore-scripts on install commands and scans for compromised packages after
safe-npm() {
  if [[ "$1" == "install" || "$1" == "i" || "$1" == "ci" || "$1" == "add" ]]; then
    echo "[shai-hulud-guard] Running npm $@ --ignore-scripts"
    command npm "$@" --ignore-scripts
    echo "[shai-hulud-guard] Scanning for compromised packages..."
    ~/.shai-hulud-guard/bin/shai-hulud-scan.sh scan . 2>/dev/null
  else
    command npm "$@"
  fi
}
safe-pnpm() {
  if [[ "$1" == "install" || "$1" == "i" || "$1" == "add" ]]; then
    echo "[shai-hulud-guard] Running pnpm $@ --ignore-scripts"
    command pnpm "$@" --ignore-scripts
    echo "[shai-hulud-guard] Scanning for compromised packages..."
    ~/.shai-hulud-guard/bin/shai-hulud-scan.sh scan . 2>/dev/null
  else
    command pnpm "$@"
  fi
}
safe-yarn() {
  if [[ "$1" == "install" || "$1" == "add" ]]; then
    echo "[shai-hulud-guard] Running yarn $@ --ignore-scripts"
    command yarn "$@" --ignore-scripts
    echo "[shai-hulud-guard] Scanning for compromised packages..."
    ~/.shai-hulud-guard/bin/shai-hulud-scan.sh scan . 2>/dev/null
  else
    command yarn "$@"
  fi
}
alias npm='safe-npm'
alias pnpm='safe-pnpm'
alias yarn='safe-yarn'
alias shai-hulud-scan='~/.shai-hulud-guard/bin/shai-hulud-scan.sh scan'
# === End Shai-Hulud Guard ===
ALIASES
    echo -e "${GREEN}  Shell aliases added to $SHELL_RC${NC}"
  fi
else
  echo -e "${YELLOW}  No .zshrc/.bashrc found. Add aliases manually.${NC}"
fi

echo ""
echo -e "${GREEN}${BOLD}Installation complete!${NC}"
echo ""
echo "  What's protected:"
echo "    - npm install / pnpm install / yarn install now run with --ignore-scripts"
echo "    - Every install auto-scans for $BLOCKED_COUNT known compromised package versions"
echo "    - Background monitor checks your projects every 5 minutes for IOC files"
echo "    - Detects router_init.js, tanstack_runner.js, setup_bun.js, Dune-themed git refs"
echo "    - Monitors for webhook.site exfiltration connections"
echo ""
echo "  Commands:"
echo "    shai-hulud-scan [dir]    Scan a directory for compromised packages"
echo "    npm install              Now safe by default (--ignore-scripts + scan)"
echo ""
echo -e "  ${YELLOW}Restart your shell or run 'source $SHELL_RC' to activate aliases.${NC}"
echo ""
