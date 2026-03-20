#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  PhantomScan — One-time capability setup
#  Run once so the scanner works without sudo for any user:
#
#    chmod +x web/install.sh
#    sudo ./web/install.sh        # OR just: bash web/install.sh (if already root)
#
#  What it does:
#    Sets cap_net_raw and cap_net_admin on the compiled binary so raw-socket
#    modules (SYN scan, ARP scan, packet capture) work without sudo.
#    No password is stored anywhere.  No sudoers modification is made.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
RESET='\033[0m'

# Resolve project root (parent of the directory that contains this script)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BINARY="${PROJECT_ROOT}/builds/phantomscan"

echo -e "${CYAN}PhantomScan — Capability Setup${RESET}"
echo -e "${CYAN}────────────────────────────────${RESET}"

# ── Check binary exists ──────────────────────────────────────────────────────
if [ ! -f "${BINARY}" ]; then
    echo -e "${RED}[!] Binary not found: ${BINARY}${RESET}"
    echo -e "${YELLOW}    Build it first: cd ${PROJECT_ROOT} && make rebuild${RESET}"
    exit 1
fi
echo -e "${CYAN}[*] Binary: ${BINARY}${RESET}"

# ── Check setcap is available ────────────────────────────────────────────────
if ! command -v setcap &>/dev/null; then
    echo -e "${RED}[!] setcap not found. Install libcap2-bin:${RESET}"
    echo -e "${YELLOW}    sudo apt install libcap2-bin${RESET}"
    exit 1
fi

# ── Check if already configured ─────────────────────────────────────────────
if getcap "${BINARY}" 2>/dev/null | grep -q "cap_net_raw"; then
    echo -e "${GREEN}[+] Capabilities already set — nothing to do.${RESET}"
    getcap "${BINARY}"
    exit 0
fi

# ── Need root to call setcap ─────────────────────────────────────────────────
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}[!] Must be root to set capabilities. Re-run with sudo:${RESET}"
    echo -e "${YELLOW}    sudo bash ${BASH_SOURCE[0]}${RESET}"
    exit 1
fi

# ── Apply capabilities ───────────────────────────────────────────────────────
echo -e "${CYAN}[*] Applying capabilities...${RESET}"
setcap "cap_net_raw,cap_net_admin+eip" "${BINARY}"

# ── Verify ───────────────────────────────────────────────────────────────────
if getcap "${BINARY}" 2>/dev/null | grep -q "cap_net_raw"; then
    echo -e "${GREEN}[+] Done! PhantomScan can now run without sudo.${RESET}"
    getcap "${BINARY}"
else
    echo -e "${RED}[!] setcap did not persist — check filesystem mount options.${RESET}"
    exit 1
fi
