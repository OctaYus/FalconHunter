#!/bin/bash
# FalconHunter Web UI — Start (WSL2-aware, auth-enabled)
#
# Usage:
#   bash start_ui.sh [OPTIONS]
#
# Options:
#   --port=PORT        Port to listen on (default: 5000)
#   --password=TOKEN   Set a custom auth token (default: auto-generated)
#   --public           Bind to 0.0.0.0 instead of 127.0.0.1 (for VPS+nginx)
#   --no-auth          Disable authentication (trusted localhost only)
#   --debug            Enable Flask debug mode

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

PREFERRED_PORT="5000"
DEBUG_FLAG=""
PASSWORD_FLAG=""
PUBLIC_FLAG=""
NO_AUTH_FLAG=""
EXPLICIT_PUBLIC=0   # user passed --public explicitly

for arg in "$@"; do
    case "$arg" in
        --port=*)     PREFERRED_PORT="${arg#*=}" ;;
        --password=*) PASSWORD_FLAG="--password=${arg#*=}" ;;
        --public)     PUBLIC_FLAG="--public"; EXPLICIT_PUBLIC=1 ;;
        --no-auth)    NO_AUTH_FLAG="--no-auth" ;;
        --debug)      DEBUG_FLAG="--debug" ;;
    esac
done

# ── WSL2 detection ────────────────────────────────────────────────────
# In WSL2, Flask must bind 0.0.0.0 so Windows portproxy can reach it
# (127.0.0.1 in WSL ≠ Windows localhost — they are different interfaces)
IS_WSL=0
if grep -qi microsoft /proc/version 2>/dev/null; then
    IS_WSL=1
    if [[ "$EXPLICIT_PUBLIC" -eq 0 ]]; then
        PUBLIC_FLAG="--public"
    fi
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PID_FILE="$SCRIPT_DIR/web_ui/.ui.pid"
LOG_FILE="$SCRIPT_DIR/web_ui/.ui.log"

# ── helpers ───────────────────────────────────────────────────────────

# Get WSL IP (what Windows uses to reach WSL)
get_wsl_ip() {
    hostname -I 2>/dev/null | awk '{print $1}'
}

# Check if a port is free (uses SO_REUSEADDR so TIME_WAIT sockets don't block)
port_free() {
    python3 -c "
import socket, sys
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    s.bind(('', ${1}))
    s.close()
    sys.exit(0)
except OSError:
    sys.exit(1)
" 2>/dev/null
}

# Kill whatever is on a port
kill_port() {
    local p="$1"
    local pids
    # via ss
    pids=$(ss -tlnp 2>/dev/null | grep ":${p} " | grep -oP 'pid=\K[0-9]+')
    for pid in $pids; do
        kill "$pid" 2>/dev/null || sudo kill -9 "$pid" 2>/dev/null || true
    done
    # via lsof
    pids=$(lsof -ti ":${p}" 2>/dev/null)
    for pid in $pids; do
        kill "$pid" 2>/dev/null || sudo kill -9 "$pid" 2>/dev/null || true
    done
    fuser -k "${p}/tcp" 2>/dev/null || sudo fuser -k "${p}/tcp" 2>/dev/null || true
    sleep 1
}

# Find a free port starting from preferred
find_free_port() {
    local base="$1"
    for port in "$base" 5001 5002 5003 5004 5005 8080 8888; do
        if port_free "$port"; then echo "$port"; return; fi
    done
    python3 -c "import socket; s=socket.socket(); s.bind(('',0)); print(s.getsockname()[1]); s.close()"
}

# Set up Windows port forwarding via netsh (WSL2 → Windows)
setup_windows_portproxy() {
    local wsl_ip="$1"
    local port="$2"
    if ! command -v powershell.exe &>/dev/null; then return; fi
    echo -e "${CYAN}[*] Setting up Windows port forwarding (port $port → WSL $wsl_ip)...${NC}"

    # Remove stale FalconHunter rules on ALL common ports (prevents leftover rules
    # from previous runs on a different port blocking the new one)
    for old_port in 5000 5001 5002 5003 5004 5005 8080 8888; do
        powershell.exe -Command "netsh interface portproxy delete v4tov4 listenport=$old_port listenaddress=127.0.0.1" \
            >/dev/null 2>&1 || true
    done

    # Add rule for current port
    if powershell.exe -Command "netsh interface portproxy add v4tov4 listenport=$port listenaddress=127.0.0.1 connectport=$port connectaddress=$wsl_ip" \
        >/dev/null 2>&1; then
        echo -e "${GREEN}[+] Port forwarding: Windows localhost:$port → WSL $wsl_ip:$port${NC}"
    else
        echo -e "${YELLOW}[!] Port forwarding needs Admin — generating fix script...${NC}"
        _write_portproxy_script "$wsl_ip" "$port"
    fi

    # Add Windows firewall rule (best-effort)
    powershell.exe -Command "
    \$ruleName = 'FalconHunter-UI-$port'
    \$existing = Get-NetFirewallRule -DisplayName \$ruleName -ErrorAction SilentlyContinue
    if (-not \$existing) {
        New-NetFirewallRule -DisplayName \$ruleName -Direction Inbound -Action Allow -Protocol TCP -LocalPort $port | Out-Null
    }
    " >/dev/null 2>&1 || true
}

# Write a self-elevating PowerShell script to the Windows Desktop
# so the user can run it once to set up portproxy + startup task permanently
_write_portproxy_script() {
    local wsl_ip="$1"
    local port="$2"

    # Windows Desktop path from WSL
    local desktop="/mnt/c/Users/OctaYus/Desktop"
    local script="$desktop/FalconHunter-Setup-Portproxy.ps1"

    cat > "$script" << PSEOF
# FalconHunter — Windows Port Forwarding Setup
# Right-click this file → "Run with PowerShell" (as Administrator)
# After running once, port forwarding will survive reboots automatically.

\$Port    = $port
\$WslIP   = "$wsl_ip"
\$TaskName = "FalconHunter-Portproxy"

Write-Host "[*] Setting up port forwarding: localhost:\$Port -> WSL \$WslIP:\$Port" -ForegroundColor Cyan

# Remove old FalconHunter portproxy rules
foreach (\$p in @(5000,5001,5002,5003,5004,5005,8080,8888)) {
    netsh interface portproxy delete v4tov4 listenport=\$p listenaddress=127.0.0.1 2>\$null | Out-Null
}

# Add new rule
netsh interface portproxy add v4tov4 listenport=\$Port listenaddress=127.0.0.1 connectport=\$Port connectaddress=\$WslIP
if (\$LASTEXITCODE -eq 0) {
    Write-Host "[+] Port forwarding set." -ForegroundColor Green
} else {
    Write-Host "[-] Failed. Make sure you are running as Administrator." -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

# Firewall rule
\$fw = Get-NetFirewallRule -DisplayName "FalconHunter-UI" -ErrorAction SilentlyContinue
if (-not \$fw) {
    New-NetFirewallRule -DisplayName "FalconHunter-UI" -Direction Inbound -Action Allow -Protocol TCP -LocalPort \$Port | Out-Null
    Write-Host "[+] Firewall rule added." -ForegroundColor Green
}

# Register a Windows startup task so portproxy survives reboots
# The task reads the current WSL IP at login time (handles dynamic IP changes)
\$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument @"
-WindowStyle Hidden -Command "
  \\\$ip = (wsl hostname -I).Trim().Split()[0]
  foreach (\\\$p in @(5000,5001,5002,5003,5004,5005,8080,8888)) {
    netsh interface portproxy delete v4tov4 listenport=\\\$p listenaddress=127.0.0.1 2>\\\$null | Out-Null
  }
  netsh interface portproxy add v4tov4 listenport=$port listenaddress=127.0.0.1 connectport=$port connectaddress=\\\$ip
"
"@

\$trigger  = New-ScheduledTaskTrigger -AtLogon
\$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 1)
\$principal = New-ScheduledTaskPrincipal -UserId (whoami) -RunLevel Highest

# Remove old task if exists
Unregister-ScheduledTask -TaskName \$TaskName -Confirm:\$false -ErrorAction SilentlyContinue

Register-ScheduledTask -TaskName \$TaskName -Action \$action -Trigger \$trigger -Settings \$settings -Principal \$principal | Out-Null
Write-Host "[+] Startup task registered — portproxy will auto-run at every login." -ForegroundColor Green
Write-Host ""
Write-Host "  Done! Open http://localhost:$port in your browser." -ForegroundColor Cyan
Read-Host "Press Enter to exit"
PSEOF

    echo -e "${GREEN}[+] Fix script written to Windows Desktop:${NC}"
    echo -e "    ${CYAN}FalconHunter-Setup-Portproxy.ps1${NC}"
    echo -e "    ${YELLOW}Right-click it → 'Run with PowerShell' (once, as Admin)${NC}"
    echo -e "    ${YELLOW}It will also install a startup task so it survives reboots.${NC}"
}

# ── already running? ──────────────────────────────────────────────────

if [[ -f "$PID_FILE" ]]; then
    OLD_PID=$(cat "$PID_FILE")
    if kill -0 "$OLD_PID" 2>/dev/null; then
        OLD_PORT=$(ss -tlnp 2>/dev/null | grep "pid=$OLD_PID" | grep -oP ':\K[0-9]+(?= )' | head -1)
        OLD_PORT="${OLD_PORT:-$PREFERRED_PORT}"
        echo -e "${YELLOW}[!] Web UI already running (PID $OLD_PID)${NC}"
        echo -e "${CYAN}    → http://localhost:${OLD_PORT}${NC}"
        echo -e "    To restart: bash terminate_ui.sh && bash start_ui.sh"
        exit 0
    else
        rm -f "$PID_FILE"
    fi
fi

# ── dependency checks ─────────────────────────────────────────────────

if ! command -v python3 &>/dev/null; then
    echo -e "${RED}[-] python3 not found.${NC}"; exit 1
fi
if ! python3 -c "import flask" 2>/dev/null; then
    echo -e "${YELLOW}[!] Flask not found — installing...${NC}"
    python3 -m pip install -q flask 2>/dev/null || pip3 install -q flask
fi

# ── resolve port ──────────────────────────────────────────────────────

PORT="$PREFERRED_PORT"
if ! port_free "$PORT"; then
    echo -e "${YELLOW}[!] Port $PORT is in use — trying to free it...${NC}"
    kill_port "$PORT"
    sleep 1
    if ! port_free "$PORT"; then
        PORT=$(find_free_port "$PREFERRED_PORT")
        echo -e "${YELLOW}[!] Still busy — using port $PORT${NC}"
    fi
fi

# ── banner ────────────────────────────────────────────────────────────

echo -e "${CYAN}"
cat << 'EOF'
  ______      __                      __  __            __
 / ____/___ _/ /________  ____  ___  / / / /_  ______  / /____  _____
/ /_  / __ `/ / ___/ __ \/ __ \/ _ \/ /_/ / / / / __ \/ __/ _ \/ ___/
/ __/ / /_/ / / /__/ /_/ / / / /  __/ __  / /_/ / / / / /_/  __/ /
/_/    \__,_/_/\___/\____/_/ /_/\___/_/ /_/\__,_/_/ /_/\__/\___/_/
EOF
echo -e "${NC}"

# ── launch ────────────────────────────────────────────────────────────

echo -e "${GREEN}[+] Starting FalconHunter Web UI on port $PORT...${NC}"

python3 "$SCRIPT_DIR/web_ui/run.py" \
    --port "$PORT" $PUBLIC_FLAG $PASSWORD_FLAG $NO_AUTH_FLAG $DEBUG_FLAG \
    >> "$LOG_FILE" 2>&1 &

UI_PID=$!
echo "$UI_PID" > "$PID_FILE"

# Wait up to 6s for the server to respond
started=0
for i in $(seq 1 12); do
    sleep 0.5
    if curl -sf "http://127.0.0.1:${PORT}/" -o /dev/null 2>/dev/null; then
        started=1; break
    fi
    if ! kill -0 "$UI_PID" 2>/dev/null; then
        echo -e "${RED}[-] Web UI crashed. Last log:${NC}"
        tail -15 "$LOG_FILE"
        rm -f "$PID_FILE"
        exit 1
    fi
done

if [[ "$started" -eq 0 ]]; then
    echo -e "${YELLOW}[!] Server slow to start — check logs if unreachable${NC}"
fi

# ── Windows port forwarding (WSL2) ────────────────────────────────────

WSL_IP=$(get_wsl_ip)
setup_windows_portproxy "$WSL_IP" "$PORT"

# ── done ─────────────────────────────────────────────────────────────

# Read the auth token (generated by Python on first run)
AUTH_TOKEN=""
TOKEN_FILE="$SCRIPT_DIR/web_ui/.auth_token"
if [[ -n "$NO_AUTH_FLAG" ]]; then
    AUTH_TOKEN="(disabled)"
elif [[ -f "$TOKEN_FILE" ]]; then
    AUTH_TOKEN=$(cat "$TOKEN_FILE")
fi

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  FalconHunter Web UI is up (PID ${UI_PID})${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════════╣${NC}"
if [[ -n "$PUBLIC_FLAG" ]]; then
    echo -e "    ${CYAN}URL     → http://${WSL_IP}:${PORT}${NC}"
    echo -e "    ${YELLOW}[!] --public mode: put nginx+HTTPS in front for VPS${NC}"
else
    echo -e "    ${CYAN}Windows → http://localhost:${PORT}${NC}"
    echo -e "    WSL     → http://127.0.0.1:${PORT}"
    echo -e "    WSL IP  → http://${WSL_IP}:${PORT}"
fi
if [[ -n "$AUTH_TOKEN" ]]; then
    echo ""
    echo -e "    ${BOLD}${GREEN}Token   → ${AUTH_TOKEN}${NC}"
    echo -e "    ${CYAN}(enter this token in the browser login page)${NC}"
fi
echo ""
echo -e "    Logs  : $LOG_FILE"
echo -e "    Stop  : bash terminate_ui.sh"
echo ""
if [[ -z "$PUBLIC_FLAG" ]]; then
    echo -e "${CYAN}  VPS users — SSH tunnel:${NC}"
    echo -e "    ssh -N -L ${PORT}:localhost:${PORT} user@YOUR_VPS"
    echo -e "    then open → http://localhost:${PORT}"
    echo ""
fi
echo -e "${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
