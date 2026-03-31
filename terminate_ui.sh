#!/bin/bash
# FalconHunter Web UI — Terminate
# Usage: bash terminate_ui.sh

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PID_FILE="$SCRIPT_DIR/web_ui/.ui.pid"

killed=0

_kill_pid() {
    local pid="$1"
    if kill "$pid" 2>/dev/null; then
        echo -e "${GREEN}[+] Stopped process (PID $pid)${NC}"
        killed=1
    elif sudo kill -9 "$pid" 2>/dev/null; then
        echo -e "${GREEN}[+] Force-stopped process (PID $pid) via sudo${NC}"
        killed=1
    else
        echo -e "${RED}[-] Could not kill PID $pid — try: sudo kill -9 $pid${NC}"
    fi
}

# Kill via PID file
if [[ -f "$PID_FILE" ]]; then
    PID=$(cat "$PID_FILE")
    if kill -0 "$PID" 2>/dev/null; then
        _kill_pid "$PID"
    else
        echo -e "${YELLOW}[!] PID $PID from file is no longer running${NC}"
    fi
    rm -f "$PID_FILE"
fi

# Kill ALL run.py processes for this project (catches root-owned ones too)
ALL_PIDS=$(ps aux | grep "[w]eb_ui/run.py\|web_ui/run\.py" | awk '{print $2}')
for pid in $ALL_PIDS; do
    echo -e "${YELLOW}[!] Found stale process (PID $pid)${NC}"
    _kill_pid "$pid"
done

# Final check — any process still on our common ports
for port in 5000 5001 5002 5003 5004 5005; do
    PIDS=$(ss -tlnp 2>/dev/null | grep ":${port} " | grep -oP 'pid=\K[0-9]+')
    for pid in $PIDS; do
        # Only kill if it's our run.py
        if ls -l /proc/"$pid"/exe 2>/dev/null | grep -q python || \
           cat /proc/"$pid"/cmdline 2>/dev/null | tr '\0' ' ' | grep -q "run.py"; then
            echo -e "${YELLOW}[!] Found process on port $port (PID $pid)${NC}"
            _kill_pid "$pid"
        fi
    done
done

if [[ "$killed" -eq 0 ]]; then
    echo -e "${YELLOW}[!] No Web UI processes found${NC}"
    # Show any remaining root-owned processes the user may need to kill manually
    ROOT_PROCS=$(ps aux | grep "[w]eb_ui/run.py" | awk '$1=="root" {print $2}')
    if [[ -n "$ROOT_PROCS" ]]; then
        echo -e "${RED}[!] Root-owned process(es) still running — kill manually:${NC}"
        for p in $ROOT_PROCS; do
            echo -e "    ${CYAN}sudo kill -9 $p${NC}"
        done
    fi
    exit 0
fi

sleep 1
# Confirm dead
STILL=$(ps aux | grep "[w]eb_ui/run.py" | awk '{print $2}')
if [[ -n "$STILL" ]]; then
    echo -e "${RED}[!] Some processes still alive — they may be root-owned:${NC}"
    for p in $STILL; do
        echo -e "    ${CYAN}sudo kill -9 $p${NC}"
    done
else
    echo -e "${GREEN}[+] Web UI fully terminated${NC}"
fi
