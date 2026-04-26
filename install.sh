#!/bin/bash
# FalconHunter — Full Tool Installer
# Usage: bash install.sh [--force] [--help]

# ─────────────────────────────────────────────
# NOTE: Do NOT use set -e here. We want to
# continue installing remaining tools even when
# individual ones fail, and collect a summary.
# ─────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

TOOLS_DIR="${HOME}/Tools"
WORDLISTS_DIR="${TOOLS_DIR}/wordlists"
# If the script was started with sudo, HOME is often /root but wrappers in
# /usr/local/bin must point at a path the normal user can read (not /root/Tools).
if [[ "$(id -u)" -eq 0 && -n "${SUDO_USER:-}" ]]; then
    _INVOKING_HOME="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
    if [[ -n "$_INVOKING_HOME" && -d "$_INVOKING_HOME" ]]; then
        TOOLS_DIR="${_INVOKING_HOME}/Tools"
        WORDLISTS_DIR="${TOOLS_DIR}/wordlists"
    fi
    unset _INVOKING_HOME
fi
FORCE=0
FAILED=()
SKIPPED=()
INSTALLED=()
START_TIME=$(date +%s)

# ── Argument parsing ──────────────────────────
for arg in "$@"; do
    case "$arg" in
        --force) FORCE=1 ;;
        --help|-h)
            echo "Usage: bash install.sh [--force]"
            echo "  --force   Reinstall all tools even if already present"
            exit 0 ;;
    esac
done

# ── Helpers ───────────────────────────────────
info()    { echo -e "${CYAN}[*]${NC} $*"; }
ok()      { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
err()     { echo -e "${RED}[-]${NC} $*"; }
section() { echo -e "\n${BOLD}${CYAN}══ $* ══${NC}"; }

is_installed() {
    [[ "$FORCE" -eq 0 ]] && { command -v "$1" &>/dev/null || [[ -f "/usr/local/bin/$1" ]]; }
}

mark_ok()      { INSTALLED+=("$1"); ok "$1 installed"; }
mark_skip()    { SKIPPED+=("$1");   ok "$1 already installed — skipping"; }
mark_fail()    { FAILED+=("$1");    err "Failed to install $1"; }

# ── 1. PATH setup ─────────────────────────────
setup_path() {
    mkdir -p "$TOOLS_DIR"
    if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
        export PATH="$HOME/.local/bin:$PATH"
        grep -qxF 'export PATH=$HOME/.local/bin:$PATH' ~/.bashrc \
            || echo 'export PATH=$HOME/.local/bin:$PATH' >> ~/.bashrc
    fi
}

# ── 2. System packages ────────────────────────
install_system_packages() {
    section "System Dependencies"
    info "Running apt update + install…"
    if sudo apt-get update -qq && \
       sudo apt-get install -y -qq \
           curl wget git python3 python3-pip python3-venv python3-virtualenv \
           make build-essential gcc cmake ruby whois zip libpcap-dev \
           python3-dev libssl-dev libffi-dev pipx screen 2>&1 | tail -3; then
        ok "System packages ready"
    else
        err "apt install had errors — continuing anyway"
    fi
    python3 -m pipx ensurepath 2>/dev/null || true
    export PATH="$HOME/.local/bin:$PATH"
}

# ── 3. Go installation ────────────────────────
install_latest_go() {
    section "Go Runtime"

    GOVERSION=$(curl -sf 'https://go.dev/VERSION?m=text' | grep -E '^go[0-9.]+' | head -n1)
    if [[ -z "$GOVERSION" ]]; then
        err "Could not fetch latest Go version from go.dev"
        FAILED+=("go")
        return 1
    fi

    # Already installed at right version?
    if command -v go &>/dev/null; then
        CURRENT=$(go version 2>/dev/null | grep -oE 'go[0-9.]+' | head -n1)
        if [[ "$CURRENT" == "$GOVERSION" && "$FORCE" -eq 0 ]]; then
            mark_skip "go ($CURRENT)"
            _setup_goenv; return 0
        fi
    fi

    info "Installing $GOVERSION…"
    if ! wget -q "https://go.dev/dl/${GOVERSION}.linux-amd64.tar.gz" -O /tmp/go.tgz; then
        err "Download failed for $GOVERSION"; FAILED+=("go"); return 1
    fi

    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf /tmp/go.tgz && rm /tmp/go.tgz
    sudo ln -sf /usr/local/go/bin/go /usr/local/bin/go

    _setup_goenv

    if ! command -v go &>/dev/null; then
        err "Go installation failed"; FAILED+=("go"); return 1
    fi
    mark_ok "go ($GOVERSION)"
}

_setup_goenv() {
    export GOROOT=/usr/local/go
    export GOPATH=$HOME/go
    export PATH=/usr/local/go/bin:$PATH:$GOPATH/bin
    mkdir -p "$GOPATH"/{bin,src,pkg}
    grep -qxF 'export GOROOT=/usr/local/go'     ~/.bashrc || echo 'export GOROOT=/usr/local/go'     >> ~/.bashrc
    grep -qxF 'export GOPATH=$HOME/go'           ~/.bashrc || echo 'export GOPATH=$HOME/go'           >> ~/.bashrc
    grep -qxF 'export PATH=/usr/local/go/bin:$PATH' ~/.bashrc || echo 'export PATH=/usr/local/go/bin:$PATH' >> ~/.bashrc
    grep -qxF 'export PATH=$PATH:$HOME/go/bin'   ~/.bashrc || echo 'export PATH=$PATH:$HOME/go/bin'   >> ~/.bashrc
}

# ── 4. Go tools ───────────────────────────────
declare -A GO_TOOLS=(
  [subfinder]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  [httpx]="github.com/projectdiscovery/httpx/cmd/httpx@latest"
  [nuclei]="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  [katana]="github.com/projectdiscovery/katana/cmd/katana@latest"
  [ffuf]="github.com/ffuf/ffuf/v2@latest"
  [dalfox]="github.com/hahwul/dalfox/v2@latest"
  [crlfuzz]="github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"
  [waybackurls]="github.com/tomnomnom/waybackurls@latest"
  [gau]="github.com/lc/gau/v2/cmd/gau@latest"
  [gf]="github.com/tomnomnom/gf@latest"
  [anew]="github.com/tomnomnom/anew@latest"
  [qsreplace]="github.com/tomnomnom/qsreplace@latest"
  [subzy]="github.com/PentestPad/subzy@latest"
  [subjack]="github.com/haccer/subjack@latest"
  [cnfinder]="github.com/OctaYus/cnfinder@latest"
  [aws_extractor]="github.com/OctaYus/aws_extractor@latest"
  [mantra]="github.com/MrEmpy/mantra@latest"
  [amass]="github.com/owasp-amass/amass/v3/...@latest"
  [kr]="github.com/assetnote/kiterunner/cmd/kr@latest"
  [gowitness]="github.com/sensepost/gowitness@latest"
  [trufflehog]="github.com/trufflesecurity/trufflehog/v3/cmd/trufflehog@latest"
)

install_go_tools() {
    section "Go Tools"
    if ! command -v go &>/dev/null; then
        err "go not found — skipping all Go tools"
        for t in "${!GO_TOOLS[@]}"; do FAILED+=("$t"); done
        return 1
    fi

    for tool in "${!GO_TOOLS[@]}"; do
        if is_installed "$tool"; then
            mark_skip "$tool"; continue
        fi
        info "Installing $tool…"
        if GO111MODULE=on go install "${GO_TOOLS[$tool]}" 2>/tmp/go_install_err; then
            binpath="$HOME/go/bin/$tool"
            # some modules install under a different binary name
            [[ ! -f "$binpath" ]] && binpath=$(find "$HOME/go/bin" -name "$tool" 2>/dev/null | head -n1)
            if [[ -f "$binpath" ]]; then
                sudo cp -f "$binpath" /usr/local/bin/ && mark_ok "$tool"
            else
                warn "$tool built but binary not found at expected path"; mark_fail "$tool"
            fi
        else
            tail -3 /tmp/go_install_err | while read -r l; do warn "  $l"; done
            mark_fail "$tool"
        fi
    done
}

# ── 5. pipx tools ─────────────────────────────
declare -A PIPX_TOOLS=(
  [waymore]="waymore"
  [s3scanner]="s3scanner"
  [dirsearch]="dirsearch"
  [wafw00f]="wafw00f"
  [arjun]="arjun"
)

install_pipx_tools() {
    section "Python pipx Tools"
    for tool in "${!PIPX_TOOLS[@]}"; do
        if is_installed "$tool"; then
            mark_skip "$tool"; continue
        fi
        info "Installing $tool via pipx…"
        if pipx install "${PIPX_TOOLS[$tool]}" 2>/tmp/pipx_err; then
            [[ -x "$HOME/.local/bin/$tool" ]] && sudo ln -sf "$HOME/.local/bin/$tool" "/usr/local/bin/$tool"
            mark_ok "$tool"
        else
            tail -2 /tmp/pipx_err | while read -r l; do warn "  $l"; done
            mark_fail "$tool"
        fi
    done
}

# ── 6. Git + Python tools ─────────────────────
declare -A GIT_PY_TOOLS=(
  [paramspider]="https://github.com/devanshbatham/ParamSpider"
  [openredirex]="https://github.com/devanshbatham/OpenRedireX"
  [secretfinder]="https://github.com/m4ll0k/SecretFinder.git"
  [corsy]="https://github.com/s0md3v/Corsy"
)

_pip_install() {
    local reqfile="$1"
    if python3 -m pip install --help 2>&1 | grep -q 'break-system-packages'; then
        python3 -m pip install -q --break-system-packages --upgrade -r "$reqfile" 2>&1 || true
    else
        python3 -m pip install -q --user --upgrade -r "$reqfile" 2>&1 || true
    fi
}

install_git_py_tools() {
    section "Git/Python Tools"
    mkdir -p "$TOOLS_DIR"
    for repo in "${!GIT_PY_TOOLS[@]}"; do
        if is_installed "$repo"; then
            mark_skip "$repo"; continue
        fi
        info "Cloning $repo…"
        local dest="$TOOLS_DIR/$repo"
        rm -rf "$dest"
        if ! git clone --depth 1 "${GIT_PY_TOOLS[$repo]}" "$dest" 2>/tmp/git_err; then
            tail -2 /tmp/git_err | while read -r l; do warn "  $l"; done
            mark_fail "$repo"; continue
        fi
        [[ -f "$dest/requirements.txt" ]] && _pip_install "$dest/requirements.txt"
        local main_py
        main_py=$(find "$dest" -maxdepth 1 -iname "${repo}.py" | head -n1)
        if [[ -n "$main_py" ]]; then
            chmod +x "$main_py"
            printf '#!/bin/bash\nexec python3 "%s" "$@"\n' "$main_py" \
                | sudo tee "/usr/local/bin/$repo" >/dev/null
            sudo chmod +x "/usr/local/bin/$repo"
            mark_ok "$repo"
        else
            warn "$repo cloned but no ${repo}.py found — may need manual setup"
            INSTALLED+=("$repo (cloned, no wrapper)")
        fi
    done
}

# ── 7. BadAuth0 (Go) ──────────────────────────
install_badauth() {
    section "BadAuth0"
    if is_installed "BadAuth0"; then
        mark_skip "BadAuth0"; return
    fi
    if ! command -v go &>/dev/null; then
        err "go not found — skipping BadAuth0"; FAILED+=("BadAuth0"); return 1
    fi
    info "Installing BadAuth0 via go install…"
    if GO111MODULE=on go install github.com/OctaYus/BadAuth0@latest 2>/tmp/go_install_err; then
        local binpath="$HOME/go/bin/BadAuth0"
        if [[ -f "$binpath" ]]; then
            sudo cp -f "$binpath" /usr/local/bin/BadAuth0
            sudo ln -sf /usr/local/bin/BadAuth0 /usr/local/bin/badauth
            mark_ok "BadAuth0"
        else
            warn "BadAuth0 built but binary not found"; mark_fail "BadAuth0"
        fi
    else
        tail -3 /tmp/go_install_err | while read -r l; do warn "  $l"; done
        mark_fail "BadAuth0"
    fi
}

# ── 8. bypass-403 ─────────────────────────────
install_bypass403() {
    section "bypass-403"
    if is_installed "bypass-403"; then mark_skip "bypass-403"; return; fi
    info "Cloning bypass-403…"
    local dest="$TOOLS_DIR/bypass-403"
    rm -rf "$dest"
    if git clone --depth 1 https://github.com/iamj0ker/bypass-403.git "$dest" 2>/tmp/git_err; then
        chmod +x "$dest/bypass-403.sh"
        sudo ln -sf "$dest/bypass-403.sh" /usr/local/bin/bypass-403
        mark_ok "bypass-403"
    else
        tail -2 /tmp/git_err | while read -r l; do warn "  $l"; done
        mark_fail "bypass-403"
    fi
}

# ── 9. gitleaks ───────────────────────────────
install_gitleaks() {
    section "gitleaks"
    if is_installed "gitleaks"; then mark_skip "gitleaks"; return; fi
    info "Building gitleaks…"
    local dest="$TOOLS_DIR/gitleaks"
    rm -rf "$dest"
    if git clone --depth 1 https://github.com/gitleaks/gitleaks.git "$dest" 2>/tmp/git_err; then
        if ( cd "$dest" && make build 2>/tmp/make_err ); then
            sudo cp -f "$dest/gitleaks" /usr/local/bin/
            mark_ok "gitleaks"
        else
            tail -3 /tmp/make_err | while read -r l; do warn "  $l"; done
            mark_fail "gitleaks"
        fi
    else
        tail -2 /tmp/git_err | while read -r l; do warn "  $l"; done
        mark_fail "gitleaks"
    fi
}

# ── 10. GF patterns ───────────────────────────
install_gf_patterns() {
    section "GF Patterns"
    local gf_patterns_dir="$HOME/.gf"
    if [[ -d "$gf_patterns_dir" && "$(ls -A "$gf_patterns_dir" 2>/dev/null)" && "$FORCE" -eq 0 ]]; then
        mark_skip "gf-patterns (~/.gf already populated)"; return
    fi
    mkdir -p "$gf_patterns_dir"
    local dest="$TOOLS_DIR/Gf-Patterns"
    rm -rf "$dest"
    if git clone --depth 1 https://github.com/1ndianl33t/Gf-Patterns.git "$dest" 2>/tmp/git_err; then
        cp "$dest"/*.json "$gf_patterns_dir/" 2>/dev/null || true
        mark_ok "gf-patterns (copied to ~/.gf)"
    else
        tail -2 /tmp/git_err | while read -r l; do warn "  $l"; done
        mark_fail "gf-patterns"
    fi
}

# ── 11. Wordlists ─────────────────────────────
install_wordlists() {
    section "Wordlists"
    mkdir -p "$WORDLISTS_DIR"

    local ffuf_wl="$WORDLISTS_DIR/ffuf-common.txt"
    if [[ ! -f "$ffuf_wl" || "$FORCE" -eq 1 ]]; then
        info "Downloading ffuf common wordlist…"
        if wget -q "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" \
                -O "$ffuf_wl" 2>/dev/null || \
           wget -q "http://www.ffuf.me/wordlist/common.txt" -O "$ffuf_wl" 2>/dev/null; then
            mark_ok "ffuf-common.txt → $ffuf_wl"
        else
            mark_fail "ffuf-common.txt"
        fi
    else
        mark_skip "ffuf-common.txt"
    fi

    local api_wl="$WORDLISTS_DIR/api-endpoints.txt"
    if [[ ! -f "$api_wl" || "$FORCE" -eq 1 ]]; then
        info "Downloading API endpoints wordlist…"
        if wget -q "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt" \
                -O "$api_wl" 2>/dev/null; then
            mark_ok "api-endpoints.txt → $api_wl"
        else
            mark_fail "api-endpoints.txt"
        fi
    else
        mark_skip "api-endpoints.txt"
    fi
}

# ── 12. Python requirements for FalconHunter ──
install_falcon_requirements() {
    section "FalconHunter Python Requirements"
    local req="$(dirname "$0")/requirements.txt"
    if [[ ! -f "$req" ]]; then
        warn "requirements.txt not found — skipping"; return
    fi
    info "Installing from requirements.txt…"
    if _pip_install "$req"; then
        ok "Python requirements installed"
    else
        warn "Some Python requirements may have failed"
    fi
}

# ── Summary ───────────────────────────────────
print_summary() {
    local end_time=$(date +%s)
    local elapsed=$(( end_time - START_TIME ))
    local mins=$(( elapsed / 60 ))
    local secs=$(( elapsed % 60 ))

    echo ""
    echo -e "${BOLD}${CYAN}╔═══════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${CYAN}║        Installation Summary           ║${NC}"
    echo -e "${BOLD}${CYAN}╚═══════════════════════════════════════╝${NC}"

    if [[ ${#INSTALLED[@]} -gt 0 ]]; then
        echo -e "\n${GREEN}${BOLD}Installed (${#INSTALLED[@]}):${NC}"
        for t in "${INSTALLED[@]}"; do echo -e "  ${GREEN}✓${NC} $t"; done
    fi

    if [[ ${#SKIPPED[@]} -gt 0 ]]; then
        echo -e "\n${CYAN}${BOLD}Already present (${#SKIPPED[@]}):${NC}"
        for t in "${SKIPPED[@]}"; do echo -e "  ${CYAN}↷${NC} $t"; done
    fi

    if [[ ${#FAILED[@]} -gt 0 ]]; then
        echo -e "\n${RED}${BOLD}Failed (${#FAILED[@]}):${NC}"
        for t in "${FAILED[@]}"; do echo -e "  ${RED}✗${NC} $t"; done
        echo -e "\n${YELLOW}[!] Run with --force to retry failed tools.${NC}"
    fi

    echo -e "\n${BOLD}Completed in ${mins}m ${secs}s${NC}"

    if [[ ${#FAILED[@]} -eq 0 ]]; then
        echo -e "${GREEN}${BOLD}[+] All tools installed successfully!${NC}"
    fi

    echo -e "${YELLOW}[!] Run: source ~/.bashrc${NC}"
}

# ── Main ──────────────────────────────────────
main() {
    echo -e "${BOLD}${GREEN}"
    cat << 'EOF'
  ______      __                      __  __            __
 / ____/___ _/ /________  ____  ___  / / / /_  ______  / /____  _____
/ /_  / __ `/ / ___/ __ \/ __ \/ _ \/ /_/ / / / / __ \/ __/ _ \/ ___/
/ __/ / /_/ / / /__/ /_/ / / / /  __/ __  / /_/ / / / / /_/  __/ /
/_/    \__,_/_/\___/\____/_/ /_/\___/_/ /_/\__,_/_/ /_/\__/\___/_/
EOF
    echo -e "${NC}"
    echo -e "${BOLD}FalconHunter Tool Installer${NC}"
    [[ "$FORCE" -eq 1 ]] && warn "Force mode: reinstalling all tools"
    echo ""

    setup_path
    install_system_packages
    install_latest_go
    install_go_tools
    install_pipx_tools
    install_git_py_tools
    install_badauth
    install_bypass403
    install_gitleaks
    install_gf_patterns
    install_wordlists
    install_falcon_requirements

    print_summary
}

main
