#!/bin/bash
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

TOOLS_DIR="${HOME}/Tools"
mkdir -p "$TOOLS_DIR"

# Ensure ~/.local/bin is in PATH for all users
if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
    export PATH="$HOME/.local/bin:$PATH"
    echo 'export PATH=$HOME/.local/bin:$PATH' >> ~/.bashrc
fi

# 1. System dependencies (except Go)
install_system_packages() {
    echo -e "${YELLOW}[+] Installing system dependencies...${NC}"
    sudo apt update
    sudo apt install -y curl wget git python3 python3-pip python3-venv python3-virtualenv make build-essential gcc cmake ruby whois zip libpcap-dev python3-dev libssl-dev libffi-dev pipx
    python3 -m pipx ensurepath
    export PATH="$HOME/.local/bin:$PATH"
    echo -e "${GREEN}[+] System dependencies installed${NC}"
}

# 2. Install latest Go (from go.dev, robust)
install_latest_go() {
    GOVERSION=$(curl -s 'https://go.dev/VERSION?m=text' | grep -E '^go[0-9.]+' | head -n1)
    if [[ -z "$GOVERSION" ]]; then
        echo -e "${RED}Could not find the latest Go version. Aborting.${NC}"
        exit 1
    fi
    echo -e "${YELLOW}[+] Downloading and installing latest Go: $GOVERSION ...${NC}"
    wget -q https://go.dev/dl/${GOVERSION}.linux-amd64.tar.gz -O /tmp/go.tgz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf /tmp/go.tgz
    rm /tmp/go.tgz

    export PATH=/usr/local/go/bin:$PATH
    sudo ln -sf /usr/local/go/bin/go /usr/local/bin/go

    if ! grep -q '/usr/local/go/bin' ~/.bashrc; then
        echo 'export PATH=/usr/local/go/bin:$PATH' >> ~/.bashrc
    fi

    if ! command -v go &>/dev/null; then
        echo -e "${RED}Go installation failed. Please check your system or install manually.${NC}"
        exit 1
    fi

    export GOROOT=/usr/local/go
    export GOPATH=$HOME/go
    export PATH=$PATH:$GOPATH/bin
    mkdir -p "$GOPATH"/{bin,src,pkg}
    grep -qxF 'export GOROOT=/usr/local/go' ~/.bashrc || echo 'export GOROOT=/usr/local/go' >> ~/.bashrc
    grep -qxF 'export GOPATH=$HOME/go' ~/.bashrc || echo 'export GOPATH=$HOME/go' >> ~/.bashrc
    grep -qxF 'export PATH=$PATH:$HOME/go/bin' ~/.bashrc || echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc

    echo -e "${GREEN}[+] $GOVERSION installed; Go is now available as 'go'.${NC}"
}

install_system_packages
install_latest_go

# 3. Go tools and installation
declare -A go_tools=(
  [subfinder]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  [amass]="github.com/owasp-amass/amass/v3/...@master"
  [httpx]="github.com/projectdiscovery/httpx/cmd/httpx@latest"
  [waybackurls]="github.com/tomnomnom/waybackurls@latest"
  [gau]="github.com/lc/gau@latest"
  [gf]="github.com/tomnomnom/gf@latest"
  [qsreplace]="github.com/tomnomnom/qsreplace@latest"
  [freq]="github.com/m1ndo/freq@latest"
  [mantra]="github.com/Brosck/mantra@latest"
  [nuclei]="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  [subzy]="github.com/PentestPad/subzy@latest"
  [subjack]="github.com/haccer/subjack@latest"
  [dalfox]="github.com/hahwul/dalfox/v2@latest"
  [anew]="github.com/tomnomnom/anew@latest"
)

install_go_tools() {
    echo -e "${YELLOW}[+] Installing Go tools...${NC}"
    for tool in "${!go_tools[@]}"; do
        if command -v "$tool" &>/dev/null || [[ -f "/usr/local/bin/$tool" ]]; then
            echo -e "${GREEN}[+] $tool is already installed${NC}"
            continue
        fi
        echo -e "${YELLOW}[+] go install ${go_tools[$tool]}${NC}"
        GO111MODULE=on go install "${go_tools[$tool]}" 2>&1 || { echo -e "${RED}[-] Failed to install $tool${NC}"; continue; }
        binpath="$HOME/go/bin/$tool"
        if [[ -f "$binpath" ]]; then
            sudo cp "$binpath" /usr/local/bin/
            echo -e "${GREEN}[+] $tool → /usr/local/bin/${NC}"
        else
            echo -e "${RED}[-] Could not find built $tool at $binpath${NC}"
        fi
    done
}

# 4. pipx tools install
declare -A pipx_tools=(
  [waymore]="waymore"
  [trufflehog]="trufflehog"
  [sstimap]="sstimap"
  [ghauri]="ghauri"
)

install_pipx_tools() {
    echo -e "${YELLOW}[+] Installing Python CLI tools with pipx...${NC}"
    for tool in "${!pipx_tools[@]}"; do
        if command -v "$tool" &>/dev/null || [[ -f "/usr/local/bin/$tool" ]]; then
            echo -e "${GREEN}[+] $tool is already installed${NC}"
            continue
        fi
        pipx install "${pipx_tools[$tool]}" || { echo -e "${RED}[-] Failed to install $tool (pipx)${NC}"; continue; }
        if [[ -x "$HOME/.local/bin/$tool" ]]; then
            sudo ln -sf "$HOME/.local/bin/$tool" "/usr/local/bin/$tool"
            echo -e "${GREEN}[+] $tool → /usr/local/bin/${NC}"
        fi
    done
}

# 5. GitHub Python tools (python wrappers)
declare -A git_py_tools=(
  [paramspider]="https://github.com/devanshbatham/ParamSpider"
  [openredirex]="https://github.com/devanshbatham/OpenRedireX"
  [secretfinder]="https://github.com/m4ll0k/SecretFinder.git"
)

install_git_py_tools() {
    mkdir -p "$TOOLS_DIR"
    pushd "$TOOLS_DIR" >/dev/null
    for repo in "${!git_py_tools[@]}"; do
        if command -v "$repo" &>/dev/null || [[ -f "/usr/local/bin/$repo" ]]; then
            echo -e "${GREEN}[+] $repo is already installed${NC}"
            continue
        fi
        rm -rf "$repo"
        git clone --depth 1 "${git_py_tools[$repo]}" "$repo"
        cd "$repo"
        # Always brute force --break-system-packages here (for requirements installs)
        if python3 -m pip --help 2>&1 | grep -q break-system-packages; then
            python3 -m pip install --break-system-packages --upgrade -r requirements.txt 2>&1 || true
        else
            python3 -m pip install --user --upgrade -r requirements.txt 2>&1 || true
        fi
        main_py=$(find . -maxdepth 1 -iname "${repo}.py" | head -n1)
        if [[ -n "$main_py" ]]; then
            chmod +x "$main_py"
            echo -e "#!/bin/bash\nexec python3 '$TOOLS_DIR/$repo/${repo}.py' \"\$@\"" | sudo tee /usr/local/bin/"$repo" > /dev/null
            sudo chmod +x /usr/local/bin/"$repo"
            echo -e "${GREEN}[+] $repo → /usr/local/bin (Python wrapper)${NC}"
        fi
        cd ..
    done
    popd >/dev/null
}

# 6. xsser via apt or pipx
install_xsser() {
    echo -e "${YELLOW}[+] Installing xsser...${NC}"
    if command -v xsser &>/dev/null || [[ -f "/usr/local/bin/xsser" ]]; then
        echo -e "${GREEN}[+] xsser is already installed${NC}"; return
    fi
    if ! sudo apt install -y xsser; then
        echo -e "${YELLOW}[!] xsser not found in apt; trying pipx...${NC}"
        pipx install xsser || { echo -e "${RED}[-] Failed to install xsser${NC}"; return; }
        if [[ -x "$HOME/.local/bin/xsser" ]]; then
            sudo ln -sf "$HOME/.local/bin/xsser" /usr/local/bin/xsser
        fi
    fi
}

# 7. Gitleaks (Go program with make)
install_gitleaks() {
    if command -v gitleaks &>/dev/null || [[ -f "/usr/local/bin/gitleaks" ]]; then
        echo -e "${GREEN}[+] gitleaks is already installed${NC}"
        return
    fi
    git clone --depth 1 https://github.com/gitleaks/gitleaks.git "$TOOLS_DIR/gitleaks"
    cd "$TOOLS_DIR/gitleaks"
    make build
    sudo cp ./gitleaks /usr/local/bin/
    cd ..
}

install_go_tools
install_pipx_tools
install_git_py_tools
install_xsser
install_gitleaks

echo -e "${GREEN}[+] All FalconHunter tools installed successfully!${NC}"
echo -e "${YELLOW}[+] Please 'source ~/.bashrc' or restart your terminal for your PATH updates to take effect.${NC}"
