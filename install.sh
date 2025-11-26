#!/bin/bash


set -e

CONFIG_FILE="./falconhunter.cfg"
if [[ -f $CONFIG_FILE ]]; then
    source "$CONFIG_FILE"
fi

# Location for external tools and data
tools="${tools:-$HOME/Tools}"

# Ensure script runs with bash >= 4
BASH_VERSION_NUM=$(bash --version | awk 'NR==1{print $4}' | cut -d'.' -f1)
if [[ $BASH_VERSION_NUM -lt 4 ]]; then
    echo "Your Bash version is lower than 4. Please update."
    exit 1
fi

# Colors
NC='\033[0m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'



declare -A go_tools=(
  [subfinder]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  [amass]="github.com/owasp-amass/amass/v3/...@master"
  [httpx]="github.com/projectdiscovery/httpx/cmd/httpx@latest"
  [waybackurls]="github.com/tomnomnom/waybackurls@latest"
  [gau]="github.com/lc/gau@latest"
  [gf]="github.com/tomnomnom/gf@latest"
  [qsreplace]="github.com/tomnomnom/qsreplace@latest"
  [freq]="github.com/m1ndo/freq@latest"
  [mantra]="github.com/anarchysteam/mantra@latest"
  [nuclei]="github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"
  [subzy]="github.com/PentestPad/subzy@latest"
  [subjack]="github.com/haccer/subjack@latest"
  [dalfox]="github.com/hahwul/dalfox/v2@latest"
  [ghauri]="github.com/r0oth3x49/ghauri@latest"
)

declare -A pip_tools=(
  [waymore]="waymore"
  [trufflehog]="trufflehog"
  [sstimap]="sstimap"
)

# For Python tools installed via git
declare -A git_py_tools=(
  [paramspider]="https://github.com/devanshbatham/ParamSpider"
  [openredirex]="https://github.com/devanshbatham/OpenRedireX"
  [secretfinder]="https://github.com/m4ll0k/SecretFinder.git"
)

# Packages via apt
apt_tools=(xsser)
# Extra: Gitleaks via build-from-source
git_repos=(gitleaks)



command_exists() {
    command -v "$1" >/dev/null 2>&1
}



install_system_packages() {
    echo -e "${YELLOW}[+] Installing system dependencies...${NC}"
    sudo apt update
    sudo apt install -y curl wget git python3 python3-pip python3-venv python3-virtualenv pipx make build-essential gcc cmake ruby whois zip libpcap-dev python3-dev libssl-dev libffi-dev
    echo -e "${GREEN}[+] System dependencies installed${NC}"
}



install_golang_version() {
    if command_exists go; then
        echo -e "${GREEN}[+] Go is already installed${NC}"
        return
    fi
    local version="go1.20.1"
    echo -e "${YELLOW}[+] Installing Go $version...${NC}"
    wget "https://golang.org/dl/${version}.linux-amd64.tar.gz"
    sudo tar -C /usr/local -xzf "${version}.linux-amd64.tar.gz"
    rm "${version}.linux-amd64.tar.gz"
    export PATH=$PATH:/usr/local/go/bin
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    echo -e "${GREEN}[+] Go installed.${NC}"
}

export_paths_and_gopath() {
    export GOPATH="$HOME/go"
    export PATH=$PATH:$GOPATH/bin
    mkdir -p "$GOPATH"/{bin,src,pkg}
    echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
    echo 'export GOPATH=$HOME/go' >> ~/.bashrc
}



install_go_tools() {
    echo -e "${YELLOW}[+] Installing Go tools...${NC}"
    for tool in "${!go_tools[@]}"; do
        if command_exists "$tool"; then
            echo -e "${GREEN}[+] $tool is already installed${NC}"
            continue
        fi
        echo -e "${YELLOW}[+] Installing $tool...${NC}"
        go install -v "${go_tools[$tool]}" 2>&1 || echo -e "${RED}[-] Failed to install $tool${NC}"
    done
}

install_pip_tools() {
    echo -e "${YELLOW}[+] Installing Python tools...${NC}"
    for tool in "${!pip_tools[@]}"; do
        if command_exists "$tool"; then
            echo -e "${GREEN}[+] $tool is already installed${NC}"
            continue
        fi
        echo -e "${YELLOW}[+] Installing $tool (pip)...${NC}"
        python3 -m pip install --break-system-packages -U "${pip_tools[$tool]}" 2>&1 || echo -e "${RED}[-] Failed to install $tool${NC}"
    done
}

install_apt_tools() {
    echo -e "${YELLOW}[+] Installing APT tools...${NC}"
    for t in "${apt_tools[@]}"; do
        if command_exists "$t"; then
            echo -e "${GREEN}[+] $t is already installed${NC}"
            continue
        fi
        sudo apt install -y "$t" 2>&1 || echo -e "${RED}[-] Failed to install $t${NC}"
    done
}

install_git_py_tools() {
    mkdir -p "$tools"
    pushd "$tools"
    for repo in "${!git_py_tools[@]}"; do
        if command_exists "$repo"; then
            echo -e "${GREEN}[+] $repo is already installed${NC}"
            continue
        fi
        rm -rf "$repo"
        git clone --depth 1 "${git_py_tools[$repo]}" "$repo"
        cd "$repo"
        if [[ -f requirements.txt ]]; then
            python3 -m pip install --break-system-packages -r requirements.txt
        fi
        # Assume main script matches repo name for most cases:
        for script in ./*.py; do
            script_name=$(basename "$script" .py)
            chmod +x "$script"
            sudo ln -sf "$PWD/$(basename "$script")" "/usr/local/bin/$script_name"
        done
        cd ..
    done
    popd
}

install_gitleaks() {
    if command_exists gitleaks; then
        echo -e "${GREEN}[+] gitleaks is already installed${NC}"
        return
    fi
    git clone https://github.com/gitleaks/gitleaks.git "$tools/gitleaks"
    cd "$tools/gitleaks"
    make build
    sudo cp ./gitleaks /usr/local/bin/
    cd ..
}

final_message() {
    echo -e "${GREEN}[+] All FalconHunter tools installed successfully!${NC}"
    echo -e "${YELLOW}[+] You may need to run 'source ~/.bashrc' or restart your terminal for changes to take effect.${NC}"
}


install_system_packages
install_golang_version
export_paths_and_gopath

install_go_tools
install_pip_tools
install_apt_tools
install_git_py_tools
install_gitleaks

final_message

exit 0
