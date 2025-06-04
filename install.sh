#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to make a Python script executable system-wide
make_py_executable() {
    local tool_name="$1"
    local script_path="$2"
    
    # Add shebang if not present
    if ! head -1 "$script_path" | grep -q "^#\!/usr/bin/env python3"; then
        sed -i '1i#!/usr/bin/env python3' "$script_path"
    fi
    
    # Make executable
    chmod +x "$script_path"
    
    # Create symlink without .py extension
    sudo ln -sf "$script_path" "/usr/local/bin/$tool_name"
}

# Function to install a Go tool
install_go_tool() {
    local tool_url="$1"
    local tool_name=$(basename "$tool_url" | cut -d@ -f1)
    
    if ! command_exists "$tool_name"; then
        echo -e "${YELLOW}[+] Installing $tool_name...${NC}"
        if ! go install -v "$tool_url" 2>&1; then
            echo -e "${RED}[-] Failed to install $tool_name${NC}"
            return 1
        fi
        echo -e "${GREEN}[+] Successfully installed $tool_name${NC}"
    else
        echo -e "${GREEN}[+] $tool_name is already installed${NC}"
    fi
}

# Function to install a Python tool
install_pip_tool() {
    local tool_name="$1"
    local package_name="${2:-$tool_name}"
    
    if ! command_exists "$tool_name"; then
        echo -e "${YELLOW}[+] Installing $tool_name...${NC}"
        if ! pip3 install "$package_name" --break-system-packages 2>&1; then
            echo -e "${RED}[-] Failed to install $tool_name${NC}"
            return 1
        fi
        echo -e "${GREEN}[+] Successfully installed $tool_name${NC}"
    else
        echo -e "${GREEN}[+] $tool_name is already installed${NC}"
    fi
}

# Function to install a git repo Python tool
install_git_py_tool() {
    local tool_name="$1"
    local repo_url="$2"
    local script_path="$3"
    
    if ! command_exists "$tool_name"; then
        echo -e "${YELLOW}[+] Installing $tool_name...${NC}"
        if ! git clone "$repo_url" "$tool_name-temp" 2>&1 || 
           ! cd "$tool_name-temp" 2>&1 || 
           ! pip3 install -r requirements.txt --break-system-packages 2>&1; then
            echo -e "${RED}[-] Failed to install $tool_name dependencies${NC}"
            cd .. && rm -rf "$tool_name-temp"
            return 1
        fi
        
        # Make the Python script executable
        make_py_executable "$tool_name" "$script_path"
        
        cd .. && rm -rf "$tool_name-temp"
        echo -e "${GREEN}[+] Successfully installed $tool_name${NC}"
    else
        echo -e "${GREEN}[+] $tool_name is already installed${NC}"
    fi
}

# Function to install Gitleaks from source
install_gitleaks() {
    if ! command_exists gitleaks; then
        echo -e "${YELLOW}[+] Installing Gitleaks from source...${NC}"
        if ! git clone https://github.com/gitleaks/gitleaks.git gitleaks-temp 2>&1 || 
           ! cd gitleaks-temp 2>&1 || 
           ! make build 2>&1 || 
           ! sudo cp ./gitleaks /usr/local/bin/ 2>&1 || 
           ! cd .. 2>&1 || 
           ! rm -rf gitleaks-temp 2>&1; then
            echo -e "${RED}[-] Failed to install Gitleaks${NC}"
            return 1
        fi
        echo -e "${GREEN}[+] Successfully installed Gitleaks${NC}"
    else
        echo -e "${GREEN}[+] Gitleaks is already installed${NC}"
    fi
}

# Update package lists and install dependencies
echo -e "${YELLOW}[+] Updating packages and installing dependencies...${NC}"
sudo apt update && sudo apt install -y curl wget git python3 python3-pip make 2>&1 || {
    echo -e "${RED}[-] Failed to install dependencies${NC}"
    exit 1
}

# Install Go if not installed
if ! command_exists go; then
    echo -e "${YELLOW}[+] Installing Go...${NC}"
    if ! wget https://golang.org/dl/go1.20.1.linux-amd64.tar.gz 2>&1 || 
       ! sudo tar -C /usr/local -xzf go1.20.1.linux-amd64.tar.gz 2>&1 || 
       ! rm go1.20.1.linux-amd64.tar.gz 2>&1; then
        echo -e "${RED}[-] Failed to install Go${NC}"
        exit 1
    fi
    export PATH=$PATH:/usr/local/go/bin
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    source ~/.bashrc
    echo -e "${GREEN}[+] Successfully installed Go${NC}"
else
    echo -e "${GREEN}[+] Go is already installed${NC}"
fi

# Setup GOPATH
GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin
mkdir -p "$GOPATH"/{bin,src,pkg}
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
echo 'export GOPATH=$HOME/go' >> ~/.bashrc
source ~/.bashrc

# List of Go tools to install
go_tools=(
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/owasp-amass/amass/v3/...@master"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/tomnomnom/waybackurls@latest"
    "github.com/lc/gau@latest"
    "github.com/tomnomnom/gf@latest"
    "github.com/tomnomnom/qsreplace@latest"
    "github.com/m1ndo/freq@latest"
    "github.com/anarchysteam/mantra@latest"
    "github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"
    "github.com/PentestPad/subzy@latest"
    "github.com/haccer/subjack@latest"
    "github.com/hahwul/dalfox/v2@latest"
    "github.com/r0oth3x49/ghauri@latest"
    "go install github.com/takshal/freq@latest"
)

# Install Go tools
for tool in "${go_tools[@]}"; do
    install_go_tool "$tool"
done

# List of Python tools to install via pip
pip_tools=(
    "waymore"
    "trufflehog"
    "sstimap"
)

# Install Python tools via pip
for tool in "${pip_tools[@]}"; do
    install_pip_tool "$tool"
done

# Install apt tools
if ! command_exists xsser; then
    echo -e "${YELLOW}[+] Installing XSShunter...${NC}"
    sudo apt install -y xsser 2>&1 || echo -e "${RED}[-] Failed to install xsser${NC}"
fi

# Install git-based Python tools
install_git_py_tool "paramspider" "https://github.com/devanshbatham/ParamSpider" "paramspider.py"
install_git_py_tool "openredirex" "https://github.com/devanshbatham/OpenRedireX" "openredirex.py"
install_git_py_tool "secretfinder" "https://github.com/m4ll0k/SecretFinder.git" "SecretFinder.py"

# Install Gitleaks from source
install_gitleaks

echo -e "${GREEN}[+] All tools installed successfully!${NC}"
echo -e "${YELLOW}[+] You may need to run 'source ~/.bashrc' or restart your terminal for changes to take effect.${NC}"