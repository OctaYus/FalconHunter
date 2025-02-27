#!/bin/bash

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Update package lists and install dependencies
sudo apt update
sudo apt install -y curl wget git python3 python3-pip

# Install Go
if ! command_exists go; then
    echo "Installing Go..."
    wget https://golang.org/dl/go1.20.1.linux-amd64.tar.gz
    sudo tar -C /usr/local -xzf go1.20.1.linux-amd64.tar.gz
    rm go1.20.1.linux-amd64.tar.gz
    export PATH=$PATH:/usr/local/go/bin
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    source ~/.bashrc
fi

# Setup GOPATH
GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin
mkdir -p "$GOPATH"/{bin,src,pkg}
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
echo 'export GOPATH=$HOME/go' >> ~/.bashrc
source ~/.bashrc

# Install tools
tools=(
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
)

for tool in "${tools[@]}"; do
    tool_name=$(basename "$tool" | cut -d@ -f1)
    if ! command_exists "$tool_name"; then
        echo "Installing $tool_name..."
        go install -v "$tool"
    fi
done

# Install Python-based tools
python_tools=(
    "waymore"
    "trufflehog"
)

for py_tool in "${python_tools[@]}"; do
    if ! command_exists "$py_tool"; then
        echo "Installing $py_tool..."
        pip3 install "$py_tool" --break-system-packages
    fi
done

# Install ParamSpider
if ! command_exists paramspider; then
    echo "Installing ParamSpider..."
    git clone https://github.com/devanshbatham/ParamSpider
    cd ParamSpider || exit
    pip3 install -r requirements.txt --break-system-packages
    sudo ln -s "$(pwd)/paramspider.py" /usr/local/bin/paramspider
    cd ..
    rm -rf ParamSpider
fi

# Install Dalfox
if ! command_exists dalfox; then
    echo "Installing Dalfox..."
    go install -v github.com/hahwul/dalfox/v2@latest
fi

# Install XSShunter
if ! command_exists xsser; then
    echo "Installing XSShunter..."
    sudo apt install xsser
fi

# Install SSTImap
if ! command_exists sstimap; then
    echo "Installing SSTImap..."
    pip3 install sstimap --break-system-packages
fi

# Install Ghauri
if ! command_exists ghauri; then
    echo "Installing Ghauri..."
    go install -v github.com/r0oth3x49/ghauri@latest
fi

# Install OpenRedireX
if ! command_exists openredirex; then
    echo "Installing OpenRedireX..."
    git clone https://github.com/devanshbatham/OpenRedireX
    cd OpenRedireX || exit
    pip3 install -r requirements.txt --break-system-packages
    sudo ln -s "$(pwd)/openredirex.py" /usr/local/bin/openredirex
    cd ..
    rm -rf OpenRedireX
fi

# Install SecretFinder
if ! command_exists SecretFinder; then
    echo "Installing SecretFinder..."
    git clone https://github.com/m4ll0k/SecretFinder
    cd SecretFinder || exit
    pip3 install -r requirements.txt --break-system-packages
    sudo ln -s "$(pwd)/SecretFinder.py" /usr/local/bin/SecretFinder
    cd ..
    rm -rf SecretFinder
fi

# Install Gitleaks
if ! command_exists gitleaks; then
    echo "Installing Gitleaks..."
    sudo apt install -y gitleaks
fi

echo "All tools installed successfully!"
