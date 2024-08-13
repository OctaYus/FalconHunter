#!/bin/bash

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Update package lists
sudo apt update

# Install dependencies
sudo apt install -y curl wget git python3 python3-pip

# Install Go
if ! command_exists go; then
    echo "Installing Go..."
    wget https://golang.org/dl/go1.20.1.linux-amd64.tar.gz
    sudo tar -C /usr/local -xzf go1.20.1.linux-amd64.tar.gz
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

# Install subfinder
if ! command_exists subfinder; then
    echo "Installing subfinder..."
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
fi

# Install amass
if ! command_exists amass; then
    echo "Installing amass..."
    go install -v github.com/owasp-amass/amass/v3/...@master
fi

# Install httpx
if ! command_exists httpx; then
    echo "Installing httpx..."
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
fi

# Install subzy
if ! command_exists subzy; then
    echo "Installing subzy..."
    go install -v github.com/LukaSikic/subzy@latest
fi

# Install waymore
if ! command_exists waymore; then
    echo "Installing waymore..."
    pip3 install waymore
fi

# Install waybackurls
if ! command_exists waybackurls; then
    echo "Installing waybackurls..."
    go install -v github.com/tomnomnom/waybackurls@latest
fi

# Install gau
if ! command_exists gau; then
    echo "Installing gau..."
    go install -v github.com/lc/gau@latest
fi

# Install paramspider
if ! command_exists paramspider; then
    echo "Installing paramspider..."
    git clone https://github.com/devanshbatham/ParamSpider
    cd ParamSpider || exit
    pip3 install -r requirements.txt
    sudo ln -s "$(pwd)/paramspider.py" /usr/local/bin/paramspider
    cd ..
fi

# Install gf
if ! command_exists gf; then
    echo "Installing gf..."
    go install -v github.com/tomnomnom/gf@latest
    echo 'source $(which gf-completion.sh)' >> ~/.bashrc
    source ~/.bashrc
fi

# Install qsreplace
if ! command_exists qsreplace; then
    echo "Installing qsreplace..."
    go install -v github.com/tomnomnom/qsreplace@latest
fi

# Install freq
if ! command_exists freq; then
    echo "Installing freq..."
    go install -v github.com/m1ndo/freq@latest
fi

# Install mantra
if ! command_exists mantra; then
    echo "Installing mantra..."
    go install -v github.com/anarchysteam/mantra@latest
fi

# Install nuclei
if ! command_exists nuclei; then
    echo "Installing nuclei..."
    go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
fi

# Clean up
rm go1.20.1.linux-amd64.tar.gz

echo "All tools installed successfully!"
