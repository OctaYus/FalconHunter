#!/bin/bash

# Check if the correct number of arguments are provided
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <output_folder> <domains_list>"    
    exit 1
fi

# Arguments
output_folder=$1
domains_list=$2

# Ensure output folder exists
mkdir -p "$output_folder"

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check for required tools
required_tools=("subfinder" "httpx" "nuclei" "waymore" "waybackurls" "gau" "gf")
for tool in "${required_tools[@]}"; do
    if ! command_exists "$tool"; then
        echo "Error: $tool is not installed." >&2
        exit 1
    fi
done

# Function to display a simple spinner animation
spinner() {
    local pid=$!
    local delay=0.1
    local spinstr='|/-\'
    while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

# Subfinder: Find subdomains and save to bb_subs.txt
echo -n "Running subfinder..."
(subfinder -dL "$domains_list" -o "$output_folder/bb_subs.txt") & spinner
echo "done."

# Httpx: Probe for alive domains and save output
echo -n "Running httpx..."
(httpx -sc -title -cl -fr -td -o "$output_folder/httpx.txt" < "$output_folder/bb_subs.txt") & spinner
echo "done."

# Extract alive domains and save to alive.txt
echo -n "Extracting alive domains..."
(cat "$output_folder/httpx.txt" | awk '{print $1}' | tee -a "$output_folder/alive.txt") & spinner
echo "done."

# Nuclei: Scan alive domains with nuclei templates and save output
echo -n "Running nuclei..."
(nuclei -l "$output_folder/alive.txt" -t fuzzing-templates -o "$output_folder/nuclei-output.txt") & spinner
echo "done."

# Waymore: Gather more URLs and save output
echo -n "Running waymore..."
(waymore -mode U -i "$output_folder/alive.txt" -oU "$output_folder/url.txt") & spinner
echo "done."

# Waybackurls: Fetch historical URLs and append to urls.txt
echo -n "Running waybackurls..."
(cat "$output_folder/alive.txt" | waybackurls > "$output_folder/urls.txt") & spinner
echo "done."

# GAU: Get all URLs and append to urls.txt
echo -n "Running gau..."
(cat "$output_folder/alive.txt" | gau >> "$output_folder/urls.txt") & spinner
echo "done."

# Extract URLs with parameters and save to params.txt
echo -n "Extracting URLs with parameters..."
(cat "$output_folder/urls.txt" | grep "=" | tee -a "$output_folder/params.txt") & spinner
echo "done."

# Extract JavaScript files and save to js-files.txt
echo -n "Extracting JavaScript files..."
(cat "$output_folder/urls.txt" | grep "\.js$" | tee -a "$output_folder/js-files.txt") & spinner
echo "done."

# Use gf to find specific vulnerabilities and save to respective files
echo -n "Running gf for XSS..."
(cat "$output_folder/params.txt" | gf xss | tee -a "$output_folder/gf-xss.txt") & spinner
echo "done."

echo -n "Running gf for LFI..."
(cat "$output_folder/params.txt" | gf lfi | tee -a "$output_folder/gf-lfi.txt") & spinner
echo "done."

echo -n "Running gf for SSRF..."
(cat "$output_folder/params.txt" | gf ssrf | tee -a "$output_folder/gf-ssrf.txt") & spinner
echo "done."

echo -n "Running gf for SQLi..."
(cat "$output_folder/params.txt" | gf sqli | tee -a "$output_folder/gf-sqli.txt") & spinner
echo "done."

echo "Script completed successfully."