import argparse
import json
import os
import subprocess
import time
from datetime import datetime as date
import logging
import logging_config
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
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
            cnfinder_cmd = ["cnfinder", "-l", subdomains_file, "-o", output]
            subprocess.run(cnfinder_cmd, check=True)

            with open(output, "r") as f:
                cnames = f.read().splitlines()

            logger.info(f"{color.GREEN}(+) Found total of: {len(cnames)} CNAME. {color.END}")

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

        logger.info(f"{color.GREEN}Initialising BucketFinder...{color.END}")

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

        except Exception as e:
            logger.exception(f"{color.RED}Error in buckets_cli: {e}{color.END}")


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
        subdomains_file = f"{self.output_file}/hosts/alive-hosts.txt"
        urls = f"{self.output_file}/urls/all-urls.txt"

        try:
            logger.info(f"{color.GREEN}(+) Collecting all URLs{color.END}")
            commands = [
                f"cat {subdomains_file} | waybackurls | anew {urls}",
                f"cat {subdomains_file} | gau --subs | anew {urls}",
            ]
            for cmd in commands:
                subprocess.run(cmd, shell=True, check=True)

            # Extract JS URLs from the aggregated all-urls file
            js_extract_cmd = f"grep -E '\\.js($|\\?)' {urls} | sed 's/\\?.*$//' | anew {self.js_output}"
            subprocess.run(js_extract_cmd, shell=True, check=True)

            # Run gf (tomnomnom/gf) patterns: read URLs from file, grep with named
            # patterns from ~/.gf/*.json, append new lines via anew (cross-platform).
            gf_list = ["xss", "ssrf", "lfi", "sqli", "ssti"]
            gf_output_dir = f"{self.output_file}/urls/"
            for pattern in gf_list:
                out_file = os.path.join(gf_output_dir, f"gf-{pattern}.txt")
                try:
                    with open(urls, "rb") as urls_f:
                        p_gf = subprocess.run(
                            ["gf", pattern],
                            stdin=urls_f,
                            capture_output=True,
                            timeout=300,
                        )
                    # gf uses grep-style exit codes: 0 = match, 1 = no match (not fatal)
                    if p_gf.stderr and p_gf.returncode not in (0, 1):
                        logger.debug(
                            f"gf {pattern} stderr: {p_gf.stderr.decode(errors='replace')}"
                        )
                    if not (p_gf.stdout and p_gf.stdout.strip()):
                        continue
                    subprocess.run(
                        ["anew", out_file],
                        input=p_gf.stdout,
                        check=False,
                        timeout=60,
                    )
                except FileNotFoundError:
                    logger.warning(
                        f"{color.RED}gf or anew not found in PATH; install from https://github.com/tomnomnom/gf and https://github.com/tomnomnom/anew{color.END}"
                    )
                    break
                except subprocess.TimeoutExpired:
                    logger.warning(f"gf {pattern} timed out, skipping")
                except Exception as e:
                    logger.warning(f"gf {pattern} failed: {e}")

        except Exception as e:
            logger.exception(
                f"{color.RED}Error occurred during URL collection: {e}{color.END}"
            )

    def extract_js_files(self):
        """Extract JavaScript files from collected URLs"""
        try:
            logger.info(f"{color.GREEN}[+] Extracting JS files...{color.END}")
            # Read from the master all-urls file and extract JS file URLs into js_output.
            all_urls = f"{self.output_file}/urls/all-urls.txt"
            extraction_command = (
                f"grep -E '\\.(js|json)($|\\?)' {all_urls} | "
                f"sed 's/\\?.*$//' | sort -u | anew {self.js_output}"
            )
            subprocess.run(extraction_command, shell=True, check=True, executable="/bin/bash")
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
    def __init__(self, telegram_token, telegram_chat_id, timeout=5, max_retries=3):
        """
        Robust Telegram notifier with retries and exception handling.

        Args:
            telegram_token (str): Bot token
            telegram_chat_id (str): Chat ID to send messages to
            timeout (int): Request timeout seconds
            max_retries (int): Number of retries for transient errors
        """
        self.token = telegram_token
        self.chat_id = telegram_chat_id
        self.timeout = timeout

        # Session with retries to mitigate transient network errors
        self.session = requests.Session()
        retries = Retry(
            total=max_retries,
            backoff_factor=0.5,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset(["GET", "POST"]),
        )
        adapter = HTTPAdapter(max_retries=retries)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

    def notify_telegram(self, token=None, chat_id=None, message=""):
        """Send Telegram notification safely (no exceptions raised to caller)"""
        token = token or self.token
        chat_id = chat_id or self.chat_id

        if not token or not chat_id:
            logger.debug("Telegram token or chat_id not provided; skipping notification.")
            return

        url = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = {"chat_id": chat_id, "text": message, "parse_mode": "HTML"}

        try:
            response = self.session.post(url, json=payload, timeout=self.timeout)
            if response.ok:
                logger.info("Notification sent successfully!")
            else:
                logger.warning(
                    f"Failed to send notification: {response.status_code} - {response.text}"
                )
        except requests.RequestException as e:
            # Network failure to Telegram should not stop the scanner
            logger.warning(f"Telegram notify failed (non-fatal): {e}")


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
