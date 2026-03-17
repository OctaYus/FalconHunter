import argparse
import json
import os
import re
import subprocess
import shutil
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
                "mantra_output.txt",
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
            subfinder_cmd = ["subfinder", "-dL", domains, "-all", "-o", output]
            logger.info(f"{color.GREEN}(+) Subdomain enumeration{color.END}")
            subprocess.run(subfinder_cmd, check=True)
        except FileNotFoundError:
            logger.warning(f"{color.RED}(-) subfinder not found in PATH{color.END}")
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
            logger.info(f"{color.GREEN}(+) Probing alive hosts{color.END}")
            subprocess.run(httpx_cmd, check=True)
            # Append only new alive targets to avoid duplicates across reruns.
            existing = set()
            if os.path.isfile(alive_output):
                with open(alive_output, "r", encoding="utf-8", errors="replace") as existing_f:
                    for line in existing_f:
                        existing.add(line.strip())
            new_lines = []
            with open(httpx_output, "r", encoding="utf-8", errors="replace") as infile:
                for line in infile:
                    parts = line.split()
                    if not parts:
                        continue
                    http_domain = parts[0]
                    if "http" in http_domain and http_domain not in existing:
                        existing.add(http_domain)
                        new_lines.append(http_domain)
            if new_lines:
                with open(alive_output, "a", encoding="utf-8") as outfile:
                    outfile.write("\n".join(new_lines) + "\n")

        except FileNotFoundError:
            logger.warning(f"{color.RED}(-) httpx not found in PATH{color.END}")
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
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3
            resolver.lifetime = 6
            answers = resolver.resolve(domain, "TXT")
            for record in answers:
                if record.to_text().startswith('"v=spf1'):
                    return True
            return False
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.LifetimeTimeout):
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
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3
            resolver.lifetime = 6
            answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
            for record in answers:
                if record.to_text().startswith('"v=DMARC1'):
                    return True
            return False
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.LifetimeTimeout):
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

    def __init__(self, domains, output_file, auth0_email=""):
        """
        Initialize with domains file and output directory

        Args:
            domains (str): Path to file containing target domains
            output_file (str): Path to output directory
        """
        self.domains = domains
        self.output_file = output_file
        self.auth0_email = auth0_email

    def get_cname(self):
        """Get CNAME records for all subdomains"""
        output = f"{self.output_file}/hosts/cnames.txt"
        subdomains_file = f"{self.output_file}/hosts/subs.txt"
        try:
            if not os.path.isfile(subdomains_file) or os.path.getsize(subdomains_file) == 0:
                logger.warning(f"{color.RED}(-) No subdomains file or empty, skipping CNAME{color.END}")
                return
            logger.info(
                f"{color.GREEN}(+) CNAME analysis for possible takeovers{color.END}"
            )
            cnfinder_cmd = ["cnfinder", "-l", subdomains_file, "-o", output]
            p = subprocess.run(cnfinder_cmd, capture_output=True, timeout=300)
            if p.returncode != 0 and p.stderr:
                logger.debug(f"cnfinder stderr: {p.stderr.decode(errors='replace')}")
            if os.path.isfile(output) and os.path.getsize(output) > 0:
                with open(output, "r", encoding="utf-8", errors="replace") as f:
                    cnames = f.read().splitlines()
                logger.info(f"{color.GREEN}(+) Found total of: {len(cnames)} CNAME. {color.END}")
        except FileNotFoundError:
            logger.warning(f"{color.RED}(-) cnfinder not found in PATH{color.END}")
        except subprocess.TimeoutExpired:
            logger.warning(f"{color.RED}(-) cnfinder timed out{color.END}")
        except Exception as e:
            logger.exception(f"{color.RED}Error reading subdomains/CNAME: {e}{color.END}")
    def test_takeover(self):
        """Test for potential subdomain takeovers using subjack and subzy (optional tools)."""
        subs_file = f"{self.output_file}/hosts/subs.txt"
        subjack_out = f"{self.output_file}/vuln/subjack.txt"
        subzy_out = f"{self.output_file}/vuln/subzy.txt"
        if not os.path.isfile(subs_file) or os.path.getsize(subs_file) == 0:
            logger.debug("No subdomains file for takeover tests, skipping")
            return
        try:
            logger.info(f"{color.GREEN}(+) Running subjack for takeover detection{color.END}")
            p = subprocess.run(
                ["subjack", "-w", subs_file, "-t", "100", "-timeout", "30", "-o", subjack_out],
                capture_output=True,
                timeout=600,
            )
            if p.returncode != 0 and p.stderr:
                logger.debug(f"subjack stderr: {p.stderr.decode(errors='replace')}")
        except FileNotFoundError:
            logger.warning(f"{color.RED}(-) subjack not found in PATH (optional){color.END}")
        except subprocess.TimeoutExpired:
            logger.warning(f"{color.RED}(-) subjack timed out{color.END}")
        try:
            logger.info(f"{color.GREEN}(+) Running subzy for takeover detection{color.END}")
            p = subprocess.run(
                ["subzy", "run", "--targets", subs_file],
                capture_output=True,
                timeout=600,
                cwd=self.output_file,
            )
            if p.stdout and p.returncode == 0:
                with open(subzy_out, "wb") as f:
                    f.write(p.stdout)
            elif p.returncode != 0 and p.stderr:
                logger.debug(f"subzy stderr: {p.stderr.decode(errors='replace')}")
        except FileNotFoundError:
            logger.warning(f"{color.RED}(-) subzy not found in PATH (optional){color.END}")
        except subprocess.TimeoutExpired:
            logger.warning(f"{color.RED}(-) subzy timed out{color.END}")
        except Exception as e:
            logger.debug(f"subzy failed: {e}")

    def auth0(self):
        """
        Test for Auth0 unauthenticated account creation (BadAuth0).
        """
        if self.auth0_email:
            try:
                logger.info(f"{color.GREEN}(+) Testing for Auth0 self account signup{color.END}")
                tenants_file = f"{self.output_file}/hosts/alive-hosts.txt"
                badauth0_cmd = [
                    "badauth",
                    "-l",
                    tenants_file,
                    "-o",
                    os.path.join(self.output_file, "auth0"),
                    "-e",
                    self.auth0_email,
                ]
                subprocess.run(badauth0_cmd, check=True)
            except FileNotFoundError:
                logger.warning(f"{color.RED}(-) badauth not found in PATH{color.END}")
            except Exception as e:
                logger.exception(f"{color.RED}(-) Error occurred: {e}{color.END}")


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
        """Main method to extract AWS CNAMEs and optionally test bucket permissions (s3scanner if in PATH)."""
        cnames_file = f"{self.output_file}/hosts/cnames.txt"
        aws_cnames_output = f"{self.output_file}/hosts/aws_cnames.txt"
        try:
            if not os.path.isfile(cnames_file) or os.path.getsize(cnames_file) == 0:
                logger.warning(f"{color.RED}(-) CNAMEs file missing or empty, skipping BucketFinder{color.END}")
                return
            logger.info(f"{color.SKY_BLUE}Reading CNAMEs from {cnames_file}{color.END}")
            bucket_count = 0
            with open(cnames_file, "r", encoding="utf-8", errors="replace") as infile, open(
                    aws_cnames_output, "w", encoding="utf-8"
            ) as outfile:
                for line in infile:
                    parts = line.strip().split()
                    if len(parts) >= 3 and "s3" in parts[2] and "amazonaws" in parts[2]:
                        bucket = parts[2].strip(".")
                        outfile.write(bucket + "\n")
                        bucket_count += 1
                        logger.debug(
                            f"{color.BLUE}Found AWS CNAME: {bucket}{color.END}"
                        )

            if bucket_count > 0:
                logger.info(
                    f"{color.SKY_BLUE}AWS CNAMEs written to {aws_cnames_output}. "
                    "To test bucket permissions, install e.g. s3scanner and run it on that file.{color.END}"
                )
                try:
                    if shutil.which("s3scanner"):
                        scan_out = f"{self.output_file}/vuln/aws_vuln_bucket.txt"
                        subprocess.run(
                            ["s3scanner", "scan", "-l", aws_cnames_output, "-o", scan_out],
                            capture_output=True,
                            timeout=900,
                        )
                        logger.info(f"{color.GREEN}(+) s3scanner bucket check completed{color.END}")
                except (FileNotFoundError, subprocess.TimeoutExpired) as e:
                    logger.debug(f"s3scanner skip: {e}")
            else:
                logger.info(f"{color.SKY_BLUE}No AWS CNAMEs found in CNAME list.{color.END}")
        except FileNotFoundError as e:
            logger.warning(f"{color.RED}(-) {e}{color.END}")
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
        self.all_urls = f"{self.output_file}/urls/all-urls.txt"
        self.js_output = f"{self.output_file}/urls/js-files.txt"
        self.leaked_docs = f"{self.output_file}/urls/leaked-docs.txt"
        self.mantra_output = f"{self.output_file}/urls/mantra_output.txt"
        self.js_findings = f"{self.output_file}/urls/js-findings.txt"

    def _filter_urls_by_regex(self, urls_file, pattern_re, dest_file):
        """Filter lines from urls_file by regex (Python-based, Windows-safe, no grep). Append unique lines to dest_file via anew."""
        try:
            if not os.path.isfile(urls_file) or os.path.getsize(urls_file) == 0:
                return
            pattern = re.compile(pattern_re)
            with open(urls_file, "rb") as f:
                lines = [
                    line.decode("utf-8", errors="replace").split("?")[0].strip()
                    for line in f
                    if pattern.search(line.decode("utf-8", errors="replace"))
                ]
            unique = sorted(set(ln for ln in lines if ln))
            if not unique:
                return
            out = b"".join((ln + "\n").encode("utf-8") for ln in unique)
            subprocess.run(
                ["anew", dest_file],
                input=out,
                capture_output=True,
                timeout=60,
            )
        except FileNotFoundError:
            logger.warning(f"{color.RED}(-) anew not found in PATH{color.END}")

    def collect_urls(self):
        """Collect URLs from various sources (wayback, gau, etc)"""
        subdomains_file = f"{self.output_file}/hosts/alive-hosts.txt"
        urls = f"{self.output_file}/urls/all-urls.txt"

        try:
            logger.info(f"{color.GREEN}(+) Collecting all URLs{color.END}")
            # waybackurls: read hosts from file, append new URLs to urls (no shell)
            try:
                if not os.path.isfile(subdomains_file) or os.path.getsize(subdomains_file) == 0:
                    logger.warning(f"{color.RED}(-) alive-hosts file missing or empty, skipping waybackurls{color.END}")
                else:
                    with open(subdomains_file, "rb") as f_in:
                        p = subprocess.run(
                            ["waybackurls"],
                            stdin=f_in,
                            capture_output=True,
                            timeout=600,
                        )
                    if p.returncode != 0 and p.stderr:
                        logger.debug(f"waybackurls stderr: {p.stderr.decode(errors='replace')}")
                    if p.stdout and p.stdout.strip():
                        subprocess.run(
                            ["anew", urls],
                            input=p.stdout,
                            capture_output=True,
                            timeout=60,
                        )
            except FileNotFoundError:
                logger.warning(f"{color.RED}(-) waybackurls or anew not found in PATH{color.END}")
            except subprocess.TimeoutExpired:
                logger.warning("waybackurls timed out, skipping")

            # gau --subs: same pipeline (no shell)
            try:
                if os.path.isfile(subdomains_file) and os.path.getsize(subdomains_file) > 0:
                    with open(subdomains_file, "rb") as f_in:
                        p = subprocess.run(
                            ["gau", "--subs"],
                            stdin=f_in,
                            capture_output=True,
                            timeout=600,
                        )
                    if p.returncode != 0 and p.stderr:
                        logger.debug(f"gau stderr: {p.stderr.decode(errors='replace')}")
                    if p.stdout and p.stdout.strip():
                        subprocess.run(
                            ["anew", urls],
                            input=p.stdout,
                            capture_output=True,
                            timeout=60,
                        )
            except FileNotFoundError:
                logger.warning(f"{color.RED}(-) gau not found in PATH{color.END}")
            except subprocess.TimeoutExpired:
                logger.warning("gau timed out, skipping")
            except subprocess.CalledProcessError as e:
                logger.warning(f"gau failed: {e}")

            # Extract JS URLs with Python regex (Windows-safe, no grep)
            self._filter_urls_by_regex(urls, r"\.js($|\?)", self.js_output)

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
        """Extract JavaScript files from collected URLs (Python regex, Windows-safe)"""
        try:
            logger.info(f"{color.GREEN}[+] Extracting JS files...{color.END}")
            all_urls = f"{self.output_file}/urls/all-urls.txt"
            if not os.path.isfile(all_urls) or os.path.getsize(all_urls) == 0:
                logger.warning(f"{color.RED}(-) all-urls.txt missing or empty, skipping JS extraction{color.END}")
                return
            self._filter_urls_by_regex(all_urls, r"\.(js|json)($|\?)", self.js_output)
            logger.info(
                f"{color.GREEN}[+] Completed: JS files saved to {self.js_output}{color.END}"
            )
        except FileNotFoundError as e:
            logger.warning(f"{color.RED}(-) {e}{color.END}")
        except Exception as e:
            logger.exception(f"{color.RED}Error occurred: {e}{color.END}")

    def extract_documents(self):
        """Extract document and backup files from collected URLs (Python regex, Windows-safe)"""
        try:
            logger.info(
                f"{color.GREEN}[+] Extracting documents and backup files...{color.END}"
            )
            doc_file_types = r"\.xls|\.xml|\.xlsx|\.json|\.pdf|\.sql|\.doc|\.docx|\.pptx|\.txt|\.zip|\.tar\.gz|\.tgz|\.bak|\.7z|\.rar"
            all_urls_path = f"{self.output_file}/urls/all-urls.txt"
            if not os.path.isfile(all_urls_path) or os.path.getsize(all_urls_path) == 0:
                logger.warning(f"{color.RED}(-) all-urls.txt missing or empty, skipping document extraction{color.END}")
                return
            self._filter_urls_by_regex(all_urls_path, doc_file_types, self.leaked_docs)
            logger.info(
                f"{color.GREEN}[+] Completed: Sensitive documents saved to {self.leaked_docs}{color.END}"
            )
        except FileNotFoundError as e:
            logger.warning(f"{color.RED}(-) {e}{color.END}")
        except Exception as e:
            logger.exception(f"{color.RED}Error occurred: {e}{color.END}")

    def extract_js_data_with_mantra(self):
        """Extract data from JavaScript files using Mantra"""
        try:
            logger.info(
                f"{color.GREEN}[+] Extracting data from JS files using Mantra...{color.END}"
            )
            mantra_files = [self.all_urls, self.js_output]
            for i in mantra_files:
                subprocess.run(f"cat {i} | mantra | anew {self.mantra_output}", check=True, shell=True)

            logger.info(
                f"{color.GREEN}[+] Completed: Mantra findings saved to {self.mantra_output}{color.END}"
            )
        except FileNotFoundError:
            logger.warning(
                f"{color.RED}(-) mantra or anew not found in PATH{color.END}"
            )
        except subprocess.TimeoutExpired:
            logger.warning(f"{color.RED}(-) mantra timed out{color.END}")
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
            if not os.path.isfile(hosts) or os.path.getsize(hosts) == 0:
                logger.warning(f"{color.RED}(-) No alive hosts file for Nuclei, skipping{color.END}")
                return
            nuclei_cmd = ["nuclei", "-l", hosts, "-o", output]
            logger.info(f"{color.GREEN}(+) Nuclei active scanning {color.END}")
            p = subprocess.run(nuclei_cmd, capture_output=True, timeout=3600)
            if p.returncode != 0 and p.stderr:
                logger.debug(f"nuclei stderr: {p.stderr.decode(errors='replace')}")
        except FileNotFoundError:
            logger.warning(f"{color.RED}(-) nuclei not found in PATH{color.END}")
        except subprocess.TimeoutExpired:
            logger.warning(f"{color.RED}(-) nuclei timed out{color.END}")
        except Exception as e:
            logger.exception(f"{color.RED}(-) Error occurred: {e}{color.END}")

    def dast_nuclei(self):
        """Run DAST Nuclei scan on all URLs"""
        urls = f"{self.output_file}/urls/all-urls.txt"
        output = f"{self.output_file}/vuln/nuclei-dast-output.txt"
        try:
            if not os.path.isfile(urls) or os.path.getsize(urls) == 0:
                logger.warning(f"{color.RED}(-) No URLs file for Nuclei DAST, skipping{color.END}")
                return
            with open(urls, "rb") as f_in:
                p = subprocess.run(
                    ["nuclei", "--dast", "-o", output],
                    stdin=f_in,
                    capture_output=True,
                    timeout=3600,
                )
            if p.returncode != 0 and p.stderr:
                logger.debug(f"nuclei dast stderr: {p.stderr.decode(errors='replace')}")
            logger.info(f"{color.GREEN}(+) Nuclei dast active scanning {color.END}")
        except FileNotFoundError:
            logger.warning(f"{color.RED}(-) nuclei not found in PATH{color.END}")
        except subprocess.TimeoutExpired:
            logger.warning(f"{color.RED}(-) nuclei DAST timed out{color.END}")
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
            config = yaml.safe_load(f)
            if not isinstance(config, dict):
                raise ValueError("Config file is empty or invalid")
            return config
    except FileNotFoundError:
        logger.warning(
            f"{color.RED}(!) Config file not found, using defaults{color.END}"
        )
        return {
            "telegram": {"token": "", "chat_id": ""},
            "cleanup": {"enabled": True, "remove_empty_files": True, "remove_empty_dirs": True},
        }
    except ValueError as e:
        logger.warning(f"{color.RED}{e}; using defaults{color.END}")
        return {
            "telegram": {"token": "", "chat_id": ""},
            "cleanup": {"enabled": True, "remove_empty_files": True, "remove_empty_dirs": True},
        }
    except Exception as e:
        logger.error(f"{color.RED}Error loading config: {e}{color.END}")
        raise


def check_tools():
    """Check for required and optional CLI tools in PATH. Required: subfinder, httpx, waybackurls, anew. Optional: gau, gf, cnfinder, badauth, mantra, nuclei, subjack, subzy, s3scanner."""
    required = ["subfinder", "httpx", "waybackurls", "anew"]
    optional = ["gau", "gf", "cnfinder", "badauth", "mantra", "nuclei", "subjack", "subzy", "s3scanner"]
    missing_required = [n for n in required if not shutil.which(n)]
    missing_optional = [n for n in optional if not shutil.which(n)]
    if missing_required:
        logger.warning(
            f"{color.RED}(!) Missing required tools (add to PATH): {', '.join(missing_required)}{color.END}"
        )
    if missing_optional:
        logger.info(
            f"{color.SKY_BLUE}(i) Optional tools not in PATH: {', '.join(missing_optional)}{color.END}"
        )
    if not missing_required and not missing_optional:
        logger.info(f"{color.GREEN}(+) All checked tools found in PATH{color.END}")
    return len(missing_required) == 0


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
        "--nuclei",
        action="store_true",
        help="Run Nuclei scans (optional)",
    )
    parser.add_argument(
        "-e", "--email", help="Email to test for auth0 misconfigurations"
    )
    parser.add_argument(
        "--cleanup-only",
        action="store_true",
        help="Run only the cleanup process on existing output directory",
    )
    parser.add_argument(
        "--check-tools",
        action="store_true",
        help="Check for required/optional CLI tools in PATH and exit (see docs for tool list)",
    )
    args = parser.parse_args()

    if args.check_tools:
        check_tools()
        return

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
        subdomains_takeover = SubdomainTakeOver(domains, output_file, args.email or "")
        subdomains_takeover.get_cname()
        subdomains_takeover.test_takeover()
        subdomains_takeover.auth0()
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
    if args.nuclei:
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
