import argparse
import json
import os
import re
import subprocess
import shutil
import threading
import time
from datetime import datetime as date
from urllib.parse import urlparse
import logging
import logging_config
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
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

print(banner)


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
                "subjack.txt",
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
                with open(domains, "r", encoding="utf-8") as df:
                    domain_list = [d.strip() for d in df if d.strip()]
                for domain in domain_list:
                    p = subprocess.run(
                        ["amass", "enum", "-passive", "-d", domain],
                        capture_output=True, timeout=300,
                    )
                    if p.stdout and p.stdout.strip():
                        subprocess.run(["anew", output], input=p.stdout,
                                       capture_output=True, timeout=60)
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
        """Test for potential subdomain takeovers using subjack and subzy (optional tools)."""
        subs_file = f"{self.output_file}/hosts/subs.txt"
        subjack_out = f"{self.output_file}/vuln/subjack.txt"
        subzy_out = f"{self.output_file}/vuln/subzy.txt"
        if not os.path.isfile(subs_file) or os.path.getsize(subs_file) == 0:
            logger.debug("No subdomains file for takeover tests, skipping")
            return
        try:
            logger.info(
                f"{color.GREEN}(+) Running subjack for takeover detection{color.END}")
            _script_dir = os.path.dirname(os.path.abspath(__file__))
            _fp = os.path.join(_script_dir, "subjack-fingerprints.json")
            _subjack_cmd = ["subjack", "-w", os.path.abspath(subs_file),
                            "-t", "100", "-timeout", "30", "-o", subjack_out]
            if os.path.isfile(_fp):
                _subjack_cmd += ["-c", _fp]
            p = subprocess.run(_subjack_cmd, capture_output=True, timeout=600)
            if p.returncode != 0 and p.stderr:
                logger.debug(
                    f"subjack stderr: {p.stderr.decode(errors='replace')}")
        except FileNotFoundError:
            logger.warning(
                f"{color.RED}(-) subjack not found in PATH (optional){color.END}")
        except subprocess.TimeoutExpired:
            logger.warning(f"{color.RED}(-) subjack timed out{color.END}")
        try:
            logger.info(
                f"{color.GREEN}(+) Running subzy for takeover detection{color.END}")
            p = subprocess.run(
                ["subzy", "run", "--targets", os.path.abspath(subs_file)],
                capture_output=True,
                timeout=600,
            )
            if p.stdout and p.returncode == 0:
                with open(subzy_out, "wb") as f:
                    f.write(p.stdout)
            elif p.returncode != 0 and p.stderr:
                logger.debug(
                    f"subzy stderr: {p.stderr.decode(errors='replace')}")
        except FileNotFoundError:
            logger.warning(
                f"{color.RED}(-) subzy not found in PATH (optional){color.END}")
        except subprocess.TimeoutExpired:
            logger.warning(f"{color.RED}(-) subzy timed out{color.END}")
        except Exception as e:
            logger.debug(f"subzy failed: {e}")

        # Aggregate subjack + subzy findings → takeovers.json
        takeovers = []
        try:
            if os.path.isfile(subjack_out):
                with open(subjack_out, "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        line = line.strip()
                        if "[Vulnerable]" in line or "[vulnerable]" in line.lower():
                            # subjack format: [Vulnerable] subdomain: service
                            parts = line.split("]", 1)[-1].strip().split(":", 1)
                            subdomain = parts[0].strip() if parts else line
                            service = parts[1].strip() if len(parts) > 1 else "unknown"
                            takeovers.append({"subdomain": subdomain, "service": service, "tool": "subjack"})
                            logger.info(f"{color.RED}[!] Takeover: {subdomain} ({service}) via subjack{color.END}")
        except Exception as e:
            logger.debug(f"Error parsing subjack output: {e}")

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
            katana_cmd = ["katana", "-list", subdomains_file,
                          "-d", str(depth_level), "-o", urls]
            subprocess.run(katana_cmd, check=True)
        except FileNotFoundError:
            logger.warning(
                f"{color.RED}(-) katana not found in PATH{color.END}")
        except subprocess.TimeoutExpired:
            logger.warning("katana timed out, skipping")

        try:
            # waybackurls: read hosts from file, append new URLs to urls (no shell)
            try:
                if not os.path.isfile(subdomains_file) or os.path.getsize(subdomains_file) == 0:
                    logger.warning(
                        f"{color.RED}(-) alive-hosts file missing or empty, skipping waybackurls{color.END}")
                else:
                    with open(subdomains_file, "rb") as f_in:
                        p = subprocess.run(
                            ["waybackurls"],
                            stdin=f_in,
                            capture_output=True,
                            timeout=600,
                        )
                    if p.returncode != 0 and p.stderr:
                        logger.debug(
                            f"waybackurls stderr: {p.stderr.decode(errors='replace')}")
                    if p.stdout and p.stdout.strip():
                        subprocess.run(
                            ["anew", urls],
                            input=p.stdout,
                            capture_output=True,
                            timeout=60,
                        )
            except FileNotFoundError:
                logger.warning(
                    f"{color.RED}(-) waybackurls or anew not found in PATH{color.END}")
            except subprocess.TimeoutExpired:
                logger.warning("waybackurls timed out, skipping")

            # gau --subs: same pipeline (no shell)
            try:
                if os.path.isfile(subdomains_file) and os.path.getsize(subdomains_file) > 0:
                    with open(subdomains_file, "rb") as f_in:
                        p = subprocess.run(
                            ["gau", "-subs", "-providers", "otx,commoncrawl", "-t", "5"],
                            stdin=f_in,
                            capture_output=True,
                            timeout=600,
                        )
                    if p.returncode != 0 and p.stderr:
                        logger.debug(
                            f"gau stderr: {p.stderr.decode(errors='replace')}")
                    if p.stdout and p.stdout.strip():
                        subprocess.run(
                            ["anew", urls],
                            input=p.stdout,
                            capture_output=True,
                            timeout=60,
                        )
            except FileNotFoundError:
                logger.warning(
                    f"{color.RED}(-) gau not found in PATH{color.END}")
            except subprocess.TimeoutExpired:
                logger.warning("gau timed out, skipping")
            except subprocess.CalledProcessError as e:
                logger.warning(f"gau failed: {e}")

            # Extract JS URLs with Python regex (Windows-safe, no grep)
            self._filter_urls_by_regex(urls, r"\.js($|\?)", self.js_output)

            # Run gf (tomnomnom/gf) patterns: read URLs from file, grep with named
            # patterns from ~/.gf/*.json, append new lines via anew (cross-platform).
            gf_list = ["xss", "ssrf", "lfi", "sqli", "ssti", "redirect"]
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

            # waymore: better archive coverage than waybackurls+gau
            try:
                if os.path.isfile(subdomains_file) and os.path.getsize(subdomains_file) > 0:
                    if shutil.which("waymore"):
                        logger.info(f"{color.GREEN}(+) Running waymore for URL collection{color.END}")
                        with open(subdomains_file, "r", encoding="utf-8") as sf:
                            hosts_list = [h.strip() for h in sf if h.strip()]
                        for host in hosts_list:
                            domain = urlparse(host).netloc or host
                            p_wm = subprocess.run(
                                ["waymore", "-i", domain, "-mode", "U", "-oU", "-"],
                                capture_output=True, timeout=300,
                            )
                            if p_wm.stdout and p_wm.stdout.strip():
                                subprocess.run(["anew", urls], input=p_wm.stdout,
                                               capture_output=True, timeout=60)
            except FileNotFoundError:
                logger.warning(f"{color.RED}(-) waymore not found in PATH (optional){color.END}")
            except subprocess.TimeoutExpired:
                logger.warning("waymore timed out, skipping")
            except Exception as e:
                logger.debug(f"waymore failed: {e}")

            # paramspider: discover parameters from alive hosts
            try:
                if os.path.isfile(subdomains_file) and os.path.getsize(subdomains_file) > 0:
                    params_out = f"{self.output_file}/urls/params.txt"
                    logger.info(f"{color.GREEN}(+) Running paramspider for parameter discovery{color.END}")
                    p_ps = subprocess.run(
                        ["paramspider", "-l", subdomains_file],
                        capture_output=True,
                        timeout=600,
                    )
                    if p_ps.stdout and p_ps.stdout.strip():
                        subprocess.run(
                            ["anew", params_out],
                            input=p_ps.stdout,
                            capture_output=True,
                            timeout=60,
                        )
            except FileNotFoundError:
                logger.warning(f"{color.RED}(-) paramspider not found in PATH (optional){color.END}")
            except subprocess.TimeoutExpired:
                logger.warning("paramspider timed out, skipping")
            except Exception as e:
                logger.debug(f"paramspider failed: {e}")

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

    def basic_nuclei(self):
        """Run Nuclei scan on alive hosts — critical/high/medium, targeted tags"""
        hosts = f"{self.output_file}/hosts/alive-hosts.txt"
        output = f"{self.output_file}/vuln/nuclei-output.txt"
        try:
            if not os.path.isfile(hosts) or os.path.getsize(hosts) == 0:
                logger.warning(
                    f"{color.RED}(-) No alive hosts file for Nuclei, skipping{color.END}")
                return
            nuclei_cmd = [
                "nuclei", "-l", hosts, "-o", output,
                "-severity", "critical,high,medium",
                "-tags", "exposure,misconfiguration,default-login,takeover,cve",
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

            logger.info(f"{color.GREEN}(+) Directory fuzzing with ffuf{color.END}")

            with open(hosts_file, "r", encoding="utf-8", errors="replace") as f:
                hosts = [line.strip() for line in f if line.strip()]

            with open(output, "w", encoding="utf-8") as out_f:
                for host in hosts:
                    url = host.rstrip("/") + "/FUZZ"
                    logger.info(f"{color.SKY_BLUE}(+) ffuf -> {host}{color.END}")
                    tmp_path = f"{self.output_file}/vuln/.ffuf_tmp_{host.replace('://', '_').replace('/', '_')}.json"
                    ffuf_cmd = [
                        "ffuf",
                        "-u", url,
                        "-w", self.wordlist,
                        "-t", str(self.threads),
                        "-timeout", str(self.timeout),
                        "-mc", self.match_codes,
                        "-o", tmp_path,
                        "-of", "json",
                        "-s",
                    ]
                    try:
                        p = subprocess.run(
                            ffuf_cmd,
                            capture_output=True,
                            timeout=1800,
                        )
                        if p.returncode != 0 and p.stderr:
                            logger.debug(
                                f"ffuf stderr ({host}): {p.stderr.decode(errors='replace')}"
                            )
                        if os.path.isfile(tmp_path) and os.path.getsize(tmp_path) > 0:
                            with open(tmp_path, "r", encoding="utf-8", errors="replace") as tf:
                                data = json.load(tf)
                            results = data.get("results", [])
                            if results:
                                out_f.write(f"# {host}\n")
                                for r in results:
                                    out_f.write(
                                        f"{r['url']} [Status: {r['status']}, Size: {r['length']}, Words: {r['words']}, Lines: {r['lines']}]\n"
                                    )
                                out_f.write("\n")
                    except subprocess.TimeoutExpired:
                        logger.warning(
                            f"{color.RED}(-) ffuf timed out for {host}{color.END}")
                    finally:
                        if os.path.isfile(tmp_path):
                            os.unlink(tmp_path)

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
            logger.info(f"{color.GREEN}(+) Running secretfinder on JS files{color.END}")
            findings = []
            with open(js_file, "r", encoding="utf-8", errors="replace") as f:
                js_urls = [u.strip() for u in f if u.strip()]
            for url in js_urls:
                try:
                    p = subprocess.run(
                        ["secretfinder", "-i", url, "-o", "cli"],
                        capture_output=True, timeout=30,
                    )
                    if p.stdout and p.stdout.strip():
                        out = p.stdout.decode(errors="replace").strip()
                        if out:
                            findings.append(f"# {url}\n{out}\n")
                except subprocess.TimeoutExpired:
                    logger.debug(f"secretfinder timed out for {url}")
                except Exception as e:
                    logger.debug(f"secretfinder failed for {url}: {e}")
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
                "mantra", "nuclei", "subjack", "subzy", "s3scanner", "ffuf",
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

    # Create notifier instance (Telegram + optional Discord/Slack)
    discord_webhook = config.get("discord", {}).get("webhook_url", "")
    slack_webhook   = config.get("slack",   {}).get("webhook_url", "")
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
        # Execute DmarcFinder (DMARC + SPF + DKIM) and zone transfer check
        dmarc_finder = DmarcFinder(domains, output_file)
        dmarc_finder.validate_domains()
        dmarc_finder.check_zone_transfer()
        notifier.notify_telegram(
            telegram_token, telegram_chat_id, "(+) Email security + zone transfer check completed"
        )
        logger.info("Email security checks completed")
    except Exception as e:
        logger.exception("Failed during email security checks")
        notifier.notify_telegram(
            telegram_token, telegram_chat_id, "(-) Email security checks failed"
        )

    try:
        # Execute SubdomainTakeOver and notify
        subdomains_takeover = SubdomainTakeOver(
            domains, output_file, args.email or "")
        subdomains_takeover.get_cname()
        subdomains_takeover.test_takeover()
        # Notify with finding count from takeovers.json
        takeovers_json_path = f"{output_file}/vuln/takeovers.json"
        takeover_count = 0
        try:
            if os.path.isfile(takeovers_json_path):
                with open(takeovers_json_path) as _tf:
                    takeover_count = len(json.load(_tf))
        except Exception:
            pass
        takeover_msg = (
            f"[!] {takeover_count} subdomain takeover(s) found!"
            if takeover_count else "(+) Subdomain takeover tests completed — no takeovers found"
        )
        notifier.notify_telegram(telegram_token, telegram_chat_id, takeover_msg)
        logger.info("Subdomain takeover tests completed")
    except Exception as e:
        logger.exception("Failed during subdomain takeover tests")
        notifier.notify_telegram(
            telegram_token, telegram_chat_id, "(-) Subdomain takeover tests failed"
        )

    try:
        # Execute BucketFinder and notify
        bucket_finder = BucketFinder(domains, output_file)
        subdomains_takeover.auth0()
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
        bucket_finder.aws_extractor()
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
            nuclei = Nuclei(domains, output_file, config.get("nuclei", {}))
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

    if args.ffuf:
        try:
            ffuf_config = config.get("ffuf", {})
            wordlist = args.wordlist or ffuf_config.get("wordlist", "")
            threads = ffuf_config.get("threads", 40)
            timeout = ffuf_config.get("timeout", 10)
            match_codes = ffuf_config.get("match_codes", "200,204,301,302,307,401,403")
            dir_fuzzer = DirFuzzer(output_file, wordlist, threads, timeout, match_codes)
            dir_fuzzer.fuzz()
            notifier.notify_telegram(
                telegram_token, telegram_chat_id, "(+) Directory fuzzing completed"
            )
            logger.info("Directory fuzzing completed")
        except Exception as e:
            logger.exception("Failed during directory fuzzing")
            notifier.notify_telegram(
                telegram_token, telegram_chat_id, "(-) Directory fuzzing failed"
            )

    if args.cors:
        try:
            cors_scanner = CorsScanner(output_file)
            cors_scanner.scan()
            notifier.notify_telegram(
                telegram_token, telegram_chat_id, "(+) CORS scan completed"
            )
            logger.info("CORS scan completed")
        except Exception as e:
            logger.exception("Failed during CORS scan")
            notifier.notify_telegram(
                telegram_token, telegram_chat_id, "(-) CORS scan failed"
            )

    if args.crlf:
        try:
            crlf_scanner = CrlfScanner(output_file)
            crlf_scanner.scan()
            notifier.notify_telegram(
                telegram_token, telegram_chat_id, "(+) CRLF scan completed"
            )
            logger.info("CRLF scan completed")
        except Exception as e:
            logger.exception("Failed during CRLF scan")
            notifier.notify_telegram(
                telegram_token, telegram_chat_id, "(-) CRLF scan failed"
            )

    if args.dirsearch:
        try:
            dirsearch_config = config.get("dirsearch", {})
            ds_wordlist = args.dirsearch_wordlist or dirsearch_config.get("wordlist", "")
            ds_threads = dirsearch_config.get("threads", 25)
            ds_extensions = dirsearch_config.get("extensions", "php,html,js,txt,json,xml,bak,zip")
            dir_fuzzer = DirectoryFuzzer(output_file, ds_wordlist, ds_threads, ds_extensions)
            dir_fuzzer.fuzz()
            notifier.notify_telegram(
                telegram_token, telegram_chat_id, "(+) dirsearch completed"
            )
            logger.info("dirsearch completed")
        except Exception as e:
            logger.exception("Failed during dirsearch")
            notifier.notify_telegram(
                telegram_token, telegram_chat_id, "(-) dirsearch failed"
            )

    if args.bypass_403:
        try:
            bypasser = FourOhThreeBypasser(output_file)
            bypasser.bypass()
            notifier.notify_telegram(
                telegram_token, telegram_chat_id, "(+) 403 bypass completed"
            )
            logger.info("403 bypass completed")
        except Exception as e:
            logger.exception("Failed during 403 bypass")
            notifier.notify_telegram(
                telegram_token, telegram_chat_id, "(-) 403 bypass failed"
            )

    if args.api:
        try:
            api_wordlist = args.api_wordlist or config.get("api_discovery", {}).get("wordlist", "")
            api_discovery = ApiDiscovery(output_file, api_wordlist)
            api_discovery.discover()
            notifier.notify_telegram(
                telegram_token, telegram_chat_id, "(+) API discovery completed"
            )
            logger.info("API discovery completed")
        except Exception as e:
            logger.exception("Failed during API discovery")
            notifier.notify_telegram(
                telegram_token, telegram_chat_id, "(-) API discovery failed"
            )

    if args.xss:
        try:
            dalfox = DalfoxScanner(output_file)
            dalfox.scan()
            notifier.notify_telegram(
                telegram_token, telegram_chat_id, "(+) Dalfox XSS scan completed"
            )
            logger.info("Dalfox XSS scan completed")
        except Exception as e:
            logger.exception("Failed during dalfox XSS scan")
            notifier.notify_telegram(
                telegram_token, telegram_chat_id, "(-) Dalfox XSS scan failed"
            )

    if args.redirect:
        try:
            redirect_scanner = OpenRedirectScanner(output_file)
            redirect_scanner.scan()
            notifier.notify_telegram(
                telegram_token, telegram_chat_id, "(+) Open redirect scan completed"
            )
            logger.info("Open redirect scan completed")
        except Exception as e:
            logger.exception("Failed during open redirect scan")
            notifier.notify_telegram(
                telegram_token, telegram_chat_id, "(-) Open redirect scan failed"
            )

    if args.secrets:
        try:
            secret_scanner = SecretScanner(output_file)
            secret_scanner.secretfinder()
            secret_scanner.trufflehog()
            notifier.notify_telegram(
                telegram_token, telegram_chat_id, "(+) Secret scanning completed"
            )
            logger.info("Secret scanning completed")
        except Exception as e:
            logger.exception("Failed during secret scanning")
            notifier.notify_telegram(
                telegram_token, telegram_chat_id, "(-) Secret scanning failed"
            )

    if args.waf:
        try:
            waf_detector = WafDetector(output_file)
            waf_detector.detect()
            notifier.notify_telegram(
                telegram_token, telegram_chat_id, "(+) WAF detection completed"
            )
            logger.info("WAF detection completed")
        except Exception as e:
            logger.exception("Failed during WAF detection")
            notifier.notify_telegram(
                telegram_token, telegram_chat_id, "(-) WAF detection failed"
            )

    if args.screenshot:
        try:
            screenshotter = ScreenshotCapture(output_file)
            screenshotter.capture()
            notifier.notify_telegram(
                telegram_token, telegram_chat_id, "(+) Screenshots captured"
            )
            logger.info("Screenshot capture completed")
        except Exception as e:
            logger.exception("Failed during screenshot capture")
            notifier.notify_telegram(
                telegram_token, telegram_chat_id, "(-) Screenshot capture failed"
            )

    if args.params:
        try:
            param_discovery = ParameterDiscovery(output_file)
            param_discovery.discover()
            notifier.notify_telegram(
                telegram_token, telegram_chat_id, "(+) Parameter discovery completed"
            )
            logger.info("Parameter discovery completed")
        except Exception as e:
            logger.exception("Failed during parameter discovery")
            notifier.notify_telegram(
                telegram_token, telegram_chat_id, "(-) Parameter discovery failed"
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
