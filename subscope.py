#!/usr/bin/env python3
"""
==============================================================================
 SubScope - High-Performance Asset Recon & Status Filter Utility
 Developer: goudawolfdev | D33P-X (Gouda Nasralla)
 Description: Multithreaded/Async web asset discovery, port scanning,
              takeover detection, WHOIS/RDAP resolver, and diff tool.
==============================================================================
"""

import argparse
import asyncio
import csv
import json
import os
import re
import socket
import ssl
import sys
import time
import urllib.request
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Any, Set, Tuple

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeRemainingColumn
from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree

# Initialize Rich Console
console = Console()

DEV_INFO = "Developer: goudawolfdev | D33P-X (Gouda Nasralla)"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443]

# Subdomain Takeover Signatures
TAKEOVER_SIGNATURES = {
    "GitHub Pages": {"cname": "github.io", "body": "There isn't a GitHub Pages site here"},
    "Heroku": {"cname": "herokudns.com", "body": "Heroku | No such app"},
    "AWS S3": {"cname": "amazonaws.com", "body": "NoSuchBucket"},
    "Shopify": {"cname": "myshopify.com", "body": "Sorry, this shop is currently unavailable"},
    "Zendesk": {"cname": "zendesk.com", "body": "No such help center"},
    "Tumblr": {"cname": "tumblr.com", "body": "Whatever you were looking for doesn't exist"},
    "Squarespace": {"cname": "squarespace.com", "body": "Squarespace - Website not found"},
    "Fly.io": {"cname": "fly.dev", "body": "App not found"}
}

def request_url(url: str, timeout: float = 5.0) -> str:
    """Helper to fetch URL content cleanly using urllib without heavy external deps."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return response.read().decode('utf-8', errors='ignore')
    except Exception:
        return ""

# ==============================================================================
# SUBDOMAIN HARVESTER
# ==============================================================================
class SubdomainHarvester:
    def __init__(self, domain: str, verbose: bool = False):
        self.domain = domain.strip().lower()
        self.verbose = verbose
        self.subdomains: Set[str] = set()
        self.wildcard_ips: Set[str] = set()
        self.is_wildcard = False

    def check_wildcard(self):
        """Detect wildcard DNS resolution to filter false positives."""
        rand_sub = f"subscope-wildcard-{int(time.time())}.{self.domain}"
        try:
            ips = socket.gethostbyname_ex(rand_sub)[2]
            self.is_wildcard = True
            self.wildcard_ips.update(ips)
            if self.verbose:
                console.print(f"[bold yellow][!][/bold yellow] Wildcard DNS detected for {self.domain} resolved to: {list(self.wildcard_ips)}")
        except Exception:
            self.is_wildcard = False

    def harvest_crt_sh(self) -> Set[str]:
        """Harvest from crt.sh certificate transparency logs."""
        found = set()
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            data = request_url(url, timeout=10.0)
            if data:
                try:
                    records = json.loads(data)
                    for item in records:
                        name = item.get("name_value", "")
                        for sub in name.split():
                            sub = sub.strip().lower()
                            if sub.endswith(self.domain) and "*" not in sub:
                                found.add(sub)
                except json.JSONDecodeError:
                    pass
        except Exception:
            pass
        return found

    def harvest_alienvault(self) -> Set[str]:
        """Harvest from AlienVault OTX Passive DNS."""
        found = set()
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
            data = request_url(url, timeout=10.0)
            if data:
                try:
                    records = json.loads(data).get("passive_dns", [])
                    for item in records:
                        hostname = item.get("hostname", "").strip().lower()
                        if hostname.endswith(self.domain):
                            found.add(hostname)
                except json.JSONDecodeError:
                    pass
        except Exception:
            pass
        return found

    def harvest_hackertarget(self) -> Set[str]:
        """Harvest from HackerTarget Host Search."""
        found = set()
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
            data = request_url(url, timeout=10.0)
            if data and "error" not in data.lower():
                for line in data.splitlines():
                    if "," in line:
                        host = line.split(",")[0].strip().lower()
                        if host.endswith(self.domain):
                            found.add(host)
        except Exception:
            pass
        return found

    def harvest_rapiddns(self) -> Set[str]:
        """Harvest from RapidDNS."""
        found = set()
        try:
            url = f"https://rapiddns.io/subdomain/{self.domain}?page=1"
            data = request_url(url, timeout=10.0)
            if data:
                matches = re.findall(r'[\w\.-]+\.' + re.escape(self.domain), data)
                for match in matches:
                    found.add(match.lower())
        except Exception:
            pass
        return found

    def generate_permutations(self, base_subs: Set[str]) -> Set[str]:
        """Generate permutations of existing subdomains to find hidden ones."""
        prefixes = ["dev", "stage", "prod", "test", "admin", "api", "vpn", "mail", "web", "app", "portal", "internal"]
        perms = set()
        for sub in list(base_subs)[:100]: # Limit base subdomains to prevent explosion
            parts = sub.split(".")
            if len(parts) > 2:
                prefix = parts[0]
                for p in prefixes:
                    perms.add(f"{prefix}-{p}.{self.domain}")
                    perms.add(f"{p}-{prefix}.{self.domain}")
                    perms.add(f"{p}.{sub}")
        return perms

    def run(self, enable_permutations: bool = False) -> List[str]:
        self.check_wildcard()
        if self.verbose:
            console.print("[cyan][*] Extracting subdomains from passive sources...[/cyan]")
        
        funcs = [self.harvest_crt_sh, self.harvest_alienvault, self.harvest_hackertarget, self.harvest_rapiddns]
        with ThreadPoolExecutor(max_workers=4) as executor:
            results = executor.map(lambda f: f(), funcs)
            for res in results:
                self.subdomains.update(res)

        # Include root domain
        self.subdomains.add(self.domain)

        if enable_permutations:
            perms = self.generate_permutations(self.subdomains)
            self.subdomains.update(perms)

        # Resolve subdomains to filter active ones and remove wildcard results
        active_subdomains = []
        
        def resolve_subdomain(sub: str):
            try:
                ips = socket.gethostbyname_ex(sub)[2]
                if self.is_wildcard:
                    # If resolved IP matches wildcard IPs, exclude it
                    if any(ip in self.wildcard_ips for ip in ips):
                        return None
                return sub
            except Exception:
                return None

        if self.verbose:
            console.print(f"[cyan][*] Resolving {len(self.subdomains)} discovered domain permutations...[/cyan]")

        with ThreadPoolExecutor(max_workers=50) as resolver:
            resolved = resolver.map(resolve_subdomain, list(self.subdomains))
            for val in resolved:
                if val:
                    active_subdomains.append(val)

        return sorted(list(set(active_subdomains)))

# ==============================================================================
# TAKEOVER CHECKER
# ==============================================================================
class TakeoverChecker:
    @staticmethod
    def check_takeover(domain: str) -> Dict[str, Any]:
        """Check subdomain CNAME and resolve to find potential sub-domain takeovers."""
        res = {"vulnerable": False, "service": "N/A", "cname": "N/A", "message": ""}
        try:
            # Let's perform standard HTTP verification
            urls = [f"https://{domain}", f"http://{domain}"]
            for url in urls:
                try:
                    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
                    with urllib.request.urlopen(req, timeout=3.0) as response:
                        body = response.read().decode('utf-8', errors='ignore')
                except urllib.error.HTTPError as e:
                    body = e.read().decode('utf-8', errors='ignore')
                except Exception:
                    continue

                for service, sig in TAKEOVER_SIGNATURES.items():
                    if sig["body"] in body:
                        res["vulnerable"] = True
                        res["service"] = service
                        res["message"] = f"Unclaimed resources found. Service: {service}"
                        return res
        except Exception:
            pass
        return res

# ==============================================================================
# ASYNC PORT SCANNER
# ==============================================================================
class AsyncPortScanner:
    def __init__(self, ports: List[int] = None, rate_limit: int = 100):
        self.ports = ports or DEFAULT_PORTS
        self.rate_limit = rate_limit

    async def scan_port(self, ip: str, port: int, semaphore: asyncio.Semaphore) -> Dict[str, Any]:
        async with semaphore:
            result = {"port": port, "open": False, "banner": "N/A", "tls": None}
            try:
                conn = asyncio.open_connection(ip, port)
                reader, writer = await asyncio.wait_for(conn, timeout=2.0)
                result["open"] = True
                
                # Try Banner Grabbing
                try:
                    if port in [21, 22, 25, 110, 143]:
                        # Read greeting banner
                        banner = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                        result["banner"] = banner.decode('utf-8', errors='ignore').strip()
                    elif port in [80, 8080]:
                        # Send simple HTTP request
                        writer.write(b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                        await writer.drain()
                        banner = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                        first_line = banner.decode('utf-8', errors='ignore').split('\r\n')[0]
                        result["banner"] = first_line
                except Exception:
                    pass
                
                writer.close()
                await writer.wait_closed()

                # Extract TLS Certificate info on standard secure ports
                if port in [443, 8443]:
                    loop = asyncio.get_event_loop()
                    tls_info = await loop.run_in_executor(None, self.get_tls_details, ip, port)
                    if tls_info:
                        result["tls"] = tls_info
                        result["banner"] = f"TLS: {tls_info.get('issuer', 'Unknown Issuer')}"

            except Exception:
                pass
            return result

    def get_tls_details(self, ip: str, port: int) -> Dict[str, Any]:
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=2.0) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    x509 = ssl.DER_cert_to_PEM_cert(cert)
                    
                    # Basic extraction
                    peercert = ssock.getpeercert()
                    subject = dict(x[0] for x in peercert.get('subject', []))
                    issuer = dict(x[0] for x in peercert.get('issuer', []))
                    
                    return {
                        "subject": subject.get('commonName', 'N/A'),
                        "issuer": issuer.get('commonName', 'N/A'),
                        "expiry": peercert.get('notAfter', 'N/A'),
                        "sans": [x[1] for x in peercert.get('subjectAltName', []) if x[0] == 'DNS']
                    }
        except Exception:
            return None

    async def scan_host(self, ip: str) -> List[Dict[str, Any]]:
        semaphore = asyncio.Semaphore(self.rate_limit)
        tasks = [self.scan_port(ip, port, semaphore) for port in self.ports]
        scan_results = await asyncio.gather(*tasks)
        return [r for r in scan_results if r["open"]]

# ==============================================================================
# WHOIS & RDAP CLIENT
# ==============================================================================
class WhoisRdapClient:
    @staticmethod
    def query_rdap(domain: str) -> Dict[str, Any]:
        """Query RDAP registry for domains."""
        try:
            url = f"https://rdap.org/domain/{domain}"
            data = request_url(url, timeout=5.0)
            if data:
                res = json.loads(data)
                events = res.get("events", [])
                created = "N/A"
                expired = "N/A"
                for event in events:
                    if event.get("eventAction") == "registration":
                        created = event.get("eventDate", "N/A")
                    elif event.get("eventAction") == "expiration":
                        expired = event.get("eventDate", "N/A")
                
                entities = res.get("entities", [])
                registrar = "N/A"
                for entity in entities:
                    if "registrar" in entity.get("roles", []):
                        vcard = entity.get("vcardArray", [])
                        if len(vcard) > 1:
                            for prop in vcard[1]:
                                if prop[0] == "fn":
                                    registrar = prop[3]
                
                return {
                    "source": "RDAP",
                    "domain": domain,
                    "registrar": registrar,
                    "created": created,
                    "expiry": expired,
                    "status": res.get("status", ["N/A"])[0]
                }
        except Exception:
            pass
        return None

    @staticmethod
    def query_whois_socket(domain: str) -> Dict[str, Any]:
        """Fallback to socket WHOIS query."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5.0)
            s.connect(("whois.iana.org", 43))
            s.send((domain + "\r\n").encode())
            response = b""
            while True:
                data = s.recv(4096)
                if not data:
                    break
                response += data
            s.close()
            resp_str = response.decode('utf-8', errors='ignore')
            
            # Simple regex search
            registrar = "N/A"
            created = "N/A"
            expiry = "N/A"
            status = "N/A"
            
            reg_match = re.search(r'(?:Registrar|registrar|org):\s*(.*)', resp_str)
            if reg_match:
                registrar = reg_match.group(1).strip()
            created_match = re.search(r'(?:Creation Date|created|Registration Time):\s*(.*)', resp_str, re.IGNORECASE)
            if created_match:
                created = created_match.group(1).strip()
            exp_match = re.search(r'(?:Registry Expiry Date|Expiration Time|expiry|expires):\s*(.*)', resp_str, re.IGNORECASE)
            if exp_match:
                expiry = exp_match.group(1).strip()
            
            return {
                "source": "WHOIS",
                "domain": domain,
                "registrar": registrar,
                "created": created,
                "expiry": expiry,
                "status": status
            }
        except Exception:
            return {"source": "WHOIS", "domain": domain, "error": "Query failed"}

    @classmethod
    def get_info(cls, domain: str) -> Dict[str, Any]:
        # Strip subdomain to get root domain
        parts = domain.split(".")
        if len(parts) > 2:
            root_domain = ".".join(parts[-2:])
        else:
            root_domain = domain
            
        rdap = cls.query_rdap(root_domain)
        if rdap and rdap.get("registrar") != "N/A":
            return rdap
        return cls.query_whois_socket(root_domain)

# ==============================================================================
# SCAN DIFF TOOL
# ==============================================================================
class ScanDiff:
    @staticmethod
    def compare(file1: str, file2: str) -> Dict[str, Any]:
        try:
            with open(file1, "r", encoding="utf-8") as f:
                d1 = json.load(f)
            with open(file2, "r", encoding="utf-8") as f:
                d2 = json.load(f)
        except Exception as e:
            return {"error": f"Failed to load scan files: {str(e)}"}

        res1 = {item["domain"]: item for item in d1.get("results", [])}
        res2 = {item["domain"]: item for item in d2.get("results", [])}

        added = []
        removed = []
        changed = []

        for dom in res2:
            if dom not in res1:
                added.append(res2[dom])
            else:
                # Compare properties
                changed_props = {}
                if res1[dom].get("status") != res2[dom].get("status"):
                    changed_props["status"] = {"old": res1[dom].get("status"), "new": res2[dom].get("status")}
                if res1[dom].get("open_ports") != res2[dom].get("open_ports"):
                    changed_props["open_ports"] = {"old": res1[dom].get("open_ports"), "new": res2[dom].get("open_ports")}
                if changed_props:
                    changed.append({"domain": dom, "changes": changed_props})

        for dom in res1:
            if dom not in res2:
                removed.append(res1[dom])

        return {"added": added, "removed": removed, "changed": changed}

# ==============================================================================
# SEVERITY ASSIGNER
# ==============================================================================
def assign_severity(item: Dict[str, Any]) -> str:
    """Assign findings severity."""
    if item.get("takeover", {}).get("vulnerable"):
        return "CRITICAL"
    
    ports = [p["port"] for p in item.get("open_ports", [])]
    # Critical ports like SSH, RDP, Database exposed publicly
    high_risk_ports = {22, 23, 3389, 3306, 5432, 445}
    if any(p in high_risk_ports for p in ports):
        return "HIGH"
    
    if len(ports) > 0:
        return "MEDIUM"
    
    if item.get("status", 0) != 0:
        return "LOW"
        
    return "INFO"

# ==============================================================================
# REPORT GENERATORS
# ==============================================================================
def generate_html_report(filepath: str, results: List[Dict[str, Any]], target: str):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for r in results:
        sev = assign_severity(r)
        counts[sev] += 1

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SubScope Recon Report - {target}</title>
    <style>
        :root {{
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --accent: #38bdf8;
            --critical: #f43f5e;
            --high: #f97316;
            --medium: #eab308;
            --low: #3b82f6;
            --info: #10b981;
        }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            margin: 0;
            padding: 20px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        header {{
            background: linear-gradient(135deg, var(--bg-secondary), #0f172a);
            padding: 30px;
            border-radius: 12px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
            margin-bottom: 30px;
            border: 1px solid #334155;
        }}
        h1 {{ margin: 0; font-size: 2.5rem; color: var(--accent); }}
        .meta {{ color: var(--text-secondary); margin-top: 10px; font-size: 0.95rem; }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }}
        .stat-card {{
            background-color: var(--bg-secondary);
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            border: 1px solid #334155;
        }}
        .stat-card h3 {{ margin: 0; font-size: 0.9rem; color: var(--text-secondary); }}
        .stat-card .val {{ font-size: 2rem; font-weight: bold; margin-top: 10px; }}
        .val.critical {{ color: var(--critical); }}
        .val.high {{ color: var(--high); }}
        .val.medium {{ color: var(--medium); }}
        .val.low {{ color: var(--low); }}
        .val.info {{ color: var(--info); }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            background-color: var(--bg-secondary);
            border-radius: 8px;
            overflow: hidden;
            border: 1px solid #334155;
        }}
        th, td {{ padding: 15px; text-align: left; border-bottom: 1px solid #334155; }}
        th {{ background-color: #1e293b; color: var(--accent); font-weight: 600; }}
        tr:hover {{ background-color: #273549; }}
        .badge {{
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: bold;
        }}
        .badge-critical {{ background-color: var(--critical); color: white; }}
        .badge-high {{ background-color: var(--high); color: white; }}
        .badge-medium {{ background-color: var(--medium); color: black; }}
        .badge-low {{ background-color: var(--low); color: white; }}
        .badge-info {{ background-color: var(--info); color: white; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>SubScope Asset Discovery Report</h1>
            <div class="meta">Target Domain: <strong>{target}</strong> | Generated on: {time.strftime('%Y-%m-%d %H:%M:%S')}</div>
        </header>

        <div class="stats-grid">
            <div class="stat-card"><h3>Critical Issues</h3><div class="val critical">{counts['CRITICAL']}</div></div>
            <div class="stat-card"><h3>High Severity</h3><div class="val high">{counts['HIGH']}</div></div>
            <div class="stat-card"><h3>Medium Severity</h3><div class="val medium">{counts['MEDIUM']}</div></div>
            <div class="stat-card"><h3>Low Severity</h3><div class="val low">{counts['LOW']}</div></div>
            <div class="stat-card"><h3>Information</h3><div class="val info">{counts['INFO']}</div></div>
        </div>

        <h2>Discovered Assets & Services</h2>
        <table>
            <thead>
                <tr>
                    <th>Domain</th>
                    <th>Severity</th>
                    <th>IP</th>
                    <th>Status</th>
                    <th>Ports</th>
                    <th>Title / Banner</th>
                </tr>
            </thead>
            <tbody>"""
            
    for r in results:
        sev = assign_severity(r)
        ports_str = ", ".join(f"{p['port']}" for p in r.get("open_ports", [])) or "None"
        banner_list = [p.get("banner", "") for p in r.get("open_ports", []) if p.get("banner") != "N/A"]
        banner_str = f"HTTP Title: {r.get('title', 'N/A')}"
        if banner_list:
            banner_str += " | Services: " + " | ".join(banner_list)
            
        html_content += f"""
                <tr>
                    <td><strong>{r['domain']}</strong></td>
                    <td><span class="badge badge-{sev.lower()}">{sev}</span></td>
                    <td>{r['ip']}</td>
                    <td>{r['status']}</td>
                    <td>{ports_str}</td>
                    <td>{banner_str}</td>
                </tr>"""

    html_content += """
            </tbody>
        </table>
    </div>
</body>
</html>"""
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html_content)

def save_csv_report(filepath: str, results: List[Dict[str, Any]]):
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Domain", "IP", "Status", "Severity", "Ports", "HTTP Title", "Server"])
        for r in results:
            sev = assign_severity(r)
            ports_str = ",".join(str(p["port"]) for p in r.get("open_ports", []))
            writer.writerow([
                r["domain"], r["ip"], r["status"], sev, ports_str, r.get("title", "N/A"), r.get("server", "N/A")
            ])

# ==============================================================================
# CONFIG FILE LOADER
# ==============================================================================
def load_config() -> Dict[str, Any]:
    config_paths = [".subscoperc", "config.json", os.path.expanduser("~/.subscoperc")]
    for path in config_paths:
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
    return {}

# ==============================================================================
# MAIN ENGINE & PARSER
# ==============================================================================
def parse_args():
    parser = argparse.ArgumentParser(
        description="SubScope - Advanced Recon, Port Scan & Takeover Suite."
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Command: run
    run_parser = subparsers.add_parser("run", help="Perform full active/passive reconnaissance")
    run_parser.add_argument("-d", "--domain", required=True, help="Target domain for scanning")
    run_parser.add_argument("-o", "--output", help="Output file prefix (will create JSON, HTML, etc.)")
    run_parser.add_argument("-t", "--threads", type=int, default=30, help="Resolution threads")
    run_parser.add_argument("--ports", help="Comma-separated ports to scan (e.g. 80,443)")
    run_parser.add_argument("--rate", type=int, default=100, help="Async Port scan rate-limiting")
    run_parser.add_argument("--permutations", action="store_true", help="Generate and scan permutations")

    # Command: enum
    enum_parser = subparsers.add_parser("enum", help="Harvest subdomains only")
    enum_parser.add_argument("-d", "--domain", required=True, help="Target domain")
    enum_parser.add_argument("--permutations", action="store_true", help="Generate permutations")

    # Command: ports
    ports_parser = subparsers.add_parser("ports", help="Fast Async Port scanner")
    ports_parser.add_argument("-d", "--domain", required=True, help="Target IP or Domain")
    ports_parser.add_argument("--ports", help="Ports list (e.g., 22,80,443)")
    ports_parser.add_argument("--rate", type=int, default=150, help="Scanner rate limit")

    # Command: whois
    whois_parser = subparsers.add_parser("whois", help="Perform RDAP / WHOIS lookup")
    whois_parser.add_argument("-d", "--domain", required=True, help="Domain target")

    # Command: diff
    diff_parser = subparsers.add_parser("diff", help="Compare two scan result JSON files")
    diff_parser.add_argument("file1", help="First JSON scan report")
    diff_parser.add_argument("file2", help="Second JSON scan report")

    return parser.parse_args()

def check_target_http(domain: str, ip: str) -> Dict[str, Any]:
    """Gather HTTP signatures."""
    res = {"status": 0, "title": "N/A", "server": "N/A"}
    for protocol in ["https", "http"]:
        try:
            req = urllib.request.Request(
                f"{protocol}://{domain}",
                headers={"User-Agent": USER_AGENT}
            )
            with urllib.request.urlopen(req, timeout=3.0) as response:
                res["status"] = response.status
                res["server"] = response.headers.get("Server", "N/A")
                body = response.read().decode('utf-8', errors='ignore')
                title_match = re.search(r'<title>(.*?)</title>', body, re.IGNORECASE | re.DOTALL)
                if title_match:
                    res["title"] = title_match.group(1).strip().replace('\n', ' ')
                return res
        except urllib.error.HTTPError as e:
            res["status"] = e.code
            res["server"] = e.headers.get("Server", "N/A")
            return res
        except Exception:
            continue
    return res

def print_banner():
    banner = r"""
   _____       __   _____
  / ___/__  __/ /_ / ___/_________  ____  ___
  \__ \/ / / / __ \\__ \/ ___/ __ \/ __ \/ _ \
 ___/ / /_/ / /_/ /__/ / /__/ /_/ / /_/ /  __/
/____/\__,_/_.___/____/\___/\____/ .___/\___/
                                /_/
"""
    console.print(Panel(
        f"[bold cyan]{banner}[/bold cyan]\n"
        f"[bold yellow]{DEV_INFO}[/bold yellow]\n"
        f"[dim]High-Performance Asset Reconnaissance, Port Scan & Takeover Suite[/dim]",
        border_style="cyan",
        expand=False
    ))

async def async_run_recon(domain: str, threads: int, ports: List[int], rate: int, perms: bool, output: str):
    console.print(f"[bold cyan][*] Running Full Recon on target: {domain}[/bold cyan]\n")

    # 1. Subdomain Gathering
    harvester = SubdomainHarvester(domain, verbose=True)
    domains = harvester.run(enable_permutations=perms)
    console.print(f"[bold green][+][/bold green] Found [bold white]{len(domains)}[/bold white] active domains.\n")

    results = []
    
    # Setup Async Port Scanner
    scanner = AsyncPortScanner(ports=ports, rate_limit=rate)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeRemainingColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("[cyan]Processing targets...", total=len(domains))
        
        for dom in domains:
            try:
                ip = socket.gethostbyname(dom)
            except Exception:
                ip = "N/A"

            # Check Takeover
            takeover = TakeoverChecker.check_takeover(dom)

            # Perform HTTP check
            http_details = {"status": 0, "title": "N/A", "server": "N/A"}
            if ip != "N/A":
                http_details = check_target_http(dom, ip)

            # Scan ports async
            open_ports = []
            if ip != "N/A":
                open_ports = await scanner.scan_host(ip)

            item = {
                "domain": dom,
                "ip": ip,
                "status": http_details["status"],
                "title": http_details["title"],
                "server": http_details["server"],
                "takeover": takeover,
                "open_ports": open_ports
            }
            results.append(item)
            progress.advance(task)

    # Output Summary Table
    table = Table(title="Scan Result Summary", show_header=True, header_style="bold cyan")
    table.add_column("Domain", style="bold white")
    table.add_column("IP", style="dim")
    table.add_column("Severity")
    table.add_column("HTTP Status", justify="center")
    table.add_column("Open Ports")
    table.add_column("Takeover")

    for r in results:
        sev = assign_severity(r)
        sev_color = {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "blue",
            "INFO": "green"
        }.get(sev, "white")

        ports_str = ", ".join(str(p["port"]) for p in r["open_ports"]) or "-"
        takeover_str = "[bold red]VULNERABLE[/bold red]" if r["takeover"]["vulnerable"] else "Safe"
        
        table.add_row(
            r["domain"],
            r["ip"],
            f"[{sev_color}]{sev}[/{sev_color}]",
            str(r["status"]) if r["status"] != 0 else "Offline",
            ports_str,
            takeover_str
        )

    console.print(table)

    # Save outputs if specified
    if output:
        json_out = f"{output}.json"
        html_out = f"{output}.html"
        csv_out = f"{output}.csv"
        
        # Write JSON
        with open(json_out, "w", encoding="utf-8") as f:
            json.dump({"target": domain, "results": results}, f, indent=4)
        # Write HTML
        generate_html_report(html_out, results, domain)
        # Write CSV
        save_csv_report(csv_out, results)

        console.print(f"\n[bold green][✔] Finished![/bold green] Outputs saved as prefix: [bold underline]{output}[/bold underline] (.json, .html, .csv)\n")

def main():
    print_banner()
    args = parse_args()
    config = load_config()

    # Merge config defaults
    ports_cfg = config.get("ports", DEFAULT_PORTS)
    if hasattr(args, 'ports') and args.ports:
        ports_list = [int(p.strip()) for p in args.ports.split(",")]
    else:
        ports_list = ports_cfg

    if args.command == "run":
        asyncio.run(async_run_recon(
            domain=args.domain,
            threads=args.threads,
            ports=ports_list,
            rate=args.rate,
            perms=args.permutations,
            output=args.output
        ))

    elif args.command == "enum":
        console.print(f"[cyan][*] Harvesting subdomains for: {args.domain}...[/cyan]")
        harvester = SubdomainHarvester(args.domain, verbose=True)
        subs = harvester.run(enable_permutations=args.permutations)
        console.print(f"\n[bold green][+][/bold green] Active discovered subdomains ({len(subs)}):")
        for s in subs:
            console.print(f" - {s}")

    elif args.command == "ports":
        target = args.domain
        try:
            ip = socket.gethostbyname(target)
        except Exception:
            ip = target
        console.print(f"[cyan][*] Async port scanning {target} ({ip})...[/cyan]")
        scanner = AsyncPortScanner(ports=ports_list, rate_limit=args.rate)
        results = asyncio.run(scanner.scan_host(ip))
        
        table = Table(title=f"Open Ports on {target}", show_header=True, header_style="bold green")
        table.add_column("Port", justify="right")
        table.add_column("Service Banner")
        for r in results:
            table.add_row(str(r["port"]), r["banner"])
        console.print(table)

    elif args.command == "whois":
        console.print(f"[cyan][*] WHOIS/RDAP Query for {args.domain}...[/cyan]")
        info = WhoisRdapClient.get_info(args.domain)
        tree = Tree(f"[bold cyan]Domain: {args.domain}[/bold cyan]")
        for k, v in info.items():
            tree.add(f"[bold]{k.capitalize()}:[/bold] {v}")
        console.print(tree)

    elif args.command == "diff":
        console.print(f"[cyan][*] Comparing {args.file1} and {args.file2}...[/cyan]")
        diff = ScanDiff.compare(args.file1, args.file2)
        if "error" in diff:
            console.print(f"[bold red][!] Error: {diff['error']}[/bold red]")
            sys.exit(1)

        tree = Tree("[bold yellow]Comparison Diff Results[/bold yellow]")
        
        added_node = tree.add("[bold green]Added Assets[/bold green]")
        for a in diff["added"]:
            added_node.add(f"{a['domain']} ({a['ip']})")

        removed_node = tree.add("[bold red]Removed Assets[/bold red]")
        for r in diff["removed"]:
            removed_node.add(f"{r['domain']}")

        changed_node = tree.add("[bold blue]Changed Assets[/bold blue]")
        for c in diff["changed"]:
            c_node = changed_node.add(f"{c['domain']}")
            for prop, change in c["changes"].items():
                c_node.add(f"{prop}: {change['old']} -> {change['new']}")

        console.print(tree)
    else:
        # Default fallback
        print("Please specify a command (run, enum, ports, whois, diff). Use --help for options.")

if __name__ == "__main__":
    main()
