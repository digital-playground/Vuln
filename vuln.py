#!/usr/bin/env python3
"""
vuln_online.py - Vulnerability Scanner v2 (Online CVE Lookup)
Prints a detailed report to the console with CVEs in a table; optional JSON/HTML output.
"""
from __future__ import annotations
import os
import sys
import re
import json
import time
import socket
import ssl
import subprocess
import csv
import traceback
from datetime import datetime, timezone
from urllib.parse import quote
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
except ImportError:
    requests = None
    print("[!] 'requests' not installed. Install with: pip install requests", file=sys.stderr)

try:
    from packaging.version import Version
except ImportError:
    Version = None

# ----------------- Configuration -----------------
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
THREAD_POOL_SIZE = 80
SOCKET_TIMEOUT = 3
RATE_LIMIT = 6
CIRCL_DELAY = 0.5

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1723, 3306, 3389, 5900, 6379, 8080, 8443, 8888
]

PROBES = {
    21: b"HELP\r\n",
    22: b"",
    25: b"EHLO example.com\r\n",
    80: b"HEAD / HTTP/1.0\r\n\r\n",
    110: b"CAPA\r\n",
    143: b"a001 CAPABILITY\r\n",
    8080: b"HEAD / HTTP/1.0\r\n\r\n",
    8888: b"HEAD / HTTP/1.0\r\n\r\n",
}

WEB_INTERESTING_PATHS = [
    "/robots.txt", "/sitemap.xml", "/.git/HEAD", "/.env",
    "/phpinfo.php", "/info.php", "/test.php", "/server-status",
    "/server-info", "/phpmyadmin/", "/admin/", "/login", "/wp-admin"
]
WEB_LISTING_DIRS = ["/images/", "/css/", "/uploads/", "/backup/", "/logs/"]

# ----------------- Utilities -----------------
def http_get(url: str, timeout: int = 10) -> tuple[int | None, str | None]:
    """Fallback HTTP GET using urllib (if requests not available)."""
    try:
        req = Request(url, headers={"User-Agent": "vuln-scanner-v2/1.0"})
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urlopen(req, timeout=timeout, context=ctx) as resp:
            try:
                content = resp.read().decode("utf-8", errors="ignore")
            except Exception:
                content = None
            code = getattr(resp, "status", None) or getattr(resp, "getcode", lambda: None)()
            return code, content
    except HTTPError as e:
        try:
            body = e.read().decode("utf-8", errors="ignore")
        except Exception:
            body = None
        return e.code, body
    except URLError as e:
        return None, str(e)
    except Exception as e:
        return None, str(e)

def safe_print(*args, **kwargs):
    try:
        print(*args, **kwargs)
    except Exception:
        sys.stdout.write(" ".join(map(str, args)) + ("\n" if not kwargs.get("end") else ""))

# ----------------- Online CVE Fetching -----------------
# In‑memory caches for a single scan
_nvd_cache = {}
_circl_cache = {}
_kev_set = None
_exploitdb_set = None
_metasploit_set = None

def fetch_nvd_cves(product: str, version: str = None) -> list:
    cache_key = (product, version)
    if cache_key in _nvd_cache:
        return _nvd_cache[cache_key]

    if not requests:
        safe_print("[-] 'requests' required for NVD queries.")
        return []

    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    keywords = [product]
    if version:
        keywords.append(version)
    query = " ".join(keywords)
    params = {"keywordSearch": query, "resultsPerPage": 50, "startIndex": 0}
    headers = {"User-Agent": "vuln-scanner-v2/1.0"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    all_cves = []
    try:
        while True:
            if not NVD_API_KEY:
                time.sleep(RATE_LIMIT)
            resp = requests.get(base_url, params=params, headers=headers, timeout=20)
            if resp.status_code == 403:
                safe_print("[-] NVD API rate limit exceeded or access denied.")
                break
            if resp.status_code != 200:
                safe_print(f"[-] NVD returned status {resp.status_code}")
                break
            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            for item in vulns:
                cve = item.get("cve", {})
                cve_id = cve.get("id")
                if not cve_id:
                    continue
                desc = next((d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
                cvssv3 = None
                severity = None
                metrics = cve.get("metrics", {})
                if "cvssMetricV31" in metrics:
                    m = metrics["cvssMetricV31"][0]
                    cvssv3 = m["cvssData"].get("baseScore")
                    severity = m.get("baseSeverity")
                elif "cvssMetricV30" in metrics:
                    m = metrics["cvssMetricV30"][0]
                    cvssv3 = m["cvssData"].get("baseScore")
                    severity = m.get("baseSeverity")
                published = cve.get("published")
                all_cves.append({
                    "cve_id": cve_id,
                    "description": desc[:180] + "..." if len(desc) > 180 else desc,
                    "cvssv3": cvssv3,
                    "severity": severity,
                    "published": published
                })
            total = data.get("totalResults", 0)
            params["startIndex"] += params["resultsPerPage"]
            if params["startIndex"] >= total or params["startIndex"] >= 200:
                break
    except Exception as e:
        safe_print(f"[-] NVD query error: {e}")

    _nvd_cache[cache_key] = all_cves
    return all_cves

def fetch_circl_enrichment(cve_id: str) -> dict:
    if cve_id in _circl_cache:
        return _circl_cache[cve_id]
    if not requests:
        return {"epss": None, "references": []}

    url = f"https://vulnerability.circl.lu/api/cve/{quote(cve_id)}"
    result = {"epss": None, "references": []}
    try:
        time.sleep(CIRCL_DELAY)
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            epss = data.get("epss")
            if isinstance(epss, dict):
                epss = epss.get("score")
            result["epss"] = epss
            result["references"] = data.get("references", [])
    except Exception as e:
        safe_print(f"[-] CIRCL error for {cve_id}: {e}")
    _circl_cache[cve_id] = result
    return result

def fetch_kev_set() -> set:
    global _kev_set
    if _kev_set is not None:
        return _kev_set
    if not requests:
        _kev_set = set()
        return _kev_set
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    kev = set()
    try:
        resp = requests.get(url, timeout=20)
        if resp.status_code == 200:
            data = resp.json()
            for item in data.get("vulnerabilities", []):
                cve = item.get("cveID")
                if cve:
                    kev.add(cve)
        else:
            safe_print(f"[-] CISA KEV returned status {resp.status_code}")
    except Exception as e:
        safe_print(f"[-] Failed to fetch CISA KEV: {e}")
    _kev_set = kev
    return kev

def fetch_exploitdb_set() -> set:
    global _exploitdb_set
    if _exploitdb_set is not None:
        return _exploitdb_set
    if not requests:
        _exploitdb_set = set()
        return _exploitdb_set

    url = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
    exploitdb = set()
    cve_pattern = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)
    try:
        resp = requests.get(url, timeout=30)
        if resp.status_code == 200:
            content = resp.text
            reader = csv.reader(content.splitlines())
            row_count = 0
            for row in reader:
                row_count += 1
                for cell in row:
                    for match in cve_pattern.findall(cell):
                        exploitdb.add(match.upper())
            safe_print(f"[*] Exploit-DB: scanned {row_count} rows, found {len(exploitdb)} unique CVEs")
        else:
            safe_print(f"[-] Exploit-DB returned status {resp.status_code}")
    except Exception as e:
        safe_print(f"[-] Failed to fetch Exploit-DB CSV: {e}")
    _exploitdb_set = exploitdb
    return exploitdb

def fetch_metasploit_set() -> set:
    global _metasploit_set
    if _metasploit_set is not None:
        return _metasploit_set
    if not requests:
        _metasploit_set = set()
        return _metasploit_set

    url = "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"
    msf = set()
    cve_pattern = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)

    def extract_cves(obj):
        if isinstance(obj, dict):
            for v in obj.values():
                extract_cves(v)
        elif isinstance(obj, list):
            for item in obj:
                extract_cves(item)
        elif isinstance(obj, str):
            for match in cve_pattern.findall(obj):
                msf.add(match.upper())

    try:
        resp = requests.get(url, timeout=20)
        if resp.status_code == 200:
            data = resp.json()
            extract_cves(data)
            safe_print(f"[*] Metasploit: scanned JSON, found {len(msf)} unique CVEs")
        else:
            safe_print(f"[-] Metasploit metadata returned status {resp.status_code}")
    except Exception as e:
        safe_print(f"[-] Failed to fetch Metasploit metadata: {e}")
    _metasploit_set = msf
    return msf

def github_search_poc(cve_id: str) -> list[str]:
    if not GITHUB_TOKEN or not requests:
        return []
    try:
        headers = {"User-Agent": "vuln-scanner-v2", "Authorization": f"token {GITHUB_TOKEN}"}
        url = f"https://api.github.com/search/code?q={quote(cve_id)}+in:file&per_page=20"
        r = requests.get(url, headers=headers, timeout=15)
        if r.status_code != 200:
            return []
        data = r.json()
        urls = []
        for item in data.get("items", [])[:8]:
            u = item.get("html_url")
            if u:
                urls.append(u)
        return urls
    except Exception as e:
        safe_print(f"[-] GitHub search error for {cve_id}: {e}")
        return []

def compute_exploitability(cve_id: str, cvssv3: float, epss: float,
                           in_kev: bool, in_exploitdb: bool, in_metasploit: bool) -> tuple[float, list]:
    score = 0.0
    evidence = []
    try:
        if epss:
            e = float(epss)
            if e >= 0.5:
                score += 0.35
                evidence.append(f"EPSS={e}")
            elif e > 0:
                score += 0.1
                evidence.append(f"EPSS={e}")
    except Exception:
        pass
    try:
        if cvssv3:
            cv = float(cvssv3)
            score += min(0.3, (cv / 10.0) * 0.3)
            evidence.append(f"CVSSv3={cv}")
    except Exception:
        pass
    if in_exploitdb:
        score += 0.25
        evidence.append("Exploit-DB")
    if in_metasploit:
        score += 0.45
        evidence.append("Metasploit")
    if in_kev:
        score += 0.40
        evidence.append("CISA-KEV")
    score = min(0.99, score)
    return score, evidence

def find_cves_online(service_name: str, version: str = None,
                     kev_set: set = None, exploitdb_set: set = None, metasploit_set: set = None) -> list:
    if not service_name:
        return []
    cve_list = fetch_nvd_cves(service_name, version)
    if not cve_list:
        return []

    enriched = []
    for cve in cve_list:
        cve_id = cve["cve_id"]
        circl = fetch_circl_enrichment(cve_id)
        epss = circl.get("epss")
        in_kev = cve_id in kev_set if kev_set else False
        in_exploitdb = cve_id in exploitdb_set if exploitdb_set else False
        in_metasploit = cve_id in metasploit_set if metasploit_set else False
        exploit_score, exploit_evidence = compute_exploitability(
            cve_id, cve.get("cvssv3"), epss, in_kev, in_exploitdb, in_metasploit
        )
        github_urls = github_search_poc(cve_id) if GITHUB_TOKEN else []

        enriched.append({
            "cve_id": cve_id,
            "description": cve.get("description", ""),
            "cvssv3": cve.get("cvssv3"),
            "severity": cve.get("severity"),
            "epss": epss,
            "references": circl.get("references", []),
            "exploitability": exploit_score,
            "exploit_evidence": exploit_evidence,
            "in_kev": in_kev,
            "in_exploitdb": in_exploitdb,
            "in_metasploit": in_metasploit,
            "github_pocs": github_urls
        })
    enriched.sort(key=lambda x: (-x["exploitability"], -float(x["cvssv3"] or 0)))
    return enriched

# ----------------- Service Fingerprint Engine -----------------
SERVICE_FINGERPRINTS = [
    ("openssh", re.compile(r"openssh[_-]?([\d.]+)", re.I)),
    ("apache", re.compile(r"server:\s*apache/?\s*([\d.]+)", re.I)),
    ("nginx", re.compile(r"server:\s*nginx/?\s*([\d.]+)", re.I)),
    ("iis", re.compile(r"server:\s*microsoft-iis/?\s*([\d.]+)", re.I)),
    ("mysql", re.compile(r"mysql.?ver(?:sion)?[:/ ]?([\d.]+)", re.I)),
    ("pure-ftpd", re.compile(r"pure[- ]?ftpd[^\d]*([\d.]+)", re.I)),
    ("vsftpd", re.compile(r"vsftpd[^\d]*([\d.]+)", re.I)),
]

def identify_service(port: int, banner: str | None) -> tuple[str, str, float, str]:
    if not banner:
        try:
            name = socket.getservbyport(port)
            return (name.lower(), "", 0.25, "port-based fallback")
        except Exception:
            return ("unknown", "", 0.15, "no banner")

    text = banner.lower()
    for name, rx in SERVICE_FINGERPRINTS:
        m = rx.search(text)
        if m:
            ver = m.group(1) if m.lastindex else ""
            return (name, ver, 0.9 if ver else 0.75, f"banner matched {name}")
    m_server = re.search(r"server:\s*([^\r\n]+)", banner, re.I)
    if m_server:
        token = m_server.group(1).strip()
        token_name = token.split()[0].lower()
        return (token_name, "", 0.6, "server header")
    if "ssh" in text:
        return ("ssh", "", 0.6, "ssh token")
    if "http" in text:
        return ("http", "", 0.5, "http token")
    return ("unknown", "", 0.2, "heuristic fallback")

# ----------------- Banner Grabber & Port Scan -----------------
def grab_banner(ip: str, port: int) -> str | None:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(SOCKET_TIMEOUT)
        sock.connect((ip, port))
        data = b""
        if port in (443, 8443):
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with ctx.wrap_socket(sock, server_hostname=ip) as ss:
                    ss.send(f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode())
                    data = ss.recv(4096)
            except Exception:
                pass
        else:
            if port in PROBES and PROBES[port]:
                try:
                    sock.send(PROBES[port])
                except Exception:
                    pass
            try:
                data = sock.recv(4096)
            except Exception:
                pass
            sock.close()
        return data.decode("utf-8", errors="ignore").strip() if data else None
    except Exception:
        return None

def scan_ports(ip: str, ports: list[int]) -> list[tuple[int, tuple[str, str, float, str], str | None]]:
    results = []
    def worker(p):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(SOCKET_TIMEOUT)
            if s.connect_ex((ip, p)) == 0:
                b = grab_banner(ip, p)
                svc = identify_service(p, b)
                return (p, svc, b)
        except Exception:
            return None
        finally:
            try:
                s.close()
            except Exception:
                pass
        return None

    with ThreadPoolExecutor(max_workers=min(THREAD_POOL_SIZE, len(ports))) as ex:
        futures = {ex.submit(worker, p): p for p in ports}
        for fut in as_completed(futures):
            r = fut.result()
            if r:
                results.append(r)
    results.sort(key=lambda x: x[0])
    return results

# ----------------- OS Detection -----------------
OS_SIGNATURES = [
    {"name": "Linux", "ttl_max": 64, "window": [5840, 29200, 64240]},
    {"name": "Windows", "ttl_max": 128, "window": [8192, 65535]},
    {"name": "FreeBSD", "ttl_max": 64, "window": [65535]},
]

def get_ttl(ip: str) -> int | None:
    param = "-n" if os.name == "nt" else "-c"
    try:
        output = subprocess.check_output(["ping", param, "1", ip], stderr=subprocess.STDOUT, timeout=5)
        out = output.decode(errors="ignore")
        m = re.search(r"ttl[=|:](\d+)", out, re.I)
        if m:
            return int(m.group(1))
    except Exception:
        pass
    return None

def advanced_os_detect(ttl: int | None, tcp_window: int | None = None, banner: str | None = None) -> tuple[str, int]:
    scores = {}
    for sig in OS_SIGNATURES:
        s = 0
        if ttl and ttl <= sig["ttl_max"]:
            s += 2
        if tcp_window and tcp_window in sig["window"]:
            s += 2
        if banner and sig["name"].lower() in (banner or "").lower():
            s += 1
        scores[sig["name"]] = s
    if not scores:
        return ("Unknown", 0)
    best = max(scores, key=scores.get)
    confidence = min(100, scores[best] * 25)
    return (best, confidence) if confidence > 0 else ("Unknown", 0)

# ----------------- Web + FTP checks -----------------
def check_web_interesting(ip: str, port: int, service_name: str) -> list:
    findings = []
    protocol = "https" if port in (443, 8443) else "http"
    base = f"{protocol}://{ip}:{port}"
    for path in WEB_INTERESTING_PATHS:
        url = base + path
        status, content = http_get(url, timeout=6)
        if status == 200:
            findings.append({
                "type": "Interesting File",
                "path": path,
                "url": url,
                "risk": "Info" if path in ["/robots.txt", "/sitemap.xml"] else "Medium",
                "confidence": 0.85
            })
        elif status == 403:
            findings.append({
                "type": "Forbidden",
                "path": path,
                "url": url,
                "risk": "Low",
                "confidence": 0.6
            })
    for path in WEB_LISTING_DIRS:
        url = base + path
        status, content = http_get(url, timeout=6)
        if status == 200 and content and "Index of" in content:
            findings.append({
                "type": "Directory Listing",
                "path": path,
                "url": url,
                "risk": "Medium",
                "confidence": 0.9
            })
    if service_name in ["apache", "http"]:
        for p in ["/server-status", "/server-info"]:
            url = base + p
            status, content = http_get(url, timeout=6)
            if status == 200:
                findings.append({
                    "type": "Server Info Leak",
                    "path": p,
                    "url": url,
                    "risk": "Medium",
                    "confidence": 0.9
                })
    return findings

def check_ftp_anonymous(ip: str, port: int) -> list:
    findings = []
    try:
        import ftplib
        ftp = ftplib.FTP()
        ftp.connect(ip, port, timeout=SOCKET_TIMEOUT)
        ftp.login("anonymous", "anonymous@")
        files = ftp.nlst()
        ftp.quit()
        findings.append({
            "type": "Anonymous FTP",
            "details": f"Files/dirs: {', '.join(files[:5])}" if files else "No files visible",
            "risk": "High",
            "confidence": 0.95
        })
    except Exception:
        pass
    return findings

# ----------------- Reporting -----------------
def generate_json_report(meta: dict, services: list, findings: list, out_file: str) -> None:
    report = {"meta": meta, "services": services, "findings": findings}
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    safe_print(f"[*] JSON report saved to {out_file}")

def generate_html_report(json_file: str, out_html: str) -> None:
    with open(json_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    html = []
    html.append("<html><head><meta charset='utf-8'><title>Vuln Scan Report</title></head><body>")
    html.append(f"<h1>Scan: {data['meta'].get('target')} @ {data['meta'].get('time')}</h1>")
    for svc in data.get("services", []):
        html.append(f"<h2>{svc['port']}/tcp - {svc['service']} {svc.get('version','')}</h2>")
        html.append("<pre>")
        html.append((svc.get("banner") or "")[:2000])
        html.append("</pre>")
        if svc.get("cves"):
            html.append("<ul>")
            for c in svc["cves"]:
                html.append(f"<li><b>{c['cve_id']}</b> {c.get('severity')} CVSS:{c.get('cvssv3')} Exploit:{int(c.get('exploitability',0)*100)}% Evidence:{', '.join(c.get('exploit_evidence',[])[:3])}</li>")
            html.append("</ul>")
    html.append("</body></html>")
    with open(out_html, "w", encoding="utf-8") as f:
        f.write("\n".join(html))
    safe_print(f"[*] HTML report saved to {out_html}")

def print_console_report(meta: dict, services: list, findings: list) -> None:
    """Print a detailed report to the console with CVEs in a table."""
    print("\n" + "="*80)
    print(" VULNERABILITY SCAN REPORT")
    print("="*80)
    print(f"Target: {meta['target']} ({meta['ip']})")
    print(f"Scan time: {meta['time']}")
    print(f"OS guess: {meta.get('os_guess', 'Unknown')} (confidence {meta.get('os_confidence', 0)}%)")
    print("-"*80)

    if not services:
        print("No open ports found.")
    else:
        for svc in services:
            print(f"\nPort {svc['port']}/tcp - {svc['service']} {svc.get('version', '')}")
            if svc.get('banner'):
                banner_preview = svc['banner'][:200].replace('\n', ' ')
                if len(svc['banner']) > 200:
                    banner_preview += "..."
                print(f"  Banner: {banner_preview}")

            if svc.get('cves'):
                print("  CVEs (top 10 by exploitability):")
                # Prepare table headers and rows
                headers = ["CVE ID", "Severity", "CVSS", "Exploitability", "Evidence"]
                rows = []
                for c in svc['cves'][:10]:
                    cve_id = c['cve_id']
                    severity = c.get('severity', 'N/A') or 'N/A'
                    cvss = str(c.get('cvssv3', 'N/A'))
                    exploit = f"{int(c['exploitability']*100)}%"
                    evidence = ', '.join(c['exploit_evidence'][:3])
                    if len(evidence) > 30:
                        evidence = evidence[:27] + "..."
                    rows.append([cve_id, severity, cvss, exploit, evidence])

                # Calculate column widths
                col_widths = [max(len(str(row[i])) for row in rows + [headers]) for i in range(len(headers))]
                # Ensure minimum widths
                col_widths = [max(w, len(h)) for w, h in zip(col_widths, headers)]

                # Print top border
                print("  +" + "+".join("-" * (w+2) for w in col_widths) + "+")
                # Print header
                header_line = "  |"
                for i, h in enumerate(headers):
                    header_line += f" {h:<{col_widths[i]}} |"
                print(header_line)
                # Print separator
                print("  +" + "+".join("-" * (w+2) for w in col_widths) + "+")
                # Print rows
                for row in rows:
                    line = "  |"
                    for i, cell in enumerate(row):
                        line += f" {str(cell):<{col_widths[i]}} |"
                    print(line)
                # Print bottom border
                print("  +" + "+".join("-" * (w+2) for w in col_widths) + "+")
            else:
                print("  No CVEs found for this service.")

    if findings:
        print("\n" + "-"*80)
        print("ADDITIONAL FINDINGS")
        print("-"*80)
        for f in findings:
            print(f"Port {f['port']}/{f['service']} - {f['type']} (Risk: {f.get('risk', 'Unknown')})")
            if f.get('url'):
                print(f"  URL: {f['url']}")
            if f.get('details'):
                print(f"  Details: {f['details']}")
    else:
        print("\nNo additional findings.")

    print("="*80 + "\n")

# ----------------- Scan Orchestration -----------------
def scan_target(target: str, ports: list[int] | None = None, out_json: str | None = None, out_html: str | None = None) -> None:
    global _nvd_cache, _circl_cache, _kev_set, _exploitdb_set, _metasploit_set
    _nvd_cache = {}
    _circl_cache = {}
    _kev_set = None
    _exploitdb_set = None
    _metasploit_set = None

    if ports is None:
        ports = COMMON_PORTS
    try:
        ip = socket.gethostbyname(target)
    except Exception:
        safe_print("[-] Could not resolve target:", target)
        return

    safe_print(f"[*] Target IP: {ip}")
    ttl = get_ttl(ip)
    os_guess, os_conf = advanced_os_detect(ttl, None, None)
    safe_print(f"[*] OS guess: TTL={ttl} -> {os_guess} (Confidence {os_conf}%)")

    safe_print("[*] Scanning common ports...")
    scan_results = scan_ports(ip, ports)

    safe_print("[*] Fetching CISA KEV, Exploit-DB, Metasploit indices...")
    kev_set = fetch_kev_set()
    exploitdb_set = fetch_exploitdb_set()
    metasploit_set = fetch_metasploit_set()
    safe_print(f"    KEV: {len(kev_set)} entries, Exploit-DB: {len(exploitdb_set)}, Metasploit: {len(metasploit_set)}")

    services_report = []
    findings = []

    for port, svc_tuple, banner in scan_results:
        name, ver, svc_conf, svc_reason = svc_tuple
        safe_print(f"    {port}/tcp : {name} {ver} (Confidence: {int(svc_conf*100)}% — {svc_reason})")
        if banner:
            banner_preview = (banner[:480] + "...") if len(banner) > 480 else banner
            safe_print(f"        Banner: {banner_preview}")

        cves = find_cves_online(name, ver if ver else None,
                                kev_set=kev_set, exploitdb_set=exploitdb_set, metasploit_set=metasploit_set)

        svc_cves = []
        for c in cves[:20]:
            safe_print(f"        {c['cve_id']} | {c.get('severity')} (CVSS: {c.get('cvssv3')}) — Exploitability: {int(c['exploitability']*100)}% — Evidence: {', '.join(c['exploit_evidence'][:3])}")
            if c.get("github_pocs"):
                safe_print(f"            GitHub PoCs: {', '.join(c['github_pocs'][:2])}")
            svc_cves.append(c)

        svc_findings = []
        if name in ("http", "https", "apache", "nginx") or port in (80, 443, 8080, 8443):
            svc_findings.extend(check_web_interesting(ip, port, name))
        if name in ("ftp", "pure-ftpd", "vsftpd") or port == 21:
            svc_findings.extend(check_ftp_anonymous(ip, port))

        for f in svc_findings:
            findings.append({"port": port, "service": name, **f})

        services_report.append({
            "port": port,
            "service": name,
            "version": ver,
            "banner": banner,
            "cves": svc_cves,
            "findings": svc_findings
        })

    meta = {
        "target": target,
        "ip": ip,
        "time": datetime.now(timezone.utc).isoformat(),
        "os_guess": os_guess,
        "os_confidence": os_conf
    }

    # Print console report
    print_console_report(meta, services_report, findings)

    # Generate files only if requested
    if out_json:
        generate_json_report(meta, services_report, findings, out_json)
    if out_html:
        if out_json:
            generate_html_report(out_json, out_html)
        else:
            safe_print("[-] HTML report requires a JSON file. Please specify an output JSON filename.")

    safe_print(f"[*] Scan complete. Open ports: {len(services_report)}")

# ----------------- Menu -----------------
def menu():
    safe_print("Vulnerability Scanner v2 (Online CVE Lookup) - Menu")
    while True:
        safe_print("\n--- Menu ---")
        safe_print("1. Scan Target")
        safe_print("2. Exit")
        choice = input("Select option (1-2): ").strip()
        if choice == "1":
            target = input("Enter target IP or hostname: ").strip()
            ports_str = input("Enter ports comma-separated or leave blank for default: ").strip()
            out_json = input("Output JSON filename (leave blank for auto): ").strip() or None
            out_html = input("Output HTML filename (leave blank for none): ").strip() or None
            if not target:
                safe_print("[-] No target provided.")
                continue
            ports = None
            if ports_str:
                try:
                    ports = [int(p.strip()) for p in ports_str.split(",") if p.strip()]
                except Exception:
                    safe_print("[-] Invalid ports input.")
                    continue
            scan_target(target, ports, out_json, out_html)
        elif choice == "2":
            safe_print("Exiting. Goodbye.")
            break
        else:
            safe_print("Invalid option. Try again.")

if __name__ == "__main__":
    try:
        menu()
    except KeyboardInterrupt:
        safe_print("\nInterrupted by user. Exiting.")
    except Exception:
        traceback.print_exc()
