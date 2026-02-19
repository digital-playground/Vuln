#!/usr/bin/env python3
"""
spent huge time building it so please donate on "singhsumit.ragc-1@oksbi"(my UPI id)
Vulnerability Scanner with NVD + CIRCL CVE Database (single-file)
Improved matching, service identification, and additional checks:
- Detailed CVE criticality (EPSS, CVSS, severity)
- Interesting file discovery on web services
- Anonymous FTP and directory listing tests

Usage: python3 vuln.py
"""
from __future__ import annotations
import os
import sys
import json
import sqlite3
import socket
import subprocess
import threading
import time
import re
import ssl
import urllib.request
import urllib.error
import ftplib
from datetime import datetime, timezone, timedelta
from urllib.request import urlopen, Request
from urllib.error import URLError
from urllib.parse import quote, urlparse

# ---------------------------- Configuration ---------------------------------
NVD_API_KEY = ""  # Optional: set to your NVD API key
CIRCL_API_BASE = "https://vulnerability.circl.lu/api"
DB_FILE = "cve_database.sqlite"
DONATION_UPI = "singhsumit.ragc-1@oksbi"
DEBUG = False  # Set to True to see debug SQL and additional logs

# Common ports to scan
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
                993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 8888]

THREADS = 50
TIMEOUT = 2  # socket timeout in seconds
RATE_LIMIT = 6  # NVD recommended minimum between API calls

# Probes to send to common ports to elicit banners
PROBES = {
    21: b"HELP\r\n",
    22: b"",  # SSH banner usually appears immediately
    25: b"EHLO example.com\r\n",
    80: b"HEAD / HTTP/1.0\r\n\r\n",
    110: b"CAPA\r\n",
    143: b"a001 CAPABILITY\r\n",
    443: b"",  # HTTPS - skip sending probe (would require TLS handshake)
    8080: b"HEAD / HTTP/1.0\r\n\r\n",
    8443: b"",
    8888: b"HEAD / HTTP/1.0\r\n\r\n",
}

# Interesting files/directories to check on web servers
WEB_INTERESTING_PATHS = [
    "/robots.txt",
    "/sitemap.xml",
    "/.git/HEAD",
    "/.env",
    "/backup.zip",
    "/backup.tar.gz",
    "/phpinfo.php",
    "/info.php",
    "/test.php",
    "/server-status",
    "/server-info",
    "/web-console/",
    "/manager/html",
    "/phpmyadmin/",
    "/admin/",
    "/login",
    "/wp-admin",
    "/wp-content",
    "/README",
    "/CHANGELOG",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    "/.well-known/security.txt",
]

# Directories that may have directory listing enabled
WEB_LISTING_DIRS = ["/images/", "/css/", "/uploads/", "/backup/", "/logs/"]

# ---------------------------- Database Setup --------------------------------
def init_database() -> None:
    """Create database and required tables if they don't exist."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    c.execute('''
        CREATE TABLE IF NOT EXISTS meta (
            source TEXT PRIMARY KEY,
            last_modified TEXT,
            last_updated TEXT
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS nvd_cves (
            id TEXT PRIMARY KEY,
            description TEXT,
            published TEXT,
            last_modified TEXT,
            cvssv2 REAL,
            cvssv3 REAL,
            vector TEXT,
            severity TEXT
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS products (
            cve_id TEXT,
            vendor TEXT,
            product TEXT,
            version_start TEXT,
            op_start TEXT,
            version_end TEXT,
            op_end TEXT,
            FOREIGN KEY(cve_id) REFERENCES nvd_cves(id)
        )
    ''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_products_vendor_product ON products(vendor, product)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_products_cve ON products(cve_id)')

    c.execute('''
        CREATE TABLE IF NOT EXISTS circl_enrich (
            cve_id TEXT PRIMARY KEY,
            exploit_predictions TEXT,
            sightings TEXT,
            external_refs TEXT,
            last_updated TEXT
        )
    ''')

    conn.commit()
    conn.close()

# ---------------------------- Date Handling ---------------------------------
def parse_nvd_date(date_str: str | None) -> datetime:
    """Parse various NVD date formats into a naive datetime object."""
    if not date_str:
        return datetime(2015, 1, 1, 0, 0)
    # Remove trailing timezone strings like " UTC-00:00"
    if ' UTC' in date_str:
        date_str = date_str.split(' UTC')[0]
    formats = ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d")
    for fmt in formats:
        try:
            return datetime.strptime(date_str, fmt)
        except Exception:
            continue
    return datetime(2015, 1, 1, 0, 0)

def format_nvd_api_date(dt: datetime) -> str:
    """Format datetime for NVD API v2.0: YYYY-MM-DDTHH:MM:SS.000+00:00"""
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + ".000+00:00"

# ---------------------------- CVE Update Functions --------------------------
def get_latest_cve_date(conn: sqlite3.Connection) -> datetime:
    c = conn.cursor()
    c.execute("SELECT MAX(published) FROM nvd_cves")
    row = c.fetchone()
    if row and row[0]:
        return parse_nvd_date(row[0])
    return datetime(2015, 1, 1, 0, 0)

def update_from_nvd() -> None:
    """Fetch CVEs from NVD using v2 REST API in 120-day chunks."""
    print("[*] Updating from NVD...")
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    latest_cve_date = get_latest_cve_date(conn)
    start_from = latest_cve_date - timedelta(days=1)
    if start_from < datetime(2015, 1, 1, 0, 0):
        start_from = datetime(2015, 1, 1, 0, 0)

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    if start_from >= now:
        print("    Database is already up to date.")
        conn.close()
        return

    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {'User-Agent': 'Mozilla/5.0'}
    if NVD_API_KEY:
        headers['apiKey'] = NVD_API_KEY

    total_processed = 0
    chunk_size = timedelta(days=120)
    current_start = start_from

    while current_start < now:
        current_end = min(current_start + chunk_size, now)
        start_index = 0
        results_per_page = 2000

        pub_start = quote(format_nvd_api_date(current_start), safe='')
        pub_end = quote(format_nvd_api_date(current_end), safe='')

        print(f"    Fetching CVEs from {current_start} to {current_end}...")

        while True:
            url = f"{base_url}?pubStartDate={pub_start}&pubEndDate={pub_end}&startIndex={start_index}&resultsPerPage={results_per_page}"
            req = Request(url, headers=headers)
            try:
                with urlopen(req, timeout=30) as resp:
                    data = json.loads(resp.read().decode('utf-8'))
            except URLError as e:
                print(f"[-] NVD API error: {e}")
                break
            except Exception as e:
                print(f"[-] Unexpected error contacting NVD: {e}")
                break

            if 'error' in data:
                print(f"[-] NVD API returned error: {data['error']}")
                break

            vulnerabilities = data.get('vulnerabilities', [])
            if not vulnerabilities:
                print("    No CVEs in this chunk.")
                break

            for cve_item in vulnerabilities:
                insert_nvd_cve_dict(c, cve_item.get('cve', {}))
                total_processed += 1
                if total_processed % 100 == 0:
                    print(f"    Processed {total_processed} CVEs...")

            total_results = data.get('totalResults', 0)
            start_index += results_per_page
            print(f"    Retrieved {min(start_index, total_results)}/{total_results} CVEs in this chunk...")
            if start_index >= total_results:
                break
            time.sleep(RATE_LIMIT)

        current_start = current_end
        time.sleep(RATE_LIMIT)

    c.execute("REPLACE INTO meta (source, last_modified, last_updated) VALUES (?, ?, ?)",
              ('nvd', now.strftime("%Y-%m-%dT%H:%M:%S"), datetime.now(timezone.utc).isoformat()))
    conn.commit()
    conn.close()
    print(f"[+] NVD update completed. Processed {total_processed} CVEs.")

def insert_nvd_cve_dict(c: sqlite3.Cursor, cve_dict: dict) -> None:
    """Insert a CVE and its configurations into the DB from NVD v2 response structure."""
    if not cve_dict:
        return
    cve_id = cve_dict.get('id')
    if not cve_id:
        return
    descriptions = cve_dict.get('descriptions', [])
    desc = next((d.get('value', '') for d in descriptions if d.get('lang') == 'en'), "")
    published = cve_dict.get('published')
    modified = cve_dict.get('lastModified')
    metrics = cve_dict.get('metrics', {})
    cvssv2 = None
    cvssv3 = None
    vector = None
    severity = None

    # CVSS extraction (attempt multiple metric keys)
    try:
        if 'cvssMetricV31' in metrics:
            m = metrics['cvssMetricV31'][0]
            cvssv3 = m['cvssData'].get('baseScore')
            vector = m['cvssData'].get('vectorString')
            severity = m.get('baseSeverity')
        elif 'cvssMetricV30' in metrics:
            m = metrics['cvssMetricV30'][0]
            cvssv3 = m['cvssData'].get('baseScore')
            vector = m['cvssData'].get('vectorString')
            severity = m.get('baseSeverity')
        if 'cvssMetricV2' in metrics:
            cvssv2 = metrics['cvssMetricV2'][0]['cvssData'].get('baseScore')
    except Exception:
        # ignore metric parsing errors
        pass

    c.execute('''
        INSERT OR REPLACE INTO nvd_cves
        (id, description, published, last_modified, cvssv2, cvssv3, vector, severity)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (cve_id, desc, published, modified, cvssv2, cvssv3, vector, severity))

    # Parse configurations -> products table
    for config in cve_dict.get('configurations', []):
        for node in config.get('nodes', []):
            parse_nvd_node(c, node, cve_id)

def parse_nvd_node(c: sqlite3.Cursor, node: dict, cve_id: str) -> None:
    """Recursively parse configuration nodes and store vendor/product/version constraints."""
    if 'children' in node:
        for child in node['children']:
            parse_nvd_node(c, child, cve_id)

    for match in node.get('cpe_match', []):
        if not match.get('vulnerable', False):
            continue
        cpe23 = match.get('cpe23Uri', '')
        parts = cpe23.split(':')
        if len(parts) < 6:
            continue
        vendor = parts[3]
        product = parts[4]
        version = parts[5]
        op_start = ''
        v_start = ''
        op_end = ''
        v_end = ''

        if version != '*':
            op_start = '='
            v_start = version
        else:
            if 'versionStartIncluding' in match:
                op_start = '>='
                v_start = match.get('versionStartIncluding', '')
            elif 'versionStartExcluding' in match:
                op_start = '>'
                v_start = match.get('versionStartExcluding', '')
            if 'versionEndIncluding' in match:
                op_end = '<='
                v_end = match.get('versionEndIncluding', '')
            elif 'versionEndExcluding' in match:
                op_end = '<'
                v_end = match.get('versionEndExcluding', '')

        c.execute('''
            INSERT INTO products
            (cve_id, vendor, product, version_start, op_start, version_end, op_end)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (cve_id, vendor, product, v_start, op_start, v_end, op_end))

def update_from_circl() -> None:
    """Fetch enrichment data for recent/un-enriched CVEs from CIRCL."""
    print("[*] Updating from CIRCL...")
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    thirty_days_ago = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%d")
    c.execute('''
        SELECT id FROM nvd_cves
        WHERE id NOT IN (SELECT cve_id FROM circl_enrich)
           OR published > ?
    ''', (thirty_days_ago,))
    cve_ids = [row[0] for row in c.fetchall()]

    if not cve_ids:
        print("    No new CVEs to enrich.")
        conn.close()
        return

    print(f"    Enriching {len(cve_ids)} CVEs from CIRCL...")
    enriched = 0
    for cve_id in cve_ids:
        try:
            url = f"{CIRCL_API_BASE}/cve/{cve_id}"
            req = Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode('utf-8'))
            epss = data.get('epss', {}).get('score')
            sightings = json.dumps(data.get('sightings', []))
            refs = json.dumps(data.get('references', []))
            c.execute('''
                INSERT OR REPLACE INTO circl_enrich
                (cve_id, exploit_predictions, sightings, external_refs, last_updated)
                VALUES (?, ?, ?, ?, ?)
            ''', (cve_id, epss, sightings, refs, datetime.now(timezone.utc).isoformat()))
            enriched += 1
            if enriched % 100 == 0:
                print(f"        Enriched {enriched} CVEs...")
        except Exception:
            # CIRCL might not have this CVE, or network issue - skip quietly
            pass
        time.sleep(0.5)

    conn.commit()
    conn.close()
    print(f"[+] CIRCL enrichment completed for {enriched} CVEs.")

def update_all() -> None:
    """Initialize DB and update from both NVD and CIRCL."""
    print("[*] Starting CVE database update...")
    init_database()
    update_from_nvd()
    update_from_circl()
    print("[+] Database update completed.")

# ---------------------------- CVE Count ------------------------------------
def show_cve_count() -> None:
    if not os.path.exists(DB_FILE):
        print("[*] Database file not found. Count = 0")
        return
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM nvd_cves")
        count = c.fetchone()[0]
        conn.close()
        print(f"[*] Total CVEs in database: {count}")
    except Exception as e:
        print(f"[-] Error reading CVE count: {e}")

# ---------------------------- Service & OS Detection -----------------------
def resolve_host(host: str) -> str | None:
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None

def get_ttl(ip: str) -> int | None:
    """Ping target and extract TTL value. Returns None on any failure."""
    param = '-n' if os.name == 'nt' else '-c'
    try:
        output = subprocess.check_output(['ping', param, '1', ip],
                                         stderr=subprocess.STDOUT,
                                         timeout=5).decode(errors='ignore')
        match = re.search(r'[Tt][Tt][Ll]=(\d+)', output)
        if match:
            return int(match.group(1))
    except Exception:
        pass
    return None

def guess_os(ttl: int | None) -> str:
    if ttl is None:
        return "Unknown"
    if ttl <= 64:
        return "Linux/Unix"
    if ttl <= 128:
        return "Windows"
    if ttl <= 255:
        return "Solaris/AIX"
    return "Unknown"

def grab_banner(ip: str, port: int) -> str | None:
    """Try to connect and fetch a banner, optionally sending a probe."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        sock.connect((ip, port))
        # If it's TLS port (443/8443) we avoid plain send; attempt TLS handshake optionally:
        if port in (443, 8443):
            try:
                ctx = ssl.create_default_context()
                with ctx.wrap_socket(sock, server_hostname=ip) as ss:
                    # send a simple HTTP HEAD over TLS
                    try:
                        ss.send(b"HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n" % ip.encode('utf-8'))
                        data = ss.recv(2048)
                    except Exception:
                        data = b""
            except Exception:
                # Fallback: we closed underlying socket above; return None
                return None
        else:
            if port in PROBES and PROBES[port]:
                try:
                    sock.send(PROBES[port])
                except Exception:
                    # ignore send errors
                    pass
            try:
                data = sock.recv(2048)
            except Exception:
                data = b""
            sock.close()

        try:
            text = data.decode('utf-8', errors='ignore').strip()
            return text
        except Exception:
            return None
    except Exception:
        return None

def scan_port(ip: str, port: int, results: list) -> None:
    """Try to connect; if open, grab banner and identify service."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        if s.connect_ex((ip, port)) == 0:
            banner = grab_banner(ip, port)
            service = identify_service(port, banner)
            results.append((port, service, banner))
        s.close()
    except Exception:
        pass

def extract_version(text: str, pattern: str) -> str:
    m = re.search(pattern, text, re.IGNORECASE)
    return m.group(1) if m else ""

def identify_service(port: int, banner: str | None) -> tuple:
    """
    Heuristic identification that always returns (name, version).
    name is normalized lower-case string.
    """
    if not banner:
        # fallback to well-known service name if available
        try:
            name = socket.getservbyport(port)
            return (name.lower(), "")
        except OSError:
            return ("unknown", "")

    banner_lower = banner.lower()

    # FTP
    if port == 21:
        if 'pure-ftpd' in banner_lower:
            return ("pure-ftpd", extract_version(banner, r'pure-ftpd[^\d]*([\d.]+)'))
        if 'vsftpd' in banner_lower:
            return ("vsftpd", extract_version(banner, r'vsftpd[^\d]*([\d.]+)'))
        if 'proftpd' in banner_lower:
            return ("proftpd", extract_version(banner, r'proftpd[^\d]*([\d.]+)'))
        return ("ftp", extract_version(banner, r'ftp[^\d]*([\d.]+)'))

    # SSH
    if port == 22:
        if 'openssh' in banner_lower:
            return ("openssh", extract_version(banner, r'openssh[_-]?([\d.]+)'))
        return ("ssh", "")

    # SMTP
    if port == 25:
        if 'postfix' in banner_lower:
            return ("postfix", extract_version(banner, r'postfix[^\d]*([\d.]+)'))
        if 'exim' in banner_lower:
            return ("exim", extract_version(banner, r'exim[^\d]*([\d.]+)'))
        if 'sendmail' in banner_lower:
            return ("sendmail", extract_version(banner, r'sendmail[^\d]*([\d.]+)'))
        return ("smtp", "")

    # HTTP-family
    if port in (80, 8080, 8443, 8888):
        server_match = re.search(r'server:\s*([^\r\n]+)', banner, re.IGNORECASE)
        if server_match:
            server = server_match.group(1).strip()
            server_lower = server.lower()
            if 'apache' in server_lower or 'httpd' in server_lower:
                return ("apache", extract_version(server, r'apache[/ ]([\d.]+)'))
            if 'nginx' in server_lower:
                return ("nginx", extract_version(server, r'nginx/([\d.]+)'))
            if 'iis' in server_lower:
                return ("iis", extract_version(server, r'iis[^\d]*([\d.]+)'))
            # generic token
            first = server.split()[0].lower()
            return (first, "")
        # fallback: look for product name anywhere
        if 'apache' in banner_lower:
            return ("apache", "")
        if 'nginx' in banner_lower:
            return ("nginx", "")
        return ("http", "")

    # POP3/IMAP
    if port == 110:
        if 'dovecot' in banner_lower:
            return ("dovecot", "")
        return ("pop3", "")
    if port == 143:
        if 'dovecot' in banner_lower:
            return ("dovecot", "")
        return ("imap", "")

    # MySQL
    if port == 3306:
        m = re.search(r'([\d]+\.[\d]+\.[\d]+)', banner)
        if m:
            return ("mysql", m.group(1))
        return ("mysql", "")

    # Default: first line of banner
    first_line = banner.split('\n', 1)[0].strip()
    if first_line:
        token = re.split(r'[\s/;()]+', first_line.lower())[0]
        return (token[:50], "")
    return ("unknown", "")

# ---------------------------- Improved CVE Lookup -------------------------
SERVICE_MAP = {
    'apache': [('apache', 'http_server'), ('apache', 'httpd'), ('apache', 'apache')],
    'nginx': [('nginx', 'nginx')],
    'openssh': [('openbsd', 'openssh'), ('openssh', 'openssh')],
    'pure-ftpd': [('pureftpd', 'pure-ftpd')],
    'vsftpd': [('vsftpd', 'vsftpd')],
    'proftpd': [('proftpd', 'proftpd')],
    'mysql': [('mysql', 'mysql')],
    'dovecot': [('dovecot', 'dovecot')],
    'postfix': [('postfix', 'postfix')],
    'exim': [('exim', 'exim')],
    'sendmail': [('sendmail', 'sendmail')],
    'iis': [('microsoft', 'iis'), ('microsoft', 'http_server')],
    'tomcat': [('apache', 'tomcat')],
    'ftp': [('', 'ftp')],
    'smtp': [('', 'smtp')],
    'pop3': [('', 'pop3')],
    'imap': [('', 'imap')],
    'http': [('', 'http_server'), ('', 'http')],
    'https': [('', 'http_server'), ('', 'http')],
}

def normalize_service_name(s: str | None) -> str:
    if not s:
        return ""
    return re.sub(r'[^a-z0-9]+', '_', s.lower()).strip('_')

def get_cve_enrichment(cve_id: str) -> tuple | None:
    """Retrieve EPSS score and references from circl_enrich table."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT exploit_predictions, external_refs FROM circl_enrich WHERE cve_id = ?", (cve_id,))
    row = c.fetchone()
    conn.close()
    return row

def find_cves(service_name: str | None, version: str | None = None) -> list:
    """
    Forgiving lookup:
      - normalizes service_name
      - tries vendor/product exact and LIKE
      - falls back to searching descriptions
    Returns list of (cve_id, short_description, cvss_score, severity, epss)
    """
    if not service_name:
        return []

    svc = normalize_service_name(service_name)
    candidates = SERVICE_MAP.get(svc, [(None, svc)])

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    all_cves: dict[str, tuple] = {}

    def run(q: str, params: tuple = ()):
        if DEBUG:
            print("DEBUG SQL:", q, params)
        try:
            c.execute(q, params)
            for row in c.fetchall():
                cid = row[0]
                all_cves[cid] = row
        except Exception as e:
            if DEBUG:
                print("SQL error:", e)

    for vendor, product in candidates:
        if vendor:
            # vendor + product exact
            run('''
                SELECT c.id, c.description, c.cvssv3, c.severity
                FROM nvd_cves c
                JOIN products p ON c.id = p.cve_id
                WHERE p.vendor = ? AND p.product = ?
            ''', (vendor, product))
            # vendor exact, product LIKE
            run('''
                SELECT c.id, c.description, c.cvssv3, c.severity
                FROM nvd_cves c
                JOIN products p ON c.id = p.cve_id
                WHERE p.vendor = ? AND p.product LIKE ?
            ''', (vendor, f'%{product}%'))
            # vendor LIKE, product LIKE (broader)
            run('''
                SELECT c.id, c.description, c.cvssv3, c.severity
                FROM nvd_cves c
                JOIN products p ON c.id = p.cve_id
                WHERE p.vendor LIKE ? AND p.product LIKE ?
            ''', (f'%{vendor}%', f'%{product}%'))
        else:
            run('''
                SELECT c.id, c.description, c.cvssv3, c.severity
                FROM nvd_cves c
                JOIN products p ON c.id = p.cve_id
                WHERE p.product LIKE ?
            ''', (f'%{product}%',))

    # fallback: search descriptions for the token
    run('''
        SELECT c.id, c.description, c.cvssv3, c.severity
        FROM nvd_cves c
        WHERE lower(c.description) LIKE ?
        LIMIT 200
    ''', (f'%{svc}%',))

    conn.close()

    results = []
    for cid, row in all_cves.items():
        _, desc, cvss, sev = row
        desc_short = (desc or "")[:140]
        # get enrichment
        enrich = get_cve_enrichment(cid)
        epss = enrich[0] if enrich and enrich[0] else "N/A"
        results.append((cid, desc_short + ("..." if len(desc or "") > 140 else ""), cvss, sev, epss))

    results.sort(key=lambda x: (-(x[2] or 0), x[0]))
    return results

# ---------------------------- Additional Vulnerability Checks --------------
def http_get(url: str, timeout: int = 5) -> tuple[int | None, str | None]:
    """Perform a GET request, return (status_code, content) or (None, None) on failure."""
    try:
        req = Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        # Disable SSL certificate verification for simplicity (may cause warnings)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urlopen(req, context=ctx, timeout=timeout) as resp:
            return resp.status, resp.read().decode('utf-8', errors='ignore')
    except urllib.error.HTTPError as e:
        return e.code, None
    except Exception:
        return None, None

def check_web_interesting(ip: str, port: int, service_name: str) -> list:
    """Check for interesting files on a web server."""
    findings = []
    protocol = "https" if port in (443, 8443) else "http"
    base_url = f"{protocol}://{ip}:{port}"

    # Check interesting paths
    for path in WEB_INTERESTING_PATHS:
        url = base_url + path
        status, content = http_get(url)
        if status == 200:
            findings.append({
                'type': 'Interesting File',
                'description': f"Found accessible file: {path}",
                'url': url,
                'risk': 'Info' if path in ['/robots.txt', '/sitemap.xml'] else 'Medium'
            })
        elif status == 403:
            findings.append({
                'type': 'Forbidden',
                'description': f"Access forbidden (might exist): {path}",
                'url': url,
                'risk': 'Low'
            })

    # Check for directory listing
    for path in WEB_LISTING_DIRS:
        url = base_url + path
        status, content = http_get(url)
        if status == 200 and content and "Index of" in content:
            findings.append({
                'type': 'Directory Listing',
                'description': f"Directory listing enabled at {path}",
                'url': url,
                'risk': 'Medium'
            })

    # Check for server info leakage via /server-status or /server-info (if accessible)
    if service_name in ['apache', 'http']:
        for path in ['/server-status', '/server-info']:
            url = base_url + path
            status, content = http_get(url)
            if status == 200:
                findings.append({
                    'type': 'Server Info Leak',
                    'description': f"Server information page exposed: {path}",
                    'url': url,
                    'risk': 'Medium'
                })

    return findings

def check_ftp_anonymous(ip: str, port: int) -> list:
    """Check if FTP allows anonymous login."""
    findings = []
    try:
        ftp = ftplib.FTP()
        ftp.connect(ip, port, timeout=TIMEOUT)
        ftp.login('anonymous', 'anonymous@')
        # Try to list files
        files = ftp.nlst()
        ftp.quit()
        findings.append({
            'type': 'Anonymous FTP',
            'description': 'Anonymous FTP login allowed',
            'details': f"Files/dirs: {', '.join(files[:5])}" if files else "No files visible",
            'risk': 'High'
        })
    except Exception:
        pass
    return findings

def check_service_vulns(ip: str, port: int, service_name: str, banner: str | None) -> list:
    """Run additional vulnerability checks based on service type."""
    findings = []
    # Web services
    if service_name in ['http', 'apache', 'nginx', 'iis', 'tomcat'] or port in (80, 443, 8080, 8443, 8888):
        findings.extend(check_web_interesting(ip, port, service_name))
    # FTP
    if service_name in ['ftp', 'vsftpd', 'proftpd', 'pure-ftpd'] or port == 21:
        findings.extend(check_ftp_anonymous(ip, port))
    # Add more checks for other services as needed

    return findings

# ---------------------------- Scanning ---------------------------------------
def scan_target(target: str) -> None:
    ip = resolve_host(target)
    if not ip:
        print(f"[-] Could not resolve {target}")
        return

    print(f"\n[*] Target IP: {ip}")

    ttl = get_ttl(ip)
    os_guess = guess_os(ttl)
    print(f"[*] OS Fingerprint: TTL={ttl} -> {os_guess}")

    print("[*] Scanning common ports...")
    results: list = []
    threads: list[threading.Thread] = []

    for port in COMMON_PORTS:
        t = threading.Thread(target=scan_port, args=(ip, port, results))
        threads.append(t)
        t.start()
        if len(threads) >= THREADS:
            for th in threads:
                th.join()
            threads = []
    for th in threads:
        th.join()

    if not results:
        print("    No open ports found.")
        return

    print("\n[+] Open Ports & Services:")
    all_findings = []
    for port, service, banner in sorted(results, key=lambda x: x[0]):
        if isinstance(service, tuple):
            service_name, service_version = service
        else:
            service_name, service_version = (service, "")

        service_display = f"{service_name} {service_version}".strip()
        print(f"    {port}/tcp : {service_display}")
        if banner:
            banner_preview = banner[:180] + ("..." if len(banner) > 180 else "")
            print(f"        Banner: {banner_preview}")

        cves = find_cves(service_name, service_version)
        if cves:
            print(f"        Potential CVEs ({len(cves)} found):")
            for cve_id, desc, score, sev, epss in cves[:5]:
                epss_disp = f" (EPSS: {epss})" if epss and epss != "N/A" else ""
                print(f"            {cve_id} | {sev} (CVSS: {score}){epss_disp}")
                if DEBUG:
                    print(f"                {desc}")
        else:
            print("        No CVEs found in local database.")

        # Additional service-specific checks
        findings = check_service_vulns(ip, port, service_name, banner)
        if findings:
            all_findings.extend(findings)
            for f in findings:
                risk = f.get('risk', 'Info')
                print(f"        [!] {risk}: {f['description']}")

    if all_findings:
        print("\n[!] Additional Vulnerabilities / Interesting Findings:")
        for idx, f in enumerate(all_findings, 1):
            print(f"    {idx}. [{f['risk']}] {f['description']}")
            if 'url' in f:
                print(f"        URL: {f['url']}")
            if 'details' in f:
                print(f"        Details: {f['details']}")

    print("\n[*] Network Map:")
    print(f"    Scanned host: {target} ({ip})")
    print(f"    Open ports: {len(results)}")

# ---------------------------- Menu & Donation -------------------------------
def show_donation() -> None:
    print("\n" + "="*50)
    print("Support the developer:")
    print(f"UPI ID: {DONATION_UPI}")
    print("="*50 + "\n")

def menu() -> None:
    while True:
        print("\n--- Vulnerability Scanner (NVD + CIRCL) ---")
        print("1. Update CVE Database (NVD + CIRCL)")
        print("2. Scan Target")
        print("3. Donation Info")
        print("4. Show CVE Count")
        print("5. Exit")
        choice = input("Select option (1-5): ").strip()

        if choice == '1':
            update_all()
        elif choice == '2':
            target = input("Enter target IP or hostname: ").strip()
            if target:
                scan_target(target)
            else:
                print("[-] No target entered.")
        elif choice == '3':
            show_donation()
        elif choice == '4':
            show_cve_count()
        elif choice == '5':
            print("[*] Exiting. Goodbye!")
            break
        else:
            print("[-] Invalid option.")

# ---------------------------- Main ------------------------------------------
if __name__ == "__main__":
    # Ensure DB exists (but do not auto-download data)
    if not os.path.exists(DB_FILE):
        init_database()
        print("[*] Database created. Please run option 1 to update.")
    try:
        menu()
    except KeyboardInterrupt:
        print("\n[*] Interrupted by user. Exiting.")
        sys.exit(0)
