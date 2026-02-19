
# Vulnerability Scanner with NVD + CIRCL CVE Database

A powerful, single-file vulnerability scanner that combines **NVD CVE data** and **CIRCL enrichment** to identify potential security issues in target systems. It performs service discovery, OS fingerprinting, CVE matching, and additional security checks (interesting files, directory listing, anonymous FTP, etc.).

---

## Features

- **Port Scanning**: Scans a predefined set of common ports (21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443,8888) with banner grabbing.
- **Service Identification**: Heuristically identifies service names and versions from banners.
- **OS Fingerprinting**: Estimates OS family based on TTL values from ping replies.
- **CVE Database**:
  - Downloads and maintains a local SQLite database of CVEs from the **NVD v2 API**.
  - Enriches CVE data with **EPSS scores** and references from the **CIRCL CVE API**.
- **CVE Matching**: For each detected service, performs flexible matching against vendor/product entries and description keywords.
- **Detailed CVE Output**: Displays CVE ID, CVSS score, severity, and EPSS probability (if available).
- **Additional Vulnerability Checks**:
  - **Interesting files** on web servers (e.g., `/robots.txt`, `.git/HEAD`, backup archives, admin panels).
  - **Directory listing** detection.
  - **Anonymous FTP** login check.
  - Web server info leakage (e.g., `/server-status`).
- **Multi-threaded**: Fast scanning with configurable thread count.
- **Donation Reminder**: Includes a non‑intrusive UPI donation prompt.

---

## Requirements

- Python **3.7+**
- Standard library modules: `socket`, `subprocess`, `threading`, `sqlite3`, `json`, `re`, `ssl`, `urllib`, `ftplib`, `datetime`
- Internet connection for initial database update and enrichment.

No external dependencies are required.

---

## Installation

1. **Clone or download** the script (`vuln.py`) to your local machine.
2. **Make it executable** (optional):
   ```bash
   chmod +x vuln.py
```

1. Run the script:
   ```bash
   python vuln.py
   ```
   On first run, the database file (cve_database.sqlite) will be created automatically. You must then update the database (option 1) before scanning.

---

Usage

Main Menu

```
--- Vulnerability Scanner (NVD + CIRCL) ---
1. Update CVE Database (NVD + CIRCL)
2. Scan Target
3. Donation Info
4. Show CVE Count
5. Exit
```

1. Update CVE Database

· Downloads CVE data from NVD in 120‑day chunks (respecting rate limits).
· Enriches recently added CVEs with data from the CIRCL API.
· The update process may take several minutes on first run.

2. Scan Target

· Enter an IP address or hostname (e.g., scanme.nmap.org).
· The scanner will:
  · Resolve the host to an IP.
  · Ping the target to estimate OS (TTL analysis).
  · Scan common ports concurrently.
  · For each open port, grab a banner and identify the service.
  · Query the local database for matching CVEs.
  · Perform additional service‑specific checks (web interesting files, anonymous FTP, etc.).
· Output includes:
  · OS fingerprint
  · List of open ports with service name/version and banner preview
  · Top 5 matching CVEs (sorted by CVSS score) with severity and EPSS (if available)
  · Additional vulnerability findings

3. Donation Info

· Displays UPI ID for supporting the developer.

4. Show CVE Count

· Prints the total number of CVEs currently stored in the local database.

5. Exit

· Terminates the program.

---

Configuration

You can adjust the following constants at the top of the script:

Variable Description
NVD_API_KEY Optional NVD API key (increases rate limit).
DB_FILE Path to the SQLite database file.
COMMON_PORTS List of ports to scan.
THREADS Number of concurrent threads for port scanning.
TIMEOUT Socket timeout in seconds.
RATE_LIMIT Delay between NVD API calls (seconds).
WEB_INTERESTING_PATHS List of paths to check on web servers.
DEBUG Set to True to enable verbose SQL logging.

---

Database Schema

The SQLite database (cve_database.sqlite) consists of three tables:

· nvd_cves: Core CVE information (ID, description, publication dates, CVSS scores, severity).
· products: Vendor/product mappings with version constraints (from CPE data).
· circl_enrich: Enrichment data (EPSS, sightings, external references) from CIRCL.
· meta: Tracks the last update timestamps.

---

Example Output

```
[*] Target IP: 45.33.32.156
[*] OS Fingerprint: TTL=48 -> Linux/Unix
[*] Scanning common ports...

[+] Open Ports & Services:
    22/tcp : openssh 6.6.1
        Banner: SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
        Potential CVEs (70 found):
            CVE-2016-1908 | None (CVSS: 9.8)
            CVE-2016-7407 | None (CVSS: 9.8)
            ...
    80/tcp : apache 2.4.7
        Banner: HTTP/1.1 200 OK ...
        Potential CVEs (200 found):
            CVE-2016-10043 | None (CVSS: 10.0)
            CVE-2016-1985 | None (CVSS: 10.0)
            ...
        [!] Medium: Directory listing enabled at /images/

[!] Additional Vulnerabilities / Interesting Findings:
    1. [Medium] Directory listing enabled at /images/
        URL: http://45.33.32.156:80/images/

[*] Network Map:
    Scanned host: scanme.nmap.org (45.33.32.156)
    Open ports: 2
```

---

Limitations

· Only scans a predefined set of common ports. For a full port scan, consider using nmap and feeding its output to this tool.
· Service identification relies on banner grabbing; some services may not reveal version information.
· CVE matching is based on local database; results are only as current as the last update.
· EPSS enrichment depends on CIRCL availability; not all CVEs will have EPSS scores.
· The script does not perform exploitation – it is a vulnerability identification tool only.

---

Legal & Ethical Use

This tool is intended for authorized security assessments and educational purposes only. Unauthorized scanning of networks or systems may violate laws and regulations. The developer assumes no liability for misuse.

---

Support

If you find this tool useful, consider supporting the developer:

UPI ID: singhsumit.ragc-1@oksbi

For issues, feature requests, or contributions, please open an issue on the project repository.

---

License

MIT License – Free to use, modify, and distribute.

```
