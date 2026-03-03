Vulnerability Scanner v3 (Online CVE Lookup + Web Crawler)

A multi‑purpose network vulnerability scanner that identifies open ports, grabs service banners, fingerprints services, and fetches relevant CVEs from online sources (NVD, CIRCL, CISA KEV, Exploit‑DB, Metasploit). It computes an exploitability score for each CVE based on CVSS, EPSS, and known exploit presence. Version 3 adds a recursive web crawler and deep web vulnerability assessment to detect common web flaws like XSS, SQL injection, and path traversal.

---

✨ New in Version 3

· Recursive Web Crawler
    Automatically crawls discovered web servers (HTTP/HTTPS) up to a configurable page limit, extracting links and forms for further analysis.
· Deep Web Vulnerability Assessment
    Tests each discovered form for:
  · Reflected Cross‑Site Scripting (XSS)
  · Error‑based SQL Injection
  · Path Traversal (e.g., ../../../../etc/passwd)
· Enhanced Web Findings
    In addition to the existing interesting‑file checks, the crawler now reports:
  · Forbidden pages (HTTP 403) as low‑risk findings
  · Directory listings
  · Server information leaks (e.g., /server-status)
· Improved Reporting
    The console report now includes all web‑related findings under a dedicated “ADDITIONAL FINDINGS” section. HTML reports have been expanded to show these findings as well.

---

🚀 Features

· Port Scanning – Scans a user‑defined list of common ports (or a custom list) with banner grabbing.
· Service Fingerprinting – Identifies service names and versions from banners using regex patterns and heuristics.
· Online CVE Lookup – Queries the NVD API for CVEs matching the service + version, enriched with EPSS scores from CIRCL.
· Exploit Intelligence – Checks CVE presence in:
  · CISA Known Exploited Vulnerabilities (KEV) catalog
  · Exploit‑DB (parsed from the official CSV)
  · Metasploit modules (from the metadata JSON)
· Exploitability Scoring – Combines CVSS, EPSS, and exploit database hits into a single 0‑99% score.
· GitHub PoC Search – If a GitHub token is provided, searches for public proof‑of‑concept code.
· OS Fingerprinting – Basic OS guess based on TTL from ping.
· Web Crawling & Deep Testing – Recursively crawls web servers and tests forms for common vulnerabilities.
· Multiple Output Formats – Console (rich table), JSON, and HTML reports.

---

📦 Requirements

· Python 3.7+
· Required packages (install via pip):
  · requests
  · packaging (optional, for version comparisons)

If requests is not installed, the scanner falls back to urllib for basic HTTP requests, but online CVE lookups and the crawler will be disabled.

---

🔧 Installation

```bash
git clone https://github.com/digital-playground/Vuln
cd vuln
pip install requests packaging
```

Optionally, set API keys and tokens as environment variables for higher rate limits and additional features:

```bash
export NVD_API_KEY="your-nvd-api-key"
export GITHUB_TOKEN="your-github-token"
```

---

🖥️ Usage

Run the scanner interactively:

```bash
python vuln.py
```

Then choose option 1 to scan a target. You will be prompted for:

· Target – IP address or hostname.
· Ports – Comma‑separated list (leave blank for default common ports).
· Output JSON filename – Leave blank to skip JSON output, or provide a name (e.g., scan.json).
· Output HTML filename – Leave blank to skip HTML output, or provide a name (e.g., report.html).
    Note: HTML generation requires a JSON file; if you specify HTML without JSON, it will be ignored.

Alternatively, you can modify the script to run non‑interactively by calling scan_target() directly.

---

📊 Understanding the Output

Console Report

· Port‑by‑port summary – Service name, version, banner preview, and the top 10 CVEs sorted by exploitability.
· CVE table – Columns: CVE ID, Severity, CVSS, Exploitability (%), and Evidence (why the score is high, e.g., "Exploit‑DB").
· Additional Findings – Lists all non‑CVE issues discovered (interesting files, directory listings, XSS, etc.) with risk level.

JSON Report

A structured file containing:

```json
{
  "meta": { "target": "...", "ip": "...", "time": "...", "os_guess": "...", "os_confidence": 50 },
  "services": [ { "port": 80, "service": "apache", "version": "", "banner": "...", "cves": [...], "findings": [...] } ],
  "findings": [ ... ]
}
```

HTML Report

A human‑readable web page summarising the scan, including all services, CVEs, and additional findings.

---

🧠 How the Web Crawler Works

1. For each web service (ports 80, 443, 8080, 8443, etc.), the crawler starts at the root (/).
2. It fetches the page, extracts all same‑domain links using regex, and adds them to a queue.
3. Forms are extracted from each page (<form> tags) and stored for later testing.
4. The crawler continues until the queue is empty or the maximum page limit (CRAWL_MAX_PAGES, default 50) is reached.
5. After crawling, each form is tested with simple payloads for XSS, SQLi, and path traversal.

---

⚙️ Configuration Options

You can tweak the following constants at the top of the script:

Constant Description
THREAD_POOL_SIZE Number of concurrent threads for port scanning (default 80).
SOCKET_TIMEOUT Socket timeout in seconds (default 3).
RATE_LIMIT Delay between NVD API calls when no API key is used (default 6 seconds).
CIRCL_DELAY Delay between CIRCL API calls (default 0.5 seconds).
CRAWL_MAX_PAGES Maximum number of pages to crawl per web service (default 50).
CRAWL_DELAY Delay between HTTP requests during crawling (default 0.1 seconds).
WEB_TEST_TIMEOUT Timeout for each vulnerability test request (default 8 seconds).
COMMON_PORTS Default list of ports to scan.
PROBES Custom probe strings for specific ports.
WEB_INTERESTING_PATHS Paths to check for interesting files.
WEB_LISTING_DIRS Directories to test for directory listing.

---

🔑 API Keys & Tokens

· NVD API Key – Obtain a free key from NVD. It increases the rate limit from 5 requests per 30 seconds to 50 requests per 30 seconds.
· GitHub Token – Generate a token here. Used to search for public PoC repositories. No special scopes are required.

Set them as environment variables:

```bash
export NVD_API_KEY="your-key"
export GITHUB_TOKEN="your-token"
```

---

⚠️ Known Limitations

· Crawler scope – Only follows links within the same domain; external redirects stop the crawl.
· Form testing – Only simple payloads are used; no blind SQLi, time‑based, or DOM‑based XSS detection.
· CIRCL API reliability – Occasionally fails due to DNS or connection issues; consider adding a fallback.
· Duplicate findings – Basic file/directory checks may appear twice (once from check_web_interesting and once from the crawler). This is a cosmetic issue.
· No JavaScript execution – Crawler does not execute JavaScript, so single‑page apps (SPAs) may not be fully explored.

---

🗺️ Future Improvements

· Add more vulnerability tests (command injection, open redirect, CSRF).
· Implement CMS fingerprinting (WordPress, Drupal, Joomla) with version‑specific CVE lookup.
· Integrate SSL/TLS analysis (weak ciphers, Heartbleed, etc.).
· Provide a command‑line interface (CLI) with arguments for non‑interactive use.
· Add support for authenticated scans (basic auth, cookies).
· Improve duplicate detection in findings.

---

📄 License

This project is released under the MIT License. See LICENSE file for details.

---

🙏 Acknowledgements

· NVD for CVE data.
· CIRCL for the enriched CVE API.
· CISA for the KEV catalog.
· Exploit‑DB for the exploits database.
· Metasploit for the module metadata.