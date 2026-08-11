#!/usr/bin/env python3
"""Deep recon: fetch page source, analyze JS/API endpoints, verify XSS."""
import sys, re, json, urllib.parse
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
sys.stderr.reconfigure(encoding='utf-8', errors='replace')
sys.path.insert(0, r"C:\Users\97912\.codex\skills\hack\scripts")
from cdp_launch import connect_playwright_cdp

TARGET = "https://jgy09.com/"
PORT = 9222

browser, pw = connect_playwright_cdp(port=PORT, stealth=True)
ctx = browser.contexts[0]

# 1. Fetch homepage with full rendering
page = ctx.new_page()
print("[*] Loading page with full render...")
page.goto(TARGET, timeout=30000, wait_until="networkidle")
html = page.content()
print(f"[*] Page length: {len(html)} chars")

# Title
title = page.title()
print(f"[*] Title: {title}")

# 2. Extract all links
links = re.findall(r'href=["\']([^"\']+)["\']', html, re.I)
internal_links = set()
external_links = set()
for link in links:
    if link.startswith("http"):
        external_links.add(link)
    elif link.startswith("/"):
        internal_links.add("https://jgy09.com" + link)
    elif link.startswith("?"):
        internal_links.add("https://jgy09.com/" + link)
    else:
        internal_links.add("https://jgy09.com/" + link)

print(f"\n[*] Internal links ({len(internal_links)}):")
for l in sorted(internal_links)[:30]:
    print(f"  {l}")
print(f"\n[*] External links ({len(external_links)}):")
for l in sorted(external_links)[:20]:
    print(f"  {l}")

# 3. Extract JS files
js_files = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', html, re.I)
print(f"\n[*] JavaScript files ({len(js_files)}):")
for js in js_files:
    print(f"  {js}")

# 4. Extract API calls from inline JS
api_patterns = re.findall(r'(?:fetch|axios|ajax|XMLHttpRequest|\.get|\.post)\(["\']([^"\']+)["\']', html, re.I)
print(f"\n[*] API endpoints in JS ({len(api_patterns)}):")
for api in api_patterns:
    print(f"  {api}")

# 5. Extract forms
forms = page.query_selector_all("form")
print(f"\n[*] Forms found: {len(forms)}")
for i, form in enumerate(forms):
    action = form.get_attribute("action") or ""
    method = (form.get_attribute("method") or "GET").upper()
    inputs = form.query_selector_all("input, textarea, select")
    print(f"  Form #{i+1}: {method} {action}")
    for inp in inputs:
        name = inp.get_attribute("name") or ""
        ftype = inp.get_attribute("type") or "text"
        val = inp.get_attribute("value") or ""
        print(f"    - {name} (type={ftype}) val={val[:50]}")

# 6. Check meta tags
metas = page.query_selector_all("meta")
print(f"\n[*] Meta tags ({len(metas)}):")
for m in metas:
    name = m.get_attribute("name") or m.get_attribute("property") or ""
    content = m.get_attribute("content") or ""
    if name and content:
        print(f"  {name}: {content[:100]}")

# 7. Check for common frameworks/CMS
generator = page.evaluate("() => document.querySelector('meta[name=\"generator\"]')?.content || ''")
print(f"\n[*] Generator: {generator or 'N/A'}")

tech = page.evaluate("""() => {
    let t = {};
    t.jquery = typeof jQuery !== 'undefined' ? jQuery.fn.jquery : false;
    t.react = typeof __REACT_DEVTOOLS_GLOBAL_HOOK__ !== 'undefined';
    t.vue = typeof __VUE_DEVTOOLS_GLOBAL_HOOK__ !== 'undefined' || typeof Vue !== 'undefined';
    t.angular = typeof ng !== 'undefined';
    t.bootstrap = document.querySelector('[class*="bootstrap"]') !== null;
    t.tailwind = document.querySelector('[class*="tailwind"]') !== null;
    return t;
}""")
print(f"[*] Tech: {tech}")

# 8. Verify XSS - check if parameters are actually reflected
print("\n[*] XSS Verification - testing actual reflection...")
test_url = TARGET + "?q=XSS_TEST_MARKER_12345"
resp = ctx.request.get(test_url, timeout=15000)
body = resp.text() if resp else ""
if "XSS_TEST_MARKER_12345" in body:
    print("  [!] Parameter 'q' IS reflected in response!")
    # Find where it's reflected
    idx = body.index("XSS_TEST_MARKER_12345")
    context = body[max(0,idx-100):idx+100]
    print(f"  Context: ...{context}...")
else:
    print("  [-] Parameter 'q' NOT reflected (false positive in scan)")

# Try with the login page
login_resp = ctx.request.get("https://jgy09.com/login/", timeout=15000)
if login_resp:
    login_body = login_resp.text()
    print(f"\n[*] /login/ page: status={login_resp.status}, length={len(login_body)}")
    login_title = re.search(r'<title>(.*?)</title>', login_body, re.I|re.S)
    if login_title:
        print(f"  Title: {login_title.group(1).strip()}")
    # Check for forms in login page
    login_forms = re.findall(r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>', login_body, re.I)
    print(f"  Forms: {login_forms}")
    # Check for known CMS/framework signatures
    if "wp-login" in login_body.lower():
        print("  [WordPress login detected]")
    if "csrf" in login_body.lower():
        print("  [CSRF token found]")
    if "laravel" in login_body.lower():
        print("  [Laravel framework detected]")
    if "thinkphp" in login_body.lower():
        print("  [ThinkPHP framework detected]")

# 9. Check common Chinese CMS/framework paths
cn_paths = [
    "/index.php", "/admin.php", "/login.php", "/api.php", "/install.php",
    "/public/", "/static/", "/runtime/", "/app/", "/config/",
    "/application/", "/thinkphp/", "/laravel/",
    "/admin/index", "/admin/login", "/admin/admin",
    "/member/", "/user/", "/users/", "/account/",
    "/upload/", "/uploads/", "/files/", "/data/",
    "/template/", "/templates/", "/views/",
    "/vendor/phpunit/", "/vendor/",
    "/.well-known/", "/.well-known/security.txt",
    "/favicon.ico", "/logo.png",
    "/index.php?s=/index/index", "/index.php?s=/admin",
    "/api/v1/", "/api/v2/", "/api/login", "/api/user",
    "/captcha", "/verify", "/code",
    "/sitemap.xml", "/robots.txt",
]
print("\n[*] Probing CN-CMS paths...")
for path in cn_paths:
    url = "https://jgy09.com" + path
    resp = ctx.request.get(url, timeout=10000, max_redirects=0)
    if resp:
        status = resp.status
        body_len = len(resp.text())
        location = resp.headers.get("location", "")
        if status in [200, 301, 302, 401, 403]:
            extra = f" -> {location}" if location else ""
            print(f"  [{status}] {path} ({body_len} bytes){extra}")
            if status == 200 and body_len > 0:
                body = resp.text()
                # Check for interesting content
                if "password" in body.lower() or "admin" in body.lower():
                    if body_len < 5000:
                        print(f"    [!] Interesting content (password/admin keyword): {body[:200]}")

# 10. Check response headers in detail
print("\n[*] Full response headers for homepage:")
resp = ctx.request.get(TARGET, timeout=15000)
if resp:
    for k, v in resp.headers.items():
        print(f"  {k}: {v}")

# 11. Check for cookie security
print("\n[*] Cookies:")
cookies = ctx.cookies()
for c in cookies:
    secure = "Secure" if c.get("secure") else "NOT-SECURE"
    httponly = "HttpOnly" if c.get("httpOnly") else "NO-HttpOnly"
    samesite = c.get("sameSite", "None")
    print(f"  {c['name']}={c['value'][:30]}... [{secure}] [{httponly}] [SameSite={samesite}]")

page.close()
print("\n[*] Deep recon complete.")
