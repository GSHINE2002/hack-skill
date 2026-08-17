#!/usr/bin/env python3
"""
Hack Scan — 统一安全扫描脚本。

Usage:
  python hack_scan.py <URL> [--output report.md] [--spider-only] [--no-active]

Examples:
  python hack_scan.py https://example.com
  python hack_scan.py https://example.com --output report.md
  python hack_scan.py https://example.com --spider-only   # 仅爬取，不主动扫描
  python hack_scan.py https://example.com --no-active      # 被动扫描 only
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from collections import Counter
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

# Ensure we can import zap_manager from the same directory
_SCRIPT_DIR = Path(__file__).parent
sys.path.insert(0, str(_SCRIPT_DIR))

try:
    from zap_manager import ensure_zap, ZAP_API_KEY, ZAP_BASE_URL
except ImportError as e:
    print(f"[!] Cannot import zap_manager: {e}", file=sys.stderr)
    print(f"    Make sure zap_manager.py is in the same directory: {_SCRIPT_DIR}", file=sys.stderr)
    sys.exit(1)

try:
    from zapv2 import ZAPv2
except ImportError:
    print("[!] zapv2 not installed. Run: pip install python-owasp-zap-v2.4", file=sys.stderr)
    sys.exit(1)

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    print("[!] playwright not installed. Run: pip install playwright && playwright install chromium", file=sys.stderr)
    sys.exit(1)


# ─── Scan Functions ──────────────────────────────────────────────────────────

def normalize_url(url: str) -> str:
    """确保 URL 有协议前缀。"""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


def spider_scan(zap: ZAPv2, target: str, max_depth: int = 5) -> list[str]:
    """运行 ZAP Spider 爬取目标站点所有 URL。"""
    print(f"\n{'='*60}")
    print(f"  SPIDER: {target}")
    print(f"{'='*60}")

    # Access the target first
    print("[*] Accessing target...")
    zap.urlopen(target)
    time.sleep(2)

    # Start spider
    print("[*] Starting spider scan...")
    scan_id = zap.spider.scan(target, recurse="true")
    if not scan_id or scan_id == "url_not_found":
        print(f"[!] Spider failed to start: {scan_id}")
        return []

    print(f"[*] Spider scan ID: {scan_id}")

    # Wait for completion
    while int(zap.spider.status(scan_id)) < 100:
        status = zap.spider.status(scan_id)
        print(f"\r[*] Spider progress: {status}%", end="", flush=True)
        time.sleep(3)

    print("\n[+] Spider complete!")

    # Get results
    results = zap.spider.results(scan_id)
    print(f"[+] Found {len(results)} URLs")

    return results


def active_scan(zap: ZAPv2, target: str) -> str:
    """运行 ZAP Active Scan（SQL注入、XSS、CSRF等）。"""
    print(f"\n{'='*60}")
    print(f"  ACTIVE SCAN: {target}")
    print(f"{'='*60}")

    print("[*] Starting active scan...")
    scan_id = zap.ascan.scan(target, recurse="true", inscopeonly="false")
    if not scan_id or scan_id == "url_not_found":
        print(f"[!] Active scan failed to start: {scan_id}")
        return ""

    print(f"[*] Active scan ID: {scan_id}")

    # Wait for completion
    while int(zap.ascan.status(scan_id)) < 100:
        status = zap.ascan.status(scan_id)
        print(f"\r[*] Active scan progress: {status}%", end="", flush=True)
        time.sleep(5)

    print("\n[+] Active scan complete!")
    return scan_id


def passive_scan_wait(zap: ZAPv2, target: str, wait: int = 30):
    """等待被动扫描完成（被动扫描在所有流量经过时自动运行）。"""
    print(f"\n{'='*60}")
    print(f"  PASSIVE SCAN: waiting {wait}s for passive rules to process")
    print(f"{'='*60}")

    # Record the number of records before
    try:
        before = zap.core.messages_count()
    except Exception:
        before = 0

    print(f"[*] Messages before: {before}")
    print(f"[*] Waiting {wait}s for passive scanner...")
    time.sleep(wait)

    try:
        after = zap.core.messages_count()
        print(f"[*] Messages after: {after}")
    except Exception:
        pass


def collect_alerts(zap: ZAPv2, baseurl: str = "") -> list[dict]:
    """收集所有告警。"""
    alerts = zap.core.alerts(baseurl=baseurl)

    # Deduplicate by (alert, url, param)
    seen = set()
    unique = []
    for a in alerts:
        key = (a.get("alert", ""), a.get("url", ""), a.get("param", ""))
        if key not in seen:
            seen.add(key)
            unique.append(a)

    return unique


# ─── Reporting ───────────────────────────────────────────────────────────────

def generate_report(target: str, spider_urls: list[str], alerts: list[dict],
                    output: str = None) -> str:
    """生成 Markdown 格式的安全报告。"""
    risk_order = {"High": 0, "Medium": 1, "Low": 2, "Informational": 3}
    sorted_alerts = sorted(alerts, key=lambda a: risk_order.get(a.get("risk", ""), 99))

    risks = Counter(a.get("risk", "Unknown") for a in alerts)

    lines = [
        f"# Security Scan Report",
        f"",
        f"**Target:** {target}",
        f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"**Tool:** OWASP ZAP via hack_scan.py",
        f"",
        f"## Summary",
        f"",
        f"| Risk Level | Count |",
        f"|------------|-------|",
    ]

    for risk in ["High", "Medium", "Low", "Informational"]:
        count = risks.get(risk, 0)
        if count > 0:
            emoji = {"High": "🔴", "Medium": "🟠", "Low": "🟡", "Informational": "🔵"}[risk]
            lines.append(f"| {emoji} {risk} | {count} |")

    lines.append(f"| **Total** | **{len(alerts)}** |")
    lines.append("")

    lines.append(f"## Discovered URLs ({len(spider_urls)})")
    lines.append("")
    for url in spider_urls[:50]:  # Show first 50
        lines.append(f"- {url}")
    if len(spider_urls) > 50:
        lines.append(f"- ... and {len(spider_urls) - 50} more")
    lines.append("")

    if alerts:
        lines.append("## Vulnerabilities")
        lines.append("")

        current_risk = None
        for alert in sorted_alerts:
            risk = alert.get("risk", "Unknown")
            if risk != current_risk:
                current_risk = risk
                emoji = {"High": "🔴", "Medium": "🟠", "Low": "🟡",
                         "Informational": "🔵"}.get(risk, "⚪")
                lines.append(f"### {emoji} {risk}")
                lines.append("")

            lines.append(f"#### {alert.get('alert', 'Unknown')}")
            lines.append(f"")
            lines.append(f"- **URL:** `{alert.get('url', 'N/A')}`")
            if alert.get("param"):
                lines.append(f"- **Parameter:** `{alert['param']}`")
            lines.append(f"- **Confidence:** {alert.get('confidence', 'N/A')}")
            if alert.get("description"):
                lines.append(f"- **Description:** {alert['description'][:300]}")
            if alert.get("solution"):
                lines.append(f"- **Solution:** {alert['solution'][:300]}")
            if alert.get("cweid") and alert.get("cweid") != "-1":
                lines.append(f"- **CWE ID:** {alert['cweid']}")
            lines.append("")

    else:
        lines.append("## No vulnerabilities found")
        lines.append("")
        lines.append("No alerts were reported. This could mean:")
        lines.append("- The target is relatively secure against tested vulnerabilities")
        lines.append("- The scan was too shallow (try increasing spider depth)")
        lines.append("- ZAP scan rules are not loaded properly (run: python zap_manager.py status)")
        lines.append("")

    report = "\n".join(lines)

    if output:
        out_path = Path(output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(report, encoding="utf-8")
        print(f"\n[+] Report saved to: {out_path.resolve()}")
    else:
        print("\n" + "=" * 60)
        print(report)

    return report


# ─── Quick Recon (no ZAP needed) ─────────────────────────────────────────────

def quick_recon(target: str):
    """不依赖 ZAP 的快速侦察：HTTP 头、技术栈、常见路径。通过 CDP 浏览器发送请求。"""
    print(f"\n{'='*60}")
    print(f"  QUICK RECON: {target}")
    print(f"{'='*60}")

    try:
        from cdp_launch import connect_playwright_cdp
    except ImportError:
        print("[!] cdp_launch not available, falling back to requests")
        _quick_recon_requests(target)
        return

    try:
        browser, pw = connect_playwright_cdp(port=9222, stealth=True)
        ctx = browser.contexts[0]

        resp = ctx.request.get(target, timeout=30000,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})
        print(f"\n[*] Status: {resp.status}")
        print(f"[*] Server: {resp.headers.get('server', 'N/A')}")
        print(f"[*] X-Powered-By: {resp.headers.get('x-powered-by', 'N/A')}")

        body = resp.text()

        # Check for WordPress
        if "wp-content" in body or "wp-json" in body:
            print("[+] WordPress detected!")

            wp_paths = [
                "/readme.html", "/wp-json/wp/v2/users/",
                "/xmlrpc.php", "/wp-admin/",
                "/wp-content/plugins/", "/wp-content/uploads/",
            ]
            print("\n[*] Checking WordPress paths...")
            for path in wp_paths:
                try:
                    r = ctx.request.get(target + path, timeout=30000)
                    status_emoji = "✅" if r.status == 200 else "❌" if r.status == 404 else "⚠️"
                    print(f"    {status_emoji} {path} → {r.status}")
                except Exception:
                    print(f"    ❌ {path} → ERROR")
    except Exception as e:
        print(f"[!] Quick recon via CDP failed: {e}")
        print("[!] Falling back to requests...")
        _quick_recon_requests(target)


def _quick_recon_requests(target: str):
    """Fallback recon using requests (only if CDP is unavailable)."""
    import requests
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }
    try:
        resp = requests.get(target, headers=headers, timeout=15, verify=False,
                           allow_redirects=True)
        print(f"\n[*] Status: {resp.status_code}")
        print(f"[*] Final URL: {resp.url}")
        print(f"[*] Server: {resp.headers.get('Server', 'N/A')}")
        print(f"[*] X-Powered-By: {resp.headers.get('X-Powered-By', 'N/A')}")

        if "wp-content" in resp.text or "wp-json" in resp.text:
            print("[+] WordPress detected!")
            wp_paths = [
                "/readme.html", "/wp-json/wp/v2/users/",
                "/xmlrpc.php", "/wp-admin/",
                "/wp-content/plugins/", "/wp-content/uploads/",
            ]
            print("\n[*] Checking WordPress paths...")
            for path in wp_paths:
                try:
                    r = requests.get(target + path, headers=headers,
                                   timeout=10, verify=False, allow_redirects=False)
                    status_emoji = "✅" if r.status_code == 200 else "❌" if r.status_code == 404 else "⚠️"
                    print(f"    {status_emoji} {path} → {r.status_code}")
                except Exception:
                    print(f"    ❌ {path} → ERROR")
    except Exception as e:
        print(f"[!] Quick recon failed: {e}")


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Hack Scan — Unified security scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python hack_scan.py https://example.com
  python hack_scan.py https://example.com --output report.md
  python hack_scan.py https://example.com --spider-only
  python hack_scan.py https://example.com --recon-only
        """
    )
    parser.add_argument("url", help="Target URL to scan")
    parser.add_argument("--output", "-o", help="Output report file (Markdown)")
    parser.add_argument("--spider-only", action="store_true",
                       help="Only run spider, no active scan")
    parser.add_argument("--no-active", action="store_true",
                       help="Skip active scan (passive only)")
    parser.add_argument("--recon-only", action="store_true",
                       help="Only do quick recon (no ZAP needed)")
    parser.add_argument("--passive-wait", type=int, default=30,
                       help="Seconds to wait for passive scan (default: 30)")
    parser.add_argument("--spider-depth", type=int, default=5,
                        help="Spider max depth (default: 5)")

    from auth_check import add_auth_args, check_auth
    add_auth_args(parser)

    args = parser.parse_args()

    auth_result = check_auth(args, args.url)
    if not auth_result.authorized:
        print(f"\n[ERROR] {auth_result.fail()}")
        sys.exit(1)

    target = normalize_url(args.url)
    print(f"[*] Target: {target}")

    # Quick recon (always runs, doesn't need ZAP)
    quick_recon(target)

    if args.recon_only:
        return

    # Ensure ZAP is running
    print(f"\n{'='*60}")
    print("  ZAP SETUP")
    print(f"{'='*60}")
    zap = ensure_zap()

    # Spider
    spider_urls = spider_scan(zap, target, max_depth=args.spider_depth)

    # Passive scan wait
    if args.spider_only or args.no_active:
        passive_scan_wait(zap, target, wait=args.passive_wait)

    # Active scan
    if not args.spider_only and not args.no_active:
        active_scan(zap, target)
        passive_scan_wait(zap, target, wait=15)

    # Collect alerts
    print(f"\n{'='*60}")
    print("  COLLECTING RESULTS")
    print(f"{'='*60}")

    parsed = urlparse(target)
    baseurl = f"{parsed.scheme}://{parsed.netloc}"
    alerts = collect_alerts(zap, baseurl=baseurl)

    print(f"[+] Total alerts: {len(alerts)}")
    risks = Counter(a.get("risk", "Unknown") for a in alerts)
    for risk in ["High", "Medium", "Low", "Informational"]:
        if risks.get(risk, 0) > 0:
            print(f"    {risk}: {risks[risk]}")

    # Generate report
    generate_report(target, spider_urls, alerts, output=args.output)


if __name__ == "__main__":
    # Suppress SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    main()
