#!/usr/bin/env python3
"""
ZAP Lifecycle Manager — 自动启动、验证、修复 ZAP 实例。

解决三个核心痛点：
  1. ZAP.exe 启动器坏了 → 自动用 java.exe 直接启动
  2. 插件损坏导致扫描规则不加载 → 自动检测并修复
  3. 路径硬编码 → 全部自动探测

Usage:
  from zap_manager import ensure_zap
  zap = ensure_zap()  # 返回就绪的 ZAPv2 实例，失败则抛异常

  # CLI 模式:
  python zap_manager.py start    # 启动并验证
  python zap_manager.py status   # 检查 ZAP 是否在运行
  python zap_manager.py stop     # 停止 ZAP
  python zap_manager.py fix      # 修复插件损坏
"""

from __future__ import annotations

import glob
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

try:
    import requests
except ImportError:
    print("[!] requests not installed. Run: pip install requests", file=sys.stderr)
    raise

# ─── Configuration ───────────────────────────────────────────────────────────

ZAP_HOST = "127.0.0.1"
ZAP_PORT = 8080
ZAP_API_KEY = "123456789"
ZAP_BASE_URL = f"http://{ZAP_HOST}:{ZAP_PORT}"

# Minimum scan rule counts for a healthy ZAP instance
MIN_ASCAN_RULES = 10
MIN_PSCAN_RULES = 10
HEALTHY_ASCAN_RULES = 50  # expected when plugins load correctly
HEALTHY_PSCAN_RULES = 60

# Timeouts
STARTUP_WAIT = 45  # seconds to wait for ZAP to fully start
POLL_INTERVAL = 2  # seconds between polls
PLUGIN_REDOWNLOAD_WAIT = 60  # seconds to wait after deleting plugins


# ─── Path Auto-Detection ─────────────────────────────────────────────────────

def find_java() -> str:
    """自动探测 java.exe 路径。优先 JAVA_HOME，然后扫描常见位置。"""
    # 1. JAVA_HOME
    java_home = os.environ.get("JAVA_HOME")
    if java_home:
        exe = Path(java_home) / "bin" / "java.exe"
        if exe.exists():
            return str(exe)

    # 2. Scan common install locations
    search_paths = [
        r"C:\Program Files\Java\*\bin\java.exe",
        r"C:\Program Files\Eclipse Adoptium\*\bin\java.exe",
        r"C:\Program Files\Microsoft\jdk-*\bin\java.exe",
        r"C:\Program Files\Zulu\*\bin\java.exe",
        r"/usr/bin/java",
        r"/usr/lib/jvm/*/bin/java",
    ]
    for pattern in search_paths:
        matches = glob.glob(pattern)
        if matches:
            # Prefer JDK 17+ if multiple found
            matches.sort(reverse=True)
            return matches[0]

    raise FileNotFoundError(
        "Java not found. Set JAVA_HOME or install JDK 17+.\n"
        "Searched: JAVA_HOME, C:\\Program Files\\Java\\*, etc."
    )


def find_zap_jar() -> str:
    """自动探测 ZAP jar 文件路径。"""
    search_paths = [
        r"C:\Program Files\ZAP\*\zap-*.jar",
        r"C:\Program Files\ZAP\zap-*.jar",
        r"C:\Program Files (x86)\ZAP\*\zap--.jar",
        os.path.expanduser("~/ZAP/zap-*.jar"),
        "/usr/share/zap/zap-*.jar",
    ]
    for pattern in search_paths:
        matches = glob.glob(pattern)
        if matches:
            # Pick the newest version
            matches.sort(reverse=True)
            return matches[0]

    raise FileNotFoundError(
        "ZAP jar not found. Install OWASP ZAP or set path manually.\n"
        "Searched: C:\\Program Files\\ZAP\\*, ~/ZAP/*, etc."
    )


def get_zap_working_dir() -> str:
    """获取 ZAP jar 所在目录，用作 WorkingDirectory。"""
    jar_path = find_zap_jar()
    return str(Path(jar_path).parent)


def get_plugin_dir() -> Path:
    """获取 ZAP 插件目录。"""
    # ZAP stores plugins in ~/ZAP/plugin/ by default
    home = Path(os.environ.get("USERPROFILE", os.path.expanduser("~")))
    plugin_dir = home / "ZAP" / "plugin"
    if not plugin_dir.exists():
        # Fallback: some installations use .ZAP/plugin
        plugin_dir = home / ".ZAP" / "plugin"
    return plugin_dir


# ─── ZAP Process Management ──────────────────────────────────────────────────

def is_zap_running() -> bool:
    """检查 ZAP 是否在运行并响应 API。"""
    try:
        resp = requests.get(
            f"{ZAP_BASE_URL}/JSON/core/view/version/",
            params={"apikey": ZAP_API_KEY},
            timeout=5,
        )
        return resp.status_code == 200
    except (requests.ConnectionError, requests.Timeout):
        return False


def find_zap_pid() -> Optional[int]:
    """查找正在运行的 ZAP 进程 PID。"""
    try:
        # On Windows
        if sys.platform == "win32":
            result = subprocess.run(
                ["tasklist", "/FI", "IMAGENAME eq java.exe", "/FO", "CSV"],
                capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.strip().split("\n")[1:]:
                if "java.exe" in line:
                    parts = line.strip('"').split('","')
                    if len(parts) >= 2:
                        return int(parts[1])
        else:
            result = subprocess.run(
                ["pgrep", "-f", "zap-.*\.jar"],
                capture_output=True, text=True, timeout=10
            )
            if result.stdout.strip():
                return int(result.stdout.strip().split("\n")[0])
    except Exception:
        pass
    return None


def kill_zap() -> bool:
    """停止 ZAP 进程。"""
    pid = find_zap_pid()
    if not pid:
        return True

    try:
        if sys.platform == "win32":
            subprocess.run(["taskkill", "/PID", str(pid), "/F"],
                         capture_output=True, timeout=10)
        else:
            subprocess.run(["kill", "-9", str(pid)],
                         capture_output=True, timeout=10)
        time.sleep(3)
        return not is_zap_running()
    except Exception as e:
        print(f"[!] Failed to kill ZAP (PID {pid}): {e}", file=sys.stderr)
        return False


def start_zap_daemon() -> subprocess.Popen:
    """用 java.exe 直接启动 ZAP daemon（绕过 ZAP.exe 的 install4j 问题）。"""
    java_exe = find_java()
    zap_jar = find_zap_jar()
    working_dir = get_zap_working_dir()

    cmd = [
        java_exe, "-Xmx855m", "-jar", zap_jar,
        "-daemon",
        "-host", ZAP_HOST,
        "-port", str(ZAP_PORT),
        "-config", f"api.key={ZAP_API_KEY}",
        "-config", "api.addrs.addr.name=.*",
        "-config", "api.addrs.addr.regex=true",
    ]

    print(f"[*] Starting ZAP daemon...")
    print(f"    Java:   {java_exe}")
    print(f"    JAR:    {zap_jar}")
    print(f"    WorkDir: {working_dir}")

    # Start as background process
    proc = subprocess.Popen(
        cmd,
        cwd=working_dir,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        # On Windows, create a new process group so it survives script exit
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0,
    )
    return proc


def wait_for_zap(timeout: int = STARTUP_WAIT) -> bool:
    """等待 ZAP API 就绪。"""
    print(f"[*] Waiting for ZAP API (up to {timeout}s)...", end="", flush=True)
    deadline = time.time() + timeout
    while time.time() < deadline:
        if is_zap_running():
            print(" OK")
            return True
        print(".", end="", flush=True)
        time.sleep(POLL_INTERVAL)
    print(" TIMEOUT")
    return False


# ─── Scan Rule Verification ──────────────────────────────────────────────────

def get_scan_rule_counts() -> tuple[int, int]:
    """返回 (active_scanners_count, passive_scanners_count)。"""
    try:
        ascan_resp = requests.get(
            f"{ZAP_BASE_URL}/JSON/ascan/view/scanners/",
            params={"apikey": ZAP_API_KEY},
            timeout=10,
        ).json()
        pscan_resp = requests.get(
            f"{ZAP_BASE_URL}/JSON/pscan/view/scanners/",
            params={"apikey": ZAP_API_KEY},
            timeout=10,
        ).json()
        ascan_count = len(ascan_resp.get("scanners", []))
        pscan_count = len(pscan_resp.get("scanners", []))
        return ascan_count, pscan_count
    except Exception as e:
        print(f"[!] Failed to get scan rule counts: {e}", file=sys.stderr)
        return 0, 0


def verify_scan_rules() -> bool:
    """验证扫描规则是否充分加载。"""
    ascan, pscan = get_scan_rule_counts()
    print(f"[*] Active scanners:  {ascan}  (expect {HEALTHY_ASCAN_RULES}+)")
    print(f"[*] Passive scanners: {pscan}  (expect {HEALTHY_PSCAN_RULES}+)")

    if ascan >= MIN_ASCAN_RULES and pscan >= MIN_PSCAN_RULES:
        if ascan < HEALTHY_ASCAN_RULES or pscan < HEALTHY_PSCAN_RULES:
            print("[!] Warning: scan rule count is lower than expected, but above minimum.")
        return True
    return False


# ─── Plugin Corruption Auto-Fix ──────────────────────────────────────────────

def check_plugin_corruption() -> list[str]:
    """检查 ZAP 日志中是否有插件损坏记录。"""
    home = Path(os.environ.get("USERPROFILE", os.path.expanduser("~")))
    log_file = home / "ZAP" / "zap.log"
    corrupted = []
    if log_file.exists():
        try:
            with open(log_file, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    if "Invalid add-on" in line or "Failed to create add-on" in line:
                        corrupted.append(line.strip())
        except Exception:
            pass
    return corrupted[-10:]  # last 10 matches


def fix_corrupted_plugins() -> bool:
    """删除损坏的 .zap 插件文件，让 ZAP 重新下载。"""
    plugin_dir = get_plugin_dir()
    if not plugin_dir.exists():
        print(f"[!] Plugin directory not found: {plugin_dir}")
        return False

    zap_files = list(plugin_dir.glob("*.zap"))
    if not zap_files:
        print(f"[*] No .zap files found in {plugin_dir}")
        return True

    print(f"[*] Deleting {len(zap_files)} corrupted plugin file(s)...")
    for f in zap_files:
        print(f"    - {f.name}")
        try:
            f.unlink()
        except Exception as e:
            print(f"    [!] Failed to delete {f.name}: {e}")

    return True


def full_auto_fix() -> bool:
    """完整的自动修复流程：停止 ZAP → 删插件 → 重启 → 等待重下载 → 验证。"""
    print("\n" + "=" * 60)
    print("  AUTO-FIX: Plugin corruption detected")
    print("=" * 60)

    # Step 1: Stop ZAP
    print("\n[1/5] Stopping ZAP...")
    kill_zap()

    # Step 2: Check corruption logs
    print("\n[2/5] Checking corruption logs...")
    corrupted = check_plugin_corruption()
    if corrupted:
        for line in corrupted:
            print(f"    {line[:120]}")
    else:
        print("    No explicit corruption logs found, but rule count is too low.")

    # Step 3: Delete plugins
    print("\n[3/5] Deleting corrupted plugins...")
    fix_corrupted_plugins()

    # Step 4: Restart ZAP
    print("\n[4/5] Restarting ZAP (plugins will re-download)...")
    start_zap_daemon()

    # Step 5: Wait longer for plugin re-download
    print(f"\n[5/5] Waiting {PLUGIN_REDOWNLOAD_WAIT}s for plugin re-download...")
    if not wait_for_zap(PLUGIN_REDOWNLOAD_WAIT):
        print("[!] ZAP did not start after plugin fix.")
        return False

    # Verify
    print("\n[*] Re-checking scan rules...")
    if verify_scan_rules():
        print("\n[+] AUTO-FIX SUCCESSFUL! ZAP is ready.")
        return True
    else:
        print("\n[!] AUTO-FIX FAILED. Manual intervention may be needed.")
        print("    Try: Start ZAP in GUI mode, let it download plugins, then restart.")
        return False


# ─── Main Entry Point ────────────────────────────────────────────────────────

def ensure_zap():
    """
    确保 ZAP 就绪：如果已在运行则直接用，否则启动并验证。
    如果插件损坏，自动修复。

    Returns:
        ZAPv2 实例（已就绪）
    Raises:
        RuntimeError: 如果 ZAP 无法启动或修复失败
    """
    from zapv2 import ZAPv2

    # Case 1: ZAP already running
    if is_zap_running():
        print("[*] ZAP is already running. Verifying scan rules...")
        if verify_scan_rules():
            print("[+] ZAP is healthy and ready.")
            return ZAPv2(apikey=ZAP_API_KEY, proxies={"http": ZAP_BASE_URL, "https": ZAP_BASE_URL})
        else:
            print("[!] ZAP is running but scan rules are broken. Running auto-fix...")
            if full_auto_fix():
                return ZAPv2(apikey=ZAP_API_KEY, proxies={"http": ZAP_BASE_URL, "https": ZAP_BASE_URL})
            raise RuntimeError("ZAP scan rules broken and auto-fix failed.")

    # Case 2: ZAP not running — start it
    print("[*] ZAP is not running. Starting...")
    start_zap_daemon()

    if not wait_for_zap():
        raise RuntimeError(f"ZAP failed to start within {STARTUP_WAIT}s.")

    # Get version for confirmation
    try:
        version = requests.get(
            f"{ZAP_BASE_URL}/JSON/core/view/version/",
            params={"apikey": ZAP_API_KEY},
            timeout=5,
        ).json()
        print(f"[*] ZAP version: {version.get('version', 'unknown')}")
    except Exception:
        pass

    # Verify scan rules
    if verify_scan_rules():
        print("[+] ZAP is healthy and ready.")
    else:
        print("[!] Scan rules not loaded properly. Running auto-fix...")
        if not full_auto_fix():
            raise RuntimeError("ZAP started but scan rules are broken and auto-fix failed.")

    return ZAPv2(apikey=ZAP_API_KEY, proxies={"http": ZAP_BASE_URL, "https": ZAP_BASE_URL})


# ─── CLI ─────────────────────────────────────────────────────────────────────

def cli():
    import argparse
    parser = argparse.ArgumentParser(description="ZAP Lifecycle Manager")
    parser.add_argument("action", choices=["start", "status", "stop", "fix", "info"],
                       help="Action to perform")
    args = parser.parse_args()

    if args.action == "start":
        zap = ensure_zap()
        print(f"\n[+] ZAP ready at {ZAP_BASE_URL}")

    elif args.action == "status":
        if is_zap_running():
            ascan, pscan = get_scan_rule_counts()
            print(f"[+] ZAP is running at {ZAP_BASE_URL}")
            print(f"    Active scanners:  {ascan}")
            print(f"    Passive scanners: {pscan}")
            if ascan < MIN_ASCAN_RULES:
                print(f"    [!] WARNING: Active scanners below {MIN_ASCAN_RULES}. Run: python zap_manager.py fix")
        else:
            print(f"[-] ZAP is NOT running.")

    elif args.action == "stop":
        if kill_zap():
            print("[+] ZAP stopped.")
        else:
            print("[!] Failed to stop ZAP.")

    elif args.action == "fix":
        if full_auto_fix():
            print("[+] Fix successful.")
        else:
            print("[!] Fix failed.")
            sys.exit(1)

    elif args.action == "info":
        print("=== ZAP Manager — Environment Info ===")
        try:
            print(f"Java:       {find_java()}")
        except FileNotFoundError as e:
            print(f"Java:       NOT FOUND — {e}")
        try:
            print(f"ZAP JAR:    {find_zap_jar()}")
        except FileNotFoundError as e:
            print(f"ZAP JAR:    NOT FOUND — {e}")
        print(f"Plugin dir: {get_plugin_dir()}")
        print(f"API URL:    {ZAP_BASE_URL}")
        print(f"API Key:    {ZAP_API_KEY}")
        print(f"Running:    {'YES' if is_zap_running() else 'NO'}")


if __name__ == "__main__":
    cli()
