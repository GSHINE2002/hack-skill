#!/usr/bin/env python3
"""
CDP Chrome Launcher — 一键启动 Chrome 远程调试实例。

替代原本 25 行不可维护的 PowerShell 单行命令。

Usage:
  python cdp_launch.py                    # 启动 Chrome with CDP
  python cdp_launch.py --port 9222        # 指定端口
  python cdp_launch.py --url https://target.com  # 启动并打开指定 URL
  python cdp_launch.py --proxy localhost:8080     # 通过 ZAP 代理
  python cdp_launch.py --status           # 检查 CDP 是否在运行
"""

from __future__ import annotations

import argparse
import asyncio
import ctypes
import glob
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

try:
    import requests
except ImportError:
    print("[!] requests not installed. Run: pip install requests", file=sys.stderr)
    sys.exit(1)


# ─── Chrome Detection ────────────────────────────────────────────────────────

def find_chrome() -> str:
    """自动探测 Chrome 可执行文件路径。"""
    # 1. Check CHROME_PATH env var
    env_chrome = os.environ.get("CHROME_PATH")
    if env_chrome and Path(env_chrome).exists():
        return env_chrome

    # 2. Common Windows locations
    if sys.platform == "win32":
        win_paths = [
            os.path.expandvars(r"%PROGRAMFILES%\Google\Chrome\Application\chrome.exe"),
            os.path.expandvars(r"%PROGRAMFILES(X86)%\Google\Chrome\Application\chrome.exe"),
            os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
        ]
        for p in win_paths:
            if Path(p).exists():
                return p

        # Also check Edge as fallback
        edge_paths = [
            os.path.expandvars(r"%PROGRAMFILES(X86)%\Microsoft\Edge\Application\msedge.exe"),
            os.path.expandvars(r"%PROGRAMFILES%\Microsoft\Edge\Application\msedge.exe"),
        ]
        for p in edge_paths:
            if Path(p).exists():
                print(f"[*] Chrome not found, using Edge: {p}")
                return p

    # 3. macOS
    elif sys.platform == "darwin":
        mac_path = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
        if Path(mac_path).exists():
            return mac_path

    # 4. Linux
    else:
        for name in ["google-chrome", "google-chrome-stable", "chromium-browser", "chromium"]:
            found = shutil.which(name)
            if found:
                return found

    raise FileNotFoundError(
        "Chrome not found. Set CHROME_PATH env var or install Google Chrome.\n"
        "Searched: PROGRAMFILES, LOCALAPPDATA, /Applications, PATH"
    )


# ─── CDP Launch ──────────────────────────────────────────────────────────────

def build_chrome_args(port: int, user_data_dir: str, url: str = None,
                      proxy: str = None) -> list[str]:
    """构建 Chrome 启动参数。"""
    args = [
        f"--user-data-dir={user_data_dir}",
        f"--remote-debugging-port={port}",
        "--start-maximized",
        "--disable-web-security",
        "--disable-site-isolation-trials",
        "--disable-features=SameSiteByDefaultCookies,CookiesWithoutSameSiteMustBeSecure,PrivacySandboxSettings4,AutomationControlled",
        "--disable-blink-features=AutomationControlled",
        "--allow-running-insecure-content",
        "--ignore-certificate-errors",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-popup-blocking",
        "--disable-extensions",
        "--disable-background-networking",
        "--disable-background-timer-throttling",
        "--disable-backgrounding-occluded-windows",
        "--disable-renderer-backgrounding",
        "--disable-features=IsolateOrigins,site-per-process",
        "--disable-site-isolation",
        "--disable-webgl",
        "--disable-notifications",
        "--disable-geolocation",
        "--disable-media-stream",
        "--disable-speech-api",
        "--disable-device-orientation",
    ]

    if proxy:
        args.append(f"--proxy-server={proxy}")

    if url:
        args.append(url)
    else:
        args.append("about:blank")

    return args


def launch_cdp(port: int = 9222, url: str = None, proxy: str = None,
               user_data_dir: str = None, stealth: bool = True) -> subprocess.Popen:
    """
    启动 Chrome with CDP remote debugging。

    Args:
        port: Remote debugging port (default: 9222)
        url: Initial URL to open
        proxy: Proxy server (e.g. "localhost:8080" for ZAP)
        user_data_dir: Chrome profile directory
        stealth: If True, start stealth daemon to inject anti-detect JS

    Returns:
        subprocess.Popen instance
    """
    chrome_exe = find_chrome()

    if not user_data_dir:
        user_data_dir = str(Path(os.environ.get("LOCALAPPDATA", os.path.expanduser("~"))) / "ChromeDevProfile")

    args = build_chrome_args(port, user_data_dir, url, proxy)

    print(f"[*] Launching Chrome with CDP...")
    print(f"    Binary:     {chrome_exe}")
    print(f"    Port:       {port}")
    print(f"    Profile:    {user_data_dir}")
    if proxy:
        print(f"    Proxy:      {proxy}")
    if url:
        print(f"    URL:        {url}")
    if stealth:
        print(f"    Stealth:    ON (anti-detect JS injection)")

    proc = subprocess.Popen(
        [chrome_exe] + args,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0,
    )

    # Wait for CDP to be ready
    print(f"[*] Waiting for CDP on port {port}...", end="", flush=True)
    for _ in range(15):
        if is_cdp_running(port):
            print(" OK")
            break
        print(".", end="", flush=True)
        time.sleep(1)
    else:
        print(" TIMEOUT")
        print(f"[!] Chrome launched but CDP port {port} not responding.")
        print("    Check if another Chrome instance is using the same profile.")
        return proc

    # Bring Chrome window to foreground (Windows)
    _bring_window_to_foreground()

    # Start stealth daemon if requested
    if stealth:
        try:
            from stealth import StealthDaemon
            daemon = StealthDaemon(port=port)
            daemon.start()
            print(f"[*] Stealth daemon started — anti-detect JS active on all pages")
        except ImportError:
            print(f"[!] Stealth daemon requires 'websockets' package. Run: pip install websockets")
        except Exception as e:
            print(f"[!] Stealth daemon failed to start: {e}")

    return proc


def _bring_window_to_foreground():
    """Bring the most recent Chrome window to the foreground (Windows only)."""
    if sys.platform != "win32":
        return
    try:
        user32 = ctypes.windll.user32
        # Enumerate all windows, find Chrome's main window, bring to front
        # Use FindWindow approach as a quick fallback
        hwnd = user32.FindWindowW(None, "Chrome")
        if hwnd:
            # Restore if minimized, then bring to front
            user32.ShowWindow(hwnd, 9)  # SW_RESTORE
            user32.SetForegroundWindow(hwnd)
            return
        # Fallback: enumerate windows to find chrome.exe
        import subprocess as sp
        result = sp.run(
            ["powershell", "-Command",
             "(Get-Process chrome -ErrorAction SilentlyContinue | "
             "Where-Object { $_.MainWindowHandle -ne 0 } | "
             "Select-Object -First 1).MainWindowHandle"],
            capture_output=True, text=True, timeout=5
        )
        hwnd_str = result.stdout.strip()
        if hwnd_str:
            hwnd = int(hwnd_str)
            user32.ShowWindow(hwnd, 9)
            user32.SetForegroundWindow(hwnd)
    except Exception:
        pass


def is_cdp_running(port: int = 9222) -> bool:
    """检查 CDP 端口是否在响应。"""
    try:
        resp = requests.get(f"http://localhost:{port}/json/version", timeout=3)
        return resp.status_code == 200
    except (requests.ConnectionError, requests.Timeout):
        return False


def get_cdp_info(port: int = 9222) -> dict | None:
    """获取 CDP 连接信息。"""
    try:
        version = requests.get(f"http://localhost:{port}/json/version", timeout=5).json()
        tabs = requests.get(f"http://localhost:{port}/json", timeout=5).json()
        return {
            "browser": version.get("Browser", "unknown"),
            "protocol_version": version.get("Protocol-Version", "unknown"),
            "user_agent": version.get("User-Agent", "unknown"),
            "webSocket_url": version.get("webSocketDebuggerUrl", ""),
            "tabs": [{"title": t.get("title", ""), "url": t.get("url", ""),
                      "ws": t.get("webSocketDebuggerUrl", "")} for t in tabs],
        }
    except Exception as e:
        print(f"[!] Failed to get CDP info: {e}")
        return None


# ─── Playwright Helper ───────────────────────────────────────────────────────

def connect_playwright_cdp(port: int = 9222, stealth: bool = True):
    """
    返回连接到 CDP 的 Playwright browser 实例 (sync API)。

    Args:
        port: CDP remote debugging port
        stealth: If True (default), injects anti-detect JS into all browser contexts

    Usage:
        from cdp_launch import connect_playwright_cdp
        browser, pw = connect_playwright_cdp()  # stealth ON by default
        page = browser.new_page()
        page.goto("https://target.com")
    """
    from playwright.sync_api import sync_playwright

    if not is_cdp_running(port):
        launch_cdp(port=port, stealth=stealth)
        time.sleep(2)

    pw = sync_playwright().start()
    browser = pw.chromium.connect_over_cdp(f"http://localhost:{port}")

    if stealth:
        from stealth import apply_stealth_sync
        for ctx in browser.contexts:
            apply_stealth_sync(ctx)
        print(f"[*] Stealth: anti-detect JS injected into {len(browser.contexts)} context(s)")

    return browser, pw


async def connect_playwright_cdp_async(port: int = 9222, stealth: bool = True):
    """
    返回连接到 CDP 的 Playwright browser 实例 (async API)。

    Use this instead of connect_playwright_cdp() when you need HumanBehavior
    (which requires async/await).

    Args:
        port: CDP remote debugging port
        stealth: If True (default), injects anti-detect JS into all browser contexts

    Usage:
        from cdp_launch import connect_playwright_cdp_async
        browser, pw = await connect_playwright_cdp_async()  # stealth ON by default
        page = await browser.new_page()
        await page.goto("https://target.com")
    """
    from playwright.async_api import async_playwright

    if not is_cdp_running(port):
        launch_cdp(port=port, stealth=stealth)
        await asyncio.sleep(2)

    pw = await async_playwright().start()
    browser = await pw.chromium.connect_over_cdp(f"http://localhost:{port}")

    if stealth:
        from stealth import apply_stealth_async
        for ctx in browser.contexts:
            await apply_stealth_async(ctx)
        print(f"[*] Stealth: anti-detect JS injected into {len(browser.contexts)} context(s)")

    return browser, pw


class PlaywrightCDPBridge:
    """
    Adapter that bridges Playwright's async CDP session to the interface
    expected by HumanBehavior (which was designed for raw WebSocket CDP).

    HumanBehavior needs an object with:
        async .call(method, params, timeout)   → CDP command
        async .evaluate(expression, ...)       → JS evaluation
        async .navigate(url, timeout)          → page navigation

    This bridge maps those to Playwright's CDPSession.send() and Page methods.
    """

    def __init__(self, page, cdp_session):
        self.page = page
        self.cdp_session = cdp_session
        self.ws = None  # compat attribute (HumanBehavior doesn't use it directly)

    async def call(self, method: str, params: dict | None = None,
                   timeout: float = 30) -> dict:
        """Send a raw CDP command via Playwright's CDPSession."""
        return await self.cdp_session.send(method, params or {})

    async def evaluate(self, expression: str, return_by_value: bool = True,
                       await_promise: bool = True, timeout: float = 30) -> dict:
        """Evaluate JS in the page. Returns {'value': result} for compat."""
        result = await self.page.evaluate(expression)
        return {"value": result}

    async def navigate(self, url: str, timeout: float = 30) -> None:
        """Navigate to URL via Playwright."""
        await self.page.goto(url, timeout=timeout * 1000)


async def create_stealth_session(
    port: int = 9222,
    human: bool = False,
    behavior_profile: str = "casual",
):
    """
    One-call convenience: connect to CDP with stealth + optional human behavior.

    Returns:
        (page, browser, pw, human_behavior_or_none)

    Usage:
        from cdp_launch import create_stealth_session

        page, browser, pw, hb = await create_stealth_session(
            port=9222, human=True, behavior_profile="casual"
        )
        await page.goto("https://target.com")

        if hb:
            await hb.read_page(scroll_px=2000)  # human-like reading
            await hb.click(500, 300)            # human-like click
            score = hb.get_score()              # behavioral score
            print(score)
    """
    browser, pw = await connect_playwright_cdp_async(port=port, stealth=True)

    # Get or create a context
    if browser.contexts:
        ctx = browser.contexts[0]
    else:
        ctx = await browser.new_context()

    page = await ctx.new_page()

    # Set up human behavior if requested
    hb = None
    if human:
        from human_behavior import HumanBehavior
        cdp_session = await ctx.new_cdp_session(page)
        # Enable Input domain — required for Input.dispatchMouseEvent / dispatchKeyEvent
        # (HumanBehavior's mouse trajectories and keyboard input depend on this)
        try:
            await cdp_session.send("Input.enable", {})
        except Exception:
            pass
        bridge = PlaywrightCDPBridge(page, cdp_session)
        hb = HumanBehavior(bridge, profile=behavior_profile)
        print(f"[*] Human behavior: profile='{behavior_profile}', ready for interaction")

    return page, browser, pw, hb


# ─── CLI ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="CDP Chrome Launcher — one command to rule them all",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cdp_launch.py                          # 启动 stealth CDP (默认)
  python cdp_launch.py --no-stealth             # 关闭 stealth
  python cdp_launch.py --human                  # stealth + human behavior
  python cdp_launch.py --url https://target.com # 启动并打开 URL
  python cdp_launch.py --proxy localhost:8080   # 通过 ZAP 代理
  python cdp_launch.py --status                 # 检查 CDP 状态
  python cdp_launch.py --info                   # 显示 CDP 连接详情
        """
    )
    parser.add_argument("--port", "-p", type=int, default=9222,
                       help="Remote debugging port (default: 9222)")
    parser.add_argument("--url", "-u", help="Initial URL to open")
    parser.add_argument("--proxy", help="Proxy server (e.g. localhost:8080 for ZAP)")
    parser.add_argument("--profile", help="Chrome user data directory")
    parser.add_argument("--no-stealth", action="store_true",
                       help="Disable stealth mode (by default stealth is ON)")
    parser.add_argument("--human", action="store_true",
                       help="Enable human behavior simulation (implies stealth). "
                            "Use create_stealth_session() in Python for full access.")
    parser.add_argument("--status", action="store_true", help="Check if CDP is running")
    parser.add_argument("--info", action="store_true", help="Show CDP connection details")

    from auth_check import add_auth_args, check_auth
    add_auth_args(parser)

    args = parser.parse_args()

    if args.url:
        auth_result = check_auth(args, args.url)
        if not auth_result.authorized:
            print(f"\n[ERROR] {auth_result.fail()}")
            sys.exit(1)

    if args.status:
        if is_cdp_running(args.port):
            print(f"[+] CDP is running on port {args.port}")
        else:
            print(f"[-] CDP is NOT running on port {args.port}")
        return

    if args.info:
        info = get_cdp_info(args.port)
        if info:
            print(f"Browser:         {info['browser']}")
            print(f"Protocol:        {info['protocol_version']}")
            print(f"User-Agent:      {info['user_agent']}")
            print(f"WebSocket URL:   {info['webSocket_url']}")
            print(f"\nTabs ({len(info['tabs'])}):")
            for t in info["tabs"]:
                print(f"  - {t['title'][:50]}  →  {t['url'][:80]}")
                print(f"    WS: {t['ws']}")
        else:
            print(f"[-] CDP not running on port {args.port}")
        return

    # Stealth is ON by default; --no-stealth disables it; --human forces it on
    stealth = not args.no_stealth or args.human

    # Launch
    launch_cdp(port=args.port, url=args.url, proxy=args.proxy,
               user_data_dir=args.profile, stealth=stealth)

    # Show connection info
    info = get_cdp_info(args.port)
    if info:
        print(f"\n[+] Chrome is ready!")
        print(f"    Browser:  {info['browser']}")
        print(f"    CDP URL:  http://localhost:{args.port}")
        print(f"    Tabs:     {len(info['tabs'])}")
        if info["webSocket_url"]:
            print(f"    WS:       {info['webSocket_url']}")

    if stealth:
        print(f"\n[*] Stealth mode ACTIVE (default).")
        print(f"    Anti-detect JS is injected into every page.")
        print(f"    navigator.webdriver = false, CDP artifacts removed.")
    if args.human:
        print(f"\n[*] Human behavior mode ready.")
        print(f"    In Python, use:")
        print(f"      from cdp_launch import create_stealth_session")
        print(f"      page, browser, pw, hb = await create_stealth_session(human=True)")
        print(f"      await hb.read_page()  # human-like scrolling")
        print(f"      await hb.click(x, y)  # human-like clicking")
        print(f"      hb.get_score()        # behavioral score")

    # AI-ready prompt
    print(f"\n[AI] CDP browser is ready for AI control.")
    print(f"     This is NOT a manual browser — it's launched for AI to drive.")
    print(f"     Connect via Playwright and send commands:")
    print(f"       from cdp_launch import connect_playwright_cdp")
    print(f"       browser, pw = connect_playwright_cdp(stealth=True)")
    print(f"       page = browser.new_page()")
    print(f"       page.goto('https://target.com')")
    print(f"     Or for full stealth + human behavior:")
    print(f"       from cdp_launch import create_stealth_session")
    print(f"       page, browser, pw, hb = await create_stealth_session(human=True)")
    print(f"     CDP endpoint: http://localhost:{args.port}")


if __name__ == "__main__":
    main()
