#!/usr/bin/env python3
"""
Stealth mode for CDP browser — anti-detect JS injection + cookie banner dismissal.

Extracted from Shopify tool's scraper_platform/core/anti_detect.py and adapted
for Playwright + raw CDP usage in the hack skill.

Three usage modes:

1. Playwright sync API:
    from cdp_launch import connect_playwright_cdp
    from stealth import dismiss_cookie_banners_sync, verify_stealth_sync

    browser, pw = connect_playwright_cdp(stealth=True)  # auto-injects
    page = browser.new_page()
    page.goto("https://target.com")
    dismiss_cookie_banners_sync(page)
    print(verify_stealth_sync(page))

2. Playwright async API (needed for HumanBehavior):
    from cdp_launch import connect_playwright_cdp_async
    from stealth import dismiss_cookie_banners_async

    browser, pw = await connect_playwright_cdp_async(stealth=True)
    page = await browser.new_page()
    await page.goto("https://target.com")
    await dismiss_cookie_banners_async(page)

3. Raw CDP daemon (for CLI --stealth, no Playwright needed):
    from stealth import StealthDaemon
    daemon = StealthDaemon(port=9222)
    daemon.start()   # background thread, injects into every new page
    # ... Chrome runs with anti-detect on every page ...
    daemon.stop()
"""

from __future__ import annotations

import asyncio
import json
import random
import threading
import time
from typing import Any

try:
    import requests
except ImportError:
    requests = None  # type: ignore

try:
    import websockets
except ImportError:
    websockets = None  # type: ignore


# ─── Anti-detect JS (injected once per page) ─────────────────────────────────

ANTI_DETECT_JS = r"""
(() => {
  // Only hide webdriver flag — this is the most critical detect vector
  try {
    Object.defineProperty(navigator, 'webdriver', { get: () => false, configurable: true });
  } catch (e) {}

  // Ensure window.chrome exists with minimal stubs (don't delete the real one!)
  if (!window.chrome) {
    window.chrome = {};
  }
  if (!window.chrome.runtime) {
    window.chrome.runtime = {};
  }
  if (!window.chrome.loadTimes) {
    window.chrome.loadTimes = function() {};
  }
  if (!window.chrome.csi) {
    window.chrome.csi = function() {};
  }

  // Remove CDP automation artifacts
  for (const key of Object.keys(window)) {
    if (/^cdc_|_selenium|_webdriver|__nightmare/i.test(key)) {
      try { delete window[key]; } catch (e) {}
    }
  }
})();
"""

# ─── Cookie banner dismissal JS ──────────────────────────────────────────────

DISMISS_COOKIE_JS = r"""
(() => {
  const exact = /^(accept all|accept cookies|agree|allow all|ok|got it|i agree|continue|同意|接受|全部接受|允许|我同意)$/i;
  const cookieContext = /cookie|consent|privacy|gdpr|偏好|隐私|同意|许可/i;
  const elements = Array.from(document.querySelectorAll('button, [role="button"], input[type="button"], input[type="submit"], a'));
  for (const el of elements) {
    const text = (el.innerText || el.value || el.getAttribute('aria-label') || '').trim();
    if (!text) continue;
    const containerText = (el.closest('[role="dialog"], .modal, .banner, [class*="cookie"], [id*="cookie"], [class*="consent"], [id*="consent"]')?.innerText || '').slice(0, 1000);
    if (exact.test(text) || (cookieContext.test(containerText) && /accept|agree|allow|同意|接受|允许/i.test(text) && text.length <= 60)) {
      el.click();
      return {handled: true, action: 'clicked', text};
    }
  }
  const close = document.querySelector('.cookie-close, .banner-close, [aria-label*="close" i], [aria-label*="dismiss" i]');
  if (close) {
    close.click();
    return {handled: true, action: 'closed', text: close.getAttribute('aria-label') || ''};
  }
  return {handled: false, action: 'none', text: ''};
})()
"""

# ─── Verification JS ─────────────────────────────────────────────────────────

VERIFY_ANTI_DETECT_JS = r"""
(() => {
  const cdcKeys = Object.keys(window).filter(k => /^cdc_|_selenium|_webdriver|__nightmare/i.test(k));
  return {
    webdriver: navigator.webdriver,
    plugins_length: navigator.plugins ? navigator.plugins.length : 0,
    languages: Array.from(navigator.languages || []),
    platform: navigator.platform,
    chrome_runtime: !!(window.chrome && window.chrome.runtime),
    chrome_loadTimes: !!(window.chrome && window.chrome.loadTimes),
    automation_keys: cdcKeys
  };
})()
"""

# ─── Proxy IP verification JS ────────────────────────────────────────────────

VERIFY_PROXY_JS = r"""
(() => new Promise(resolve => {
  fetch('https://api.ipify.org?format=json', {cache: 'no-store'})
    .then(r => r.json())
    .then(d => resolve(d.ip || 'unknown'))
    .catch(() => resolve('unknown'));
}))()
"""

# ─── User agents ────────────────────────────────────────────────────────────

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
]


def random_user_agent() -> str:
    """Return a random Chrome User-Agent string."""
    return random.choice(USER_AGENTS)


# ─── Playwright sync helpers ─────────────────────────────────────────────────

def apply_stealth_sync(context: Any) -> None:
    """Add anti-detect init script to a Playwright browser context (sync API).

    The script runs on every new document (page load) before any page JS executes.
    """
    context.add_init_script(ANTI_DETECT_JS)


def dismiss_cookie_banners_sync(page: Any) -> dict[str, Any]:
    """Dismiss cookie/consent banners on the page (sync API)."""
    try:
        result = page.evaluate(DISMISS_COOKIE_JS)
        return result if isinstance(result, dict) else {"handled": False}
    except Exception:
        return {"handled": False, "action": "error"}


def verify_stealth_sync(page: Any) -> dict[str, Any]:
    """Verify anti-detect fingerprint is active (sync API)."""
    try:
        result = page.evaluate(VERIFY_ANTI_DETECT_JS)
        return result if isinstance(result, dict) else {}
    except Exception as exc:
        return {"error": str(exc)}


def verify_proxy_sync(page: Any) -> str:
    """Detect browser external IP for proxy verification (sync API)."""
    try:
        result = page.evaluate(VERIFY_PROXY_JS)
        return str(result or "unknown")
    except Exception:
        return "unknown"


# ─── Playwright async helpers ────────────────────────────────────────────────

async def apply_stealth_async(context: Any) -> None:
    """Add anti-detect init script to a Playwright browser context (async API)."""
    await context.add_init_script(ANTI_DETECT_JS)


async def dismiss_cookie_banners_async(page: Any) -> dict[str, Any]:
    """Dismiss cookie/consent banners on the page (async API)."""
    try:
        result = await page.evaluate(DISMISS_COOKIE_JS)
        return result if isinstance(result, dict) else {"handled": False}
    except Exception:
        return {"handled": False, "action": "error"}


async def verify_stealth_async(page: Any) -> dict[str, Any]:
    """Verify anti-detect fingerprint is active (async API)."""
    try:
        result = await page.evaluate(VERIFY_ANTI_DETECT_JS)
        return result if isinstance(result, dict) else {}
    except Exception as exc:
        return {"error": str(exc)}


async def verify_proxy_async(page: Any) -> str:
    """Detect browser external IP for proxy verification (async API)."""
    try:
        result = await page.evaluate(VERIFY_PROXY_JS)
        return str(result or "unknown")
    except Exception:
        return "unknown"


# ─── Raw CDP Stealth Daemon (for CLI --stealth) ──────────────────────────────

class StealthDaemon:
    """
    Background thread that injects anti-detect JS into all CDP targets.

    Uses Target.setAutoAttach (flatten mode) to catch new pages and injects:
      1. Page.addScriptToEvaluateOnNewDocument — for all future navigations
      2. Runtime.evaluate — for the current page immediately

    Non-blocking: waitForDebuggerOnStart=False, so pages load normally even
    if injection fails or the daemon is slow.

    Usage:
        daemon = StealthDaemon(port=9222)
        daemon.start()   # background thread
        # ... Chrome runs with anti-detect on every page ...
        daemon.stop()
    """

    def __init__(self, port: int = 9222):
        if websockets is None:
            raise ImportError("websockets not installed. Run: pip install websockets")
        if requests is None:
            raise ImportError("requests not installed. Run: pip install requests")

        self.port = port
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def start(self) -> None:
        """Start the daemon in a background daemon thread."""
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="stealth-daemon"
        )
        self._thread.start()

    def stop(self) -> None:
        """Signal the daemon to stop."""
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)

    def _run(self) -> None:
        """Thread entry point — runs the async event loop."""
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(self._async_run())
        except Exception as e:
            print(f"[stealth] daemon error: {e}", flush=True)

    async def _async_run(self) -> None:
        """Main daemon loop: connect to browser WS, listen for new targets."""
        try:
            version = requests.get(
                f"http://localhost:{self.port}/json/version", timeout=5
            ).json()
        except Exception as e:
            print(f"[stealth] cannot connect to CDP on port {self.port}: {e}", flush=True)
            return

        ws_url = version.get("webSocketDebuggerUrl")
        if not ws_url:
            print("[stealth] no webSocketDebuggerUrl found", flush=True)
            return

        try:
            async with websockets.connect(ws_url, close_timeout=5) as ws:
                # Enable Target discovery
                await ws.send(json.dumps({
                    "id": 1,
                    "method": "Target.setDiscoverTargets",
                    "params": {"discover": True},
                }))

                # Auto-attach to all targets (non-blocking mode)
                await ws.send(json.dumps({
                    "id": 2,
                    "method": "Target.setAutoAttach",
                    "params": {
                        "autoAttach": True,
                        "waitForDebuggerOnStart": False,
                        "flatten": True,
                    },
                }))

                print(
                    "[stealth] daemon active — injecting anti-detect JS into all pages",
                    flush=True,
                )

                msg_id = 100  # Start high to avoid clashing with setup IDs

                # Listen for attached targets and inject scripts
                while not self._stop.is_set():
                    try:
                        raw = await asyncio.wait_for(ws.recv(), timeout=1.0)
                        msg = json.loads(raw)

                        if msg.get("method") == "Target.attachedToTarget":
                            session_id = msg["params"].get("sessionId")
                            if session_id:
                                await self._inject_target(ws, session_id, msg_id)
                                msg_id += 10

                    except asyncio.TimeoutError:
                        continue
                    except websockets.ConnectionClosed:
                        print("[stealth] WebSocket closed, daemon stopping", flush=True)
                        break

        except Exception as e:
            print(f"[stealth] daemon WebSocket error: {e}", flush=True)

    async def _inject_target(self, ws: Any, session_id: str, base_id: int) -> None:
        """Fire-and-forget: inject anti-detect JS into a target session."""
        try:
            # Enable Page domain
            await ws.send(json.dumps({
                "id": base_id,
                "method": "Page.enable",
                "sessionId": session_id,
            }))

            # Register init script for all future navigations
            await ws.send(json.dumps({
                "id": base_id + 1,
                "method": "Page.addScriptToEvaluateOnNewDocument",
                "params": {"source": ANTI_DETECT_JS},
                "sessionId": session_id,
            }))

            # Evaluate on current page right now
            await ws.send(json.dumps({
                "id": base_id + 2,
                "method": "Runtime.evaluate",
                "params": {
                    "expression": ANTI_DETECT_JS,
                    "returnByValue": True,
                },
                "sessionId": session_id,
            }))

            # Drain responses (best-effort, don't block)
            for _ in range(3):
                try:
                    await asyncio.wait_for(ws.recv(), timeout=0.3)
                except asyncio.TimeoutError:
                    break

        except Exception:
            pass  # Non-critical — page still works without stealth
