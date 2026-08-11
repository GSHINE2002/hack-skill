#!/usr/bin/env python3
"""
Human Behavior Simulator — realistic human-like interaction for CDP browser.

Adapted from the Shopify scraping tool's scraper_platform/core/human_behavior.py.
The only change: removed the hard dependency on CdpSession. Now accepts any
object that provides `.call()`, `.evaluate()`, and `.navigate()` methods
(duck typing). The PlaywrightCDPBridge in cdp_launch.py satisfies this interface.

Capabilities:
1. Bezier-curve mouse trajectory generation (natural movement, hand tremor)
2. Multiple behavior profiles (casual, researcher, power_user, elderly)
3. Reading behavior simulation (variable scroll speed, pauses)
4. Behavioral scoring system (quantifies "human-likeness" 0-100)
5. CDP-native integration via Input.dispatchMouseEvent / dispatchKeyEvent

Required interface (duck-typed):
    class CdpLike:
        async def call(self, method: str, params: dict | None = None,
                       timeout: float = 30) -> dict
        async def evaluate(self, expression: str, return_by_value: bool = True,
                           await_promise: bool = True, timeout: float = 30) -> dict
        async def navigate(self, url: str, timeout: float = 30) -> None

Usage:
    from cdp_launch import connect_playwright_cdp_async, PlaywrightCDPBridge
    from human_behavior import HumanBehavior

    browser, pw = await connect_playwright_cdp_async(port=9222, stealth=True)
    page = await browser.new_page()
    await page.goto("https://target.com")

    # Create bridge + human behavior controller
    ctx = browser.contexts[0]
    cdp_session = await ctx.new_cdp_session(page)
    bridge = PlaywrightCDPBridge(page, cdp_session)
    hb = HumanBehavior(bridge, profile="casual")

    await hb.move_to(500, 300)          # Bezier curve mouse move
    await hb.click(500, 300)            # Human-like click with hesitation
    await hb.read_page(scroll_px=3000)  # Simulate reading + scrolling
    await hb.type_text("search term")   # Human-like typing with pauses
    score = hb.get_score()              # Get behavioral score (0-100)
"""

from __future__ import annotations

import asyncio
import math
import random
import time
from typing import Any, Protocol, runtime_checkable


# ============================================================
# Duck-typed protocol (for type checkers, not enforced at runtime)
# ============================================================

@runtime_checkable
class CdpLike(Protocol):
    """Interface that HumanBehavior expects from its CDP connection."""
    async def call(self, method: str, params: dict[str, Any] | None = None,
                   timeout: float = 30) -> dict[str, Any]: ...
    async def evaluate(self, expression: str, return_by_value: bool = True,
                       await_promise: bool = True, timeout: float = 30) -> dict[str, Any]: ...
    async def navigate(self, url: str, timeout: float = 30) -> None: ...


# ============================================================
# Behavior Profiles
# ============================================================

PROFILES: dict[str, dict[str, Any]] = {
    "casual": {
        "name": "Casual Browser",
        "mouse_speed_range": (150, 400),     # px/s
        "mouse_jitter": 0.3,
        "click_delay_range": (0.1, 0.5),     # seconds
        "scroll_pause_range": (0.5, 2.5),
        "page_read_time_range": (3, 15),
        "keystroke_wpm_range": (30, 60),
        "scroll_distance_range": (150, 400),
        "scroll_max_range": (1500, 4000),
    },
    "researcher": {
        "name": "Researcher",
        "mouse_speed_range": (100, 250),
        "mouse_jitter": 0.2,
        "click_delay_range": (0.3, 1.0),
        "scroll_pause_range": (1.0, 4.0),
        "page_read_time_range": (8, 30),
        "keystroke_wpm_range": (40, 80),
        "scroll_distance_range": (100, 250),
        "scroll_max_range": (2000, 6000),
    },
    "power_user": {
        "name": "Power User",
        "mouse_speed_range": (300, 800),
        "mouse_jitter": 0.15,
        "click_delay_range": (0.05, 0.2),
        "scroll_pause_range": (0.3, 1.2),
        "page_read_time_range": (2, 8),
        "keystroke_wpm_range": (60, 120),
        "scroll_distance_range": (200, 500),
        "scroll_max_range": (1000, 3000),
    },
    "elderly": {
        "name": "Elderly User",
        "mouse_speed_range": (50, 150),
        "mouse_jitter": 0.5,
        "click_delay_range": (0.5, 2.0),
        "scroll_pause_range": (2.0, 6.0),
        "page_read_time_range": (10, 40),
        "keystroke_wpm_range": (15, 35),
        "scroll_distance_range": (80, 200),
        "scroll_max_range": (800, 2500),
    },
}


# ============================================================
# Bezier-curve Trajectory Generator
# ============================================================

def _bezier_point(
    t: float,
    p0: tuple[float, float],
    p1: tuple[float, float],
    p2: tuple[float, float],
    p3: tuple[float, float],
) -> tuple[float, float]:
    """Cubic Bezier interpolation at parameter t."""
    mt = 1 - t
    x = (mt**3 * p0[0] + 3 * mt**2 * t * p1[0] +
         3 * mt * t**2 * p2[0] + t**3 * p3[0])
    y = (mt**3 * p0[1] + 3 * mt**2 * t * p1[1] +
         3 * mt * t**2 * p2[1] + t**3 * p3[1])
    return (x, y)


def generate_trajectory(
    start: tuple[float, float],
    end: tuple[float, float],
    profile: dict[str, Any],
    duration_ms: int | None = None,
) -> list[tuple[float, float]]:
    """
    Generate a list of (x, y) points forming a natural mouse path.
    Uses cubic Bezier curves with micro-jitter for hand tremor simulation.
    """
    dx = end[0] - start[0]
    dy = end[1] - start[1]
    distance = math.sqrt(dx**2 + dy**2)

    if duration_ms is None:
        speed = random.randint(
            int(profile["mouse_speed_range"][0]),
            int(profile["mouse_speed_range"][1]),
        )
        duration_ms = max(100, int(distance / max(speed, 1) * 1000))

    num_points = max(8, duration_ms // 16)  # ~60fps
    jitter = profile["mouse_jitter"]

    # Random control points offset from the straight line
    cp1 = (
        start[0] + dx * 0.3 + random.uniform(-1, 1) * distance * jitter,
        start[1] + dy * 0.1 + random.uniform(-1, 1) * distance * jitter,
    )
    cp2 = (
        start[0] + dx * 0.7 + random.uniform(-1, 1) * distance * jitter,
        start[1] + dy * 0.9 + random.uniform(-1, 1) * distance * jitter,
    )

    points: list[tuple[float, float]] = []
    for i in range(num_points + 1):
        t = i / num_points
        px, py = _bezier_point(t, start, cp1, cp2, end)
        # Add hand tremor
        px += random.gauss(0, 0.5)
        py += random.gauss(0, 0.5)
        points.append((round(px, 1), round(py, 1)))

    return points


# ============================================================
# Human Behavior Controller
# ============================================================

class HumanBehavior:
    """
    Wraps a CDP-like connection with human-like interaction patterns.

    Records all actions for behavioral scoring.

    Args:
        cdp: Any object with async .call(), .evaluate(), .navigate() methods.
             Use PlaywrightCDPBridge from cdp_launch.py to bridge Playwright.
        profile: Behavior profile name — "casual", "researcher",
                 "power_user", or "elderly".
    """

    def __init__(self, cdp: Any, profile: str = "casual"):
        self.cdp = cdp
        self.profile = PROFILES.get(profile, PROFILES["casual"])
        self.profile_name = profile
        self.behavior_log: list[dict[str, Any]] = []
        self._session_start = time.monotonic()
        self._last_action = self._session_start
        self._current_pos: tuple[float, float] = (0.0, 0.0)

    # ── Internal: record + dispatch ───────────────────────────────────────

    def _record(self, event: dict[str, Any]) -> None:
        now = time.monotonic()
        event["session_time"] = round(now - self._session_start, 2)
        event["idle_time"] = round(now - self._last_action, 2)
        self.behavior_log.append(event)
        self._last_action = now

    async def _dispatch_mouse(
        self, x: float, y: float, button: str = "none",
        click_count: int = 0,
    ) -> None:
        """Send a CDP Input.dispatchMouseEvent."""
        params: dict[str, Any] = {
            "type": "mouseMoved",
            "x": x,
            "y": y,
            "button": button,
            "clickCount": click_count,
        }
        if button != "none" and click_count > 0:
            params["type"] = "mousePressed" if click_count == 1 else "mouseReleased"
        try:
            await self.cdp.call("Input.dispatchMouseEvent", params, timeout=5)
        except Exception:
            pass  # Non-critical if Input domain isn't enabled

    # ── Public API ─────────────────────────────────────────────────────────

    async def move_to(
        self, x: float, y: float, duration_ms: int | None = None,
    ) -> None:
        """
        Move mouse to (x, y) along a Bezier-curve trajectory.
        Dispatches ~60fps mouseMoved events via CDP.
        """
        start = self._current_pos
        trajectory = generate_trajectory(start, (x, y), self.profile, duration_ms)

        step_delay = (duration_ms or 500) / max(len(trajectory), 1) / 1000
        step_delay = max(0.005, min(step_delay, 0.05))

        for px, py in trajectory:
            await self._dispatch_mouse(px, py)
            await asyncio.sleep(step_delay)

        self._current_pos = (x, y)
        self._record({
            "type": "mouse_move",
            "from": start,
            "to": (x, y),
            "points": len(trajectory),
            "duration_ms": duration_ms or 500,
        })

    async def click(
        self, x: float, y: float, double_click: bool = False,
    ) -> None:
        """
        Human-like click: move to target, hover briefly, then click.
        Small chance (5%) of accidental double-click.
        """
        # Move to target first
        await self.move_to(x, y)

        # Hover (hesitation before click)
        hover_time = random.uniform(0.05, 0.3)
        await asyncio.sleep(hover_time)

        # Click delay
        click_delay = random.uniform(
            self.profile["click_delay_range"][0],
            self.profile["click_delay_range"][1],
        )
        await asyncio.sleep(click_delay)

        # Random double-click chance
        is_double = double_click or random.random() < 0.05

        # Press
        await self._dispatch_mouse(x, y, button="left", click_count=1)
        await asyncio.sleep(random.uniform(0.02, 0.08))
        # Release
        await self._dispatch_mouse(x, y, button="left", click_count=0)
        params_release = {
            "type": "mouseReleased",
            "x": x, "y": y,
            "button": "left",
            "clickCount": 1,
        }
        try:
            await self.cdp.call("Input.dispatchMouseEvent", params_release, timeout=5)
        except Exception:
            pass

        if is_double:
            await asyncio.sleep(random.uniform(0.05, 0.15))
            await self._dispatch_mouse(x, y, button="left", click_count=2)
            try:
                await self.cdp.call("Input.dispatchMouseEvent", {
                    "type": "mouseReleased", "x": x, "y": y,
                    "button": "left", "clickCount": 2,
                }, timeout=5)
            except Exception:
                pass

        self._record({
            "type": "click",
            "x": x, "y": y,
            "hover_time": round(hover_time, 3),
            "click_delay": round(click_delay, 3),
            "is_double_click": is_double,
        })

    async def scroll(
        self, dx: int = 0, dy: int = 0, smooth: bool = True,
    ) -> None:
        """
        Human-like scroll via CDP Input.dispatchMouseEvent (mouseWheel).
        Falls back to window.scrollBy if CDP dispatch fails.
        """
        if smooth:
            # Scroll in small bursts
            total = dy
            remaining = total
            while abs(remaining) > 10:
                step = int(remaining * random.uniform(0.3, 0.6))
                step = max(-300, min(300, step))
                try:
                    await self.cdp.call("Input.dispatchMouseEvent", {
                        "type": "mouseWheel",
                        "x": self._current_pos[0],
                        "y": self._current_pos[1],
                        "deltaX": 0,
                        "deltaY": step,
                    }, timeout=5)
                except Exception:
                    # Fallback: JS scroll
                    await self.cdp.evaluate(
                        f"window.scrollBy(0, {step});", await_promise=True
                    )
                remaining -= step
                await asyncio.sleep(random.uniform(
                    self.profile["scroll_pause_range"][0],
                    self.profile["scroll_pause_range"][1],
                ))
        else:
            try:
                await self.cdp.call("Input.dispatchMouseEvent", {
                    "type": "mouseWheel",
                    "x": self._current_pos[0],
                    "y": self._current_pos[1],
                    "deltaX": dx,
                    "deltaY": dy,
                }, timeout=5)
            except Exception:
                await self.cdp.evaluate(
                    f"window.scrollBy({dx}, {dy});", await_promise=True
                )

        self._record({
            "type": "scroll",
            "dx": dx,
            "dy": dy,
            "smooth": smooth,
        })

    async def read_page(
        self,
        scroll_px: int | None = None,
        read_seconds: float | None = None,
    ) -> None:
        """
        Simulate a human reading a page: random scrolling with pauses.

        Args:
            scroll_px: Total pixels to scroll. If None, uses profile default.
            read_seconds: Total reading time. If None, uses profile default.
        """
        if scroll_px is None:
            scroll_px = random.randint(
                self.profile["scroll_max_range"][0],
                self.profile["scroll_max_range"][1],
            )
        if read_seconds is None:
            read_seconds = random.uniform(
                self.profile["page_read_time_range"][0],
                self.profile["page_read_time_range"][1],
            )

        start_time = time.monotonic()
        scrolled = 0

        while scrolled < scroll_px and (time.monotonic() - start_time) < read_seconds:
            # Scroll a burst
            burst = random.randint(
                self.profile["scroll_distance_range"][0],
                self.profile["scroll_distance_range"][1],
            )
            await self.scroll(dy=burst)
            scrolled += burst

            # Pause (reading)
            pause = random.uniform(
                self.profile["scroll_pause_range"][0],
                self.profile["scroll_pause_range"][1],
            )
            await asyncio.sleep(pause)

            # Occasional mouse movement while "reading"
            if random.random() < 0.3:
                rand_x = random.uniform(100, 1200)
                rand_y = random.uniform(100, 800)
                await self.move_to(rand_x, rand_y, duration_ms=random.randint(300, 800))

        self._record({
            "type": "page_read",
            "total_scrolled": scrolled,
            "duration": round(time.monotonic() - start_time, 1),
        })

    async def type_text(
        self, text: str, selector: str | None = None,
    ) -> None:
        """
        Type text with human-like timing: variable speed, occasional pauses,
        small chance of typo + backspace.

        Args:
            text: The text to type.
            selector: CSS selector of the input element. If None, types into
                      whatever element currently has focus.
        """
        if selector:
            # Click the element first
            expr = f"""
            (() => {{
              const el = document.querySelector({repr(selector)});
              if (el) {{ el.focus(); return true; }}
              return false;
            }})()
            """
            await self.cdp.evaluate(expr, await_promise=True)
            await asyncio.sleep(random.uniform(0.2, 0.5))

        wpm = random.randint(
            self.profile["keystroke_wpm_range"][0],
            self.profile["keystroke_wpm_range"][1],
        )
        base_interval = 60.0 / wpm  # seconds per char

        keystrokes = 0
        for char in text:
            # Variable interval
            interval = base_interval * random.uniform(0.5, 2.0)

            # Occasionally make a typo and correct it
            if random.random() < 0.02 and char not in " \n":
                wrong_char = chr(ord(char) + random.choice([-1, 1]))
                try:
                    await self.cdp.call("Input.dispatchKeyEvent", {
                        "type": "char",
                        "text": wrong_char,
                    }, timeout=3)
                except Exception:
                    pass
                await asyncio.sleep(interval)
                # Backspace
                try:
                    await self.cdp.call("Input.dispatchKeyEvent", {
                        "type": "keyDown",
                        "key": "Backspace",
                        "code": "Backspace",
                        "windowsVirtualKeyCode": 8,
                    }, timeout=3)
                    await self.cdp.call("Input.dispatchKeyEvent", {
                        "type": "keyUp",
                        "key": "Backspace",
                        "code": "Backspace",
                        "windowsVirtualKeyCode": 8,
                    }, timeout=3)
                except Exception:
                    pass
                await asyncio.sleep(random.uniform(0.1, 0.3))

            # Type the actual char
            try:
                await self.cdp.call("Input.dispatchKeyEvent", {
                    "type": "char",
                    "text": char,
                }, timeout=3)
            except Exception:
                pass

            keystrokes += 1
            await asyncio.sleep(interval)

            # Random pause (thinking)
            if random.random() < 0.08:
                await asyncio.sleep(random.uniform(0.5, 2.0))

        self._record({
            "type": "type_text",
            "text_length": len(text),
            "keystrokes": keystrokes,
            "wpm": wpm,
        })

    async def navigate_like_human(self, url: str) -> None:
        """
        Simulate the full flow of a human navigating to a URL:
        1. Brief pause (as if deciding to navigate)
        2. Navigate
        3. Wait for page load
        4. Brief reading pause
        """
        # Decision pause
        await asyncio.sleep(random.uniform(0.5, 2.0))
        self._record({"type": "navigation_decision", "url": url})

        # Navigate via CDP
        await self.cdp.navigate(url)
        self._record({"type": "navigation", "url": url})

        # Wait a bit for load
        await asyncio.sleep(random.uniform(1.0, 3.0))

        # Initial reading
        await self.read_page(
            scroll_px=random.randint(200, 800),
            read_seconds=random.uniform(2, 5),
        )

    # ── Behavioral Scoring ─────────────────────────────────────────────────

    def get_score(self) -> dict[str, Any]:
        """
        Score the behavioral log for "human-likeness" (0-100).
        Returns detailed per-metric breakdown.
        """
        if not self.behavior_log:
            return {"total": 0, "metrics": {}, "verdict": "EMPTY"}

        metrics: dict[str, float] = {}

        # 1. Mouse smoothness
        mouse_moves = [e for e in self.behavior_log if e.get("type") == "mouse_move"]
        if mouse_moves:
            avg_points = sum(e.get("points", 0) for e in mouse_moves) / len(mouse_moves)
            metrics["mouse_smoothness"] = min(100, 50 + avg_points * 1.5)
        else:
            metrics["mouse_smoothness"] = 50

        # 2. Timing variation (coefficient of variation)
        delays = [e.get("idle_time", 0) for e in self.behavior_log if e.get("idle_time")]
        if len(delays) >= 2:
            mean_d = sum(delays) / len(delays)
            if mean_d > 0:
                variance = sum((d - mean_d)**2 for d in delays) / len(delays)
                cv = math.sqrt(variance) / mean_d
                metrics["timing_variation"] = 90 if 0.2 < cv < 0.8 else (70 if 0.1 < cv < 1.0 else 40)
            else:
                metrics["timing_variation"] = 40
        else:
            metrics["timing_variation"] = 50

        # 3. Scroll pattern
        scrolls = [e for e in self.behavior_log if e.get("type") == "scroll"]
        if scrolls:
            metrics["scroll_pattern"] = min(100, 50 + len(scrolls) * 8)
        else:
            metrics["scroll_pattern"] = 50

        # 4. Page read time
        reads = [e for e in self.behavior_log if e.get("type") == "page_read"]
        if reads:
            avg_time = sum(r.get("duration", 0) for r in reads) / len(reads)
            metrics["page_read_time"] = 90 if 3 < avg_time < 60 else (70 if 1 < avg_time < 120 else 40)
        else:
            metrics["page_read_time"] = 50

        # 5. Click behavior
        clicks = [e for e in self.behavior_log if e.get("type") == "click"]
        if clicks:
            has_hesitation = any(c.get("hover_time", 0) > 0.05 for c in clicks)
            has_double = any(c.get("is_double_click") for c in clicks)
            score = 70 + (10 if has_hesitation else 0) + (5 if has_double else 0)
            metrics["click_behavior"] = min(100, score)
        else:
            metrics["click_behavior"] = 50

        # 6. Action diversity
        types_seen = set(e.get("type", "") for e in self.behavior_log)
        metrics["action_diversity"] = min(100, len(types_seen) * 20)

        # Weighted total
        weights = {
            "mouse_smoothness": 0.15,
            "timing_variation": 0.20,
            "scroll_pattern": 0.15,
            "page_read_time": 0.15,
            "click_behavior": 0.10,
            "action_diversity": 0.25,
        }
        total = sum(metrics.get(k, 0) * w for k, w in weights.items())
        total = round(min(100, max(0, total)), 1)

        if total >= 85:
            verdict = "EXCELLENT — Nearly indistinguishable from human"
        elif total >= 70:
            verdict = "GOOD — Mostly human-like with minor anomalies"
        elif total >= 50:
            verdict = "MODERATE — Some human traits, some bot indicators"
        elif total >= 30:
            verdict = "POOR — Clearly automated behavior"
        else:
            verdict = "VERY POOR — Obvious bot behavior"

        return {
            "total": total,
            "metrics": {k: round(v, 1) for k, v in metrics.items()},
            "verdict": verdict,
            "events": len(self.behavior_log),
        }

    def get_log(self) -> list[dict[str, Any]]:
        """Return the full behavior log."""
        return self.behavior_log

    def reset(self) -> None:
        """Reset the behavior log for a new session."""
        self.behavior_log.clear()
        self._session_start = time.monotonic()
        self._last_action = self._session_start
