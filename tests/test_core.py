#!/usr/bin/env python3
"""
Unit tests for core pure functions in the hack skill.

Run:
  python -m pytest tests/test_core.py -v
  # or without pytest:
  python tests/test_core.py
"""

import sys
import math
import os
from pathlib import Path

# Ensure scripts/ is on the path
_SCRIPT_DIR = Path(__file__).parent.parent / "scripts"
sys.path.insert(0, str(_SCRIPT_DIR))


# ─── human_behavior.py: _bezier_point, generate_trajectory ──────────────────

def test_bezier_point_endpoints():
    """Bezier curve should return exact start and end points at t=0 and t=1."""
    from human_behavior import _bezier_point
    p0, p1, p2, p3 = (0, 0), (10, 20), (30, 40), (50, 50)
    # t=0 → p0
    x, y = _bezier_point(0.0, p0, p1, p2, p3)
    assert abs(x - 0.0) < 1e-9 and abs(y - 0.0) < 1e-9, f"t=0 should be start: ({x},{y})"
    # t=1 → p3
    x, y = _bezier_point(1.0, p0, p1, p2, p3)
    assert abs(x - 50.0) < 1e-9 and abs(y - 50.0) < 1e-9, f"t=1 should be end: ({x},{y})"


def test_bezier_point_midpoint():
    """Bezier midpoint should be within bounding box of control points."""
    from human_behavior import _bezier_point
    p0, p1, p2, p3 = (0, 0), (10, 20), (30, 40), (50, 50)
    x, y = _bezier_point(0.5, p0, p1, p2, p3)
    assert 0 <= x <= 50, f"x={x} out of [0,50]"
    assert 0 <= y <= 50, f"y={y} out of [0,50]"


def test_generate_trajectory_basic():
    """Trajectory should start near start point and end near end point."""
    from human_behavior import generate_trajectory, PROFILES
    profile = PROFILES["casual"]
    points = generate_trajectory((0, 0), (500, 300), profile, duration_ms=500)
    assert len(points) >= 8, f"Too few points: {len(points)}"
    # First point should be near (0,0)
    assert abs(points[0][0]) < 5 and abs(points[0][1]) < 5, f"Start too far: {points[0]}"
    # Last point should be near (500,300) — within jitter tolerance
    assert abs(points[-1][0] - 500) < 10 and abs(points[-1][1] - 300) < 10, f"End too far: {points[-1]}"


def test_generate_trajectory_duration():
    """Trajectory point count should roughly correspond to duration (~60fps)."""
    from human_behavior import generate_trajectory, PROFILES
    profile = PROFILES["power_user"]
    points = generate_trajectory((0, 0), (100, 100), profile, duration_ms=1000)
    # ~60fps → 1000ms/16 ≈ 62 points ± some
    assert 50 <= len(points) <= 80, f"Expected ~62 points, got {len(points)}"


# ─── ai_fuzzer.py: PayloadGenerator ──────────────────────────────────────────

def test_payload_generator_sqli():
    """SQLi templates should be returned for goal='sqli'."""
    from ai_fuzzer import PayloadGenerator
    gen = PayloadGenerator(goal="sqli")
    payloads = gen.generate_base_payloads(count=5)
    assert len(payloads) <= 5
    assert len(payloads) > 0
    # Should contain classic SQLi payload
    assert any("'" in p for p in payloads), "Should contain quote-based payloads"


def test_payload_generator_xss():
    """XSS templates should be returned for goal='xss'."""
    from ai_fuzzer import PayloadGenerator
    gen = PayloadGenerator(goal="xss")
    payloads = gen.generate_base_payloads(count=10)
    assert len(payloads) > 0
    assert any("<script>" in p or "<svg" in p or "<img" in p for p in payloads), \
        "Should contain HTML-based XSS payloads"


def test_payload_generator_mutate():
    """Mutation should produce URL-encoded variants."""
    from ai_fuzzer import PayloadGenerator
    gen = PayloadGenerator(goal="sqli")
    variants = gen._mutate("' OR '1'='1")
    assert len(variants) > 0
    # One variant should contain %27 (URL-encoded quote)
    assert any("%27" in v for v in variants), f"Should contain URL-encoded variant: {variants}"


def test_payload_generator_nosql():
    """NoSQL templates should contain $gt, $ne, $regex operators."""
    from ai_fuzzer import PayloadGenerator
    gen = PayloadGenerator(goal="nosql")
    payloads = gen.generate_base_payloads(count=5)
    combined = " ".join(payloads)
    assert "$gt" in combined or "$ne" in combined or "$regex" in combined or "$where" in combined, \
        f"Should contain NoSQL operators: {payloads}"


# ─── ai_fuzzer.py: FuzzResult dataclass ──────────────────────────────────────

def test_fuzz_result_defaults():
    """FuzzResult should have sensible defaults."""
    from ai_fuzzer import FuzzResult
    r = FuzzResult(
        url="https://example.com",
        param="id",
        payload="' OR '1'='1",
        vuln_type="sqli",
    )
    assert r.confidence == 0
    assert r.confirmed is False
    assert r.error_keywords == []
    assert r.iteration == 0


# ─── auth_auditor.py: _create_alg_none_jwt ──────────────────────────────────

def test_create_alg_none_jwt():
    """alg=none JWT should have empty signature and correct header."""
    from auth_auditor import AuthAuditor
    auditor = AuthAuditor.__new__(AuthAuditor)
    token = auditor._create_alg_none_jwt()
    parts = token.split(".")
    assert len(parts) == 3, f"JWT should have 3 parts, got {len(parts)}"
    assert parts[2] == "", f"Signature should be empty, got '{parts[2]}'"
    # Decode header
    import base64, json
    header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
    header = json.loads(base64.urlsafe_b64decode(header_b64).decode())
    assert header["alg"] == "none", f"alg should be 'none', got '{header['alg']}'"
    assert header["typ"] == "JWT"


def test_analyze_jwt_missing_exp():
    """JWT without 'exp' claim should be flagged."""
    from auth_auditor import AuthAuditor
    import base64, json
    auditor = AuthAuditor.__new__(AuthAuditor)

    # Create a JWT without exp
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).decode().rstrip("=")
    payload = base64.urlsafe_b64encode(json.dumps({"sub": "user1"}).encode()).decode().rstrip("=")
    token = f"{header}.{payload}.fake_sig"

    issues = auditor._analyze_jwt(token)
    # Should find missing exp and missing iss
    titles = [i.title for i in issues]
    assert any("expiration" in t.lower() for t in titles), f"Should flag missing exp: {titles}"
    assert any("issuer" in t.lower() for t in titles), f"Should flag missing iss: {titles}"


def test_analyze_jwt_alg_none():
    """JWT with alg=none should be flagged as critical."""
    from auth_auditor import AuthAuditor
    import base64, json
    auditor = AuthAuditor.__new__(AuthAuditor)

    header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).decode().rstrip("=")
    payload = base64.urlsafe_b64encode(json.dumps({"sub": "user1", "exp": 9999999999}).encode()).decode().rstrip("=")
    token = f"{header}.{payload}."

    issues = auditor._analyze_jwt(token)
    titles = [i.title for i in issues]
    assert any("alg=none" in t.lower() for t in titles), f"Should flag alg=none: {titles}"
    # Should have critical severity
    assert any(i.severity == "critical" for i in issues), f"Should be critical: {issues}"


# ─── stealth.py: random_user_agent ───────────────────────────────────────────

def test_random_user_agent():
    """random_user_agent should return a valid Chrome UA string."""
    from stealth import random_user_agent, USER_AGENTS
    ua = random_user_agent()
    assert "Chrome" in ua, f"Should contain 'Chrome': {ua}"
    assert "Mozilla" in ua, f"Should contain 'Mozilla': {ua}"
    assert ua in USER_AGENTS, f"Should be from the predefined list: {ua}"


# ─── Run via plain python (no pytest needed) ─────────────────────────────────

if __name__ == "__main__":
    tests = [
        test_bezier_point_endpoints,
        test_bezier_point_midpoint,
        test_generate_trajectory_basic,
        test_generate_trajectory_duration,
        test_payload_generator_sqli,
        test_payload_generator_xss,
        test_payload_generator_mutate,
        test_payload_generator_nosql,
        test_fuzz_result_defaults,
        test_create_alg_none_jwt,
        test_analyze_jwt_missing_exp,
        test_analyze_jwt_alg_none,
        test_random_user_agent,
    ]
    passed = 0
    failed = 0
    for test in tests:
        try:
            test()
            print(f"  [PASS] {test.__name__}")
            passed += 1
        except Exception as e:
            print(f"  [FAIL] {test.__name__}: {e}")
            failed += 1
    print(f"\n{'='*50}")
    print(f"  Results: {passed} passed, {failed} failed, {len(tests)} total")
    print(f"{'='*50}")
    sys.exit(1 if failed else 0)
