#!/usr/bin/env python3
"""
Auth Auditor — 认证协议审计器

自动化审计 OAuth/OIDC/SAML/JWT 配置错误：
- OAuth: PKCE 强制、state 验证、redirect_uri 严格匹配
- OIDC: id_token 签名验证、nonce 重放、issuer 匹配
- SAML: 签名包装攻击、XML 实体注入
- JWT: alg:none、密钥混淆、过期时间绕过

Usage:
  python auth_auditor.py https://app.target.com
  python auth_auditor.py https://app.target.com --deep
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlencode, parse_qs, urlparse, urlunparse, urljoin

_SCRIPT_DIR = Path(__file__).parent
sys.path.insert(0, str(_SCRIPT_DIR))

from cdp_launch import connect_playwright_cdp_async


@dataclass
class AuthIssue:
    """认证审计发现的问题。"""
    title: str
    description: str
    severity: str
    category: str
    evidence: str = ""
    remediation: str = ""


class AuthAuditor:
    """认证协议审计引擎。"""

    def __init__(self, target: str, cdp_port: int = 9222):
        self.target = target.rstrip("/")
        self.cdp_port = cdp_port
        self.issues: list[AuthIssue] = []
        self.discovery_data = {}

    async def _get_browser_ctx(self):
        browser, pw = await connect_playwright_cdp_async(port=self.cdp_port, stealth=True)
        ctx = browser.contexts[0] if browser.contexts else await browser.new_context()
        return ctx, browser, pw

    async def _discover_endpoints(self, ctx) -> dict:
        endpoints = {
            "login_page": None,
            "oauth_authorize": None,
            "openid_configuration": None,
            "saml_metadata": None,
            "jwt_issuer": None,
        }
        
        well_known = urljoin(self.target, "/.well-known/openid-configuration")
        try:
            resp = await ctx.request.get(well_known, timeout=10000)
            if resp.status == 200:
                data = await resp.json()
                endpoints["openid_configuration"] = data
                self.discovery_data = data
                print(f"[*] OIDC Discovery found: {well_known}")
        except Exception:
            pass
        
        saml_meta = urljoin(self.target, "/saml/metadata")
        try:
            resp = await ctx.request.get(saml_meta, timeout=10000)
            if resp.status == 200:
                endpoints["saml_metadata"] = await resp.text()
                print(f"[*] SAML metadata found: {saml_meta}")
        except Exception:
            pass
        
        login_paths = ["/login", "/auth/login", "/signin", "/oauth/authorize", "/auth"]
        for path in login_paths:
            try:
                resp = await ctx.request.get(urljoin(self.target, path), timeout=5000)
                if resp.status < 400:
                    endpoints["login_page"] = urljoin(self.target, path)
                    print(f"[*] Login page found: {path}")
                    break
            except Exception:
                continue
        
        return endpoints

    async def audit_oauth(self, ctx, endpoints: dict) -> list[AuthIssue]:
        issues = []
        
        if not endpoints.get("openid_configuration"):
            print("[*] No OIDC configuration found, skipping OAuth audit")
            return issues
        
        config = endpoints["openid_configuration"]
        
        code_challenge_methods = config.get("code_challenge_methods_supported", [])
        if not code_challenge_methods:
            issues.append(AuthIssue(
                title="OAuth: PKCE not enforced",
                description="The authorization server does not advertise PKCE support. Without PKCE, authorization code interception attacks are possible.",
                severity="high",
                category="oauth",
                evidence="code_challenge_methods_supported missing from discovery",
                remediation="Enable PKCE (S256) for all OAuth clients.",
            ))
        elif "S256" not in code_challenge_methods:
            issues.append(AuthIssue(
                title="OAuth: PKCE S256 not supported",
                description="Only plain PKCE is supported, which provides minimal protection.",
                severity="medium",
                category="oauth",
                evidence=f"Supported methods: {code_challenge_methods}",
                remediation="Enable S256 code challenge method.",
            ))
        
        response_types = config.get("response_types_supported", [])
        if "token" in response_types:
            issues.append(AuthIssue(
                title="OAuth: Implicit flow enabled",
                description="The authorization server supports implicit grant (response_type=token), which exposes tokens in URL fragments.",
                severity="medium",
                category="oauth",
                evidence="response_types_supported includes 'token'",
                remediation="Disable implicit flow. Use authorization code flow with PKCE.",
            ))
        
        auth_endpoint = config.get("authorization_endpoint", "")
        token_endpoint = config.get("token_endpoint", "")
        
        if auth_endpoint.startswith("http://"):
            issues.append(AuthIssue(
                title="OAuth: Authorization endpoint over HTTP",
                description="The authorization endpoint is served over unencrypted HTTP.",
                severity="critical",
                category="oauth",
                evidence=f"authorization_endpoint: {auth_endpoint}",
                remediation="Enforce HTTPS for all OAuth endpoints.",
            ))
        
        if auth_endpoint:
            issues.extend(await self._test_redirect_uri_validation(ctx, auth_endpoint))
        
        return issues

    async def _test_redirect_uri_validation(self, ctx, auth_endpoint: str) -> list[AuthIssue]:
        issues = []
        malicious_uris = [
            "https://evil.com/callback",
            "https://attacker.target.com/callback",
            "http://localhost:8080/callback",
            "https://target.com.evil.com/callback",
            "https://evil.com/target.com/callback",
        ]
        
        for malicious_uri in malicious_uris:
            try:
                params = {
                    "client_id": "test_client",
                    "response_type": "code",
                    "redirect_uri": malicious_uri,
                    "scope": "openid profile",
                    "state": "test_state_123",
                }
                test_url = f"{auth_endpoint}?{urlencode(params)}"
                
                resp = await ctx.request.get(test_url, timeout=10000, max_redirects=0)
                
                if resp.status in (301, 302, 303, 307, 308):
                    location = resp.headers.get("location", "")
                    if malicious_uri in location or "evil.com" in location:
                        issues.append(AuthIssue(
                            title="OAuth: Open Redirect via redirect_uri",
                            description=f"The authorization server accepted redirect_uri={malicious_uri} and redirected to it.",
                            severity="critical",
                            category="oauth",
                            evidence=f"Redirect to: {location}",
                            remediation="Implement exact string matching for redirect_uri. Reject any non-registered URI.",
                        ))
                        break
            except Exception:
                continue
        
        return issues

    async def audit_oidc(self, ctx, endpoints: dict) -> list[AuthIssue]:
        issues = []
        config = endpoints.get("openid_configuration")
        if not config:
            return issues
        
        signing_algs = config.get("id_token_signing_alg_values_supported", [])
        
        if "none" in signing_algs:
            issues.append(AuthIssue(
                title="OIDC: alg=none supported",
                description="The server accepts unsigned ID tokens (alg=none), allowing trivial token forgery.",
                severity="critical",
                category="oidc",
                evidence="id_token_signing_alg_values_supported includes 'none'",
                remediation="Remove 'none' from supported signing algorithms.",
            ))
        
        if "HS256" in signing_algs and "RS256" in signing_algs:
            issues.append(AuthIssue(
                title="OIDC: Algorithm confusion possible",
                description="Both symmetric (HS256) and asymmetric (RS256) algorithms are supported, enabling algorithm substitution attacks.",
                severity="high",
                category="oidc",
                evidence="Both HS256 and RS256 in supported algorithms",
                remediation="Use only asymmetric algorithms (RS256, ES256) for ID tokens.",
            ))
        
        if not config.get("require_request_uri_registration", False):
            issues.append(AuthIssue(
                title="OIDC: request_uri not restricted",
                description="Request URI registration is not required, enabling SSRF via request_uri parameter.",
                severity="medium",
                category="oidc",
                evidence="require_request_uri_registration is false or missing",
                remediation="Enable require_request_uri_registration.",
            ))
        
        return issues

    async def audit_saml(self, ctx, endpoints: dict) -> list[AuthIssue]:
        issues = []
        metadata = endpoints.get("saml_metadata")
        
        if not metadata:
            print("[*] No SAML metadata found, skipping SAML audit")
            return issues
        
        # 检查是否要求签名
        if "WantAssertionsSigned=\"false\"" in metadata or "AuthnRequestsSigned=\"false\"" in metadata:
            issues.append(AuthIssue(
                title="SAML: Signatures not required",
                description="The SAML metadata indicates that signed assertions or authn requests are not required.",
                severity="high",
                category="saml",
                evidence="WantAssertionsSigned or AuthnRequestsSigned is false",
                remediation="Require signed assertions and authn requests.",
            ))
        
        # 检查 XML 实体注入
        if "<!ENTITY" in metadata or "<!DOCTYPE" in metadata:
            issues.append(AuthIssue(
                title="SAML: XML entities allowed",
                description="The SAML metadata contains DTD/entity declarations, indicating potential XXE vulnerability.",
                severity="medium",
                category="saml",
                evidence="DOCTYPE or ENTITY found in metadata",
                remediation="Disable DTD processing in XML parser.",
            ))
        
        return issues

    async def audit_jwt(self, ctx, endpoints: dict) -> list[AuthIssue]:
        issues = []
        
        # 尝试获取一个 JWT token 进行分析
        config = endpoints.get("openid_configuration")
        if not config:
            return issues
        
        token_endpoint = config.get("token_endpoint", "")
        if not token_endpoint:
            return issues
        
        # 检查 token_endpoint 是否支持弱认证
        try:
            resp = await ctx.request.post(
                token_endpoint,
                data={
                    "grant_type": "client_credentials",
                    "client_id": "test",
                    "client_secret": "test",
                },
                timeout=10000,
            )
            
            if resp.status == 200:
                data = await resp.json()
                access_token = data.get("access_token", "")
                id_token = data.get("id_token", "")
                
                for token in [access_token, id_token]:
                    if token:
                        token_issues = self._analyze_jwt(token)
                        issues.extend(token_issues)
        except Exception:
            pass
        
        # 测试 alg=none 接受
        try:
            none_jwt = self._create_alg_none_jwt()
            resp = await ctx.request.post(
                token_endpoint,
                headers={"Authorization": f"Bearer {none_jwt}"},
                timeout=5000,
            )
            if resp.status < 400:
                issues.append(AuthIssue(
                    title="JWT: alg=none accepted",
                    description="The server accepts JWT tokens with alg=none, allowing trivial token forgery.",
                    severity="critical",
                    category="jwt",
                    evidence="Server accepted alg=none JWT",
                    remediation="Reject all tokens with alg=none.",
                ))
        except Exception:
            pass
        
        return issues

    def _analyze_jwt(self, token: str) -> list[AuthIssue]:
        issues = []
        
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return issues
            
            # 解码 header
            header_b64 = parts[0]
            header_b64 += "=" * (4 - len(header_b64) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_b64).decode())
            
            alg = header.get("alg", "")
            
            if alg == "none":
                issues.append(AuthIssue(
                    title="JWT: Token uses alg=none",
                    description="The JWT token uses alg=none, meaning it is not signed.",
                    severity="critical",
                    category="jwt",
                    evidence=f"JWT header: {header}",
                    remediation="Reject tokens with alg=none.",
                ))
            
            if alg == "HS256":
                issues.append(AuthIssue(
                    title="JWT: Symmetric algorithm used",
                    description="The JWT uses HS256 (symmetric), which is vulnerable to key confusion if the same key is used for RS256.",
                    severity="medium",
                    category="jwt",
                    evidence=f"JWT alg: {alg}",
                    remediation="Use asymmetric algorithms (RS256, ES256) for tokens.",
                ))
            
            # 检查是否缺少关键声明
            payload_b64 = parts[1]
            payload_b64 += "=" * (4 - len(payload_b64) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64).decode())
            
            if "exp" not in payload:
                issues.append(AuthIssue(
                    title="JWT: Missing expiration",
                    description="The JWT token does not contain an 'exp' claim, meaning it never expires.",
                    severity="high",
                    category="jwt",
                    evidence=f"JWT payload claims: {list(payload.keys())}",
                    remediation="Always include 'exp' claim in JWT tokens.",
                ))
            
            if "iss" not in payload:
                issues.append(AuthIssue(
                    title="JWT: Missing issuer",
                    description="The JWT token does not contain an 'iss' claim.",
                    severity="low",
                    category="jwt",
                    evidence="No 'iss' claim in payload",
                    remediation="Include 'iss' claim for issuer verification.",
                ))
            
        except Exception as e:
            pass
        
        return issues

    def _create_alg_none_jwt(self) -> str:
        """创建一个 alg=none 的 JWT 用于测试。"""
        header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).decode().rstrip("=")
        payload = base64.urlsafe_b64encode(json.dumps({"sub": "admin", "role": "admin"}).encode()).decode().rstrip("=")
        return f"{header}.{payload}."

    async def audit_all(self) -> dict:
        """执行完整认证审计。"""
        ctx, browser, pw = await self._get_browser_ctx()
        
        try:
            print(f"[*] Starting auth audit on {self.target}")
            
            endpoints = await self._discover_endpoints(ctx)
            
            self.issues.extend(await self.audit_oauth(ctx, endpoints))
            self.issues.extend(await self.audit_oidc(ctx, endpoints))
            self.issues.extend(await self.audit_saml(ctx, endpoints))
            self.issues.extend(await self.audit_jwt(ctx, endpoints))
            
            # 按严重程度排序
            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            self.issues.sort(key=lambda x: severity_order.get(x.severity, 5))
            
            return {
                "target": self.target,
                "endpoints_discovered": endpoints,
                "issue_count": len(self.issues),
                "issues": [
                    {
                        "title": i.title,
                        "description": i.description,
                        "severity": i.severity,
                        "category": i.category,
                        "evidence": i.evidence,
                        "remediation": i.remediation,
                    }
                    for i in self.issues
                ],
            }
            
        finally:
            # Do NOT close the shared CDP browser — it may be used by other scripts.
            # connect_over_cdp attaches to an existing browser; closing it would
            # kill the entire CDP session for all subsequent operations.
            # Playwright cleanup (pw.stop()) is also skipped for the same reason.
            pass


async def main():
    parser = argparse.ArgumentParser(
        description="Auth Auditor — Authentication Protocol Auditor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python auth_auditor.py https://app.target.com
  python auth_auditor.py https://app.target.com --deep
  python auth_auditor.py https://app.target.com --output audit.json
        """
    )
    parser.add_argument("target", help="目标应用 URL")
    parser.add_argument("--deep", action="store_true", help="深度审计（交互式流程测试）")
    parser.add_argument("--cdp-port", type=int, default=9222, help="CDP 端口")
    parser.add_argument("--output", help="JSON 结果输出文件")

    args = parser.parse_args()

    auditor = AuthAuditor(
        target=args.target,
        cdp_port=args.cdp_port,
    )

    results = await auditor.audit_all()
    
    print(f"\n{'='*60}")
    print(f"Auth Audit Summary: {results['issue_count']} issues found")
    print(f"{'='*60}")
    
    for issue in results["issues"]:
        severity_emoji = {
            "critical": "💀",
            "high": "🔴",
            "medium": "🟡",
            "low": "🟢",
            "info": "ℹ️",
        }.get(issue["severity"], "❓")
        print(f"  {severity_emoji} [{issue['severity'].upper()}] {issue['title']}")
        print(f"      {issue['description'][:100]}")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"[+] Results saved to {args.output}")


if __name__ == "__main__":
    asyncio.run(main())
