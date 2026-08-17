#!/usr/bin/env python3
"""
Orchestrator — 统一攻击调度器

协调 recon、AI 模糊测试、认证审计三个阶段，
自动选择最优攻击路径，输出统一报告。

Usage:
  python orchestrator.py https://target.com
  python orchestrator.py https://target.com --full          # 全阶段
  python orchestrator.py https://target.com --ai-fuzz       # 仅 AI 模糊测试
  python orchestrator.py https://target.com --auth-audit    # 仅认证审计
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

_SCRIPT_DIR = Path(__file__).parent
sys.path.insert(0, str(_SCRIPT_DIR))

# Import our new modules (will be created alongside)
from ai_fuzzer import AdaptiveFuzzer, FuzzResult
from auth_auditor import AuthAuditor

# Import existing CDP infrastructure
from cdp_launch import connect_playwright_cdp_async, is_cdp_running, launch_cdp


class AttackOrchestrator:
    """
    统一攻击编排器。

    Phase 1: Recon — 技术栈识别、端点发现
    Phase 2: AI Fuzz — 自适应漏洞发现
    Phase 3: Auth Audit — 认证协议审计
    """

    def __init__(self, target: str, cdp_port: int = 9222, output_dir: str = None):
        self.target = target.rstrip("/")
        self.domain = urlparse(self.target).netloc
        self.cdp_port = cdp_port
        self.output_dir = Path(output_dir) if output_dir else Path("reports")
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.recon_data = {}
        self.fuzz_results: list[FuzzResult] = []
        self.auth_results = {}
        self.timeline = []

    def _log(self, phase: str, msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        entry = f"[{ts}] [{phase}] {msg}"
        self.timeline.append(entry)
        print(entry)

    async def _ensure_cdp(self):
        """确保 CDP 浏览器已启动。"""
        if not is_cdp_running(self.cdp_port):
            self._log("SETUP", f"CDP not running on port {self.cdp_port}, launching...")
            launch_cdp(port=self.cdp_port, stealth=True)
            await asyncio.sleep(3)
        else:
            self._log("SETUP", f"CDP already running on port {self.cdp_port}")

    async def phase_recon(self) -> dict:
        """
        Phase 1: 快速侦察
        使用 CDP 获取目标基础信息，推断技术栈。
        """
        self._log("RECON", f"Starting recon on {self.target}")

        browser, pw = await connect_playwright_cdp_async(port=self.cdp_port, stealth=True)
        ctx = browser.contexts[0] if browser.contexts else await browser.new_context()
        page = await ctx.new_page()

        try:
            resp = await page.goto(self.target, wait_until="networkidle", timeout=30000)
            
            # 收集基础信息
            title = await page.title()
            headers = resp.headers if resp else {}
            
            # 推断技术栈
            tech_stack = self._infer_tech_stack(headers, await page.content())
            
            # 检查常见路径
            api_paths = ["/api", "/graphql", "/wp-json", "/swagger", "/api/v1"]
            found_paths = []
            for path in api_paths:
                try:
                    r = await ctx.request.get(f"{self.target}{path}", timeout=5000)
                    if r.status < 404:
                        found_paths.append({"path": path, "status": r.status})
                except Exception:
                    pass

            self.recon_data = {
                "target": self.target,
                "title": title,
                "server": headers.get("server", "unknown"),
                "tech_stack": tech_stack,
                "api_paths": found_paths,
                "has_login": await self._detect_login_page(page),
            }

            self._log("RECON", f"Tech stack: {', '.join(tech_stack)}")
            self._log("RECON", f"API paths found: {len(found_paths)}")
            self._log("RECON", f"Login page: {self.recon_data['has_login']}")

        finally:
            await page.close()

        return self.recon_data

    def _infer_tech_stack(self, headers: dict, html: str) -> list[str]:
        """根据响应头和 HTML 推断技术栈。"""
        stack = []
        server = headers.get("server", "").lower()
        
        if "nginx" in server:
            stack.append("nginx")
        if "apache" in server:
            stack.append("apache")
        if "cloudflare" in server:
            stack.append("cloudflare")
        
        html_lower = html.lower()
        if "wp-content" in html_lower or "wp-json" in html_lower:
            stack.append("wordpress")
        if "react" in html_lower or "__react" in html_lower:
            stack.append("react")
        if "vue" in html_lower:
            stack.append("vue")
        if "next.js" in html_lower or "_next" in html_lower:
            stack.append("nextjs")
        if "graphql" in html_lower:
            stack.append("graphql")
        if "swagger" in html_lower or "openapi" in html_lower:
            stack.append("swagger")
        if "django" in html_lower:
            stack.append("django")
        if "laravel" in html_lower:
            stack.append("laravel")
        if "spring" in html_lower:
            stack.append("spring")
        
        x_powered = headers.get("x-powered-by", "").lower()
        if "php" in x_powered:
            stack.append("php")
        if "asp.net" in x_powered:
            stack.append("aspnet")
        
        return stack

    async def _detect_login_page(self, page) -> bool:
        """检测页面是否包含登录表单。"""
        selectors = [
            "input[type='password']",
            "input[name*='password']",
            "input[name*='passwd']",
            "input[id*='password']",
            "button[type='submit']",
            "a[href*='login']",
            "a[href*='signin']",
            "a[href*='auth']",
        ]
        for sel in selectors:
            try:
                if await page.locator(sel).count() > 0:
                    return True
            except Exception:
                continue
        return False

    async def phase_ai_fuzz(self, params: list[str] = None, goal: str = "sqli") -> list[FuzzResult]:
        """
        Phase 2: AI 自适应模糊测试
        """
        self._log("AI-FUZZ", f"Starting adaptive fuzzing, goal={goal}")

        fuzzer = AdaptiveFuzzer(
            target=self.target,
            cdp_port=self.cdp_port,
            goal=goal,
        )

        # 自动发现参数
        if not params:
            params = await fuzzer.discover_params()
            self._log("AI-FUZZ", f"Auto-discovered params: {params}")

        results = []
        for param in params:
            self._log("AI-FUZZ", f"Fuzzing param: {param}")
            param_results = await fuzzer.fuzz_param(param, max_iterations=30)
            results.extend(param_results)

        self.fuzz_results = results
        
        # 统计
        confirmed = [r for r in results if r.confirmed]
        self._log("AI-FUZZ", f"Total payloads: {len(results)}, Confirmed: {len(confirmed)}")
        
        return results

    async def phase_auth_audit(self) -> dict:
        """
        Phase 4: 认证协议审计
        仅在检测到登录页面时执行。
        """
        if not self.recon_data.get("has_login"):
            self._log("AUTH", "No login page detected, skipping auth audit phase")
            return {}

        self._log("AUTH", "Starting authentication protocol audit")

        auditor = AuthAuditor(
            target=self.target,
            cdp_port=self.cdp_port,
        )

        results = await auditor.audit_all()
        self.auth_results = results
        
        issues = len(results.get("issues", []))
        self._log("AUTH", f"Issues found: {issues}")
        
        return results

    def generate_report(self) -> str:
        """生成统一 Markdown 报告。"""
        report_path = self.output_dir / f"report_{self.domain}_{int(time.time())}.md"
        
        lines = [
            f"# 渗透测试报告: {self.target}",
            f"",
            f"**生成时间:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"**目标:** {self.target}",
            f"",
            "---",
            "",
            "## 执行时间线",
            "",
        ]
        for entry in self.timeline:
            lines.append(f"- {entry}")
        
        lines.extend([
            "",
            "---",
            "",
            "## Phase 1: 侦察结果",
            "",
            f"```json\n{json.dumps(self.recon_data, indent=2, ensure_ascii=False)}\n```",
            "",
            "---",
            "",
            "## Phase 2: AI 模糊测试",
            "",
        ])
        
        if self.fuzz_results:
            confirmed = [r for r in self.fuzz_results if r.confirmed]
            lines.append(f"**总 Payload 数:** {len(self.fuzz_results)}")
            lines.append(f"**确认漏洞:** {len(confirmed)}")
            lines.append("")
            for r in confirmed[:20]:  # 最多显示 20 个
                lines.append(f"### {r.vuln_type} @ {r.url}")
                lines.append(f"- **参数:** `{r.param}`")
                lines.append(f"- **Payload:** `{r.payload[:200]}`")
                lines.append(f"- **置信度:** {r.confidence}%")
                lines.append(f"- **响应特征:** {r.response_signature}")
                lines.append("")
        else:
            lines.append("未执行或未发现漏洞。")
        
        lines.extend([
            "",
            "---",
            "",
            "## Phase 3: 认证审计",
            "",
        ])
        
        if self.auth_results:
            issues = self.auth_results.get("issues", [])
            for issue in issues:
                severity = issue.get("severity", "info")
                lines.append(f"- **[{severity.upper()}]** {issue.get('title', 'Unknown')}")
                lines.append(f"  - {issue.get('description', '')}")
        else:
            lines.append("未检测到登录页面或跳过此阶段。")
        
        lines.extend([
            "",
            "---",
            "",
            "## 总结",
            "",
        ])
        
        total_issues = (
            len([r for r in self.fuzz_results if r.confirmed]) +
            len(self.auth_results.get("issues", []))
        )
        lines.append(f"**总发现问题数:** {total_issues}")
        
        report_text = "\n".join(lines)
        report_path.write_text(report_text, encoding="utf-8")
        
        self._log("REPORT", f"Report saved to {report_path}")
        return str(report_path)

    async def run(self, phases: list[str] = None):
        """
        执行完整攻击链。

        Args:
            phases: 指定执行的阶段，默认全部
        """
        if phases is None:
            phases = ["recon", "ai_fuzz", "auth_audit"]

        await self._ensure_cdp()

        if "recon" in phases:
            await self.phase_recon()

        if "ai_fuzz" in phases:
            # 自动推断目标类型
            goal = "sqli"
            if "graphql" in self.recon_data.get("tech_stack", []):
                goal = "graphql_injection"
            await self.phase_ai_fuzz(goal=goal)

        if "auth_audit" in phases:
            await self.phase_auth_audit()

        report_path = self.generate_report()
        return report_path


async def main():
    parser = argparse.ArgumentParser(
        description="Attack Orchestrator — 统一渗透测试调度器",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python orchestrator.py https://target.com              # 全阶段
  python orchestrator.py https://target.com --ai-fuzz    # 仅 AI 模糊测试
  python orchestrator.py https://target.com --auth-audit  # 仅认证审计
  python orchestrator.py https://target.com --full        # 显式全阶段
        """
    )
    parser.add_argument("target", help="目标 URL")
    parser.add_argument("--cdp-port", type=int, default=9222, help="CDP 端口")
    parser.add_argument("--output-dir", default="reports", help="报告输出目录")
    parser.add_argument("--full", action="store_true", help="执行全阶段")
    parser.add_argument("--ai-fuzz", action="store_true", help="仅 AI 模糊测试")
    parser.add_argument("--auth-audit", action="store_true", help="仅认证审计")
    parser.add_argument("--recon-only", action="store_true", help="仅侦察")

    from auth_check import add_auth_args, check_auth
    add_auth_args(parser)

    args = parser.parse_args()

    auth_result = check_auth(args, args.target)
    if not auth_result.authorized:
        print(f"\n[ERROR] {auth_result.fail()}")
        sys.exit(1)

    # 确定执行阶段
    phases = []
    if args.recon_only:
        phases = ["recon"]
    elif args.ai_fuzz:
        phases = ["recon", "ai_fuzz"]
    elif args.auth_audit:
        phases = ["recon", "auth_audit"]
    else:
        phases = ["recon", "ai_fuzz", "auth_audit"]

    orch = AttackOrchestrator(
        target=args.target,
        cdp_port=args.cdp_port,
        output_dir=args.output_dir,
    )

    report_path = await orch.run(phases=phases)
    print(f"\n[+] Report: {report_path}")


if __name__ == "__main__":
    asyncio.run(main())
