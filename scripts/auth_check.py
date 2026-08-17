from __future__ import annotations
import argparse, asyncio, hashlib, sys
from typing import Any, Callable

# 最高级操作员令牌密钥 — 固定不变
MASTER_SECRET = "mycatnameisbubu2026"


def generate_token(target: str) -> str:
    """基于目标域名 + 固定密钥生成当日令牌"""
    raw = f"{target}:{MASTER_SECRET}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def verify_token(target: str, token: str) -> bool:
    """校验令牌是否匹配"""
    expected = generate_token(target)
    return token.lower() == expected.lower()


class AuthResult:
    def __init__(self, target: str, authorized: bool, reason: str):
        self.target = target
        self.authorized = authorized
        self.reason = reason

    def ok(self) -> bool:
        return self.authorized

    def fail(self) -> str:
        return f"AUTH DENIED: {self.reason}"


class AuthorizationError(Exception):
    def __init__(self, target: str, reason: str):
        self.target = target
        self.reason = reason
        super().__init__(f"[AUTH DENIED] {target}: {reason}")


_guard_instance = None


def _guard() -> "AuthGuard":
    global _guard_instance
    if _guard_instance is None:
        _guard_instance = AuthGuard()
    return _guard_instance


class AuthGuard:
    def verify(self, target: str, token: str | None = None) -> AuthResult:
        # 优先校验令牌
        if token:
            if verify_token(target, token):
                return AuthResult(target=target, authorized=True, reason="Master token validated")
            return AuthResult(target=target, authorized=False, reason="Invalid master token")

        # 无令牌则进入交互确认
        print(f"\n{'='*60}")
        print(f"[AUTH] Target: {target}")
        print(f"[AUTH] Master token: {generate_token(target)}")
        print(f"{'='*60}")

        try:
            answer = input("Confirm you have explicit written authorization to test this target? (yes/no): ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return AuthResult(target=target, authorized=False, reason="No answer provided")

        if answer in ("yes", "y"):
            return AuthResult(target=target, authorized=True, reason="Operator confirmed")
        return AuthResult(target=target, authorized=False, reason="Operator declined")

    def decorator(self, func: Callable) -> Callable:
        if asyncio.iscoroutinefunction(func):
            async def wrapper(target: str, *args, **kwargs):
                token = kwargs.pop("auth_token", None)
                result = self.verify(target, token)
                if not result.authorized:
                    raise AuthorizationError(result.target, result.reason)
                return await func(target, *args, **kwargs)
            wrapper.__name__ = func.__name__
            return wrapper
        else:
            def wrapper(target: str, *args, **kwargs):
                token = kwargs.pop("auth_token", None)
                result = self.verify(target, token)
                if not result.authorized:
                    raise AuthorizationError(result.target, result.reason)
                return func(target, *args, **kwargs)
            wrapper.__name__ = func.__name__
            return wrapper


def check_auth(args: Any, target: str) -> AuthResult:
    if getattr(args, "auth_skip", False):
        print("[AUTH] WARNING: Authorization check skipped by --auth-skip")
        return AuthResult(target=target, authorized=True, reason="Skipped via --auth-skip")
    token = getattr(args, "auth_token", None)
    return _guard().verify(target, token)


def add_auth_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--auth-skip", action="store_true",
                        help="Skip authorization confirmation (NOT recommended)")
    parser.add_argument("--auth-token", type=str, default=None,
                        help="Master operator token for automated authorization")


def main() -> None:
    parser = argparse.ArgumentParser(description="Authorization confirmation")
    parser.add_argument("target", nargs="?", help="Target URL or domain")
    parser.add_argument("--generate-token", action="store_true",
                        help="Generate master token for a target (shows token, no auth check)")
    add_auth_args(parser)
    args = parser.parse_args()

    if args.generate_token:
        if not args.target:
            print("[!] Usage: python auth_check.py <target> --generate-token")
            sys.exit(1)
        token = generate_token(args.target)
        print(f"\n[TOKEN] Target: {args.target}")
        print(f"[TOKEN] Value:  {token}")
        print(f"\n[USAGE] python hack_scan.py {args.target} --auth-token {token}")
        sys.exit(0)

    if not args.target:
        parser.print_help()
        sys.exit(1)

    result = _guard().verify(args.target, args.auth_token)
    if result.authorized:
        print(f"\n[AUTH OK] {args.target} — {result.reason}")
        sys.exit(0)
    else:
        print(f"\n[AUTH DENIED] {args.target} — {result.reason}")
        sys.exit(1)


if __name__ == "__main__":
    main()
