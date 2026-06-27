"""
AnarkisHunter — vuln_ratelimit.py
====================================
Rate limit & brute force protection checker.
Kirim N request cepat, cek apakah server menerapkan rate limit
(429 Too Many Requests / 503 / cookie challenge).

Usage standalone:
    python modules/vuln/vuln_ratelimit.py --url http://target.local/login
"""

import sys
import time
import argparse
from pathlib import Path
from typing import Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from modules.utils.utils_request import HTTPClient, normalize_url
from modules.utils.report import ScanResult


def run_ratelimit_check(
    target: str,
    requests_count: int = 30,
    method: str = "GET",
    data: Dict = None,
    timeout: int = 8,
) -> Dict:
    url = normalize_url(target)
    result = {
        "url": url,
        "method": method,
        "total_requests": requests_count,
        "status_distribution": {},
        "rate_limited": False,
        "rate_limit_status": None,
        "rate_limit_header": None,
        "avg_latency": 0.0,
        "blocked_after": None,
        "error": None,
    }

    try:
        with HTTPClient(timeout=timeout) as client:
            latencies = []
            for i in range(requests_count):
                t0 = time.time()
                if method == "POST":
                    resp = client.post(url, data=data or {})
                else:
                    resp = client._request(method, url)
                elapsed = time.time() - t0
                if not resp:
                    continue
                latencies.append(elapsed)
                code = resp.status_code
                result["status_distribution"][code] = result["status_distribution"].get(code, 0) + 1

                # Check for rate limit headers
                for h in ["X-RateLimit-Limit", "X-RateLimit-Remaining", "Retry-After"]:
                    if h in resp.headers and not result["rate_limit_header"]:
                        result["rate_limit_header"] = f"{h}: {resp.headers[h]}"

                if code in (429, 503):
                    result["rate_limited"] = True
                    result["rate_limit_status"] = code
                    if result["blocked_after"] is None:
                        result["blocked_after"] = i + 1
                    break

            if latencies:
                result["avg_latency"] = sum(latencies) / len(latencies)

    except Exception as e:
        result["error"] = str(e)

    return result


def analyze_ratelimit_findings(data: Dict) -> List[ScanResult]:
    findings = []
    url = data.get("url", "")

    if not data.get("rate_limited") and not data.get("rate_limit_header"):
        findings.append(ScanResult(
            title="No Rate Limiting Detected",
            severity="MEDIUM",
            description=(
                f"Server tidak menerapkan rate limit. {data['total_requests']} request berhasil "
                "tanpa block. Rentan brute force / DoS."
            ),
            url=url,
            evidence=f"Status distribution: {data['status_distribution']}",
            recommendation=(
                "Implementasikan rate limit (mis. nginx limit_req, Flask-Limiter); "
                "tambah CAPTCHA setelah N percobaan gagal; account lockout temporary"
            ),
            owasp="A04",
            module="vuln_ratelimit",
        ))
    else:
        findings.append(ScanResult(
            title=f"Rate Limit Active (blocked after {data.get('blocked_after')} req)",
            severity="INFO",
            description=(
                f"Server menerapkan rate limit. "
                f"Block setelah {data.get('blocked_after')} request "
                f"({data.get('rate_limit_status')})"
            ),
            url=url,
            evidence=data.get("rate_limit_header") or f"Status: {data.get('rate_limit_status')}",
            module="vuln_ratelimit",
        ))

    return findings


# ─── Standalone ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from rich.console import Console

    console = Console()
    parser = argparse.ArgumentParser(description="AnarkisHunter — Rate Limit Check")
    parser.add_argument("--url", required=True)
    parser.add_argument("--count", type=int, default=30)
    parser.add_argument("--method", default="GET")
    args = parser.parse_args()

    console.print(f"\n[red]🚦 Rate Limit Check: [bold]{args.url}[/bold] ({args.count} req)[/red]\n")
    data = run_ratelimit_check(args.url, requests_count=args.count, method=args.method)
    if data.get("error"):
        console.print(f"[red]Error: {data['error']}[/red]")
        sys.exit(1)

    console.print(f"[green]Status distribution:[/green] {data['status_distribution']}")
    console.print(f"[green]Avg latency:[/green] {data['avg_latency']:.3f}s")
    if data["rate_limited"]:
        console.print(f"[green]✓ Rate limited after {data['blocked_after']} requests ({data['rate_limit_status']})[/green]")
    else:
        console.print(f"[red]✗ No rate limit detected[/red]")
    if data["rate_limit_header"]:
        console.print(f"[cyan]Header: {data['rate_limit_header']}[/cyan]")
