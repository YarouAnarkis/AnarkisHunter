"""
AnarkisHunter — vuln_redirect.py
==================================
Open Redirect detector — test parameter yang menerima URL,
cek apakah server me-redirect ke domain external tanpa validasi.

Usage standalone:
    python modules/vuln/vuln_redirect.py --url "http://target.local/redirect?url=test"
"""

import sys
import argparse
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from modules.utils.utils_request import HTTPClient, normalize_url, get_domain
from modules.utils.report import ScanResult


# Payload redirect ke domain attacker
REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "https://evil.com/?",
    "/\\evil.com",
    "////evil.com",
    "https:evil.com",
    "https://target.com.evil.com",
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
]

# Parameter umum untuk redirect
COMMON_REDIRECT_PARAMS = [
    "url", "next", "redirect", "redirect_url", "redirect_uri",
    "return", "return_url", "returnUrl", "back", "back_url",
    "goto", "go", "to", "u", "r", "destination", "continue",
    "callback", "callback_url", "callbackUrl", "dest",
]


def inject_param(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    params[param] = payload
    return urlunparse(parsed._replace(query=urlencode(params)))


def run_redirect_scan(
    target: str,
    params: Optional[List[str]] = None,
    payloads: Optional[List[str]] = None,
    timeout: int = 10,
) -> Dict:
    url = normalize_url(target)
    parsed = urlparse(url)
    url_params = dict(parse_qsl(parsed.query, keep_blank_values=True))

    if not params:
        # Test parameter dari URL + common params
        params = list(url_params.keys()) + COMMON_REDIRECT_PARAMS
        params = list(dict.fromkeys(params))

    payloads = payloads or REDIRECT_PAYLOADS
    target_domain = get_domain(url)

    result = {
        "target": url,
        "params_tested": params,
        "payloads_used": len(payloads),
        "vulnerabilities": [],
        "error": None,
    }

    try:
        with HTTPClient(timeout=timeout, follow_redirects=False) as client:
            for param in params:
                for payload in payloads:
                    test_url = inject_param(url, param, payload)
                    resp = client.get(test_url)
                    if not resp:
                        continue

                    # 3xx + Location ke domain external?
                    if 300 <= resp.status_code < 400:
                        loc = resp.headers.get("Location", "")
                        if not loc:
                            continue
                        loc_low = loc.lower()
                        # Match domain "evil.com" atau "javascript:"
                        if ("evil.com" in loc_low or
                                loc_low.startswith("javascript:") or
                                loc_low.startswith("data:")):
                            result["vulnerabilities"].append({
                                "param": param,
                                "payload": payload,
                                "type": "Open Redirect",
                                "redirect_to": loc,
                                "status": resp.status_code,
                                "url": test_url,
                            })
                            continue
                        # Domain external
                        try:
                            redirect_domain = get_domain(loc) if loc.startswith("http") else None
                        except Exception:
                            redirect_domain = None
                        if redirect_domain and redirect_domain != target_domain:
                            if "evil" in redirect_domain or redirect_domain in payload.lower():
                                result["vulnerabilities"].append({
                                    "param": param,
                                    "payload": payload,
                                    "type": "Open Redirect (external domain)",
                                    "redirect_to": loc,
                                    "status": resp.status_code,
                                    "url": test_url,
                                })

                    # Meta refresh / JS redirect detection (200 + JS redirect)
                    if resp.status_code == 200:
                        body = resp.text[:3000]
                        if (("evil.com" in body and "location" in body.lower()) or
                                "window.location" in body and "evil.com" in body):
                            result["vulnerabilities"].append({
                                "param": param,
                                "payload": payload,
                                "type": "Open Redirect (JS / Meta refresh)",
                                "redirect_to": "JS redirect to evil.com",
                                "status": resp.status_code,
                                "url": test_url,
                            })

    except Exception as e:
        result["error"] = str(e)

    return result


def analyze_redirect_findings(data: Dict) -> List[ScanResult]:
    findings = []
    seen = set()
    for v in data.get("vulnerabilities", []):
        key = (v["param"], v["type"])
        if key in seen:
            continue
        seen.add(key)
        findings.append(ScanResult(
            title=f"Open Redirect on parameter '{v['param']}'",
            severity="MEDIUM",
            description=f"Parameter '{v['param']}' menerima URL eksternal tanpa validasi.",
            url=v["url"],
            evidence=f"Redirected to: {v['redirect_to']}",
            payload=v["payload"],
            recommendation=(
                "Validate URL whitelist; jangan terima absolute URL eksternal; "
                "redirect via index path saja"
            ),
            owasp="A01",
            module="vuln_redirect",
        ))
    return findings


# ─── Standalone ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from rich.console import Console
    from rich.table import Table

    console = Console()
    parser = argparse.ArgumentParser(description="AnarkisHunter — Open Redirect")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--param", nargs="+")
    args = parser.parse_args()

    console.print(f"\n[red]↪  Open Redirect Scan: [bold]{args.url}[/bold][/red]\n")
    data = run_redirect_scan(args.url, args.param)

    if data.get("error"):
        console.print(f"[red]Error: {data['error']}[/red]")
        sys.exit(1)

    console.print(f"[green]Params:[/green] {len(data['params_tested'])} | [green]Payloads:[/green] {data['payloads_used']}")
    console.print(f"[red]Vulnerabilities:[/red] {len(data['vulnerabilities'])}\n")

    if data["vulnerabilities"]:
        t = Table(title="🚨 Open Redirects", border_style="red")
        t.add_column("Param", style="cyan")
        t.add_column("Type", style="yellow")
        t.add_column("Redirect", style="red", overflow="fold")
        for v in data["vulnerabilities"][:20]:
            t.add_row(v["param"], v["type"], v["redirect_to"][:80])
        console.print(t)
