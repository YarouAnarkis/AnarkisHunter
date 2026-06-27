"""
AnarkisHunter — vuln_xss.py
=============================
Cross-Site Scripting detector (Reflected XSS).
Inject payload ke parameter, cek apakah payload muncul di response tanpa encoding.

Usage standalone:
    python modules/vuln/vuln_xss.py --url "http://target.local/search?q=test"
"""

import sys
import re
import argparse
import html
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from modules.utils.utils_request import HTTPClient, normalize_url
from modules.utils.utils_payload import payload_manager
from modules.utils.report import ScanResult


# Marker token unik untuk reflection detection
XSS_MARKER = "ANARKxss42"

# Payload yang dipakai untuk test (sebagian besar dengan marker)
TEST_PAYLOADS = [
    f"<script>alert('{XSS_MARKER}')</script>",
    f"<img src=x onerror=alert('{XSS_MARKER}')>",
    f"<svg/onload=alert('{XSS_MARKER}')>",
    f"\"><script>alert('{XSS_MARKER}')</script>",
    f"'><script>alert('{XSS_MARKER}')</script>",
    f"javascript:alert('{XSS_MARKER}')",
    f"<iframe src='javascript:alert(\\'{XSS_MARKER}\\')'>",
    f"<body onload=alert('{XSS_MARKER}')>",
    f"<input onfocus=alert('{XSS_MARKER}') autofocus>",
    f"<details open ontoggle=alert('{XSS_MARKER}')>",
]


def inject_param(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    params[param] = payload
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def check_reflection(response_body: str, payload: str) -> Dict:
    """Cek apakah payload reflected, dan dalam konteks apa."""
    result = {
        "reflected": False,
        "encoded": False,
        "exact_match": False,
        "context": "unknown",
    }
    # Exact match (high confidence)
    if payload in response_body:
        result["reflected"] = True
        result["exact_match"] = True
    # HTML-encoded
    elif html.escape(payload) in response_body:
        result["reflected"] = True
        result["encoded"] = True
    # Marker presence (lower confidence)
    elif XSS_MARKER in response_body:
        result["reflected"] = True

    if result["exact_match"]:
        idx = response_body.find(payload)
        # Take 100 chars before and after
        ctx = response_body[max(0, idx - 100):idx + len(payload) + 100]
        lower = ctx.lower()
        if "<script" in lower and "</script" in lower:
            result["context"] = "inside-script"
        elif "href=" in lower or "src=" in lower:
            result["context"] = "attribute"
        elif "<style" in lower:
            result["context"] = "inside-style"
        else:
            result["context"] = "html-body"
        result["context_snippet"] = ctx[:300]

    return result


def run_xss_scan(
    target: str,
    params: Optional[List[str]] = None,
    payloads: Optional[List[str]] = None,
    timeout: int = 10,
) -> Dict:
    url = normalize_url(target)
    parsed = urlparse(url)
    url_params = dict(parse_qsl(parsed.query, keep_blank_values=True))

    if not params:
        params = list(url_params.keys())
    if not params:
        return {"target": url, "error": "No parameters in URL", "vulnerabilities": []}

    payloads = payloads or TEST_PAYLOADS
    result = {
        "target": url,
        "params_tested": params,
        "total_payloads": len(payloads),
        "vulnerabilities": [],
        "error": None,
    }

    try:
        with HTTPClient(timeout=timeout) as client:
            for param in params:
                for payload in payloads:
                    test_url = inject_param(url, param, payload)
                    resp = client.get(test_url)
                    if not resp:
                        continue

                    refl = check_reflection(resp.text, payload)
                    if refl["exact_match"]:
                        result["vulnerabilities"].append({
                            "param": param,
                            "payload": payload,
                            "type": "Reflected XSS",
                            "context": refl.get("context"),
                            "evidence": refl.get("context_snippet", "")[:300],
                            "url": test_url,
                            "status": resp.status_code,
                            "encoded": refl["encoded"],
                        })
                    elif refl["encoded"]:
                        result["vulnerabilities"].append({
                            "param": param,
                            "payload": payload,
                            "type": "Reflected (HTML-encoded)",
                            "context": "encoded — safe rendering",
                            "evidence": "Payload reflected tapi sudah HTML-encoded",
                            "url": test_url,
                            "status": resp.status_code,
                            "encoded": True,
                        })

    except Exception as e:
        result["error"] = str(e)

    return result


def analyze_xss_findings(data: Dict) -> List[ScanResult]:
    findings = []
    for v in data.get("vulnerabilities", []):
        if v.get("encoded"):
            sev = "INFO"
            title = f"Parameter Reflected (HTML-encoded): '{v['param']}'"
        else:
            sev = "HIGH" if v.get("context") in ("html-body", "inside-script", "attribute") else "MEDIUM"
            title = f"Reflected XSS on '{v['param']}' ({v.get('context', 'unknown')})"

        findings.append(ScanResult(
            title=title,
            severity=sev,
            description=(
                f"Parameter '{v['param']}' direflect ke response tanpa encoding. "
                f"Context: {v.get('context', 'unknown')}"
            ),
            url=v["url"],
            evidence=v["evidence"][:500],
            payload=v["payload"],
            recommendation=(
                "Encode output sesuai context (HTML, attribute, JS, CSS, URL); "
                "implement Content Security Policy (CSP); validasi input; "
                "gunakan template engine yang auto-escape"
            ),
            owasp="A03",
            module="vuln_xss",
        ))
    return findings


# ─── Standalone ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from rich.console import Console
    from rich.table import Table

    console = Console()
    parser = argparse.ArgumentParser(description="AnarkisHunter — XSS Detector")
    parser.add_argument("--url", required=True, help="Target URL dengan parameter")
    parser.add_argument("--param", nargs="+")
    parser.add_argument("--timeout", type=int, default=10)
    args = parser.parse_args()

    console.print(f"\n[red]🪞 XSS Scan: [bold]{args.url}[/bold][/red]\n")
    data = run_xss_scan(args.url, args.param, timeout=args.timeout)

    if data.get("error"):
        console.print(f"[red]Error: {data['error']}[/red]")
        sys.exit(1)

    console.print(f"[green]Params:[/green] {', '.join(data['params_tested'])}")
    console.print(f"[green]Payloads:[/green] {data['total_payloads']}")
    console.print(f"[red]Vulnerabilities:[/red] {len(data['vulnerabilities'])}\n")

    if data["vulnerabilities"]:
        t = Table(title="🚨 XSS Findings", border_style="red")
        t.add_column("Param", style="cyan", width=12)
        t.add_column("Type", style="yellow")
        t.add_column("Context", style="white")
        t.add_column("Payload", style="dim", overflow="fold")
        for v in data["vulnerabilities"][:20]:
            t.add_row(v["param"], v["type"], v.get("context", ""), v["payload"][:60])
        console.print(t)
