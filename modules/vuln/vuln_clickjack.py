"""
AnarkisHunter — vuln_clickjack.py
====================================
Clickjacking checker — pastikan X-Frame-Options atau CSP frame-ancestors
melindungi halaman dari di-embed dalam iframe.

Usage standalone:
    python modules/vuln/vuln_clickjack.py --url http://target.local
"""

import sys
import argparse
from pathlib import Path
from typing import Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from modules.utils.utils_request import HTTPClient, normalize_url
from modules.utils.report import ScanResult


def run_clickjack_check(target: str, timeout: int = 10) -> Dict:
    url = normalize_url(target)
    result = {
        "url": url,
        "xfo": None,
        "csp": None,
        "csp_frame_ancestors": None,
        "vulnerable": False,
        "poc_html": "",
        "error": None,
    }

    try:
        with HTTPClient(timeout=timeout) as client:
            resp = client.get(url)
            if not resp:
                result["error"] = "Connection failed"
                return result

            result["xfo"] = resp.headers.get("X-Frame-Options")
            result["csp"] = resp.headers.get("Content-Security-Policy")

            # Parse CSP frame-ancestors
            if result["csp"]:
                for directive in result["csp"].split(";"):
                    directive = directive.strip()
                    if directive.lower().startswith("frame-ancestors"):
                        result["csp_frame_ancestors"] = directive[len("frame-ancestors"):].strip()
                        break

            # Vulnerable jika tidak ada XFO maupun frame-ancestors
            has_xfo_protect = result["xfo"] and result["xfo"].lower() in ("deny", "sameorigin")
            has_csp_protect = result["csp_frame_ancestors"] and "'none'" in result["csp_frame_ancestors"]
            has_csp_strict = result["csp_frame_ancestors"] and "self" in result["csp_frame_ancestors"]

            result["vulnerable"] = not (has_xfo_protect or has_csp_protect or has_csp_strict)

            if result["vulnerable"]:
                result["poc_html"] = (
                    "<!DOCTYPE html><html><head><title>Clickjacking PoC</title></head>"
                    "<body><h1>Clickjacking Test</h1>"
                    f"<iframe src=\"{url}\" width=\"800\" height=\"600\"></iframe>"
                    "</body></html>"
                )

    except Exception as e:
        result["error"] = str(e)

    return result


def analyze_clickjack_findings(data: Dict) -> List[ScanResult]:
    findings = []
    if data.get("vulnerable"):
        findings.append(ScanResult(
            title="Clickjacking Vulnerability",
            severity="MEDIUM",
            description=(
                "Halaman tidak melindungi diri dari di-embed dalam iframe. "
                "Bisa diserang dengan Clickjacking."
            ),
            url=data.get("url"),
            evidence=(
                f"X-Frame-Options: {data.get('xfo') or '(absent)'}\n"
                f"CSP frame-ancestors: {data.get('csp_frame_ancestors') or '(absent)'}"
            ),
            payload=data.get("poc_html", "")[:300],
            recommendation=(
                "Set X-Frame-Options: DENY atau SAMEORIGIN, "
                "atau CSP frame-ancestors 'none' / 'self'"
            ),
            owasp="A05",
            module="vuln_clickjack",
        ))
    return findings


# ─── Standalone ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from rich.console import Console

    console = Console()
    parser = argparse.ArgumentParser(description="AnarkisHunter — Clickjacking Checker")
    parser.add_argument("--url", required=True)
    args = parser.parse_args()

    console.print(f"\n[red]🪟 Clickjacking: [bold]{args.url}[/bold][/red]\n")
    data = run_clickjack_check(args.url)
    if data.get("error"):
        console.print(f"[red]Error: {data['error']}[/red]")
        sys.exit(1)

    console.print(f"X-Frame-Options: [cyan]{data['xfo'] or '(absent)'}[/cyan]")
    console.print(f"CSP frame-ancestors: [cyan]{data['csp_frame_ancestors'] or '(absent)'}[/cyan]")
    if data["vulnerable"]:
        console.print("\n[bold red]🚨 VULNERABLE TO CLICKJACKING[/bold red]")
        console.print("\n[bold]PoC HTML:[/bold]")
        console.print(f"[dim]{data['poc_html'][:300]}[/dim]")
    else:
        console.print("\n[green]✓ Protected[/green]")
