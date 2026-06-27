"""
AnarkisHunter — scan_methods.py
==================================
HTTP methods tester — cek method yang allowed via OPTIONS dan probe
methods yang berbahaya (PUT, DELETE, TRACE, CONNECT).

Usage standalone:
    python modules/scanner/scan_methods.py --url http://target.local
"""

import sys
import argparse
from pathlib import Path
from typing import Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from modules.utils.utils_request import HTTPClient, normalize_url
from modules.utils.report import ScanResult


ALL_METHODS = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH",
               "TRACE", "CONNECT", "COPY", "MOVE", "PROPFIND", "PROPPATCH",
               "MKCOL", "LOCK", "UNLOCK"]

DANGEROUS_METHODS = {"PUT", "DELETE", "TRACE", "CONNECT", "COPY", "MOVE",
                     "PROPFIND", "PROPPATCH", "MKCOL"}


def run_methods_scan(target: str, timeout: int = 8) -> Dict:
    """Test semua HTTP method pada target."""
    url = normalize_url(target)
    result = {
        "url": url,
        "options_allow": "",
        "tested_methods": [],
        "allowed_methods": [],
        "dangerous_allowed": [],
        "trace_enabled": False,
        "error": None,
    }

    try:
        with HTTPClient(timeout=timeout) as client:
            opts = client.options(url)
            if opts:
                result["options_allow"] = (
                    opts.headers.get("Allow", "")
                    or opts.headers.get("Access-Control-Allow-Methods", "")
                )

            for method in ALL_METHODS:
                try:
                    resp = client._request(method, url)
                    if not resp:
                        continue
                    status = resp.status_code
                    allowed = status not in {405, 501}
                    info = {
                        "method": method,
                        "status": status,
                        "size": len(resp.content),
                        "allowed": allowed,
                    }
                    result["tested_methods"].append(info)
                    if allowed:
                        result["allowed_methods"].append(method)
                        if method in DANGEROUS_METHODS:
                            result["dangerous_allowed"].append(method)
                    if method == "TRACE" and allowed and status < 400:
                        result["trace_enabled"] = True
                except Exception:
                    continue
    except Exception as e:
        result["error"] = str(e)

    return result


def analyze_methods_findings(data: Dict) -> List[ScanResult]:
    findings = []
    url = data.get("url", "")

    if data.get("trace_enabled"):
        findings.append(ScanResult(
            title="HTTP TRACE Method Enabled",
            severity="MEDIUM",
            description="HTTP TRACE bisa dipakai untuk Cross-Site Tracing (XST) attack",
            url=url,
            evidence="TRACE returned 2xx/3xx",
            recommendation="Disable TRACE di web server config",
            owasp="A05",
            module="scan_methods",
        ))

    for m in data.get("dangerous_allowed", []):
        if m == "TRACE":
            continue
        sev = "HIGH" if m in {"PUT", "DELETE"} else "MEDIUM"
        findings.append(ScanResult(
            title=f"Dangerous HTTP Method Allowed: {m}",
            severity=sev,
            description=f"Method {m} accessible — bisa menyebabkan unauthorized modification",
            url=url,
            evidence=f"{m} returned non-405",
            recommendation=f"Disable atau batasi method {m} via authentication & IP whitelist",
            owasp="A01",
            module="scan_methods",
        ))

    if data.get("options_allow"):
        findings.append(ScanResult(
            title="OPTIONS Method Discloses Allowed Methods",
            severity="INFO",
            description=f"Server discloses allowed methods: {data['options_allow']}",
            url=url,
            evidence=f"Allow: {data['options_allow']}",
            module="scan_methods",
        ))

    return findings


# ─── Standalone ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from rich.console import Console
    from rich.table import Table

    console = Console()
    parser = argparse.ArgumentParser(description="AnarkisHunter — HTTP Methods Tester")
    parser.add_argument("--url", required=True, help="Target URL")
    args = parser.parse_args()

    console.print(f"\n[cyan]🔧 HTTP Methods Scan: [bold]{args.url}[/bold][/cyan]\n")
    data = run_methods_scan(args.url)

    if data.get("error"):
        console.print(f"[red]Error: {data['error']}[/red]")
        sys.exit(1)

    if data["options_allow"]:
        console.print(f"[green]OPTIONS Allow:[/green] {data['options_allow']}")
    console.print(f"[green]Allowed methods:[/green] {', '.join(data['allowed_methods'])}")
    console.print(f"[red]Dangerous allowed:[/red] {', '.join(data['dangerous_allowed']) or 'none'}\n")

    t = Table(title="Method Test Results", border_style="cyan")
    t.add_column("Method", style="cyan", width=12)
    t.add_column("Status", style="white", width=10)
    t.add_column("Allowed", style="green", width=10)
    t.add_column("Danger", style="red", width=8)
    for m in data["tested_methods"]:
        danger = "⚠" if m["method"] in DANGEROUS_METHODS and m["allowed"] else ""
        t.add_row(
            m["method"], str(m["status"]),
            "[green]✓[/green]" if m["allowed"] else "[dim]✗[/dim]",
            f"[red]{danger}[/red]" if danger else "",
        )
    console.print(t)
