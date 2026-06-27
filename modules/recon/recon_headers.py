"""
AnarkisHunter — recon_headers.py
==================================
HTTP header grabber & analyzer.
Mengumpulkan semua response headers, mendeteksi server fingerprint,
dan menganalisis security headers yang hilang.

Usage standalone:
    python modules/recon/recon_headers.py --url http://target.local
"""

import sys
import argparse
from pathlib import Path
from typing import Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from modules.utils.utils_request import HTTPClient, normalize_url
from modules.utils.report import ScanResult
from config.settings import SECURITY_HEADERS


# Header yang membocorkan informasi teknologi
INFO_DISCLOSURE_HEADERS = [
    "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
    "X-Generator", "X-Drupal-Cache", "X-Drupal-Dynamic-Cache",
    "X-Backend-Server", "X-Served-By", "X-Runtime", "X-Version",
    "X-Application-Context", "Via",
]


def run_header_recon(target: str, timeout: int = 10) -> Dict:
    """
    Ambil response headers dari target.

    Args:
        target: URL target
        timeout: timeout request (detik)

    Returns:
        Dict dengan headers, status, info_disclosure, security_missing
    """
    url = normalize_url(target)
    result = {
        "url": url,
        "status_code": None,
        "headers": {},
        "info_disclosure": {},
        "missing_security": [],
        "weak_security": [],
        "cookies": [],
        "error": None,
    }

    try:
        with HTTPClient(timeout=timeout) as client:
            resp = client.get(url)
            if resp is None:
                result["error"] = "Connection failed"
                return result

            result["status_code"] = resp.status_code
            result["headers"] = dict(resp.headers)

            # Information disclosure
            for h in INFO_DISCLOSURE_HEADERS:
                val = resp.headers.get(h)
                if val:
                    result["info_disclosure"][h] = val

            # Missing & weak security headers
            for hname, meta in SECURITY_HEADERS.items():
                val = resp.headers.get(hname)
                if not val:
                    result["missing_security"].append({
                        "header": hname,
                        "severity": meta["severity"],
                        "description": meta["description"],
                    })
                else:
                    expected = meta.get("expected")
                    if expected and expected.lower() not in val.lower():
                        result["weak_security"].append({
                            "header": hname,
                            "value": val,
                            "expected": expected,
                            "severity": meta["severity"],
                        })

            # Cookies info
            for c in resp.cookies:
                result["cookies"].append({
                    "name": c.name,
                    "value": (c.value or "")[:50],
                    "secure": c.secure,
                    "httponly": c.has_nonstandard_attr("HttpOnly") or c.has_nonstandard_attr("httponly"),
                    "samesite": c.get_nonstandard_attr("SameSite") if hasattr(c, "get_nonstandard_attr") else None,
                })

    except Exception as e:
        result["error"] = str(e)

    return result


def analyze_header_findings(data: Dict) -> List[ScanResult]:
    """Analisis header untuk masalah keamanan."""
    findings = []
    url = data.get("url", "")

    # Information disclosure
    for h, val in data.get("info_disclosure", {}).items():
        findings.append(ScanResult(
            title=f"Information Disclosure via {h}",
            severity="LOW",
            description=f"Header '{h}' membocorkan informasi teknologi: {val}",
            url=url,
            evidence=f"{h}: {val}",
            recommendation=f"Hapus atau samarkan header '{h}' di konfigurasi server",
            owasp="A05",
            module="recon_headers",
        ))

    # Missing security headers
    for missing in data.get("missing_security", []):
        findings.append(ScanResult(
            title=f"Missing Security Header: {missing['header']}",
            severity=missing["severity"],
            description=missing["description"],
            url=url,
            evidence=f"Header tidak ditemukan: {missing['header']}",
            recommendation=f"Tambahkan header {missing['header']} sesuai best practice",
            owasp="A05",
            module="recon_headers",
        ))

    # Weak security headers
    for weak in data.get("weak_security", []):
        findings.append(ScanResult(
            title=f"Weak Security Header: {weak['header']}",
            severity=weak["severity"],
            description=f"Header {weak['header']} memiliki nilai lemah/tidak sesuai best practice",
            url=url,
            evidence=f"Current: {weak['value']}\nExpected: {weak['expected']}",
            recommendation=f"Ubah header ke: {weak['expected']}",
            owasp="A05",
            module="recon_headers",
        ))

    return findings


# ─── Standalone ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from rich.console import Console
    from rich.table import Table

    console = Console()
    parser = argparse.ArgumentParser(description="AnarkisHunter — HTTP Header Recon")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--timeout", type=int, default=10)
    args = parser.parse_args()

    console.print(f"\n[cyan]🔎 HTTP Header Recon: [bold]{args.url}[/bold][/cyan]\n")
    data = run_header_recon(args.url, args.timeout)

    if data.get("error"):
        console.print(f"[red]Error: {data['error']}[/red]")
        sys.exit(1)

    console.print(f"[green]Status:[/green] {data['status_code']}\n")

    # All headers
    hdr_table = Table(title="Response Headers", border_style="cyan")
    hdr_table.add_column("Header", style="cyan")
    hdr_table.add_column("Value", style="white", overflow="fold")
    for k, v in data["headers"].items():
        hdr_table.add_row(k, str(v)[:100])
    console.print(hdr_table)

    # Info disclosure
    if data["info_disclosure"]:
        console.print("\n[yellow]⚠ Information Disclosure:[/yellow]")
        for h, v in data["info_disclosure"].items():
            console.print(f"  [yellow]{h}[/yellow] = {v}")

    # Missing security
    if data["missing_security"]:
        console.print("\n[red]✗ Missing Security Headers:[/red]")
        for m in data["missing_security"]:
            console.print(f"  [{m['severity']}] {m['header']} — {m['description']}")

    findings = analyze_header_findings(data)
    console.print(f"\n[bold]Total findings: {len(findings)}[/bold]")
