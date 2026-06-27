"""
AnarkisHunter — vuln_lfi.py
=============================
Local File Inclusion detector. Inject path traversal payload,
deteksi pattern /etc/passwd, Windows files, PHP wrappers.

Usage standalone:
    python modules/vuln/vuln_lfi.py --url "http://target.local/page?file=index"
"""

import sys
import re
import argparse
import base64
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from modules.utils.utils_request import HTTPClient, normalize_url
from modules.utils.utils_payload import payload_manager
from modules.utils.report import ScanResult


# Indicators bahwa file di-include
PASSWD_PATTERN = re.compile(r"root:[x*]?:0:0:")
WIN_INI_PATTERN = re.compile(r"\[fonts\]|\[extensions\]", re.I)
HOSTS_PATTERN = re.compile(r"127\.0\.0\.1\s+localhost", re.I)
PHP_BASE64_PATTERN = re.compile(r"PD9waHA")  # "<?ph" base64-encoded


def inject_param(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    params[param] = payload
    return urlunparse(parsed._replace(query=urlencode(params)))


def detect_lfi_evidence(text: str, payload: str) -> Optional[str]:
    """Identifikasi bukti LFI di response."""
    if PASSWD_PATTERN.search(text):
        m = PASSWD_PATTERN.search(text)
        return f"/etc/passwd content matched: {m.group(0)}"
    if HOSTS_PATTERN.search(text) and "passwd" in payload:
        return "/etc/hosts content matched"
    if WIN_INI_PATTERN.search(text):
        return "Windows ini content detected"
    if "php://filter" in payload and PHP_BASE64_PATTERN.search(text):
        # Decode preview
        m = re.search(r"([A-Za-z0-9+/=]{40,})", text)
        if m:
            try:
                decoded = base64.b64decode(m.group(1)[:200]).decode("utf-8", errors="replace")[:200]
                return f"PHP source disclosed (base64): {decoded[:150]}"
            except Exception:
                pass
        return "PHP filter base64 content detected"
    return None


def run_lfi_scan(
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
        return {"target": url, "error": "No parameters", "vulnerabilities": []}

    payloads = payloads or payload_manager.get("lfi")
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

                    ev = detect_lfi_evidence(resp.text, payload)
                    if ev:
                        result["vulnerabilities"].append({
                            "param": param, "payload": payload,
                            "evidence": ev, "url": test_url,
                            "status": resp.status_code,
                            "type": "Path Traversal / LFI",
                        })

    except Exception as e:
        result["error"] = str(e)

    return result


def analyze_lfi_findings(data: Dict) -> List[ScanResult]:
    findings = []
    for v in data.get("vulnerabilities", []):
        findings.append(ScanResult(
            title=f"Local File Inclusion on '{v['param']}'",
            severity="CRITICAL",
            description=f"LFI/Path Traversal terdeteksi pada parameter '{v['param']}'",
            url=v["url"],
            evidence=v["evidence"][:500],
            payload=v["payload"],
            recommendation=(
                "Whitelist nama file; sanitize ../; gunakan basename(); "
                "simpan file di luar webroot; never include user input directly"
            ),
            owasp="A01",
            module="vuln_lfi",
        ))
    return findings


# ─── Standalone ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from rich.console import Console
    from rich.table import Table

    console = Console()
    parser = argparse.ArgumentParser(description="AnarkisHunter — LFI Detector")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--param", nargs="+")
    args = parser.parse_args()

    console.print(f"\n[red]📂 LFI Scan: [bold]{args.url}[/bold][/red]\n")
    data = run_lfi_scan(args.url, args.param)

    if data.get("error"):
        console.print(f"[red]Error: {data['error']}[/red]")
        sys.exit(1)

    console.print(f"[green]Params:[/green] {', '.join(data['params_tested'])}")
    console.print(f"[red]Vulns:[/red] {len(data['vulnerabilities'])}\n")

    if data["vulnerabilities"]:
        t = Table(title="🚨 LFI Findings", border_style="red")
        t.add_column("Param", style="cyan")
        t.add_column("Payload", style="white", overflow="fold")
        t.add_column("Evidence", style="red", overflow="fold")
        for v in data["vulnerabilities"][:20]:
            t.add_row(v["param"], v["payload"][:50], v["evidence"][:100])
        console.print(t)
