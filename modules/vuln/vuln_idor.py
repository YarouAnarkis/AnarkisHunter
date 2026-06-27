"""
AnarkisHunter — vuln_idor.py
==============================
Insecure Direct Object Reference detector.
Test parameter numerik (user_id, order_id) dengan mengubah nilai,
cek apakah respons berbeda → kemungkinan IDOR.

Usage standalone:
    python modules/vuln/vuln_idor.py --url "http://target.local/user?id=1"
"""

import sys
import argparse
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from modules.utils.utils_request import HTTPClient, normalize_url
from modules.utils.report import ScanResult


# Parameter umum yang mengindikasikan ID
ID_PARAM_PATTERNS = [
    "id", "user_id", "userid", "uid", "account", "account_id",
    "order_id", "orderid", "invoice", "doc", "document",
    "file", "file_id", "object", "object_id", "key",
    "ref", "reference", "ticket", "msg", "msg_id",
]


def is_numeric(val: str) -> bool:
    try:
        int(val)
        return True
    except (ValueError, TypeError):
        return False


def inject_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    params[param] = value
    return urlunparse(parsed._replace(query=urlencode(params)))


def run_idor_scan(
    target: str,
    params: Optional[List[str]] = None,
    timeout: int = 10,
) -> Dict:
    url = normalize_url(target)
    parsed = urlparse(url)
    url_params = dict(parse_qsl(parsed.query, keep_blank_values=True))

    # Auto-detect candidate ID params
    candidates = []
    for k, v in url_params.items():
        if params and k not in params:
            continue
        if is_numeric(v):
            candidates.append((k, v))
        elif any(pat in k.lower() for pat in ID_PARAM_PATTERNS):
            candidates.append((k, v))

    if not candidates:
        return {"target": url, "error": "No ID-like parameters found", "vulnerabilities": []}

    result = {
        "target": url,
        "params_tested": [c[0] for c in candidates],
        "vulnerabilities": [],
        "error": None,
    }

    try:
        with HTTPClient(timeout=timeout) as client:
            for param, orig_val in candidates:
                # Baseline
                base_resp = client.get(url)
                if not base_resp:
                    continue
                base_status = base_resp.status_code
                base_size = len(base_resp.content)
                base_title = _extract_title(base_resp.text)

                # Test values
                if is_numeric(orig_val):
                    test_vals = [str(int(orig_val) + 1), str(int(orig_val) - 1), "0", "9999"]
                else:
                    test_vals = ["1", "2", "admin", "0"]

                differences = []
                for tv in test_vals:
                    test_url = inject_param(url, param, tv)
                    resp = client.get(test_url)
                    if not resp:
                        continue
                    new_status = resp.status_code
                    new_size = len(resp.content)
                    new_title = _extract_title(resp.text)

                    # Heuristik IDOR: response different tapi tetap 200
                    is_diff = (
                        new_status == 200 and
                        (abs(new_size - base_size) > 100 or
                         (new_title and base_title and new_title != base_title))
                    )
                    differences.append({
                        "value": tv, "url": test_url, "status": new_status,
                        "size": new_size, "title": new_title, "is_diff": is_diff,
                    })

                if any(d["is_diff"] for d in differences):
                    result["vulnerabilities"].append({
                        "param": param,
                        "original_value": orig_val,
                        "type": "Possible IDOR",
                        "evidence": "\n".join(
                            f"{d['value']} → HTTP {d['status']} ({d['size']}b) '{d['title']}'"
                            for d in differences
                        ),
                        "url": url,
                    })

    except Exception as e:
        result["error"] = str(e)

    return result


def _extract_title(html: str) -> str:
    import re
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    return m.group(1).strip()[:80] if m else ""


def analyze_idor_findings(data: Dict) -> List[ScanResult]:
    findings = []
    for v in data.get("vulnerabilities", []):
        findings.append(ScanResult(
            title=f"Possible IDOR on parameter '{v['param']}'",
            severity="HIGH",
            description=(
                f"Parameter '{v['param']}' menerima nilai berbeda dengan respons berbeda. "
                "Kemungkinan IDOR — perlu verifikasi manual dengan akun berbeda."
            ),
            url=v["url"],
            evidence=v["evidence"][:500],
            recommendation=(
                "Implement authorization check di backend untuk setiap object access; "
                "jangan rely pada hidden / obscured ID; gunakan indirect reference"
            ),
            owasp="A01",
            module="vuln_idor",
        ))
    return findings


# ─── Standalone ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from rich.console import Console
    from rich.table import Table

    console = Console()
    parser = argparse.ArgumentParser(description="AnarkisHunter — IDOR Detector")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--param", nargs="+")
    args = parser.parse_args()

    console.print(f"\n[red]🔑 IDOR Scan: [bold]{args.url}[/bold][/red]\n")
    data = run_idor_scan(args.url, args.param)

    if data.get("error"):
        console.print(f"[red]Error: {data['error']}[/red]")
        sys.exit(1)

    console.print(f"[red]Vulnerabilities:[/red] {len(data['vulnerabilities'])}\n")
    if data["vulnerabilities"]:
        for v in data["vulnerabilities"]:
            console.print(f"[red][IDOR][/red] param='{v['param']}' (original={v['original_value']})")
            for line in v["evidence"].splitlines():
                console.print(f"   • {line}")
            console.print()
