"""
AnarkisHunter — vuln_cmdi.py
==============================
Command Injection detector. Inject command separator + perintah,
cek output di response (output-based) atau time-based.

Usage standalone:
    python modules/vuln/vuln_cmdi.py --url "http://target.local/ping?host=8.8.8.8"
"""

import sys
import re
import time
import argparse
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from modules.utils.utils_request import HTTPClient, normalize_url
from modules.utils.utils_payload import payload_manager
from modules.utils.utils_verifier import FindingVerifier, confidence_to_severity
from modules.utils.utils_waf_bypass import waf_bypass
from modules.utils.report import ScanResult


# Output indicators kalau command jalan
LINUX_INDICATORS = [
    r"uid=\d+\(", r"gid=\d+\(", r"root:x:", r"/bin/(bash|sh)",
    r"Linux\s+\S+\s+\d+\.\d+", r"darwin\s+\S+",
]
WINDOWS_INDICATORS = [
    r"Volume in drive",
    r"Directory of [A-Z]:",
    r"Windows IP Configuration",
    r"Microsoft Windows \[Version",
    r"<DIR>\s+\.",
]


def inject_param(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    params[param] = payload
    return urlunparse(parsed._replace(query=urlencode(params)))


def detect_cmd_output(text: str) -> Optional[str]:
    for pat in LINUX_INDICATORS + WINDOWS_INDICATORS:
        m = re.search(pat, text)
        if m:
            return m.group(0)[:200]
    return None


def run_cmdi_scan(
    target: str,
    params: Optional[List[str]] = None,
    payloads: Optional[List[str]] = None,
    timeout: int = 15,
    threads: int = 10,
    test_time_based: bool = True,
    proxy: Optional[str] = None,
) -> Dict:
    url = normalize_url(target)
    parsed = urlparse(url)
    url_params = dict(parse_qsl(parsed.query, keep_blank_values=True))

    if not params:
        params = list(url_params.keys())
    if not params:
        return {"target": url, "error": "No parameters", "vulnerabilities": []}

    payloads = payloads or payload_manager.get("cmd")
    result = {
        "target": url,
        "params_tested": params,
        "total_payloads": len(payloads),
        "vulnerabilities": [],
        "findings": [],
        "error": None,
    }

    try:
        with HTTPClient(timeout=timeout, threads=threads, proxy=proxy) as client:
            verifier = FindingVerifier(client, url)
            verifier.capture_baseline()
            seen = set()

            for param in params:
                base_val = url_params.get(param, "1")
                for payload in payloads:
                    is_time = "sleep" in payload.lower() or "ping" in payload.lower()
                    if is_time and not test_time_based:
                        continue

                    test_payload = f"{base_val}{payload}"
                    test_url = inject_param(url, param, test_payload)
                    key = f"{param}:{test_payload}"
                    if key in seen:
                        continue

                    def check_fn(base, test, p=payload, tp=test_payload, itb=is_time):
                        if not test or verifier.is_same_as_baseline(test):
                            return None
                        out = detect_cmd_output(test.text)
                        if out:
                            return {"type": "Output-based Command Injection", "evidence": out}
                        return None

                    finding = verifier.verify_finding(test_url, check_fn, min_confidence=55)
                    if finding:
                        seen.add(key)
                        result["vulnerabilities"].append({
                            "param": param, "payload": payload,
                            "type": finding.get("type", "Command Injection"),
                            "evidence": finding.get("evidence", ""), "url": test_url,
                            "confidence": finding.get("confidence", 0),
                        })

        result["findings"] = analyze_cmdi_findings(result)

    except Exception as e:
        result["error"] = str(e)

    return result


def analyze_cmdi_findings(data: Dict) -> List[ScanResult]:
    findings = []
    for v in data.get("vulnerabilities", []):
        findings.append(ScanResult(
            title=f"Command Injection ({v['type']}) on '{v['param']}'",
            severity=confidence_to_severity(v.get("confidence", 0), "CRITICAL"),
            description=f"Command injection on '{v['param']}' [confidence: {v.get('confidence', 0)}%]",
            url=v["url"],
            evidence=v["evidence"][:500],
            payload=v["payload"],
            owasp="A03",
            module="vuln_cmdi",
            confidence=v.get("confidence", 0),
        ))
    return findings


# ─── Standalone ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from rich.console import Console
    from rich.table import Table

    console = Console()
    parser = argparse.ArgumentParser(description="AnarkisHunter — Command Injection")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--param", nargs="+")
    parser.add_argument("--no-time", action="store_true")
    args = parser.parse_args()

    console.print(f"\n[red]💻 Command Injection Scan: [bold]{args.url}[/bold][/red]\n")
    data = run_cmdi_scan(args.url, args.param, test_time_based=not args.no_time)

    if data.get("error"):
        console.print(f"[red]Error: {data['error']}[/red]")
        sys.exit(1)

    console.print(f"[green]Params:[/green] {', '.join(data['params_tested'])}")
    console.print(f"[red]Vulnerabilities:[/red] {len(data['vulnerabilities'])}\n")

    if data["vulnerabilities"]:
        t = Table(title="🚨 CmdI Findings", border_style="red")
        t.add_column("Param", style="cyan")
        t.add_column("Type", style="yellow")
        t.add_column("Payload", style="white", overflow="fold")
        t.add_column("Evidence", style="red", overflow="fold")
        for v in data["vulnerabilities"][:20]:
            t.add_row(v["param"], v["type"], v["payload"][:50], v["evidence"][:60])
        console.print(t)
