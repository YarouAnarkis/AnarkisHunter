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
from modules.utils.utils_verifier import FindingVerifier, confidence_to_severity
from modules.utils.utils_waf_bypass import waf_bypass
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
    threads: int = 10,
    proxy: Optional[str] = None,
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
        "findings": [],
        "error": None,
    }

    try:
        with HTTPClient(timeout=timeout, threads=threads, proxy=proxy) as client:
            verifier = FindingVerifier(client, url)
            verifier.capture_baseline()
            seen = set()

            for param in params:
                for payload in payloads:
                    variants = waf_bypass.generate_bypass_variants(payload, url, param)
                    for variant in variants:
                        actual = variant["payload"]
                        test_url = variant.get("url") or inject_param(url, param, actual)
                        key = f"{param}:{actual}"
                        if key in seen:
                            continue

                        def check_fn(base, test, p=actual):
                            if not test or verifier.is_same_as_baseline(test):
                                return None
                            ev = detect_lfi_evidence(test.text, p)
                            if ev:
                                return {"type": "Path Traversal / LFI", "evidence": ev}
                            return None

                        finding = verifier.verify_finding(test_url, check_fn, min_confidence=55)
                        if not finding:
                            continue
                        seen.add(key)
                        result["vulnerabilities"].append({
                            "param": param, "payload": actual,
                            "evidence": finding.get("evidence", ""), "url": test_url,
                            "type": finding.get("type", "LFI"),
                            "confidence": finding.get("confidence", 0),
                        })

        result["findings"] = analyze_lfi_findings(result)

    except Exception as e:
        result["error"] = str(e)

    return result


def analyze_lfi_findings(data: Dict) -> List[ScanResult]:
    findings = []
    for v in data.get("vulnerabilities", []):
        findings.append(ScanResult(
            title=f"Local File Inclusion on '{v['param']}'",
            severity=confidence_to_severity(v.get("confidence", 0), "CRITICAL"),
            description=f"LFI/Path Traversal on '{v['param']}' [confidence: {v.get('confidence', 0)}%]",
            url=v["url"],
            evidence=v["evidence"][:500],
            payload=v["payload"],
            owasp="A03",
            module="vuln_lfi",
            confidence=v.get("confidence", 0),
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
