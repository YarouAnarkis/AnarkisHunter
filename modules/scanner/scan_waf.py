"""
AnarkisHunter — scan_waf.py
=============================
WAF detection via response headers, cookies, body fingerprint, dan
probe dengan payload yang biasanya di-block WAF.

Usage standalone:
    python modules/scanner/scan_waf.py --url http://target.local
"""

import sys
import argparse
from pathlib import Path
from typing import Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from modules.utils.utils_request import HTTPClient, normalize_url
from modules.utils.report import ScanResult
from config.settings import WAF_SIGNATURES


# Payload yang biasanya dipicu/diblok WAF
WAF_TRIGGER_PAYLOADS = [
    "?id=1' OR '1'='1",
    "?q=<script>alert(1)</script>",
    "?file=../../../etc/passwd",
    "?cmd=;cat /etc/passwd",
]

# Block indicators
BLOCK_INDICATORS = [
    "blocked", "forbidden", "access denied", "security violation",
    "wafprotection", "modsecurity", "request rejected", "not acceptable",
]


def _detect_waf_in_response(resp) -> List[str]:
    """Detect WAF dari single response."""
    detected = []
    headers_str = str(resp.headers).lower()
    cookies_str = " ".join(c.name.lower() for c in resp.cookies)
    body_low = resp.text.lower()[:5000]
    haystack = headers_str + " " + cookies_str + " " + body_low

    for waf_name, signatures in WAF_SIGNATURES.items():
        for sig in signatures:
            if sig.lower() in haystack:
                if waf_name not in detected:
                    detected.append(waf_name)
                break
    return detected


def run_waf_scan(target: str, timeout: int = 10) -> Dict:
    """Detect WAF & test bypass dengan payload."""
    url = normalize_url(target)
    result = {
        "url": url,
        "detected_wafs": [],
        "baseline_status": None,
        "blocked_payloads": [],
        "passing_payloads": [],
        "block_rate": 0.0,
        "error": None,
    }

    try:
        with HTTPClient(timeout=timeout) as client:
            # Baseline
            baseline = client.get(url)
            if not baseline:
                result["error"] = "Baseline request failed"
                return result
            result["baseline_status"] = baseline.status_code
            result["detected_wafs"] = _detect_waf_in_response(baseline)

            # Probe payloads
            for payload in WAF_TRIGGER_PAYLOADS:
                test_url = url + payload
                resp = client.get(test_url)
                if not resp:
                    continue

                # Tambah deteksi WAF dari probe response juga
                new_wafs = _detect_waf_in_response(resp)
                for w in new_wafs:
                    if w not in result["detected_wafs"]:
                        result["detected_wafs"].append(w)

                # Block detection
                body_low = resp.text.lower()[:3000]
                is_blocked = (
                    resp.status_code in {403, 406, 419, 429, 503} or
                    any(ind in body_low for ind in BLOCK_INDICATORS)
                )

                info = {
                    "payload": payload,
                    "status": resp.status_code,
                    "size": len(resp.content),
                    "blocked": is_blocked,
                }
                if is_blocked:
                    result["blocked_payloads"].append(info)
                else:
                    result["passing_payloads"].append(info)

            total = len(WAF_TRIGGER_PAYLOADS)
            if total:
                result["block_rate"] = len(result["blocked_payloads"]) / total * 100

    except Exception as e:
        result["error"] = str(e)

    return result


def analyze_waf_findings(data: Dict) -> List[ScanResult]:
    findings = []
    url = data.get("url", "")

    if data.get("detected_wafs"):
        findings.append(ScanResult(
            title=f"WAF Detected: {', '.join(data['detected_wafs'])}",
            severity="INFO",
            description=f"WAF terdeteksi: {', '.join(data['detected_wafs'])}",
            url=url,
            evidence=f"WAFs: {data['detected_wafs']} | Block rate: {data['block_rate']:.0f}%",
            recommendation="Gunakan payload obfuscation / encoding untuk bypass WAF (jika authorized)",
            module="scan_waf",
        ))
    elif data.get("block_rate", 0) > 50:
        findings.append(ScanResult(
            title="Unknown WAF/Firewall Detected",
            severity="INFO",
            description=f"Tidak ada signature WAF cocok, tapi {data['block_rate']:.0f}% payload diblok",
            url=url,
            evidence=f"Blocked: {len(data['blocked_payloads'])} dari {len(WAF_TRIGGER_PAYLOADS)}",
            module="scan_waf",
        ))
    else:
        findings.append(ScanResult(
            title="No WAF Detected",
            severity="MEDIUM",
            description="Tidak ada WAF terdeteksi. Target rentan terhadap brute-force serangan.",
            url=url,
            evidence=f"Block rate: {data.get('block_rate', 0):.0f}%",
            recommendation="Pertimbangkan deploy WAF (Cloudflare, ModSecurity, AWS WAF)",
            owasp="A05",
            module="scan_waf",
        ))

    return findings


# ─── Standalone ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from rich.console import Console
    from rich.table import Table

    console = Console()
    parser = argparse.ArgumentParser(description="AnarkisHunter — WAF Detection")
    parser.add_argument("--url", required=True, help="Target URL")
    args = parser.parse_args()

    console.print(f"\n[cyan]🛡  WAF Detection: [bold]{args.url}[/bold][/cyan]\n")
    data = run_waf_scan(args.url)

    if data.get("error"):
        console.print(f"[red]Error: {data['error']}[/red]")
        sys.exit(1)

    console.print(f"[green]Baseline:[/green] HTTP {data['baseline_status']}")
    console.print(f"[green]Detected WAFs:[/green] {', '.join(data['detected_wafs']) or 'none'}")
    console.print(f"[yellow]Block rate:[/yellow] {data['block_rate']:.0f}%\n")

    t = Table(title="Payload Tests", border_style="cyan")
    t.add_column("Payload", style="yellow", overflow="fold")
    t.add_column("Status", style="white", width=8)
    t.add_column("Result", style="cyan", width=15)
    for p in data["blocked_payloads"] + data["passing_payloads"]:
        result_str = "[red]BLOCKED[/red]" if p["blocked"] else "[green]passed[/green]"
        t.add_row(p["payload"][:60], str(p["status"]), result_str)
    console.print(t)
