"""
AnarkisHunter — vuln_headers.py
==================================
Deep security header analyzer (lebih lengkap dari recon_headers).
Validasi nilai CSP, HSTS, parsing detail security headers.

Usage standalone:
    python modules/vuln/vuln_headers.py --url http://target.local
"""

import sys
import argparse
import re
from pathlib import Path
from typing import Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from modules.utils.utils_request import HTTPClient, normalize_url
from modules.utils.report import ScanResult


def parse_csp(csp: str) -> Dict:
    """Parse CSP directive."""
    directives = {}
    for part in csp.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        if not tokens:
            continue
        name = tokens[0].lower()
        directives[name] = tokens[1:]
    return directives


def run_header_audit(target: str, timeout: int = 10) -> Dict:
    url = normalize_url(target)
    result = {
        "url": url,
        "headers": {},
        "csp_analysis": {},
        "hsts_analysis": {},
        "issues": [],
        "error": None,
    }

    try:
        with HTTPClient(timeout=timeout) as client:
            resp = client.get(url)
            if not resp:
                result["error"] = "Connection failed"
                return result
            headers = dict(resp.headers)
            result["headers"] = headers

            # CSP analysis
            csp = headers.get("Content-Security-Policy", "")
            if csp:
                parsed = parse_csp(csp)
                result["csp_analysis"] = {
                    "raw": csp,
                    "directives": parsed,
                    "weaknesses": [],
                }
                weak = result["csp_analysis"]["weaknesses"]
                # unsafe-inline
                for d, vals in parsed.items():
                    if "'unsafe-inline'" in vals:
                        weak.append((d, "'unsafe-inline' allows inline scripts/styles"))
                    if "'unsafe-eval'" in vals:
                        weak.append((d, "'unsafe-eval' allows eval()"))
                    if "*" in vals:
                        weak.append((d, "wildcard source allowed"))
                    if "data:" in vals and d in ("script-src", "default-src"):
                        weak.append((d, "data: scheme allowed for scripts"))
                if "default-src" not in parsed and "script-src" not in parsed:
                    weak.append(("missing", "no default-src or script-src"))
            else:
                result["issues"].append({
                    "header": "Content-Security-Policy",
                    "issue": "Missing CSP",
                    "severity": "MEDIUM",
                })

            # HSTS analysis
            hsts = headers.get("Strict-Transport-Security", "")
            if hsts:
                result["hsts_analysis"] = {"raw": hsts}
                max_age_m = re.search(r"max-age=(\d+)", hsts, re.I)
                if max_age_m:
                    age = int(max_age_m.group(1))
                    result["hsts_analysis"]["max_age"] = age
                    if age < 31536000:  # 1 year
                        result["issues"].append({
                            "header": "HSTS",
                            "issue": f"HSTS max-age terlalu pendek ({age}s, recommended ≥31536000)",
                            "severity": "LOW",
                        })
                if "includesubdomains" not in hsts.lower():
                    result["issues"].append({
                        "header": "HSTS",
                        "issue": "HSTS tidak include subdomains",
                        "severity": "LOW",
                    })
                if "preload" not in hsts.lower():
                    result["issues"].append({
                        "header": "HSTS",
                        "issue": "HSTS tidak preload",
                        "severity": "LOW",
                    })
            elif url.startswith("https"):
                result["issues"].append({
                    "header": "HSTS",
                    "issue": "Missing HSTS on HTTPS",
                    "severity": "HIGH",
                })

            # X-Frame-Options vs CSP frame-ancestors
            xfo = headers.get("X-Frame-Options", "")
            csp_fa = result["csp_analysis"].get("directives", {}).get("frame-ancestors")
            if not xfo and not csp_fa:
                result["issues"].append({
                    "header": "X-Frame-Options/frame-ancestors",
                    "issue": "No clickjacking protection",
                    "severity": "MEDIUM",
                })

            # Referrer-Policy
            if not headers.get("Referrer-Policy"):
                result["issues"].append({
                    "header": "Referrer-Policy",
                    "issue": "Missing Referrer-Policy",
                    "severity": "LOW",
                })

            # Permissions-Policy
            if not headers.get("Permissions-Policy"):
                result["issues"].append({
                    "header": "Permissions-Policy",
                    "issue": "Missing Permissions-Policy",
                    "severity": "LOW",
                })

    except Exception as e:
        result["error"] = str(e)

    return result


def analyze_header_audit_findings(data: Dict) -> List[ScanResult]:
    findings = []
    url = data.get("url", "")
    for issue in data.get("issues", []):
        findings.append(ScanResult(
            title=f"Security Header Issue: {issue['header']}",
            severity=issue["severity"],
            description=issue["issue"],
            url=url,
            evidence=str(data["headers"].get(issue["header"], "(absent)"))[:300],
            recommendation="Configure security header sesuai OWASP Secure Headers project",
            owasp="A05",
            module="vuln_headers",
        ))

    # CSP weaknesses
    for d, w in data.get("csp_analysis", {}).get("weaknesses", []):
        findings.append(ScanResult(
            title=f"Weak CSP Directive: {d}",
            severity="MEDIUM",
            description=f"CSP directive '{d}' lemah: {w}",
            url=url,
            evidence=str(data["csp_analysis"].get("raw", ""))[:500],
            recommendation="Hindari 'unsafe-inline', 'unsafe-eval', dan wildcard sources",
            owasp="A05",
            module="vuln_headers",
        ))

    return findings


# ─── Standalone ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from rich.console import Console

    console = Console()
    parser = argparse.ArgumentParser(description="AnarkisHunter — Security Headers Audit")
    parser.add_argument("--url", required=True)
    args = parser.parse_args()

    console.print(f"\n[red]🛡  Header Audit: [bold]{args.url}[/bold][/red]\n")
    data = run_header_audit(args.url)
    if data.get("error"):
        console.print(f"[red]Error: {data['error']}[/red]")
        sys.exit(1)

    console.print(f"[red]Issues:[/red] {len(data['issues'])}\n")
    for i in data["issues"]:
        c = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan"}.get(i["severity"], "white")
        console.print(f"  [{c}][{i['severity']}][/{c}] {i['header']} — {i['issue']}")

    if data.get("csp_analysis", {}).get("weaknesses"):
        console.print("\n[bold]CSP Weaknesses:[/bold]")
        for d, w in data["csp_analysis"]["weaknesses"]:
            console.print(f"  [yellow]→[/yellow] {d}: {w}")
