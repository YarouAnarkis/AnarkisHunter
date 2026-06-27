"""
AnarkisHunter — vuln_cors_deep.py
====================================
Deep CORS misconfiguration analyzer (lebih advanced dari scan_cors).
Test bypass techniques: subdomain reflection, regex bypass, null origin,
trusted subdomain takeover potential.

Usage standalone:
    python modules/vuln/vuln_cors_deep.py --url http://target.local/api
"""

import sys
import argparse
from pathlib import Path
from typing import Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from modules.utils.utils_request import HTTPClient, normalize_url, get_domain
from modules.utils.report import ScanResult


def _test(client: HTTPClient, url: str, origin: str) -> Dict:
    try:
        resp = client.get(url, headers={"Origin": origin})
        if not resp:
            return None
        return {
            "origin": origin,
            "status": resp.status_code,
            "acao": resp.headers.get("Access-Control-Allow-Origin", ""),
            "acac": resp.headers.get("Access-Control-Allow-Credentials", ""),
            "vary": resp.headers.get("Vary", ""),
        }
    except Exception:
        return None


def run_cors_deep_scan(target: str, timeout: int = 10) -> Dict:
    url = normalize_url(target)
    target_domain = get_domain(url)

    test_cases = [
        # name, origin
        ("Wildcard test", "*"),
        ("Reflected origin (random)", "https://anarkis-evil.com"),
        ("Null origin", "null"),
        ("Subdomain typo bypass", f"https://attacker.{target_domain}"),
        ("Subdomain prefix bypass", f"https://{target_domain}.evil.com"),
        ("Subdomain suffix bypass", f"https://evil{target_domain}"),
        ("Prefix dash bypass", f"https://evil-{target_domain}"),
        ("Backslash bypass", f"https://{target_domain}\\@evil.com"),
        ("Underscore bypass", f"https://{target_domain}_evil.com"),
        ("Trusted subdomain", f"https://test.{target_domain}"),
        ("HTTPS to HTTP downgrade", f"http://{target_domain}"),
    ]

    result = {
        "target": url,
        "target_domain": target_domain,
        "tests": [],
        "issues": [],
        "error": None,
    }

    try:
        with HTTPClient(timeout=timeout) as client:
            for name, origin in test_cases:
                test = _test(client, url, origin)
                if test:
                    test["case"] = name
                    result["tests"].append(test)
                    _check_issue(test, target_domain, result["issues"])

    except Exception as e:
        result["error"] = str(e)

    return result


def _check_issue(test: Dict, target_domain: str, issues: List) -> None:
    acao = (test.get("acao") or "").lower()
    acac = (test.get("acac") or "").lower()
    origin = test["origin"]

    if not acao:
        return

    # Reflected with credentials = CRITICAL
    if acao == origin.lower() and acac == "true":
        issues.append({
            "case": test["case"],
            "type": "Origin reflected with credentials (account takeover)",
            "severity": "CRITICAL",
            "origin": origin,
            "acao": acao,
        })
        return

    # Wildcard + credentials = HIGH (browser blocks but config broken)
    if acao == "*" and acac == "true":
        issues.append({
            "case": test["case"],
            "type": "Wildcard ACAO with Credentials (misconfig)",
            "severity": "HIGH",
            "origin": origin,
            "acao": acao,
        })
        return

    # Wildcard
    if acao == "*":
        issues.append({
            "case": test["case"],
            "type": "Wildcard ACAO",
            "severity": "MEDIUM",
            "origin": origin,
            "acao": acao,
        })
        return

    # Null origin allowed
    if origin == "null" and acao == "null":
        issues.append({
            "case": test["case"],
            "type": "Null origin allowed (sandbox iframe attack)",
            "severity": "HIGH",
            "origin": origin,
            "acao": acao,
        })
        return

    # Reflected evil origin (any subdomain bypass)
    if "evil" in acao or acao == origin.lower():
        if target_domain not in acao or origin == acao:
            issues.append({
                "case": test["case"],
                "type": "Origin bypass — server reflects untrusted origin",
                "severity": "HIGH" if acac == "true" else "MEDIUM",
                "origin": origin,
                "acao": acao,
            })


def analyze_cors_deep_findings(data: Dict) -> List[ScanResult]:
    findings = []
    seen = set()
    for issue in data.get("issues", []):
        key = (issue["type"], issue["origin"])
        if key in seen:
            continue
        seen.add(key)
        findings.append(ScanResult(
            title=f"CORS: {issue['type']} ({issue['case']})",
            severity=issue["severity"],
            description=f"CORS misconfiguration: {issue['type']}",
            url=data.get("target"),
            evidence=f"Origin sent: {issue['origin']} | ACAO returned: {issue['acao']}",
            payload=f"Origin: {issue['origin']}",
            recommendation=(
                "Strict whitelist; jangan reflect Origin; jangan combine wildcard "
                "dengan credentials; deny null origin"
            ),
            owasp="A05",
            module="vuln_cors_deep",
        ))
    return findings


# ─── Standalone ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from rich.console import Console
    from rich.table import Table

    console = Console()
    parser = argparse.ArgumentParser(description="AnarkisHunter — Deep CORS")
    parser.add_argument("--url", required=True)
    args = parser.parse_args()

    console.print(f"\n[red]🌐 Deep CORS Scan: [bold]{args.url}[/bold][/red]\n")
    data = run_cors_deep_scan(args.url)
    if data.get("error"):
        console.print(f"[red]Error: {data['error']}[/red]")
        sys.exit(1)

    t = Table(title="CORS Tests", border_style="cyan")
    t.add_column("Case", style="cyan", overflow="fold")
    t.add_column("Origin", style="yellow", overflow="fold")
    t.add_column("ACAO", style="green", overflow="fold")
    t.add_column("ACAC", style="red", width=8)
    for test in data["tests"]:
        t.add_row(test["case"][:25], test["origin"][:40],
                  test.get("acao", "") or "[dim]none[/dim]", test.get("acac", ""))
    console.print(t)

    if data["issues"]:
        console.print("\n[bold red]Issues:[/bold red]")
        for i in data["issues"]:
            c = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow"}.get(i["severity"], "white")
            console.print(f"  [{c}][{i['severity']}][/{c}] {i['type']}")
