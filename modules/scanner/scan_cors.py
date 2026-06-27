"""
AnarkisHunter — scan_cors.py
==============================
CORS misconfiguration checker — test berbagai Origin untuk identifikasi
weak CORS policy (wildcard, reflection, null origin, etc).

Usage standalone:
    python modules/scanner/scan_cors.py --url http://target.local
"""

import sys
import argparse
from pathlib import Path
from typing import Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from modules.utils.utils_request import HTTPClient, normalize_url, get_domain
from modules.utils.report import ScanResult


def _test_origin(client: HTTPClient, url: str, origin: str) -> Dict:
    """Test CORS dengan Origin tertentu."""
    try:
        resp = client.get(url, headers={"Origin": origin})
        if not resp:
            return {"origin": origin, "error": "no response"}
        return {
            "origin": origin,
            "status": resp.status_code,
            "acao": resp.headers.get("Access-Control-Allow-Origin", ""),
            "acac": resp.headers.get("Access-Control-Allow-Credentials", ""),
            "acam": resp.headers.get("Access-Control-Allow-Methods", ""),
            "acah": resp.headers.get("Access-Control-Allow-Headers", ""),
            "max_age": resp.headers.get("Access-Control-Max-Age", ""),
        }
    except Exception as e:
        return {"origin": origin, "error": str(e)}


def run_cors_scan(target: str, timeout: int = 10) -> Dict:
    """Test CORS policy dengan berbagai origin."""
    url = normalize_url(target)
    target_domain = get_domain(url)

    test_origins = [
        f"https://evil.com",
        f"http://evil.com",
        f"null",
        f"https://{target_domain}.evil.com",
        f"https://evil{target_domain}",
        f"https://evil-{target_domain}",
        f"https://attacker.com",
    ]

    result = {
        "url": url,
        "target_domain": target_domain,
        "tests": [],
        "issues": [],
        "error": None,
    }

    try:
        with HTTPClient(timeout=timeout) as client:
            # Pertama: test tanpa origin (baseline)
            baseline = client.get(url)
            if baseline:
                result["baseline_acao"] = baseline.headers.get("Access-Control-Allow-Origin", "")

            for origin in test_origins:
                test = _test_origin(client, url, origin)
                result["tests"].append(test)
                _check_issue(test, origin, target_domain, result["issues"])

    except Exception as e:
        result["error"] = str(e)

    return result


def _check_issue(test: Dict, origin: str, target_domain: str, issues: List) -> None:
    """Cek apakah test menunjukkan issue CORS."""
    acao = (test.get("acao") or "").lower()
    acac = (test.get("acac") or "").lower()

    # 1. Reflected Origin + credentials
    if acao == origin.lower() and acac == "true":
        issues.append({
            "type": "Reflected Origin with Credentials",
            "severity": "CRITICAL",
            "origin": origin,
            "evidence": f"ACAO: {test.get('acao')} | ACAC: {test.get('acac')}",
        })
        return

    # 2. Wildcard + credentials (browser will block, but misconfig)
    if acao == "*" and acac == "true":
        issues.append({
            "type": "Wildcard ACAO with Credentials (broken config)",
            "severity": "HIGH",
            "origin": origin,
            "evidence": f"ACAO: * | ACAC: true",
        })
        return

    # 3. Wildcard ACAO
    if acao == "*":
        issues.append({
            "type": "Wildcard Allow-Origin",
            "severity": "MEDIUM",
            "origin": origin,
            "evidence": f"ACAO: *",
        })
        return

    # 4. null origin allowed
    if origin == "null" and acao == "null":
        issues.append({
            "type": "Null Origin Allowed",
            "severity": "HIGH",
            "origin": origin,
            "evidence": f"ACAO: null",
        })
        return

    # 5. Subdomain wildcard via suffix bypass (e.g. evil-target.com)
    if origin.replace("https://", "").replace("http://", "") in acao and target_domain not in acao:
        issues.append({
            "type": "Origin Suffix/Prefix Bypass Vulnerability",
            "severity": "HIGH",
            "origin": origin,
            "evidence": f"ACAO: {test.get('acao')} (reflected evil origin)",
        })


def analyze_cors_findings(data: Dict) -> List[ScanResult]:
    findings = []
    url = data.get("url", "")

    for issue in data.get("issues", []):
        findings.append(ScanResult(
            title=f"CORS Misconfiguration: {issue['type']}",
            severity=issue["severity"],
            description=(
                f"CORS policy mengizinkan origin yang seharusnya tidak dipercaya. "
                f"Origin tested: {issue['origin']}"
            ),
            url=url,
            evidence=issue["evidence"],
            payload=f"Origin: {issue['origin']}",
            recommendation=(
                "Whitelist origin secara eksplisit; jangan reflect Origin header; "
                "jangan kombinasi ACAO=* dengan credentials; cek dengan strict matching"
            ),
            owasp="A05",
            module="scan_cors",
        ))

    return findings


# ─── Standalone ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from rich.console import Console
    from rich.table import Table

    console = Console()
    parser = argparse.ArgumentParser(description="AnarkisHunter — CORS Scanner")
    parser.add_argument("--url", required=True, help="Target URL")
    args = parser.parse_args()

    console.print(f"\n[cyan]🌐 CORS Misconfiguration Scan: [bold]{args.url}[/bold][/cyan]\n")
    data = run_cors_scan(args.url)

    if data.get("error"):
        console.print(f"[red]Error: {data['error']}[/red]")
        sys.exit(1)

    t = Table(title="CORS Tests", border_style="cyan")
    t.add_column("Origin Sent", style="yellow", overflow="fold")
    t.add_column("ACAO Returned", style="green", overflow="fold")
    t.add_column("ACAC", style="red", width=8)
    for test in data["tests"]:
        t.add_row(
            test["origin"],
            test.get("acao", "") or "[dim]none[/dim]",
            test.get("acac", "") or "",
        )
    console.print(t)

    if data["issues"]:
        console.print("\n[bold red]Issues found:[/bold red]")
        for i in data["issues"]:
            color = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow"}.get(i["severity"], "white")
            console.print(f"  [{color}][{i['severity']}][/{color}] {i['type']} — origin={i['origin']}")
    else:
        console.print("\n[green]No CORS issues detected[/green]")
