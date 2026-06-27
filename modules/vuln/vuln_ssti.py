"""
AnarkisHunter — vuln_ssti.py
==============================
Server-Side Template Injection detector. Inject template syntax,
cek apakah expression dievaluasi server-side (Jinja2, Twig, Freemarker, etc).

Usage standalone:
    python modules/vuln/vuln_ssti.py --url "http://target.local/page?name=test"
"""

import sys
import argparse
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from modules.utils.utils_request import HTTPClient, normalize_url
from modules.utils.utils_payload import payload_manager
from modules.utils.report import ScanResult


# Payload yang akan evaluate jika SSTI ada
SSTI_TESTS = [
    {"payload": "{{7*7}}", "expect": "49", "engine": "Jinja2/Twig"},
    {"payload": "${7*7}", "expect": "49", "engine": "Freemarker/JSP"},
    {"payload": "#{7*7}", "expect": "49", "engine": "Ruby ERB"},
    {"payload": "<%= 7*7 %>", "expect": "49", "engine": "ERB/EJS"},
    {"payload": "{{7*'7'}}", "expect": "7777777", "engine": "Jinja2"},
    {"payload": "${7*'7'}", "expect": "7777777", "engine": "Velocity"},
    {"payload": "{{ 'anark' + 'hunter' }}", "expect": "anarkhunter", "engine": "Jinja2"},
    {"payload": "{{ config }}", "expect": "Config", "engine": "Jinja2 (Flask)"},
]


def inject_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    params[param] = value
    return urlunparse(parsed._replace(query=urlencode(params)))


def run_ssti_scan(
    target: str,
    params: Optional[List[str]] = None,
    timeout: int = 10,
) -> Dict:
    url = normalize_url(target)
    parsed = urlparse(url)
    url_params = dict(parse_qsl(parsed.query, keep_blank_values=True))

    if not params:
        params = list(url_params.keys())
    if not params:
        return {"target": url, "error": "No parameters", "vulnerabilities": []}

    result = {
        "target": url,
        "params_tested": params,
        "vulnerabilities": [],
        "error": None,
    }

    try:
        with HTTPClient(timeout=timeout) as client:
            for param in params:
                for test in SSTI_TESTS:
                    test_url = inject_param(url, param, test["payload"])
                    resp = client.get(test_url)
                    if not resp:
                        continue
                    if test["expect"] in resp.text and test["payload"] not in resp.text:
                        result["vulnerabilities"].append({
                            "param": param,
                            "payload": test["payload"],
                            "expected": test["expect"],
                            "engine": test["engine"],
                            "url": test_url,
                            "status": resp.status_code,
                            "evidence": f"Payload {test['payload']} evaluated to {test['expect']}",
                        })

    except Exception as e:
        result["error"] = str(e)

    return result


def analyze_ssti_findings(data: Dict) -> List[ScanResult]:
    findings = []
    for v in data.get("vulnerabilities", []):
        findings.append(ScanResult(
            title=f"Server-Side Template Injection ({v['engine']}) on '{v['param']}'",
            severity="CRITICAL",
            description=f"SSTI terdeteksi pada parameter '{v['param']}' — engine: {v['engine']}",
            url=v["url"],
            evidence=v["evidence"],
            payload=v["payload"],
            recommendation=(
                "Jangan pernah render user input sebagai template; "
                "gunakan template syntax dengan auto-escape; "
                "sandbox template engine; whitelist filter & global"
            ),
            owasp="A03",
            module="vuln_ssti",
        ))
    return findings


# ─── Standalone ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from rich.console import Console
    from rich.table import Table

    console = Console()
    parser = argparse.ArgumentParser(description="AnarkisHunter — SSTI Detector")
    parser.add_argument("--url", required=True)
    parser.add_argument("--param", nargs="+")
    args = parser.parse_args()

    console.print(f"\n[red]🧩 SSTI Scan: [bold]{args.url}[/bold][/red]\n")
    data = run_ssti_scan(args.url, args.param)
    if data.get("error"):
        console.print(f"[red]Error: {data['error']}[/red]")
        sys.exit(1)

    console.print(f"[red]Vulns:[/red] {len(data['vulnerabilities'])}\n")
    if data["vulnerabilities"]:
        t = Table(title="🚨 SSTI Findings", border_style="red")
        t.add_column("Param", style="cyan")
        t.add_column("Engine", style="yellow")
        t.add_column("Payload", style="white", overflow="fold")
        t.add_column("Evidence", style="red", overflow="fold")
        for v in data["vulnerabilities"]:
            t.add_row(v["param"], v["engine"], v["payload"], v["evidence"][:60])
        console.print(t)
