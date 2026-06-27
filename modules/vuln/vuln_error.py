"""
AnarkisHunter — vuln_error.py
================================
Verbose error message detector. Trigger error dengan payload aneh,
cek response untuk stack trace, error path disclosure, DB error.

Usage standalone:
    python modules/vuln/vuln_error.py --url http://target.local/page
"""

import sys
import re
import argparse
from pathlib import Path
from typing import Dict, List
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from modules.utils.utils_request import HTTPClient, normalize_url
from modules.utils.report import ScanResult


ERROR_TRIGGERS = [
    "'", "\"", "\\", "%00", "[", "{", "../../../",
    "%27", "%22", "../%00",
]

ERROR_PATTERNS = {
    "Python Stack Trace":   re.compile(r"Traceback \(most recent call last\)|File \".+?\", line \d+,"),
    "PHP Error":            re.compile(r"<b>(?:Warning|Notice|Fatal error|Parse error)</b>:|on line \d+", re.I),
    "ASP.NET Error":        re.compile(r"System\.\w+Exception|at \w+\.\w+\(.+?\)|Stack Trace:"),
    "Java Stack Trace":     re.compile(r"java\.lang\.\w+(?:Exception|Error)|at [\w.$]+\([\w.]+\.java:\d+\)"),
    "Ruby Error":           re.compile(r"NoMethodError|NameError|\(Errno::\w+\)|\.rb:\d+:in `"),
    "Node.js Error":        re.compile(r"at [\w./<>]+ \([\w./]+\.js:\d+:\d+\)|TypeError:|ReferenceError:"),
    "SQL Error":            re.compile(r"SQL syntax|ORA-\d+|sqlite3\.OperationalError|valid PostgreSQL", re.I),
    "Path Disclosure":      re.compile(r"(?:/var/www/|/home/\w+/|/srv/|C:\\inetpub\\|C:\\xampp\\|/Applications/)"),
    "DB Connection Error":  re.compile(r"could not connect to|connection refused|database.*server", re.I),
}


def inject_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    params[param] = value
    return urlunparse(parsed._replace(query=urlencode(params)))


def run_error_scan(target: str, timeout: int = 10) -> Dict:
    url = normalize_url(target)
    parsed = urlparse(url)
    url_params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    result = {
        "url": url,
        "errors_found": [],
        "error": None,
    }

    try:
        with HTTPClient(timeout=timeout) as client:
            # 1. Baseline check
            base = client.get(url)
            if base:
                for name, pat in ERROR_PATTERNS.items():
                    m = pat.search(base.text)
                    if m:
                        result["errors_found"].append({
                            "trigger": "(baseline)", "type": name,
                            "evidence": m.group(0)[:200], "url": url, "status": base.status_code,
                        })

            # 2. Param fuzzing
            for param in url_params.keys():
                for trigger in ERROR_TRIGGERS:
                    test_url = inject_param(url, param, trigger)
                    resp = client.get(test_url)
                    if not resp:
                        continue
                    for name, pat in ERROR_PATTERNS.items():
                        m = pat.search(resp.text)
                        if m:
                            result["errors_found"].append({
                                "trigger": trigger, "param": param, "type": name,
                                "evidence": m.group(0)[:200],
                                "url": test_url, "status": resp.status_code,
                            })

            # 3. 404 / nonexistent path
            base404 = client.get(url.rstrip("/") + "/anarkis_nonexistent_404_test")
            if base404:
                for name, pat in ERROR_PATTERNS.items():
                    m = pat.search(base404.text)
                    if m:
                        result["errors_found"].append({
                            "trigger": "(404)", "type": name,
                            "evidence": m.group(0)[:200],
                            "url": url + "/anarkis_nonexistent_404_test",
                            "status": base404.status_code,
                        })

    except Exception as e:
        result["error"] = str(e)

    # Dedupe by type+trigger
    seen = set()
    deduped = []
    for r in result["errors_found"]:
        key = (r["type"], r.get("trigger", ""))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(r)
    result["errors_found"] = deduped

    return result


def analyze_error_findings(data: Dict) -> List[ScanResult]:
    findings = []
    for e in data.get("errors_found", []):
        sev_map = {
            "SQL Error": "HIGH", "Path Disclosure": "MEDIUM",
            "Python Stack Trace": "MEDIUM", "PHP Error": "MEDIUM",
            "ASP.NET Error": "MEDIUM", "Java Stack Trace": "MEDIUM",
        }
        sev = sev_map.get(e["type"], "LOW")
        findings.append(ScanResult(
            title=f"Verbose Error Disclosed: {e['type']}",
            severity=sev,
            description=f"{e['type']} terungkap di response (trigger: {e.get('trigger', '')})",
            url=e["url"],
            evidence=e["evidence"][:300],
            payload=str(e.get("trigger", "")),
            recommendation=(
                "Disable verbose error / debug mode di production; "
                "tampilkan generic error message ke user; log error ke file"
            ),
            owasp="A05",
            module="vuln_error",
        ))
    return findings


# ─── Standalone ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from rich.console import Console
    from rich.table import Table

    console = Console()
    parser = argparse.ArgumentParser(description="AnarkisHunter — Error Disclosure")
    parser.add_argument("--url", required=True)
    args = parser.parse_args()

    console.print(f"\n[red]🐛 Error Disclosure: [bold]{args.url}[/bold][/red]\n")
    data = run_error_scan(args.url)
    if data.get("error"):
        console.print(f"[red]Error: {data['error']}[/red]")
        sys.exit(1)

    console.print(f"[red]Errors disclosed:[/red] {len(data['errors_found'])}\n")
    if data["errors_found"]:
        t = Table(title="Errors", border_style="red")
        t.add_column("Type", style="yellow")
        t.add_column("Trigger", style="cyan")
        t.add_column("Evidence", style="white", overflow="fold")
        for e in data["errors_found"][:20]:
            t.add_row(e["type"], str(e.get("trigger", ""))[:20], e["evidence"][:80])
        console.print(t)
