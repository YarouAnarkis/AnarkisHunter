"""
AnarkisHunter — vuln_sqli.py
==============================
SQL Injection detector (error-based, boolean-based, time-based).
Inject payload ke parameter URL & form, deteksi pattern error DB,
behavioral diff, time delay.

Usage standalone:
    python modules/vuln/vuln_sqli.py --url "http://target.local/page.php?id=1"
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
from modules.utils.report import ScanResult


# Pattern error SQL untuk error-based detection
SQL_ERROR_PATTERNS = [
    # MySQL
    r"SQL syntax.*MySQL", r"Warning.*mysql_", r"MySQLSyntaxErrorException",
    r"valid MySQL result", r"check the manual that corresponds to your (MySQL|MariaDB)",
    # PostgreSQL
    r"PostgreSQL.*ERROR", r"Warning.*\Wpg_", r"valid PostgreSQL result",
    r"Npgsql\.", r"PG::SyntaxError:", r"PG::UndefinedTable:",
    # MSSQL
    r"Driver.*SQL[\-\_\ ]*Server", r"OLE DB.*SQL Server", r"\bSQL Server.*Driver",
    r"Warning.*mssql_", r"\bSQL Server.*\d+\b", r"System\.Data\.SqlClient\.SqlException",
    r"\[Microsoft\]\[ODBC SQL Server Driver\]",
    # Oracle
    r"ORA-\d{4,5}:", r"Oracle error", r"Oracle.*Driver", r"Warning.*\Woci_",
    r"quoted string not properly terminated",
    # SQLite
    r"SQLite/JDBCDriver", r"SQLite\.Exception", r"sqlite3\.OperationalError",
    r"Warning.*sqlite_", r"SQLITE_ERROR",
    # Generic
    r"SQL syntax.*error", r"syntax error.*query", r"unclosed quotation mark",
    r"quoted string not properly terminated",
]


def inject_param(url: str, param: str, payload: str) -> str:
    """Inject payload pada parameter URL."""
    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    params[param] = payload
    new_query = urlencode(params)
    return urlunparse(parsed._replace(query=new_query))


def detect_sql_error(text: str) -> Optional[str]:
    """Cari pattern SQL error di response."""
    for pat in SQL_ERROR_PATTERNS:
        m = re.search(pat, text, re.I)
        if m:
            return m.group(0)[:200]
    return None


def run_sqli_scan(
    target: str,
    params: Optional[List[str]] = None,
    payloads: Optional[List[str]] = None,
    timeout: int = 10,
    test_time_based: bool = True,
) -> Dict:
    """SQLi scan terhadap URL dengan parameter."""
    url = normalize_url(target)
    parsed = urlparse(url)
    url_params = dict(parse_qsl(parsed.query, keep_blank_values=True))

    if not params:
        params = list(url_params.keys())
    if not params:
        return {"target": url, "error": "No parameters to test (provide URL dengan ?key=value)",
                "vulnerabilities": []}

    payloads = payloads or payload_manager.get("sqli")
    result = {
        "target": url,
        "params_tested": params,
        "total_payloads": len(payloads),
        "vulnerabilities": [],
        "baseline_size": 0,
        "error": None,
    }

    try:
        with HTTPClient(timeout=timeout) as client:
            # Baseline
            base_resp = client.get(url)
            if not base_resp:
                result["error"] = "Baseline request failed"
                return result
            result["baseline_size"] = len(base_resp.content)
            baseline_text = base_resp.text[:5000]

            # Tiap parameter test semua payload
            for param in params:
                for payload in payloads:
                    if not test_time_based and "SLEEP" in payload.upper():
                        continue
                    test_url = inject_param(url, param, payload)

                    is_time_based = any(
                        t in payload.upper() for t in ["SLEEP", "WAITFOR", "PG_SLEEP"]
                    )

                    t0 = time.time()
                    resp = client.get(test_url)
                    elapsed = time.time() - t0

                    if not resp:
                        continue

                    # 1. Error-based
                    err = detect_sql_error(resp.text)
                    if err:
                        result["vulnerabilities"].append({
                            "param": param, "payload": payload, "type": "Error-based",
                            "evidence": err, "url": test_url,
                            "status": resp.status_code,
                        })
                        continue

                    # 2. Time-based
                    if is_time_based and elapsed > 4.5:
                        result["vulnerabilities"].append({
                            "param": param, "payload": payload, "type": "Time-based",
                            "evidence": f"Response delayed {elapsed:.1f}s (payload mengandung SLEEP/WAITFOR)",
                            "url": test_url, "status": resp.status_code,
                        })

                    # 3. Boolean-based: cek diff dengan baseline
                    size_diff = abs(len(resp.content) - result["baseline_size"])
                    if size_diff > 200 and size_diff < 5000:
                        # Cek apakah payload jelas SQL injection
                        if "OR '1'='1'" in payload or "OR 1=1" in payload:
                            result["vulnerabilities"].append({
                                "param": param, "payload": payload, "type": "Boolean-based",
                                "evidence": f"Response size diff: {size_diff} bytes vs baseline",
                                "url": test_url, "status": resp.status_code,
                            })

    except Exception as e:
        result["error"] = str(e)

    return result


def analyze_sqli_findings(data: Dict) -> List[ScanResult]:
    findings = []
    for v in data.get("vulnerabilities", []):
        findings.append(ScanResult(
            title=f"SQL Injection ({v['type']}) on parameter '{v['param']}'",
            severity="CRITICAL",
            description=f"SQL Injection vulnerability terdeteksi pada parameter '{v['param']}'",
            url=v["url"],
            evidence=v["evidence"][:500],
            payload=v["payload"],
            recommendation=(
                "Gunakan parameterized queries / prepared statements; "
                "validate & escape input; gunakan ORM dengan benar; deploy WAF"
            ),
            owasp="A03",
            module="vuln_sqli",
        ))
    return findings


# ─── Standalone ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from rich.console import Console
    from rich.table import Table

    console = Console()
    parser = argparse.ArgumentParser(description="AnarkisHunter — SQL Injection Detector")
    parser.add_argument("--url", required=True, help="Target URL dengan parameter")
    parser.add_argument("--param", nargs="+", help="Spesifik parameter (default: semua)")
    parser.add_argument("--no-time", action="store_true", help="Skip time-based test")
    parser.add_argument("--timeout", type=int, default=10)
    args = parser.parse_args()

    console.print(f"\n[red]💉 SQLi Scan: [bold]{args.url}[/bold][/red]\n")
    data = run_sqli_scan(args.url, args.param, timeout=args.timeout,
                         test_time_based=not args.no_time)

    if data.get("error"):
        console.print(f"[red]Error: {data['error']}[/red]")
        sys.exit(1)

    console.print(f"[green]Parameters tested:[/green] {', '.join(data['params_tested'])}")
    console.print(f"[green]Payloads used:[/green] {data['total_payloads']}")
    console.print(f"[red]Vulnerabilities:[/red] {len(data['vulnerabilities'])}\n")

    if data["vulnerabilities"]:
        t = Table(title="🚨 SQLi Findings", border_style="red")
        t.add_column("Param", style="cyan")
        t.add_column("Type", style="yellow")
        t.add_column("Payload", style="white", overflow="fold")
        t.add_column("Evidence", style="red", overflow="fold")
        for v in data["vulnerabilities"][:20]:
            t.add_row(v["param"], v["type"], v["payload"][:60], v["evidence"][:80])
        console.print(t)
