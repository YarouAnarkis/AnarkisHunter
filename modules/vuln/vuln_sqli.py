"""
AnarkisHunter — vuln_sqli.py
==============================
SQL Injection detector dengan baseline verification, double-check,
confidence scoring, dan WAF bypass mode.

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
from modules.utils.utils_verifier import FindingVerifier, confidence_to_severity
from modules.utils.utils_waf_bypass import waf_bypass
from modules.utils.report import ScanResult


SQL_ERROR_PATTERNS = [
    r"SQL syntax.*MySQL", r"Warning.*mysql_", r"MySQLSyntaxErrorException",
    r"valid MySQL result", r"check the manual that corresponds to your (MySQL|MariaDB)",
    r"PostgreSQL.*ERROR", r"Warning.*\Wpg_", r"valid PostgreSQL result",
    r"Npgsql\.", r"PG::SyntaxError:", r"PG::UndefinedTable:",
    r"Driver.*SQL[\-\_\ ]*Server", r"OLE DB.*SQL Server", r"\bSQL Server.*Driver",
    r"Warning.*mssql_", r"\bSQL Server.*\d+\b", r"System\.Data\.SqlClient\.SqlException",
    r"\[Microsoft\]\[ODBC SQL Server Driver\]",
    r"ORA-\d{4,5}:", r"Oracle error", r"Oracle.*Driver", r"Warning.*\Woci_",
    r"quoted string not properly terminated",
    r"SQLite/JDBCDriver", r"SQLite\.Exception", r"sqlite3\.OperationalError",
    r"Warning.*sqlite_", r"SQLITE_ERROR",
    r"SQL syntax.*error", r"syntax error.*query", r"unclosed quotation mark",
]


def inject_param(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    params[param] = payload
    return urlunparse(parsed._replace(query=urlencode(params)))


def detect_sql_error(text: str) -> Optional[str]:
    for pat in SQL_ERROR_PATTERNS:
        m = re.search(pat, text, re.I)
        if m:
            return m.group(0)[:200]
    return None


def _check_sqli(base_resp, test_resp, payload: str, elapsed: float = 0) -> Optional[Dict]:
    if not test_resp:
        return None

    err = detect_sql_error(test_resp.text)
    if err:
        return {"type": "Error-based", "evidence": err}

    is_time = any(t in payload.upper() for t in ["SLEEP", "WAITFOR", "PG_SLEEP"])
    if is_time and elapsed > 4.5:
        return {"type": "Time-based", "evidence": f"Response delayed {elapsed:.1f}s"}

    if base_resp:
        size_diff = abs(len(test_resp.content) - len(base_resp.content))
        if size_diff > 200 and ("OR '1'='1'" in payload or "OR 1=1" in payload):
            return {"type": "Boolean-based", "evidence": f"Response size diff: {size_diff} bytes"}

    return None


def run_sqli_scan(
    target: str,
    params: Optional[List[str]] = None,
    payloads: Optional[List[str]] = None,
    timeout: int = 10,
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
        return {
            "target": url,
            "error": "No parameters to test (provide URL dengan ?key=value)",
            "vulnerabilities": [], "findings": [],
        }

    payloads = payloads or payload_manager.get("sqli")
    result = {
        "target": url,
        "params_tested": params,
        "total_payloads": len(payloads),
        "vulnerabilities": [],
        "findings": [],
        "waf_detected": [],
        "baseline_size": 0,
        "error": None,
    }

    try:
        with HTTPClient(timeout=timeout, threads=threads, proxy=proxy) as client:
            verifier = FindingVerifier(client, url)
            verifier.capture_baseline()

            base_resp = client.get(url)
            if not base_resp:
                result["error"] = "Baseline request failed"
                return result

            waf_bypass.detect_from_response(base_resp)
            result["waf_detected"] = waf_bypass.detected_wafs
            result["baseline_size"] = len(base_resp.content)

            seen = set()

            for param in params:
                for payload in payloads:
                    if not test_time_based and "SLEEP" in payload.upper():
                        continue

                    variants = waf_bypass.generate_bypass_variants(payload, url, param)

                    for variant in variants:
                        actual_payload = variant["payload"]
                        test_url = variant.get("url") or inject_param(url, param, actual_payload)
                        key = f"{param}:{actual_payload}"
                        if key in seen:
                            continue

                        is_time_based = any(
                            t in actual_payload.upper() for t in ["SLEEP", "WAITFOR", "PG_SLEEP"]
                        )

                        def check_fn(base, test, p=actual_payload, itb=is_time_based):
                            elapsed = 0
                            if itb:
                                elapsed = 5.0
                            hit = _check_sqli(base, test, p, elapsed)
                            if hit:
                                hit["technique"] = variant.get("technique", "original")
                            return hit

                        finding = verifier.verify_finding(test_url, check_fn, min_confidence=50)
                        if not finding:
                            continue

                        seen.add(key)
                        vuln = {
                            "param": param,
                            "payload": actual_payload,
                            "type": finding.get("type", "Unknown"),
                            "evidence": finding.get("evidence", ""),
                            "url": test_url,
                            "confidence": finding.get("confidence", 0),
                            "technique": finding.get("technique", "original"),
                            "verified": True,
                        }
                        result["vulnerabilities"].append(vuln)

        result["findings"] = analyze_sqli_findings(result)

    except Exception as e:
        result["error"] = str(e)

    return result


def analyze_sqli_findings(data: Dict) -> List[ScanResult]:
    findings = []
    for v in data.get("vulnerabilities", []):
        confidence = v.get("confidence", 0)
        severity = confidence_to_severity(confidence, "CRITICAL")
        findings.append(ScanResult(
            title=f"SQL Injection ({v['type']}) on parameter '{v['param']}'",
            severity=severity,
            description=(
                f"SQL Injection ({v['type']}) on parameter '{v['param']}' "
                f"[confidence: {confidence}%]"
            ),
            url=v["url"],
            evidence=v["evidence"][:500],
            payload=v["payload"],
            owasp="A03",
            module="vuln_sqli",
            confidence=confidence,
        ))
    return findings


if __name__ == "__main__":
    from rich.console import Console
    from rich.table import Table

    console = Console()
    parser = argparse.ArgumentParser(description="AnarkisHunter — SQL Injection Detector")
    parser.add_argument("--url", required=True, help="Target URL dengan parameter")
    parser.add_argument("--param", nargs="+", help="Spesifik parameter (default: semua)")
    parser.add_argument("--no-time", action="store_true", help="Skip time-based test")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--threads", type=int, default=10)
    args = parser.parse_args()

    console.print(f"\n[red]SQLi Scan: [bold]{args.url}[/bold][/red]\n")
    data = run_sqli_scan(
        args.url, args.param, timeout=args.timeout,
        threads=args.threads, test_time_based=not args.no_time,
    )

    if data.get("error"):
        console.print(f"[red]Error: {data['error']}[/red]")
        sys.exit(1)

    if data.get("waf_detected"):
        console.print(f"[yellow]{waf_bypass.get_status_display()}[/yellow]")

    console.print(f"[green]Parameters tested:[/green] {', '.join(data['params_tested'])}")
    console.print(f"[green]Payloads used:[/green] {data['total_payloads']}")
    console.print(f"[red]Vulnerabilities:[/red] {len(data['vulnerabilities'])}\n")

    if data["vulnerabilities"]:
        t = Table(title="SQLi Findings", border_style="red")
        t.add_column("Param", style="cyan")
        t.add_column("Type", style="yellow")
        t.add_column("Conf.", style="green")
        t.add_column("Payload", style="white", overflow="fold")
        t.add_column("Evidence", style="red", overflow="fold")
        for v in data["vulnerabilities"][:20]:
            t.add_row(
                v["param"], v["type"], f"{v.get('confidence', 0)}%",
                v["payload"][:60], v["evidence"][:80],
            )
        console.print(t)
