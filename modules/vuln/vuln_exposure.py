"""
AnarkisHunter — vuln_exposure.py
==================================
Sensitive data exposure detector — scan body response untuk:
PII (email, phone), credit card, SSN-like, private keys, JWT, etc.

Usage standalone:
    python modules/vuln/vuln_exposure.py --url http://target.local
"""

import sys
import re
import argparse
from pathlib import Path
from typing import Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from modules.utils.utils_request import HTTPClient, normalize_url
from modules.utils.report import ScanResult


PII_PATTERNS = {
    "Email":        re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"),
    "Phone (ID)":   re.compile(r"(?:\+62|62|0)8\d{8,11}"),
    "Phone (US)":   re.compile(r"\+?1?[\s\-.]?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}\b"),
    "Credit Card":  re.compile(r"\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|6(?:011|5\d{2})\d{12})\b"),
    "SSN":          re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "IBAN":         re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b"),
    "JWT":          re.compile(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"),
    "PEM Private Key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "SSH Private Key": re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----"),
    "API Token":    re.compile(r"(?i)(api[_-]?key|access[_-]?token)[\"': =]+([A-Za-z0-9_\-]{20,})"),
    "AWS Access Key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "Bearer Token": re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*"),
    "Stack Trace":  re.compile(r"(?:Traceback \(most recent call last\)|java\.lang\.\w+Exception|at\s+\w+\.\w+\(.+?\.java:\d+\))"),
}


def run_exposure_scan(target: str, timeout: int = 10) -> Dict:
    url = normalize_url(target)
    result = {
        "url": url,
        "findings": {},
        "total_matches": 0,
        "error": None,
    }

    try:
        with HTTPClient(timeout=timeout) as client:
            resp = client.get(url)
            if not resp:
                result["error"] = "Connection failed"
                return result

            text = resp.text[:200000]  # max 200KB
            for name, pat in PII_PATTERNS.items():
                matches = pat.findall(text)
                if not matches:
                    continue
                # Normalize matches
                normalized = []
                for m in matches[:50]:
                    if isinstance(m, tuple):
                        m = " | ".join(str(x) for x in m if x)
                    normalized.append(str(m)[:100])
                result["findings"][name] = list(dict.fromkeys(normalized))
                result["total_matches"] += len(normalized)

    except Exception as e:
        result["error"] = str(e)

    return result


def analyze_exposure_findings(data: Dict) -> List[ScanResult]:
    findings = []
    url = data.get("url", "")
    SEV_MAP = {
        "Credit Card": "CRITICAL", "SSN": "CRITICAL", "PEM Private Key": "CRITICAL",
        "SSH Private Key": "CRITICAL", "AWS Access Key": "CRITICAL",
        "API Token": "HIGH", "JWT": "HIGH", "Bearer Token": "HIGH",
        "IBAN": "HIGH", "Phone (ID)": "MEDIUM", "Phone (US)": "MEDIUM",
        "Email": "LOW", "Stack Trace": "MEDIUM",
    }
    for name, matches in data.get("findings", {}).items():
        sev = SEV_MAP.get(name, "MEDIUM")
        findings.append(ScanResult(
            title=f"Sensitive Data Exposure: {name}",
            severity=sev,
            description=f"Ditemukan {len(matches)} match untuk {name} di response body",
            url=url,
            evidence="\n".join(matches[:15]),
            recommendation=(
                "Jangan expose data sensitif di public response; "
                "redact PII; gunakan encryption at rest & in transit"
            ),
            owasp="A02",
            module="vuln_exposure",
        ))
    return findings


# ─── Standalone ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from rich.console import Console
    from rich.table import Table

    console = Console()
    parser = argparse.ArgumentParser(description="AnarkisHunter — Data Exposure Scanner")
    parser.add_argument("--url", required=True)
    args = parser.parse_args()

    console.print(f"\n[red]🔓 Data Exposure: [bold]{args.url}[/bold][/red]\n")
    data = run_exposure_scan(args.url)
    if data.get("error"):
        console.print(f"[red]Error: {data['error']}[/red]")
        sys.exit(1)

    console.print(f"[red]Total matches:[/red] {data['total_matches']}\n")
    for name, matches in data["findings"].items():
        console.print(f"[bold yellow]{name}[/bold yellow] ({len(matches)})")
        for m in matches[:5]:
            console.print(f"  → {m}")
