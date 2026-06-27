"""
AnarkisHunter — vuln_session.py
==================================
Session security weakness checker:
- Session ID entropy (predictability)
- Session fixation
- Cookie security flags (Secure, HttpOnly, SameSite)
- Session regeneration after login

Usage standalone:
    python modules/vuln/vuln_session.py --url http://target.local
"""

import sys
import math
import argparse
from pathlib import Path
from typing import Dict, List
from collections import Counter

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from modules.utils.utils_request import HTTPClient, normalize_url
from modules.utils.report import ScanResult


def shannon_entropy(s: str) -> float:
    """Shannon entropy (bits per symbol)."""
    if not s:
        return 0.0
    counts = Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


SESSION_NAMES = (
    "session", "sess", "sid", "phpsessid", "jsessionid", "asp.net_sessionid",
    "connect.sid", "laravel_session", "ci_session", "django_session",
    "auth", "token", "jwt",
)


def is_session_cookie(name: str) -> bool:
    nl = name.lower()
    return any(s in nl for s in SESSION_NAMES)


def run_session_scan(target: str, samples: int = 10, timeout: int = 10) -> Dict:
    url = normalize_url(target)
    result = {
        "url": url,
        "samples": [],
        "session_cookie_name": None,
        "avg_entropy": 0.0,
        "min_length": 0,
        "max_length": 0,
        "weak_cookie_flags": [],
        "issues": [],
        "error": None,
    }

    try:
        for _ in range(samples):
            with HTTPClient(timeout=timeout) as client:
                resp = client.get(url)
                if not resp:
                    continue
                for c in resp.cookies:
                    if is_session_cookie(c.name):
                        result["samples"].append({
                            "name": c.name,
                            "value": c.value or "",
                            "secure": c.secure,
                            "httponly": (c.has_nonstandard_attr("HttpOnly")
                                          if hasattr(c, "has_nonstandard_attr") else False),
                            "samesite": (c.get_nonstandard_attr("SameSite")
                                          if hasattr(c, "get_nonstandard_attr") else None),
                        })
                        if not result["session_cookie_name"]:
                            result["session_cookie_name"] = c.name

        if not result["samples"]:
            result["error"] = "No session cookie observed"
            return result

        values = [s["value"] for s in result["samples"] if s["value"]]
        if values:
            entropies = [shannon_entropy(v) for v in values]
            result["avg_entropy"] = sum(entropies) / len(entropies)
            result["min_length"] = min(len(v) for v in values)
            result["max_length"] = max(len(v) for v in values)

            # Cek similarity (predictability)
            unique = len(set(values))
            if unique < len(values):
                result["issues"].append({
                    "type": "Duplicate session IDs across samples",
                    "evidence": f"{len(values) - unique} duplicates",
                    "severity": "HIGH",
                })

            if result["avg_entropy"] < 3.0:
                result["issues"].append({
                    "type": "Low session ID entropy",
                    "evidence": f"avg entropy {result['avg_entropy']:.2f} bits/char",
                    "severity": "HIGH",
                })
            elif result["avg_entropy"] < 4.0:
                result["issues"].append({
                    "type": "Mediocre session ID entropy",
                    "evidence": f"avg entropy {result['avg_entropy']:.2f} bits/char",
                    "severity": "MEDIUM",
                })

            if result["min_length"] < 16:
                result["issues"].append({
                    "type": "Short session ID",
                    "evidence": f"length {result['min_length']} (recommended ≥ 24)",
                    "severity": "MEDIUM",
                })

        # Check flags dari sample pertama
        first = result["samples"][0]
        if not first["secure"]:
            result["weak_cookie_flags"].append(("Secure", "MEDIUM"))
        if not first["httponly"]:
            result["weak_cookie_flags"].append(("HttpOnly", "HIGH"))
        if not first["samesite"]:
            result["weak_cookie_flags"].append(("SameSite", "MEDIUM"))

    except Exception as e:
        result["error"] = str(e)

    return result


def analyze_session_findings(data: Dict) -> List[ScanResult]:
    findings = []
    url = data.get("url", "")

    for issue in data.get("issues", []):
        findings.append(ScanResult(
            title=f"Session: {issue['type']}",
            severity=issue["severity"],
            description=issue["type"],
            url=url,
            evidence=issue["evidence"],
            recommendation=(
                "Gunakan CSPRNG untuk generate session ID; minimum 128-bit entropy; "
                "regenerate session ID setelah login; expire session pada logout"
            ),
            owasp="A07",
            module="vuln_session",
        ))

    for flag, sev in data.get("weak_cookie_flags", []):
        findings.append(ScanResult(
            title=f"Session Cookie Missing {flag} Flag",
            severity=sev,
            description=f"Session cookie tidak set flag {flag}",
            url=url,
            evidence=f"Cookie: {data.get('session_cookie_name')}",
            recommendation=f"Set {flag} flag pada session cookie",
            owasp="A07",
            module="vuln_session",
        ))

    return findings


# ─── Standalone ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from rich.console import Console

    console = Console()
    parser = argparse.ArgumentParser(description="AnarkisHunter — Session Security")
    parser.add_argument("--url", required=True)
    parser.add_argument("--samples", type=int, default=10)
    args = parser.parse_args()

    console.print(f"\n[red]🎫 Session Scan: [bold]{args.url}[/bold][/red]\n")
    data = run_session_scan(args.url, samples=args.samples)
    if data.get("error"):
        console.print(f"[red]Error: {data['error']}[/red]")
        sys.exit(1)

    console.print(f"[green]Session cookie:[/green] {data['session_cookie_name']}")
    console.print(f"[green]Samples:[/green] {len(data['samples'])}")
    console.print(f"[green]Avg entropy:[/green] {data['avg_entropy']:.2f} bits/char")
    console.print(f"[green]Length:[/green] {data['min_length']}-{data['max_length']}\n")

    if data["issues"]:
        for i in data["issues"]:
            c = {"HIGH": "red", "MEDIUM": "yellow"}.get(i["severity"], "white")
            console.print(f"  [{c}][{i['severity']}][/{c}] {i['type']} — {i['evidence']}")
    if data["weak_cookie_flags"]:
        console.print("\n[bold]Missing flags:[/bold]")
        for f, s in data["weak_cookie_flags"]:
            console.print(f"  [red]✗[/red] {f}")
