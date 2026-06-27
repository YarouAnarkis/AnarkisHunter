"""
AnarkisHunter — scan_cookies.py
==================================
Cookie attribute analyzer — Secure, HttpOnly, SameSite, Domain, Expiry.

Usage standalone:
    python modules/scanner/scan_cookies.py --url http://target.local
"""

import sys
import argparse
from pathlib import Path
from typing import Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from modules.utils.utils_request import HTTPClient, normalize_url
from modules.utils.report import ScanResult


# Session cookie name patterns
SESSION_NAMES = [
    "session", "sess", "phpsessid", "jsessionid", "asp.net_sessionid",
    "connect.sid", "laravel_session", "ci_session", "django_session",
    "_session", "sid", "sessid", "auth", "token", "jwt",
]


def is_session_cookie(name: str) -> bool:
    name_low = name.lower()
    return any(pat in name_low for pat in SESSION_NAMES)


def run_cookie_scan(target: str, timeout: int = 10) -> Dict:
    """
    Analisis attribute semua cookie yang di-set.

    Returns:
        Dict berisi cookie analysis
    """
    url = normalize_url(target)
    result = {
        "url": url,
        "cookies": [],
        "session_cookies": [],
        "weak_cookies": [],
        "error": None,
    }

    try:
        with HTTPClient(timeout=timeout) as client:
            resp = client.get(url)
            if not resp:
                result["error"] = "Connection failed"
                return result

            # Parse semua Set-Cookie header
            raw_set_cookies = []
            if hasattr(resp.raw, "headers"):
                try:
                    raw_set_cookies = resp.raw.headers.getlist("Set-Cookie")
                except Exception:
                    pass
            if not raw_set_cookies:
                # fallback ke cookies jar
                for c in resp.cookies:
                    raw_set_cookies.append(_cookie_to_str(c))

            for raw in raw_set_cookies:
                analyzed = _analyze_cookie_string(raw, url.startswith("https"))
                result["cookies"].append(analyzed)
                if is_session_cookie(analyzed["name"]):
                    result["session_cookies"].append(analyzed)
                weaknesses = analyzed.get("weaknesses", [])
                if weaknesses:
                    result["weak_cookies"].append(analyzed)

    except Exception as e:
        result["error"] = str(e)

    return result


def _cookie_to_str(cookie) -> str:
    """Convert requests cookie to Set-Cookie-like string."""
    parts = [f"{cookie.name}={cookie.value or ''}"]
    if cookie.expires:
        parts.append(f"Expires={cookie.expires}")
    if cookie.domain:
        parts.append(f"Domain={cookie.domain}")
    if cookie.path:
        parts.append(f"Path={cookie.path}")
    if cookie.secure:
        parts.append("Secure")
    if cookie.has_nonstandard_attr("HttpOnly") or cookie.has_nonstandard_attr("httponly"):
        parts.append("HttpOnly")
    ss = cookie.get_nonstandard_attr("SameSite") if hasattr(cookie, "get_nonstandard_attr") else None
    if ss:
        parts.append(f"SameSite={ss}")
    return "; ".join(parts)


def _analyze_cookie_string(raw: str, is_https: bool) -> Dict:
    """Parse & analisis Set-Cookie string."""
    parts = [p.strip() for p in raw.split(";")]
    name_value = parts[0]
    name, _, value = name_value.partition("=")
    attrs = {p.split("=")[0].strip().lower(): (p.split("=", 1)[1].strip() if "=" in p else True)
             for p in parts[1:]}

    result = {
        "name": name.strip(),
        "value": value.strip()[:80],
        "value_full_length": len(value),
        "secure": "secure" in attrs,
        "httponly": "httponly" in attrs,
        "samesite": attrs.get("samesite"),
        "domain": attrs.get("domain"),
        "path": attrs.get("path", "/"),
        "expires": attrs.get("expires"),
        "max_age": attrs.get("max-age"),
        "raw": raw[:300],
        "weaknesses": [],
    }

    is_session = is_session_cookie(result["name"])

    if not result["secure"]:
        if is_https:
            result["weaknesses"].append(("Missing Secure flag", "HIGH" if is_session else "MEDIUM"))
        elif is_session:
            result["weaknesses"].append(("Session cookie without Secure (HTTPS recommended)", "LOW"))

    if not result["httponly"] and is_session:
        result["weaknesses"].append(("Missing HttpOnly flag (XSS dapat curi)", "HIGH"))
    elif not result["httponly"]:
        result["weaknesses"].append(("Missing HttpOnly flag", "LOW"))

    if not result["samesite"]:
        result["weaknesses"].append(("Missing SameSite attribute (CSRF risk)", "MEDIUM"))
    elif result["samesite"].lower() == "none" and not result["secure"]:
        result["weaknesses"].append(("SameSite=None tanpa Secure", "HIGH"))

    if result["domain"] and result["domain"].startswith("."):
        result["weaknesses"].append(("Cookie shared across subdomains", "LOW"))

    return result


def analyze_cookie_findings(data: Dict) -> List[ScanResult]:
    findings = []
    url = data.get("url", "")

    for c in data.get("cookies", []):
        for desc, sev in c.get("weaknesses", []):
            findings.append(ScanResult(
                title=f"Insecure Cookie: {c['name']} — {desc}",
                severity=sev,
                description=f"Cookie '{c['name']}' tidak aman: {desc}",
                url=url,
                evidence=c["raw"],
                recommendation="Set Secure, HttpOnly, SameSite=Lax/Strict pada session cookie",
                owasp="A02",
                module="scan_cookies",
            ))

    return findings


# ─── Standalone ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from rich.console import Console
    from rich.table import Table

    console = Console()
    parser = argparse.ArgumentParser(description="AnarkisHunter — Cookie Analyzer")
    parser.add_argument("--url", required=True, help="Target URL")
    args = parser.parse_args()

    console.print(f"\n[cyan]🍪 Cookie Analyzer: [bold]{args.url}[/bold][/cyan]\n")
    data = run_cookie_scan(args.url)

    if data.get("error"):
        console.print(f"[red]Error: {data['error']}[/red]")
        sys.exit(1)

    console.print(f"[green]Cookies:[/green] {len(data['cookies'])}")
    console.print(f"[yellow]Session:[/yellow] {len(data['session_cookies'])}")
    console.print(f"[red]Weak:[/red] {len(data['weak_cookies'])}\n")

    for c in data["cookies"]:
        t = Table(title=f"🍪 {c['name']}", border_style="cyan")
        t.add_column("Attribute", style="cyan")
        t.add_column("Value", style="white")
        t.add_row("Value (preview)", c["value"])
        t.add_row("Length", str(c["value_full_length"]))
        t.add_row("Secure", "[green]✓[/green]" if c["secure"] else "[red]✗[/red]")
        t.add_row("HttpOnly", "[green]✓[/green]" if c["httponly"] else "[red]✗[/red]")
        t.add_row("SameSite", c["samesite"] or "[red]not set[/red]")
        t.add_row("Domain", c["domain"] or "")
        t.add_row("Path", c["path"])
        t.add_row("Expires", c["expires"] or "session")
        console.print(t)
        for desc, sev in c.get("weaknesses", []):
            color = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan"}.get(sev, "white")
            console.print(f"  [{color}][{sev}][/{color}] {desc}")
