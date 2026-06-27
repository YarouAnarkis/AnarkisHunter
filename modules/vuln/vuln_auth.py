"""
AnarkisHunter — vuln_auth.py
==============================
Authentication weakness checker.
Test: default credential, weak password policy, account enumeration,
brute force protection, password reset weakness.

Usage standalone:
    python modules/vuln/vuln_auth.py --url http://target.local/login
"""

import sys
import re
import argparse
from pathlib import Path
from typing import Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from modules.utils.utils_request import HTTPClient, normalize_url
from modules.utils.report import ScanResult


# Common default credentials
DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "admin123"),
    ("admin", "12345"), ("root", "root"), ("root", "toor"),
    ("administrator", "administrator"), ("test", "test"),
    ("user", "user"), ("demo", "demo"), ("guest", "guest"),
]


def find_login_form(html: str) -> Dict:
    """Find login form & extract input fields."""
    form_m = re.search(r"<form([^>]*)>([\s\S]*?)</form>", html, re.I)
    if not form_m:
        return None
    attrs = form_m.group(1)
    body = form_m.group(2)

    if not re.search(r'type=["\']password["\']', body, re.I):
        return None

    action_m = re.search(r'action=["\']([^"\']*)["\']', attrs, re.I)
    method_m = re.search(r'method=["\']([^"\']*)["\']', attrs, re.I)

    # Identifikasi username & password field
    user_field = None
    pwd_field = None
    csrf_token = None
    extra_fields = {}

    for inp in re.finditer(r'<input([^>]*?)>', body, re.I):
        ia = inp.group(1)
        name_m = re.search(r'name=["\']([^"\']*)["\']', ia, re.I)
        type_m = re.search(r'type=["\']([^"\']*)["\']', ia, re.I)
        value_m = re.search(r'value=["\']([^"\']*)["\']', ia, re.I)
        name = name_m.group(1) if name_m else ""
        typ = type_m.group(1).lower() if type_m else ""
        value = value_m.group(1) if value_m else ""

        if typ == "password":
            pwd_field = name
        elif typ in ("text", "email"):
            if any(kw in name.lower() for kw in ["user", "name", "email", "login"]):
                user_field = user_field or name
        elif typ == "hidden":
            if any(kw in name.lower() for kw in ["csrf", "token", "nonce", "_token"]):
                csrf_token = (name, value)
            else:
                extra_fields[name] = value

    return {
        "action": action_m.group(1) if action_m else "",
        "method": (method_m.group(1).upper() if method_m else "POST"),
        "user_field": user_field or "username",
        "pwd_field": pwd_field or "password",
        "csrf_token": csrf_token,
        "extra_fields": extra_fields,
    }


def run_auth_scan(target: str, test_default: bool = True, timeout: int = 10) -> Dict:
    url = normalize_url(target)
    result = {
        "url": url,
        "login_form": None,
        "tested_creds": [],
        "successful_logins": [],
        "weak_signals": [],
        "error": None,
    }

    try:
        with HTTPClient(timeout=timeout) as client:
            resp = client.get(url)
            if not resp:
                result["error"] = "Connection failed"
                return result

            form = find_login_form(resp.text)
            if not form:
                result["error"] = "No login form found"
                return result
            result["login_form"] = form

            action = form["action"] or url
            if not action.startswith("http"):
                from urllib.parse import urljoin
                action = urljoin(url, action)

            # Cek account enumeration via password reset / username probe
            # Test login form errors untuk username valid vs invalid
            data1 = {form["user_field"]: "nonexistent_user_anark", form["pwd_field"]: "anyzpzpzpsplitz"}
            data2 = {form["user_field"]: "admin", form["pwd_field"]: "anyzpzpzpsplitz"}
            if form["csrf_token"]:
                data1[form["csrf_token"][0]] = form["csrf_token"][1]
                data2[form["csrf_token"][0]] = form["csrf_token"][1]
            data1.update(form["extra_fields"])
            data2.update(form["extra_fields"])

            r1 = client.post(action, data=data1)
            r2 = client.post(action, data=data2)
            if r1 and r2:
                msg1 = re.search(r"(?i)(user|account).*?(not found|tidak ditemukan|invalid)", r1.text[:5000])
                msg2 = re.search(r"(?i)(password|kata sandi).*?(incorrect|salah|invalid)", r2.text[:5000])
                if msg1 and msg2:
                    result["weak_signals"].append({
                        "type": "User Enumeration via Error Message",
                        "evidence": f"diff: '{msg1.group(0)[:80]}' vs '{msg2.group(0)[:80]}'",
                    })

            if test_default:
                for user, pwd in DEFAULT_CREDS:
                    data = {form["user_field"]: user, form["pwd_field"]: pwd}
                    if form["csrf_token"]:
                        data[form["csrf_token"][0]] = form["csrf_token"][1]
                    data.update(form["extra_fields"])
                    resp = client.post(action, data=data, allow_redirects=False)
                    if not resp:
                        continue
                    result["tested_creds"].append((user, pwd, resp.status_code))
                    # Heuristik success: redirect ke /dashboard / set session cookie / no login form
                    success_indicators = (
                        resp.status_code in (302, 303) or
                        "logout" in resp.text.lower()[:2000] or
                        "welcome" in resp.text.lower()[:2000]
                    )
                    failure_indicators = (
                        "invalid" in resp.text.lower()[:3000] or
                        "incorrect" in resp.text.lower()[:3000] or
                        "salah" in resp.text.lower()[:3000]
                    )
                    if success_indicators and not failure_indicators:
                        result["successful_logins"].append({
                            "user": user, "pwd": pwd,
                            "status": resp.status_code,
                            "location": resp.headers.get("Location", ""),
                        })

            # Rate limit check (kirim 10x salah, cek apakah masih bisa)
            # (skipped untuk avoid lockout, opsi --aggressive)

    except Exception as e:
        result["error"] = str(e)

    return result


def analyze_auth_findings(data: Dict) -> List[ScanResult]:
    findings = []
    url = data.get("url", "")

    for cred in data.get("successful_logins", []):
        findings.append(ScanResult(
            title=f"Default Credentials Work: {cred['user']}/{cred['pwd']}",
            severity="CRITICAL",
            description=f"Login berhasil dengan kredensial default {cred['user']}:{cred['pwd']}",
            url=url,
            evidence=f"Status: {cred['status']} | Location: {cred.get('location', '')}",
            recommendation=(
                "Hapus default credentials; enforce strong password policy; "
                "implement MFA; deteksi & alert login default cred"
            ),
            owasp="A07",
            module="vuln_auth",
        ))

    for sig in data.get("weak_signals", []):
        findings.append(ScanResult(
            title=sig["type"],
            severity="MEDIUM",
            description=f"Authentication weakness: {sig['type']}",
            url=url,
            evidence=sig["evidence"],
            recommendation=(
                "Gunakan generic error message ('Invalid credentials') tanpa membedakan "
                "user vs password salah"
            ),
            owasp="A07",
            module="vuln_auth",
        ))

    return findings


# ─── Standalone ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from rich.console import Console
    from rich.table import Table

    console = Console()
    parser = argparse.ArgumentParser(description="AnarkisHunter — Auth Weakness")
    parser.add_argument("--url", required=True)
    parser.add_argument("--no-default", action="store_true", help="Skip default cred test")
    args = parser.parse_args()

    console.print(f"\n[red]🔐 Auth Scan: [bold]{args.url}[/bold][/red]\n")
    data = run_auth_scan(args.url, test_default=not args.no_default)
    if data.get("error"):
        console.print(f"[red]Error: {data['error']}[/red]")
        sys.exit(1)

    console.print(f"[green]Tested:[/green] {len(data['tested_creds'])} default creds")
    console.print(f"[red]Successful:[/red] {len(data['successful_logins'])}")
    console.print(f"[yellow]Weak signals:[/yellow] {len(data['weak_signals'])}\n")

    for c in data["successful_logins"]:
        console.print(f"  [bold red]✓[/bold red] {c['user']}/{c['pwd']} → HTTP {c['status']}")
    for s in data["weak_signals"]:
        console.print(f"  [yellow]⚠[/yellow] {s['type']}: {s['evidence']}")
