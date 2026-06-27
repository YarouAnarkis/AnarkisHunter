"""
AnarkisHunter — vuln_csrf.py
==============================
CSRF (Cross-Site Request Forgery) vulnerability checker.
Scan halaman untuk form tanpa CSRF token, atau form yang menerima
request tanpa validasi origin/referer.

Usage standalone:
    python modules/vuln/vuln_csrf.py --url http://target.local
"""

import sys
import re
import argparse
from pathlib import Path
from typing import Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from modules.utils.utils_request import HTTPClient, normalize_url
from modules.utils.report import ScanResult


CSRF_TOKEN_PATTERNS = [
    r'name=["\']csrf[_-]?token["\']',
    r'name=["\']_token["\']',
    r'name=["\']authenticity_token["\']',
    r'name=["\']_csrf["\']',
    r'name=["\']nonce["\']',
    r'name=["\']xsrf[_-]?token["\']',
    r'name=["\']__RequestVerificationToken["\']',
]


def has_csrf_token(form_html: str) -> bool:
    for pat in CSRF_TOKEN_PATTERNS:
        if re.search(pat, form_html, re.I):
            return True
    return False


def extract_forms(html: str) -> List[Dict]:
    forms = []
    for m in re.finditer(r"<form([^>]*)>([\s\S]*?)</form>", html, re.I):
        attrs = m.group(1)
        body = m.group(2)
        method_m = re.search(r'method=["\']([^"\']*)["\']', attrs, re.I)
        action_m = re.search(r'action=["\']([^"\']*)["\']', attrs, re.I)
        forms.append({
            "method": (method_m.group(1) if method_m else "GET").upper(),
            "action": action_m.group(1) if action_m else "",
            "body": body[:5000],
            "has_csrf": has_csrf_token(body),
            "has_password": bool(re.search(r'type=["\']password["\']', body, re.I)),
        })
    return forms


def run_csrf_scan(target: str, timeout: int = 10) -> Dict:
    url = normalize_url(target)
    result = {
        "target": url,
        "forms": [],
        "vulnerable_forms": [],
        "samesite_cookies": [],
        "referer_required": None,
        "error": None,
    }

    try:
        with HTTPClient(timeout=timeout) as client:
            resp = client.get(url)
            if not resp:
                result["error"] = "Connection failed"
                return result

            forms = extract_forms(resp.text)
            result["forms"] = forms

            for f in forms:
                # Hanya POST/PUT/DELETE/PATCH yang biasa CSRF-sensitive
                if f["method"] in ("GET", "HEAD"):
                    continue
                if not f["has_csrf"]:
                    result["vulnerable_forms"].append(f)

            # Cek SameSite cookies
            for c in resp.cookies:
                ss = None
                if hasattr(c, "get_nonstandard_attr"):
                    ss = c.get_nonstandard_attr("SameSite")
                result["samesite_cookies"].append({
                    "name": c.name,
                    "samesite": ss,
                })

            # Test referer requirement (kirim POST tanpa referer ke action pertama)
            if result["vulnerable_forms"]:
                first = result["vulnerable_forms"][0]
                action = first["action"] or url
                if not action.startswith("http"):
                    from urllib.parse import urljoin
                    action = urljoin(url, action)
                # Coba POST kosong tanpa Referer
                ref_resp = client.post(action, data={}, headers={"Referer": ""})
                if ref_resp:
                    if ref_resp.status_code in (403, 419):
                        result["referer_required"] = True
                    else:
                        result["referer_required"] = False

    except Exception as e:
        result["error"] = str(e)

    return result


def analyze_csrf_findings(data: Dict) -> List[ScanResult]:
    findings = []
    target = data.get("target", "")

    for f in data.get("vulnerable_forms", []):
        sev = "HIGH" if f.get("has_password") else "MEDIUM"
        findings.append(ScanResult(
            title=f"CSRF — Form Tanpa Token ({f['method']})",
            severity=sev,
            description=(
                f"Form {f['method']} ke {f['action']} tidak memiliki CSRF token. "
                f"Bisa diserang via CSRF jika user terotentikasi mengunjungi halaman attacker."
            ),
            url=target,
            evidence=f"Form action: {f['action']} | Method: {f['method']} | Has password: {f['has_password']}",
            recommendation=(
                "Tambahkan CSRF token (random per-session) di semua form yang melakukan state-change; "
                "set cookie SameSite=Lax atau Strict; cek Origin/Referer header"
            ),
            owasp="A01",
            module="vuln_csrf",
        ))

    # Missing SameSite
    for c in data.get("samesite_cookies", []):
        if not c["samesite"]:
            findings.append(ScanResult(
                title=f"Cookie '{c['name']}' Tanpa SameSite",
                severity="LOW",
                description="Cookie tanpa attribute SameSite — meningkatkan CSRF risk",
                url=target,
                evidence=f"Cookie: {c['name']}",
                recommendation="Set SameSite=Lax (default) atau Strict",
                owasp="A01",
                module="vuln_csrf",
            ))

    return findings


# ─── Standalone ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from rich.console import Console
    from rich.table import Table

    console = Console()
    parser = argparse.ArgumentParser(description="AnarkisHunter — CSRF Checker")
    parser.add_argument("--url", required=True, help="Target URL")
    args = parser.parse_args()

    console.print(f"\n[red]🔄 CSRF Scan: [bold]{args.url}[/bold][/red]\n")
    data = run_csrf_scan(args.url)

    if data.get("error"):
        console.print(f"[red]Error: {data['error']}[/red]")
        sys.exit(1)

    console.print(f"[green]Total forms:[/green] {len(data['forms'])}")
    console.print(f"[red]Vulnerable:[/red] {len(data['vulnerable_forms'])}")
    if data.get("referer_required") is True:
        console.print("[green]✓[/green] Server requires Referer header")
    elif data.get("referer_required") is False:
        console.print("[red]✗[/red] Server tidak validate Referer header")

    if data["vulnerable_forms"]:
        t = Table(title="CSRF-Vulnerable Forms", border_style="red")
        t.add_column("Method", style="cyan", width=8)
        t.add_column("Action", style="yellow", overflow="fold")
        t.add_column("Has Pwd", style="red", width=8)
        for f in data["vulnerable_forms"]:
            t.add_row(f["method"], f["action"], "✓" if f.get("has_password") else "")
        console.print(t)
