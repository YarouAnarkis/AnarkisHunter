"""
AnarkisHunter — scan_forms.py
================================
HTML form analyzer — extract semua form, action, method, input fields,
csrf tokens. Identifikasi form yang menarik untuk SQLi/XSS/CSRF test.

Usage standalone:
    python modules/scanner/scan_forms.py --url http://target.local
"""

import sys
import re
import argparse
from pathlib import Path
from typing import Dict, List
from urllib.parse import urljoin

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from modules.utils.utils_request import HTTPClient, normalize_url
from modules.utils.report import ScanResult


def run_form_scan(target: str, timeout: int = 10) -> Dict:
    """
    Ekstrak & analisis semua form pada halaman target.

    Returns:
        Dict berisi forms detail
    """
    url = normalize_url(target)
    result = {
        "url": url,
        "total_forms": 0,
        "forms": [],
        "no_csrf_forms": [],
        "login_forms": [],
        "upload_forms": [],
        "search_forms": [],
        "error": None,
    }

    try:
        with HTTPClient(timeout=timeout) as client:
            resp = client.get(url)
            if not resp:
                result["error"] = "Connection failed"
                return result

            try:
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(resp.text, "html.parser")
                forms = soup.find_all("form")
            except ImportError:
                forms = _parse_forms_regex(resp.text)
            except Exception:
                forms = []

            for f in forms:
                form_data = _extract_form_data(f, url)
                result["forms"].append(form_data)

                # Kategorisasi
                if not form_data["has_csrf"]:
                    result["no_csrf_forms"].append(form_data)
                if form_data["is_login"]:
                    result["login_forms"].append(form_data)
                if form_data["is_upload"]:
                    result["upload_forms"].append(form_data)
                if form_data["is_search"]:
                    result["search_forms"].append(form_data)

            result["total_forms"] = len(result["forms"])

    except Exception as e:
        result["error"] = str(e)

    return result


def _extract_form_data(form_elem, base_url: str) -> Dict:
    """Extract data dari form element (BeautifulSoup)."""
    if hasattr(form_elem, "get"):
        # BeautifulSoup
        action = form_elem.get("action", "")
        method = (form_elem.get("method") or "GET").upper()
        inputs = []
        for inp in form_elem.find_all(["input", "select", "textarea"]):
            inputs.append({
                "name": inp.get("name", ""),
                "type": inp.get("type", inp.name),
                "value": (inp.get("value") or "")[:80],
                "required": inp.has_attr("required"),
            })
    else:
        # Dict dari regex parse
        action = form_elem.get("action", "")
        method = form_elem.get("method", "GET").upper()
        inputs = form_elem.get("inputs", [])

    full_action = urljoin(base_url, action) if action else base_url

    # Detect type
    field_names = " ".join((i.get("name") or "").lower() for i in inputs)
    field_types = " ".join((i.get("type") or "").lower() for i in inputs)
    field_text = field_names + " " + field_types

    is_login = any(kw in field_text for kw in ["password", "passwd", "pwd"]) and "password" in field_types
    is_upload = "file" in field_types
    is_search = any(kw in field_text for kw in ["search", "query", "q", "keyword"])
    is_register = "confirm" in field_names or "register" in field_names

    has_csrf = any(any(kw in (i.get("name") or "").lower() for kw in
                        ["csrf", "_token", "authenticity", "nonce", "xsrf"]) for i in inputs)

    return {
        "action": full_action,
        "method": method,
        "inputs": inputs,
        "input_count": len(inputs),
        "is_login": is_login,
        "is_upload": is_upload,
        "is_search": is_search,
        "is_register": is_register,
        "has_csrf": has_csrf,
    }


def _parse_forms_regex(html: str) -> List[Dict]:
    """Fallback parser tanpa BeautifulSoup."""
    forms = []
    for form_match in re.finditer(r"<form([^>]*)>([\s\S]*?)</form>", html, re.I):
        attrs = form_match.group(1)
        body = form_match.group(2)
        action_m = re.search(r'action=["\']([^"\']*)["\']', attrs, re.I)
        method_m = re.search(r'method=["\']([^"\']*)["\']', attrs, re.I)
        inputs = []
        for inp in re.finditer(
                r'<(input|select|textarea)([^>]*)/?>', body, re.I):
            attrs_in = inp.group(2)
            name = re.search(r'name=["\']([^"\']*)["\']', attrs_in, re.I)
            typ = re.search(r'type=["\']([^"\']*)["\']', attrs_in, re.I)
            inputs.append({
                "name": name.group(1) if name else "",
                "type": typ.group(1) if typ else inp.group(1),
                "value": "", "required": "required" in attrs_in,
            })
        forms.append({
            "action": action_m.group(1) if action_m else "",
            "method": method_m.group(1).upper() if method_m else "GET",
            "inputs": inputs,
        })
    return forms


def analyze_form_findings(data: Dict) -> List[ScanResult]:
    findings = []
    url = data.get("url", "")

    for form in data.get("login_forms", []):
        if not form["has_csrf"]:
            findings.append(ScanResult(
                title="Login Form Without CSRF Token",
                severity="HIGH",
                description="Form login tanpa CSRF token — rentan CSRF attack",
                url=url,
                evidence=f"Action: {form['action']}, Method: {form['method']}",
                recommendation="Tambahkan CSRF token tersembunyi di form",
                owasp="A01",
                module="scan_forms",
            ))
        if form["method"] == "GET":
            findings.append(ScanResult(
                title="Login Form Uses GET Method",
                severity="HIGH",
                description="Form login submit via GET — credential muncul di URL & log server",
                url=url,
                evidence=f"Action: {form['action']}",
                recommendation="Ubah method ke POST",
                owasp="A02",
                module="scan_forms",
            ))

    for form in data.get("no_csrf_forms", []):
        if form in data.get("search_forms", []):
            continue  # Search form tidak perlu CSRF
        findings.append(ScanResult(
            title=f"Form Without CSRF Protection",
            severity="MEDIUM",
            description="Form mutating tanpa CSRF token",
            url=url,
            evidence=f"Action: {form['action']} | Method: {form['method']} | Inputs: {form['input_count']}",
            recommendation="Implementasikan CSRF protection",
            owasp="A01",
            module="scan_forms",
        ))

    for form in data.get("upload_forms", []):
        findings.append(ScanResult(
            title="File Upload Form Detected",
            severity="MEDIUM",
            description="File upload form detected — perlu validasi ketat",
            url=url,
            evidence=f"Action: {form['action']}",
            recommendation="Validasi extension, MIME type, magic bytes; simpan di luar webroot",
            owasp="A04",
            module="scan_forms",
        ))

    return findings


# ─── Standalone ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from rich.console import Console
    from rich.table import Table

    console = Console()
    parser = argparse.ArgumentParser(description="AnarkisHunter — Form Analyzer")
    parser.add_argument("--url", required=True, help="Target URL")
    args = parser.parse_args()

    console.print(f"\n[cyan]📋 Form Analyzer: [bold]{args.url}[/bold][/cyan]\n")
    data = run_form_scan(args.url)

    if data.get("error"):
        console.print(f"[red]Error: {data['error']}[/red]")
        sys.exit(1)

    console.print(f"[green]Total forms:[/green] {data['total_forms']}")
    console.print(f"[red]No CSRF:[/red] {len(data['no_csrf_forms'])}")
    console.print(f"[yellow]Login:[/yellow] {len(data['login_forms'])}")
    console.print(f"[yellow]Upload:[/yellow] {len(data['upload_forms'])}")
    console.print(f"[cyan]Search:[/cyan] {len(data['search_forms'])}\n")

    for i, form in enumerate(data["forms"], 1):
        t = Table(title=f"Form #{i}", border_style="cyan")
        t.add_column("Field", style="cyan")
        t.add_column("Value", style="white")
        t.add_row("Action", form["action"])
        t.add_row("Method", form["method"])
        t.add_row("Inputs", str(form["input_count"]))
        t.add_row("CSRF", "✓" if form["has_csrf"] else "[red]✗[/red]")
        t.add_row("Type", ", ".join(filter(None, [
            "login" if form["is_login"] else "",
            "upload" if form["is_upload"] else "",
            "search" if form["is_search"] else "",
            "register" if form["is_register"] else "",
        ])) or "general")
        console.print(t)

        for inp in form["inputs"][:15]:
            console.print(f"    • [{inp.get('type')}] {inp.get('name')}")
