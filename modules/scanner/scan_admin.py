"""
AnarkisHunter — scan_admin.py
================================
Admin panel finder. Probe 200+ path admin/login dari config.ADMIN_PATHS.

Usage standalone:
    python modules/scanner/scan_admin.py --url http://target.local
"""

import sys
import argparse
from pathlib import Path
from typing import Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from modules.utils.utils_request import HTTPClient, normalize_url
from modules.utils.report import ScanResult
from config.settings import ADMIN_PATHS


# Confirm patterns untuk admin page
ADMIN_INDICATORS = [
    "admin", "login", "password", "username", "sign in", "log in",
    "dashboard", "control panel", "administrator", "panel",
    "<input type=\"password\"", "<input type='password'",
]


def _probe_admin(client: HTTPClient, base: str, path: str) -> Dict:
    """Probe satu admin path."""
    url = base.rstrip("/") + path if path.startswith("/") else base.rstrip("/") + "/" + path
    try:
        resp = client.get(url)
        if not resp:
            return {"path": path, "url": url, "status": None, "found": False}

        text_low = resp.text.lower()[:3000]
        confidence = 0

        # Indicator
        for ind in ADMIN_INDICATORS:
            if ind in text_low:
                confidence += 1

        # Form login → strong signal
        has_login_form = ("<form" in text_low and
                          ('type="password"' in text_low or "type='password'" in text_low))
        if has_login_form:
            confidence += 5

        found = resp.status_code in {200, 301, 302, 401, 403} and confidence > 0

        return {
            "path": path,
            "url": url,
            "status": resp.status_code,
            "size": len(resp.content),
            "confidence": confidence,
            "has_login_form": has_login_form,
            "title": _extract_title(resp.text),
            "found": found,
        }
    except Exception:
        return {"path": path, "url": url, "status": None, "found": False}


def _extract_title(html: str) -> str:
    """Extract <title>"""
    import re
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    return m.group(1).strip()[:100] if m else ""


def run_admin_scan(
    target: str,
    paths: List[str] = None,
    threads: int = 20,
    timeout: int = 8,
    delay: float = 0,
    proxy: Optional[str] = None,
) -> Dict:
    """Scan admin panel paths."""
    base_url = normalize_url(target)
    paths = paths or ADMIN_PATHS

    result = {
        "target": base_url,
        "total_tested": len(paths),
        "found": [],
        "login_forms": [],
        "error": None,
    }

    try:
        with HTTPClient(timeout=timeout, threads=threads, delay=delay, proxy=proxy) as client:
            with ThreadPoolExecutor(max_workers=threads) as ex:
                futures = {ex.submit(_probe_admin, client, base_url, p): p for p in paths}
                for fut in as_completed(futures):
                    try:
                        res = fut.result()
                        if res.get("found"):
                            result["found"].append(res)
                            if res.get("has_login_form"):
                                result["login_forms"].append(res)
                    except Exception:
                        continue
    except Exception as e:
        result["error"] = str(e)

    result["found"].sort(key=lambda x: (-x["confidence"], x["path"]))
    return result


def analyze_admin_findings(data: Dict) -> List[ScanResult]:
    findings = []
    for f in data.get("login_forms", []):
        findings.append(ScanResult(
            title=f"Admin Login Form Accessible: {f['path']}",
            severity="MEDIUM",
            description=f"Halaman login admin terdeteksi (form password). HTTP {f['status']}.",
            url=f["url"],
            evidence=f"Title: {f['title']}\nConfidence: {f['confidence']}",
            recommendation=(
                "Lindungi admin panel: IP whitelist, 2FA, rate limiting, "
                "ubah path default, monitor brute force"
            ),
            owasp="A07",
            module="scan_admin",
        ))

    # Admin paths yang found tapi bukan form
    for f in data.get("found", []):
        if f.get("has_login_form"):
            continue
        findings.append(ScanResult(
            title=f"Admin-Related Path: {f['path']}",
            severity="LOW" if f["status"] in (401, 403) else "INFO",
            description=f"Path admin-related ditemukan: HTTP {f['status']}",
            url=f["url"],
            evidence=f"Title: {f['title']} | Confidence: {f['confidence']}",
            module="scan_admin",
        ))

    return findings


# ─── Standalone ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from rich.console import Console
    from rich.table import Table

    console = Console()
    parser = argparse.ArgumentParser(description="AnarkisHunter — Admin Panel Finder")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--threads", type=int, default=20)
    args = parser.parse_args()

    console.print(f"\n[cyan]🛡  Admin Panel Scan: [bold]{args.url}[/bold][/cyan]\n")
    data = run_admin_scan(args.url, threads=args.threads)

    console.print(f"[green]Tested:[/green] {data['total_tested']} paths")
    console.print(f"[green]Found:[/green] {len(data['found'])}")
    console.print(f"[red]Login forms:[/red] {len(data['login_forms'])}\n")

    if data["found"]:
        t = Table(title="Admin/Login Paths", border_style="red")
        t.add_column("Status", style="cyan", width=8)
        t.add_column("Path", style="yellow", overflow="fold")
        t.add_column("Title", style="white", overflow="fold")
        t.add_column("Login Form", style="red", width=10)
        for f in data["found"][:30]:
            t.add_row(
                str(f["status"]), f["path"],
                f["title"][:50],
                "✓" if f.get("has_login_form") else "",
            )
        console.print(t)
