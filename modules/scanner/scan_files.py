"""
AnarkisHunter — scan_files.py
================================
Sensitive file finder (config files, dotfiles, dump files, backup, dll).
Probe path-path standar dari config.SENSITIVE_FILES.

Usage standalone:
    python modules/scanner/scan_files.py --url http://target.local
"""

import sys
import argparse
from pathlib import Path
from typing import Dict, List
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from modules.utils.utils_request import HTTPClient, normalize_url
from modules.utils.report import ScanResult
from config.settings import SENSITIVE_FILES


# Content patterns yang konfirmasi file valid (bukan custom 404 page)
CONFIRM_PATTERNS = {
    ".env": ["DB_PASSWORD", "APP_KEY", "DB_HOST", "API_KEY"],
    ".git/HEAD": ["ref: refs/heads"],
    ".git/config": ["[core]", "[remote"],
    "wp-config.php": ["DB_NAME", "DB_USER", "DB_PASSWORD"],
    "config.php": ["<?php", "DB_", "password"],
    "phpinfo.php": ["phpinfo()", "PHP Version", "_SERVER"],
    "robots.txt": ["User-agent", "Disallow"],
    ".htaccess": ["RewriteEngine", "AuthType"],
    "web.config": ["<configuration>", "<system.web"],
    "backup.sql": ["INSERT INTO", "CREATE TABLE", "DROP TABLE"],
    "id_rsa": ["BEGIN OPENSSH", "BEGIN RSA PRIVATE"],
}


def _probe_file(client: HTTPClient, base: str, path: str) -> Dict:
    """Probe satu file."""
    url = base.rstrip("/") + "/" + path.lstrip("/")
    try:
        resp = client.get(url)
        if not resp:
            return {"path": path, "url": url, "status": None, "found": False}

        found = False
        confirmed = False
        evidence = ""

        # File ditemukan jika status 200 + size > 0 + bukan HTML 404
        if resp.status_code == 200 and len(resp.content) > 0:
            text_low = resp.text.lower()[:5000]
            # Lewati custom 404 yang return 200
            if "<title>404" in text_low or "page not found" in text_low or "not found" in text_low[:200]:
                found = False
            else:
                found = True
                # Konfirmasi dengan pattern
                patterns = CONFIRM_PATTERNS.get(path, [])
                for pat in patterns:
                    if pat.lower() in resp.text.lower():
                        confirmed = True
                        evidence = pat
                        break

        return {
            "path": path,
            "url": url,
            "status": resp.status_code,
            "size": len(resp.content),
            "content_type": resp.headers.get("Content-Type", "")[:50],
            "found": found,
            "confirmed": confirmed,
            "evidence": evidence,
            "preview": resp.text[:200] if found else "",
        }
    except Exception:
        return {"path": path, "url": url, "status": None, "found": False}


def run_file_scan(target: str, files: List[str] = None, threads: int = 15, timeout: int = 8) -> Dict:
    """Scan file sensitif pada target."""
    base_url = normalize_url(target)
    files = files or SENSITIVE_FILES

    result = {
        "target": base_url,
        "total_tested": len(files),
        "found": [],
        "confirmed": [],
        "error": None,
    }

    try:
        with HTTPClient(timeout=timeout) as client:
            with ThreadPoolExecutor(max_workers=threads) as ex:
                futures = {ex.submit(_probe_file, client, base_url, f): f for f in files}
                for fut in as_completed(futures):
                    try:
                        res = fut.result()
                        if res.get("found"):
                            result["found"].append(res)
                            if res.get("confirmed"):
                                result["confirmed"].append(res)
                    except Exception:
                        continue
    except Exception as e:
        result["error"] = str(e)

    result["found"].sort(key=lambda x: (not x["confirmed"], x["path"]))
    return result


def analyze_file_findings(data: Dict) -> List[ScanResult]:
    """Analisis hasil scan file."""
    findings = []

    SEVERITY_MAP = {
        ".env": "CRITICAL", ".env.local": "CRITICAL", ".env.production": "CRITICAL",
        ".git/HEAD": "HIGH", ".git/config": "HIGH", ".git/index": "HIGH",
        "wp-config.php": "CRITICAL", "config.php": "HIGH",
        "phpinfo.php": "HIGH", "info.php": "HIGH",
        "backup.sql": "CRITICAL", "dump.sql": "CRITICAL", "backup.zip": "HIGH",
        "id_rsa": "CRITICAL", "id_dsa": "CRITICAL",
        ".htpasswd": "HIGH",
        "web.config": "MEDIUM",
        "credentials": "CRITICAL", "credentials.json": "CRITICAL",
    }

    for f in data.get("found", []):
        path = f["path"]
        severity = SEVERITY_MAP.get(path, "MEDIUM" if f.get("confirmed") else "LOW")

        title = f"Sensitive File Exposed: {path}"
        if f.get("confirmed"):
            title = f"⚠ Sensitive File Confirmed: {path}"

        findings.append(ScanResult(
            title=title,
            severity=severity,
            description=f"File sensitif accessible: {path} (HTTP {f['status']}, {f['size']} bytes)",
            url=f["url"],
            evidence=f"Confirmed pattern: {f.get('evidence', 'N/A')}\nPreview: {f.get('preview', '')[:300]}",
            recommendation=f"Hapus atau batasi akses ke {path} via .htaccess / web.config / nginx",
            owasp="A05",
            module="scan_files",
        ))

    return findings


# ─── Standalone ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from rich.console import Console
    from rich.table import Table

    console = Console()
    parser = argparse.ArgumentParser(description="AnarkisHunter — Sensitive File Scanner")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--threads", type=int, default=15)
    args = parser.parse_args()

    console.print(f"\n[cyan]🗃  Sensitive File Scan: [bold]{args.url}[/bold][/cyan]\n")
    data = run_file_scan(args.url, threads=args.threads)

    console.print(f"[green]Tested:[/green] {data['total_tested']} files")
    console.print(f"[red]Found:[/red] {len(data['found'])}")
    console.print(f"[red]Confirmed:[/red] {len(data['confirmed'])}\n")

    if data["found"]:
        t = Table(title="Sensitive Files Found", border_style="red")
        t.add_column("✓", style="green", width=3)
        t.add_column("Status", style="cyan", width=8)
        t.add_column("Path", style="yellow", overflow="fold")
        t.add_column("Size", style="white", width=8)
        t.add_column("Evidence", style="dim")
        for f in data["found"]:
            check = "✓" if f["confirmed"] else "?"
            t.add_row(check, str(f["status"]), f["path"], str(f["size"]), f.get("evidence", "")[:30])
        console.print(t)
