"""
AnarkisHunter — scan_backup.py
=================================
Backup file finder — generate backup file variants berbasis crawl result
atau path tertentu, probe untuk file backup tersedia.

Variants: .bak, .backup, .old, ~, .swp, .orig, .save, .copy, .tmp, .1,
plus combinations dengan tanggal & timestamp.

Usage standalone:
    python modules/scanner/scan_backup.py --url http://target.local
"""

import sys
import argparse
import datetime
from pathlib import Path
from typing import Dict, List, Set
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from modules.utils.utils_request import HTTPClient, normalize_url
from modules.utils.report import ScanResult


# Backup suffix patterns
BACKUP_SUFFIXES = [
    ".bak", ".backup", ".old", ".orig", ".save", ".copy", ".tmp",
    ".swp", ".swo", "~", ".1", ".2", ".original",
    ".bak.txt", ".old.txt", ".backup.txt",
]

# File base name yang umum punya backup
COMMON_TARGETS = [
    "index", "config", "wp-config", "database", "settings", "admin",
    "login", "main", "home", "default", "backup", "site",
]

# File extensions yang sering dibackup
TARGET_EXTENSIONS = [".php", ".asp", ".aspx", ".jsp", ".html", ".htm", ".js",
                     ".py", ".rb", ".inc", ".conf", ".config", ".xml", ".yaml"]


def _generate_backup_variants(base_paths: List[str]) -> List[str]:
    """Generate backup variants dari base paths."""
    variants: Set[str] = set()

    # Tahun & tanggal
    today = datetime.date.today()
    years = [today.year, today.year - 1]
    date_str = today.strftime("%Y%m%d")

    for path in base_paths:
        # Tambah suffix saja
        for suffix in BACKUP_SUFFIXES:
            variants.add(path + suffix)

        # Sisipkan tanggal di belakang nama file
        if "." in path:
            base, dot, ext = path.rpartition(".")
            for year in years:
                variants.add(f"{base}_{year}.{ext}")
                variants.add(f"{base}-{year}.{ext}")
            variants.add(f"{base}_{date_str}.{ext}")
            variants.add(f"{base}_backup.{ext}")
            variants.add(f"{base}_old.{ext}")
        else:
            variants.add(f"{path}_{today.year}")
            variants.add(f"{path}_backup")

    # Default known backup archives
    for name in ["backup", "backups", "site", "www", "html", "wwwroot", "public_html"]:
        for ext in [".zip", ".tar", ".tar.gz", ".rar", ".7z", ".sql.gz", ".sql"]:
            variants.add(f"{name}{ext}")
            variants.add(f"{name}_{today.year}{ext}")

    return sorted(variants)


def _probe_backup(client: HTTPClient, base: str, path: str) -> Dict:
    """Probe single backup path."""
    url = base.rstrip("/") + "/" + path.lstrip("/")
    try:
        resp = client.head(url)
        if not resp:
            return {"path": path, "url": url, "found": False}
        # HEAD bisa di-block, fallback GET ringkas
        if resp.status_code in {405, 501}:
            resp = client.get(url)
            if not resp:
                return {"path": path, "url": url, "found": False}

        found = resp.status_code == 200
        return {
            "path": path,
            "url": url,
            "status": resp.status_code,
            "size": int(resp.headers.get("Content-Length", 0) or len(resp.content or b"")),
            "content_type": resp.headers.get("Content-Type", "")[:50],
            "found": found,
        }
    except Exception:
        return {"path": path, "url": url, "found": False}


def run_backup_scan(
    target: str,
    base_paths: List[str] = None,
    threads: int = 20,
    timeout: int = 8,
) -> Dict:
    """Scan backup files on target."""
    base_url = normalize_url(target)
    base_paths = base_paths or [
        f"{n}{e}" for n in COMMON_TARGETS for e in TARGET_EXTENSIONS
    ]
    variants = _generate_backup_variants(base_paths)

    result = {
        "target": base_url,
        "total_tested": len(variants),
        "found": [],
        "error": None,
    }

    try:
        with HTTPClient(timeout=timeout) as client:
            with ThreadPoolExecutor(max_workers=threads) as ex:
                futures = {ex.submit(_probe_backup, client, base_url, v): v for v in variants}
                for fut in as_completed(futures):
                    try:
                        res = fut.result()
                        if res.get("found"):
                            result["found"].append(res)
                    except Exception:
                        continue
    except Exception as e:
        result["error"] = str(e)

    result["found"].sort(key=lambda x: -x.get("size", 0))
    return result


def analyze_backup_findings(data: Dict) -> List[ScanResult]:
    findings = []
    for f in data.get("found", []):
        sev = "HIGH"
        if any(f["path"].endswith(s) for s in [".sql", ".sql.gz", ".zip", ".tar.gz"]):
            sev = "CRITICAL"
        findings.append(ScanResult(
            title=f"Backup File Found: {f['path']}",
            severity=sev,
            description=f"File backup accessible ({f['size']} bytes). Bisa berisi source code / data leak.",
            url=f["url"],
            evidence=f"Status: {f['status']} | Size: {f['size']} bytes | Type: {f['content_type']}",
            recommendation="Hapus file backup dari webroot atau batasi akses",
            owasp="A05",
            module="scan_backup",
        ))
    return findings


# ─── Standalone ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from rich.console import Console
    from rich.table import Table

    console = Console()
    parser = argparse.ArgumentParser(description="AnarkisHunter — Backup File Finder")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--threads", type=int, default=20)
    args = parser.parse_args()

    console.print(f"\n[cyan]💾 Backup File Scan: [bold]{args.url}[/bold][/cyan]\n")
    data = run_backup_scan(args.url, threads=args.threads)

    console.print(f"[green]Tested:[/green] {data['total_tested']}")
    console.print(f"[red]Found:[/red] {len(data['found'])}\n")

    if data["found"]:
        t = Table(title="Backup Files Found", border_style="red")
        t.add_column("Path", style="yellow", overflow="fold")
        t.add_column("Size", style="white", width=12)
        t.add_column("Type", style="dim")
        for f in data["found"][:40]:
            t.add_row(f["path"], f"{f['size']:,}", f["content_type"])
        console.print(t)
    else:
        console.print("[green]No backup files found[/green]")
