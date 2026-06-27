"""
AnarkisHunter — scan_dirs.py
===============================
Directory bruteforce scanner (status codes berdasarkan response).
Threaded, dengan rate limiting & WAF awareness.

Usage standalone:
    python modules/scanner/scan_dirs.py --url http://target.local
    python modules/scanner/scan_dirs.py --url http://target.local --wordlist big.txt --threads 30
"""

import sys
import argparse
from pathlib import Path
from typing import Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from modules.utils.utils_request import HTTPClient, normalize_url
from modules.utils.utils_wordlist import wordlist_manager
from modules.utils.report import ScanResult


# Status code groups
INTERESTING_CODES = {200, 201, 202, 204, 301, 302, 307, 308, 401, 403}


def _scan_one_path(client: HTTPClient, base: str, path: str) -> Optional[Dict]:
    """Test satu path, return dict jika interesting."""
    url = base.rstrip("/") + "/" + path.lstrip("/")
    try:
        resp = client.get(url)
        if not resp:
            return None
        if resp.status_code in INTERESTING_CODES:
            return {
                "path": path,
                "url": url,
                "status": resp.status_code,
                "size": len(resp.content),
                "content_type": resp.headers.get("Content-Type", "")[:50],
            }
    except Exception:
        pass
    return None


def run_dir_scan(
    target: str,
    wordlist: Optional[List[str]] = None,
    threads: int = 20,
    timeout: int = 8,
    extensions: Optional[List[str]] = None,
) -> Dict:
    """
    Bruteforce direktori pada target.

    Args:
        target: URL base
        wordlist: List path/dir untuk dicoba (default: BUILTIN_DIRS)
        threads: Worker concurrency
        extensions: Tambahan extension (mis. ['.php', '.html'])

    Returns:
        Dict berisi found paths
    """
    base_url = normalize_url(target)
    paths = wordlist or wordlist_manager.get("directories")

    # Expand with extensions
    if extensions:
        expanded = []
        for p in paths:
            expanded.append(p)
            if "." not in p:
                for ext in extensions:
                    expanded.append(p + ext)
        paths = expanded

    result = {
        "target": base_url,
        "total_tested": len(paths),
        "found": [],
        "by_status": {},
        "error": None,
    }

    try:
        with HTTPClient(timeout=timeout) as client:
            with ThreadPoolExecutor(max_workers=threads) as ex:
                futures = {ex.submit(_scan_one_path, client, base_url, p): p for p in paths}
                for fut in as_completed(futures):
                    try:
                        res = fut.result()
                        if res:
                            result["found"].append(res)
                            result["by_status"][res["status"]] = result["by_status"].get(res["status"], 0) + 1
                    except Exception:
                        continue
    except Exception as e:
        result["error"] = str(e)

    result["found"].sort(key=lambda x: (x["status"], x["path"]))
    return result


def analyze_dir_findings(data: Dict) -> List[ScanResult]:
    """Analisis hasil dir scan."""
    findings = []
    target = data.get("target", "")

    for f in data.get("found", []):
        path_lower = f["path"].lower()
        severity = "INFO"
        title = f"Path Found ({f['status']}): {f['path']}"

        if f["status"] == 200:
            if any(kw in path_lower for kw in ["admin", "panel", "dashboard", "cpanel"]):
                severity = "MEDIUM"
                title = f"Admin Interface Accessible: {f['path']}"
            elif any(kw in path_lower for kw in [".env", "config", ".git", "backup", "phpinfo"]):
                severity = "HIGH"
                title = f"Sensitive File Accessible: {f['path']}"
        elif f["status"] in (401, 403):
            severity = "LOW"
            title = f"Restricted Path ({f['status']}): {f['path']}"

        findings.append(ScanResult(
            title=title,
            severity=severity,
            description=f"Path {f['path']} returned HTTP {f['status']} ({f['size']} bytes)",
            url=f["url"],
            evidence=f"Status: {f['status']} | Content-Type: {f['content_type']} | Size: {f['size']}",
            recommendation="Review apakah path ini seharusnya accessible publicly",
            owasp="A05" if severity != "INFO" else "",
            module="scan_dirs",
        ))

    return findings


# ─── Standalone ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from rich.console import Console
    from rich.table import Table

    console = Console()
    parser = argparse.ArgumentParser(description="AnarkisHunter — Directory Bruteforce")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--wordlist", help="Wordlist file")
    parser.add_argument("--threads", type=int, default=20)
    parser.add_argument("--timeout", type=int, default=8)
    parser.add_argument("--ext", nargs="+", help="Extensions e.g. .php .html")
    args = parser.parse_args()

    wl = None
    if args.wordlist:
        wl = wordlist_manager.load_file(args.wordlist)

    console.print(f"\n[cyan]📁 Directory Scan: [bold]{args.url}[/bold] ({args.threads} threads)[/cyan]\n")
    data = run_dir_scan(args.url, wl, args.threads, args.timeout, args.ext)

    console.print(f"[green]Tested:[/green] {data['total_tested']} paths")
    console.print(f"[green]Found:[/green] {len(data['found'])}\n")

    if data["found"]:
        t = Table(title="Found Paths", border_style="green")
        t.add_column("Status", style="cyan", width=8)
        t.add_column("Path", style="yellow", overflow="fold")
        t.add_column("Size", style="white", width=10)
        t.add_column("Content-Type", style="dim")
        for f in data["found"]:
            color = "green" if f["status"] == 200 else "yellow" if f["status"] < 400 else "red"
            t.add_row(f"[{color}]{f['status']}[/{color}]", f["path"], str(f["size"]), f["content_type"])
        console.print(t)

    if data["by_status"]:
        console.print("\n[bold]By status:[/bold]")
        for code, count in sorted(data["by_status"].items()):
            console.print(f"  [{code}] → {count}")
