"""
AnarkisHunter — scan_dirs.py
===============================
Directory bruteforce scanner — async parallel dengan httpx.
Connection pooling, --threads, --timeout support.

Usage standalone:
    python modules/scanner/scan_dirs.py --url http://target.local
    python modules/scanner/scan_dirs.py --url http://target.local --wordlist big.txt --threads 30
"""

import sys
import argparse
import asyncio
from pathlib import Path
from typing import Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from modules.utils.utils_request import HTTPClient, normalize_url, async_batch_request
from modules.utils.utils_wordlist import wordlist_manager
from modules.utils.utils_scan_async import run_async
from modules.utils.report import ScanResult


INTERESTING_CODES = {200, 201, 202, 204, 301, 302, 307, 308, 401, 403}


async def _async_dir_scan(
    base_url: str,
    paths: List[str],
    threads: int,
    timeout: int,
    delay: float = 0,
    proxy: Optional[str] = None,
) -> List[Dict]:
    urls = [base_url.rstrip("/") + "/" + p.lstrip("/") for p in paths]
    found = []

    async with HTTPClient(timeout=timeout, threads=threads, delay=delay, proxy=proxy) as client:
        def _filter_result(url: str, resp) -> Optional[Dict]:
            if resp and resp.status_code in INTERESTING_CODES:
                path = url.replace(base_url.rstrip("/") + "/", "")
                return {
                    "path": path,
                    "url": url,
                    "status": resp.status_code,
                    "size": len(resp.content),
                    "content_type": resp.headers.get("Content-Type", "")[:50],
                }
            return None

        semaphore = asyncio.Semaphore(threads)

        async def _fetch(url: str):
            async with semaphore:
                resp = await client.aget(url)
                return _filter_result(url, resp)

        tasks = [_fetch(u) for u in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        found = [r for r in results if isinstance(r, dict)]

    return found


def run_dir_scan(
    target: str,
    wordlist: Optional[List[str]] = None,
    threads: int = 20,
    timeout: int = 8,
    extensions: Optional[List[str]] = None,
    delay: float = 0,
    proxy: Optional[str] = None,
) -> Dict:
    base_url = normalize_url(target)
    paths = wordlist or wordlist_manager.load("directories")

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
        "findings": [],
        "error": None,
    }

    try:
        found = run_async(_async_dir_scan(base_url, paths, threads, timeout, delay, proxy))
        result["found"] = found
        for res in found:
            result["by_status"][res["status"]] = result["by_status"].get(res["status"], 0) + 1
        result["findings"] = analyze_dir_findings(result)
    except Exception as e:
        result["error"] = str(e)

    result["found"].sort(key=lambda x: (x["status"], x["path"]))
    return result


def analyze_dir_findings(data: Dict) -> List[ScanResult]:
    findings = []

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
            owasp="A05" if severity != "INFO" else "",
            module="scan_dirs",
        ))

    return findings


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

    wl = wordlist_manager.load("directories", args.wordlist) if args.wordlist else None

    console.print(f"\n[cyan]Directory Scan: [bold]{args.url}[/bold] ({args.threads} threads)[/cyan]\n")
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
