"""
AnarkisHunter — recon_wayback.py
===================================
Wayback Machine API checker.
Mengambil daftar URL historis dari archive.org via CDX API.
Berguna untuk menemukan endpoint lama yang mungkin masih hidup.

Usage standalone:
    python modules/recon/recon_wayback.py --url http://target.local
    python modules/recon/recon_wayback.py --domain example.com --limit 100
"""

import sys
import argparse
from pathlib import Path
from typing import Dict, List
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from modules.utils.utils_request import HTTPClient, normalize_url, get_domain
from modules.utils.report import ScanResult


# Path / extension yang menarik dari sudut pandang pentester
INTERESTING_EXTENSIONS = [
    ".sql", ".bak", ".backup", ".old", ".zip", ".tar", ".tar.gz", ".rar",
    ".7z", ".log", ".conf", ".config", ".ini", ".env", ".yml", ".yaml",
    ".json", ".xml", ".db", ".sqlite", ".sqlite3", ".swp", ".swo",
    ".pem", ".key", ".crt", ".pfx",
]

INTERESTING_PATHS = [
    "admin", "login", "backup", "phpinfo", "test", "dev", "debug",
    "config", "wp-admin", "phpmyadmin", "api", ".git", ".env",
]


def run_wayback_recon(target: str, limit: int = 200, timeout: int = 15) -> Dict:
    """
    Query Wayback Machine CDX API.

    Returns:
        Dict berisi URL historis
    """
    if target.startswith("http"):
        domain = get_domain(normalize_url(target))
    else:
        domain = target.strip()
    if domain.startswith("www."):
        domain = domain[4:]

    result = {
        "domain": domain,
        "total_urls": 0,
        "urls": [],
        "interesting": [],
        "unique_paths": [],
        "unique_extensions": [],
        "snapshots_first": None,
        "snapshots_last": None,
        "error": None,
    }

    # Format CDX API
    api = (
        f"http://web.archive.org/cdx/search/cdx"
        f"?url={quote(domain)}/*"
        f"&output=json&fl=original,timestamp&collapse=urlkey"
        f"&limit={limit}"
    )

    try:
        with HTTPClient(timeout=timeout) as client:
            resp = client.get(api)
            if not resp or resp.status_code != 200:
                result["error"] = f"Wayback API error: HTTP {resp.status_code if resp else 'no response'}"
                return result

            try:
                data = resp.json()
            except Exception:
                result["error"] = "Invalid JSON from Wayback"
                return result

            # First row is header
            if not data or len(data) < 2:
                return result

            entries = data[1:]
            result["total_urls"] = len(entries)

            extensions_set = set()
            paths_set = set()

            for entry in entries:
                if not entry or len(entry) < 2:
                    continue
                url = entry[0]
                ts = entry[1]
                result["urls"].append({"url": url, "timestamp": ts})

                # Track first/last snapshot
                if result["snapshots_first"] is None or ts < result["snapshots_first"]:
                    result["snapshots_first"] = ts
                if result["snapshots_last"] is None or ts > result["snapshots_last"]:
                    result["snapshots_last"] = ts

                # Extract path & extension
                url_lower = url.lower()
                for ext in INTERESTING_EXTENSIONS:
                    if url_lower.endswith(ext):
                        extensions_set.add(ext)
                        result["interesting"].append({"url": url, "reason": f"extension {ext}"})
                        break
                else:
                    for path in INTERESTING_PATHS:
                        if f"/{path}" in url_lower:
                            paths_set.add(path)
                            result["interesting"].append({"url": url, "reason": f"path {path}"})
                            break

            result["unique_extensions"] = sorted(extensions_set)
            result["unique_paths"] = sorted(paths_set)

    except Exception as e:
        result["error"] = str(e)

    return result


def analyze_wayback_findings(data: Dict) -> List[ScanResult]:
    """Analisis hasil Wayback untuk URL menarik."""
    findings = []
    base_url = f"http://{data.get('domain', '')}"

    if data.get("interesting"):
        # Group by reason
        evidence_lines = [f"[{i['reason']}] {i['url']}" for i in data["interesting"][:25]]
        findings.append(ScanResult(
            title=f"Interesting Historical URLs ({len(data['interesting'])})",
            severity="LOW",
            description=(
                f"Wayback Machine berisi {len(data['interesting'])} URL menarik dari sudut pandang security. "
                "Beberapa endpoint lama mungkin masih aktif & belum di-patch."
            ),
            url=base_url,
            evidence="\n".join(evidence_lines),
            recommendation="Cek satu per satu URL menarik, hapus endpoint lama yang tidak dipakai",
            owasp="A05",
            module="recon_wayback",
        ))

    if data.get("total_urls"):
        findings.append(ScanResult(
            title=f"Wayback Machine Archive ({data['total_urls']} URLs)",
            severity="INFO",
            description=(
                f"Target ter-archive {data['total_urls']} URL di Wayback Machine. "
                f"Snapshot: {data.get('snapshots_first', 'N/A')} → {data.get('snapshots_last', 'N/A')}"
            ),
            url=base_url,
            module="recon_wayback",
        ))

    return findings


# ─── Standalone ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from rich.console import Console
    from rich.table import Table

    console = Console()
    parser = argparse.ArgumentParser(description="AnarkisHunter — Wayback Machine")
    parser.add_argument("--url", help="Target URL")
    parser.add_argument("--domain", help="Target domain")
    parser.add_argument("--limit", type=int, default=200)
    args = parser.parse_args()

    target = args.url or args.domain
    if not target:
        console.print("[red]Provide --url or --domain[/red]")
        sys.exit(1)

    console.print(f"\n[cyan]🕰  Wayback Machine: [bold]{target}[/bold] (limit={args.limit})[/cyan]\n")
    data = run_wayback_recon(target, args.limit)

    if data.get("error"):
        console.print(f"[red]Error: {data['error']}[/red]")
        sys.exit(1)

    console.print(f"[green]Total URLs:[/green] {data['total_urls']}")
    console.print(f"[green]First snapshot:[/green] {data.get('snapshots_first', 'N/A')}")
    console.print(f"[green]Last snapshot:[/green] {data.get('snapshots_last', 'N/A')}\n")

    if data["interesting"]:
        t = Table(title=f"Interesting URLs ({len(data['interesting'])})", border_style="yellow")
        t.add_column("URL", style="cyan", overflow="fold")
        t.add_column("Reason", style="yellow")
        for item in data["interesting"][:30]:
            t.add_row(item["url"], item["reason"])
        console.print(t)

    if data["unique_extensions"]:
        console.print(f"\n[bold]Found extensions:[/bold] {', '.join(data['unique_extensions'])}")
    if data["unique_paths"]:
        console.print(f"[bold]Found paths:[/bold] {', '.join(data['unique_paths'])}")
