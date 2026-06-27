"""
AnarkisHunter — recon_links.py
=================================
Full link crawler (internal + external).
Crawl halaman target sampai depth tertentu, ekstrak semua link,
kategorisasi internal vs external, identifikasi parameter URLs.

Usage standalone:
    python modules/recon/recon_links.py --url http://target.local --depth 2
"""

import sys
import re
import argparse
from pathlib import Path
from typing import Dict, List, Set
from urllib.parse import urljoin, urlparse, parse_qsl

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from modules.utils.utils_request import (
    HTTPClient, normalize_url, extract_base_url, is_same_domain, get_domain
)
from modules.utils.report import ScanResult


HREF_PATTERN = re.compile(r'(?:href|src|action)=["\']([^"\']+)["\']', re.I)


def run_links_crawl(
    target: str,
    depth: int = 2,
    max_pages: int = 100,
    timeout: int = 10,
) -> Dict:
    """
    Crawl link dari halaman target.

    Args:
        target: URL awal
        depth: Crawl depth maksimal
        max_pages: Maksimum halaman di-crawl

    Returns:
        Dict berisi semua link kategorisasi
    """
    base_url = normalize_url(target)
    base = extract_base_url(base_url)

    result = {
        "target": base_url,
        "pages_crawled": 0,
        "internal_links": [],
        "external_links": [],
        "parameter_urls": [],
        "interesting_extensions": [],
        "subdomains_found": [],
        "broken_links": [],
        "error": None,
    }

    visited: Set[str] = set()
    queue: List = [(base_url, 0)]
    internal_set: Set[str] = set()
    external_set: Set[str] = set()
    param_set: Set[str] = set()
    interesting_ext: Set[str] = set()
    subdomains: Set[str] = set()

    INTERESTING_EXT = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".zip",
                       ".tar.gz", ".sql", ".bak", ".backup", ".old",
                       ".log", ".conf", ".env", ".json", ".xml"}

    try:
        with HTTPClient(timeout=timeout) as client:
            while queue and result["pages_crawled"] < max_pages:
                url, cur_depth = queue.pop(0)
                if url in visited:
                    continue
                visited.add(url)

                resp = client.get(url)
                if not resp:
                    result["broken_links"].append(url)
                    continue
                if resp.status_code >= 400:
                    result["broken_links"].append(f"{url} [{resp.status_code}]")
                    continue

                result["pages_crawled"] += 1
                text = resp.text

                # Ekstrak href / src / action
                for m in HREF_PATTERN.finditer(text):
                    raw = m.group(1).strip()
                    if not raw or raw.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
                        continue
                    full = urljoin(url, raw)

                    parsed = urlparse(full)
                    if not parsed.scheme.startswith("http"):
                        continue

                    if is_same_domain(full, base_url):
                        internal_set.add(full)
                        # Subdomain berbeda?
                        link_domain = get_domain(full)
                        target_dom = get_domain(base_url)
                        if link_domain != target_dom and target_dom in link_domain:
                            subdomains.add(link_domain)
                        # Parameter URL?
                        if parsed.query:
                            param_set.add(full)
                        # Interesting extension?
                        path_lower = parsed.path.lower()
                        for ext in INTERESTING_EXT:
                            if path_lower.endswith(ext):
                                interesting_ext.add(full)
                                break
                        # Add ke queue untuk crawl lebih dalam
                        if cur_depth < depth and full not in visited:
                            queue.append((full, cur_depth + 1))
                    else:
                        external_set.add(full)

    except Exception as e:
        result["error"] = str(e)

    result["internal_links"] = sorted(internal_set)
    result["external_links"] = sorted(external_set)
    result["parameter_urls"] = sorted(param_set)
    result["interesting_extensions"] = sorted(interesting_ext)
    result["subdomains_found"] = sorted(subdomains)

    return result


def analyze_links_findings(data: Dict) -> List[ScanResult]:
    """Analisis link hasil crawl."""
    findings = []
    target = data.get("target", "")

    # Parameter URLs — attack surface untuk SQLi/XSS/SSRF
    if data.get("parameter_urls"):
        findings.append(ScanResult(
            title=f"URLs with Parameters ({len(data['parameter_urls'])})",
            severity="INFO",
            description=(
                f"Ditemukan {len(data['parameter_urls'])} URL dengan query parameter. "
                "Ini target utama untuk SQLi, XSS, SSRF, IDOR."
            ),
            url=target,
            evidence="\n".join(data["parameter_urls"][:20]),
            module="recon_links",
        ))

    # Interesting file extensions
    if data.get("interesting_extensions"):
        findings.append(ScanResult(
            title=f"Sensitive File Links Found ({len(data['interesting_extensions'])})",
            severity="LOW",
            description=(
                "Link ke file dengan extension sensitif (backup, sql, conf, dll) — "
                "bisa berisi data leak"
            ),
            url=target,
            evidence="\n".join(data["interesting_extensions"][:15]),
            recommendation="Pastikan file tersebut tidak accessible / berisi data sensitif",
            owasp="A05",
            module="recon_links",
        ))

    # Subdomains
    if data.get("subdomains_found"):
        findings.append(ScanResult(
            title=f"Subdomains Discovered via Links ({len(data['subdomains_found'])})",
            severity="INFO",
            description="Subdomain terdeteksi via link crawling",
            url=target,
            evidence="\n".join(data["subdomains_found"]),
            module="recon_links",
        ))

    # Broken links
    if data.get("broken_links"):
        findings.append(ScanResult(
            title=f"Broken Links ({len(data['broken_links'])})",
            severity="INFO",
            description=f"Ditemukan {len(data['broken_links'])} broken link",
            url=target,
            evidence="\n".join(data["broken_links"][:15]),
            module="recon_links",
        ))

    return findings


# ─── Standalone ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from rich.console import Console
    from rich.table import Table

    console = Console()
    parser = argparse.ArgumentParser(description="AnarkisHunter — Link Crawler")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--depth", type=int, default=2)
    parser.add_argument("--max-pages", type=int, default=100)
    args = parser.parse_args()

    console.print(f"\n[cyan]🔗 Link Crawler: [bold]{args.url}[/bold] (depth={args.depth}, max={args.max_pages})[/cyan]\n")
    data = run_links_crawl(args.url, args.depth, args.max_pages)

    if data.get("error"):
        console.print(f"[yellow]Warning: {data['error']}[/yellow]")

    summary = Table(title="Crawl Summary", border_style="green")
    summary.add_column("Metric", style="cyan")
    summary.add_column("Count", style="white")
    summary.add_row("Pages crawled", str(data["pages_crawled"]))
    summary.add_row("Internal links", str(len(data["internal_links"])))
    summary.add_row("External links", str(len(data["external_links"])))
    summary.add_row("Parameter URLs", str(len(data["parameter_urls"])))
    summary.add_row("Interesting files", str(len(data["interesting_extensions"])))
    summary.add_row("Subdomains", str(len(data["subdomains_found"])))
    summary.add_row("Broken links", str(len(data["broken_links"])))
    console.print(summary)

    if data["parameter_urls"]:
        console.print("\n[bold]Sample parameter URLs:[/bold]")
        for u in data["parameter_urls"][:15]:
            console.print(f"  [yellow]→[/yellow] {u}")

    if data["interesting_extensions"]:
        console.print("\n[bold red]Interesting files:[/bold red]")
        for u in data["interesting_extensions"][:10]:
            console.print(f"  [red]→[/red] {u}")

    if data["subdomains_found"]:
        console.print("\n[bold]Subdomains:[/bold]")
        for s in data["subdomains_found"]:
            console.print(f"  [cyan]•[/cyan] {s}")
