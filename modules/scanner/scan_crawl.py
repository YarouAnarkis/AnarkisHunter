"""
AnarkisHunter — scan_crawl.py
================================
Full web crawler dengan BFS — kumpulkan URL, form, parameter,
hash konten untuk dedup, respect robots optionally.

Usage standalone:
    python modules/scanner/scan_crawl.py --url http://target.local --depth 3 --max 200
"""

import sys
import re
import hashlib
import argparse
from pathlib import Path
from typing import Dict, List, Set
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from modules.utils.utils_request import (
    HTTPClient, normalize_url, extract_base_url, is_same_domain, get_domain
)
from modules.utils.report import ScanResult
from config.settings import DEFAULT_MAX_DEPTH, DEFAULT_MAX_PAGES


HREF_PATTERN = re.compile(r'(?:href|src|action)=["\']([^"\']+)["\']', re.I)
FORM_PATTERN = re.compile(r"<form\s+[^>]*action=['\"]([^'\"]+)['\"]", re.I)
PARAM_PATTERN = re.compile(r"\?[^\s'\"<>]+")


def run_full_crawl(
    target: str,
    depth: int = DEFAULT_MAX_DEPTH,
    max_pages: int = DEFAULT_MAX_PAGES,
    timeout: int = 10,
    same_domain_only: bool = True,
) -> Dict:
    """
    BFS crawler.

    Returns:
        Dict berisi peta crawl + statistics
    """
    base_url = normalize_url(target)
    base_domain = get_domain(base_url)

    result = {
        "target": base_url,
        "base_domain": base_domain,
        "pages": [],
        "unique_urls": [],
        "forms_found": [],
        "params_found": [],
        "content_hashes": {},
        "external_urls": [],
        "errors": [],
        "stats": {
            "pages_crawled": 0,
            "total_links": 0,
            "broken": 0,
            "duplicates": 0,
        },
    }

    visited: Set[str] = set()
    queue: List = [(base_url, 0)]
    seen_hashes: Set[str] = set()

    try:
        with HTTPClient(timeout=timeout) as client:
            while queue and result["stats"]["pages_crawled"] < max_pages:
                url, cur_depth = queue.pop(0)
                # Hapus fragment
                url = url.split("#")[0]
                if url in visited:
                    continue
                visited.add(url)

                resp = client.get(url)
                if not resp:
                    result["errors"].append({"url": url, "error": "no response"})
                    result["stats"]["broken"] += 1
                    continue
                if resp.status_code >= 400:
                    result["errors"].append({"url": url, "status": resp.status_code})
                    result["stats"]["broken"] += 1
                    continue

                # Hash content untuk dedup
                content_hash = hashlib.md5(resp.text.encode("utf-8", errors="ignore")).hexdigest()[:16]
                if content_hash in seen_hashes:
                    result["stats"]["duplicates"] += 1
                else:
                    seen_hashes.add(content_hash)

                result["stats"]["pages_crawled"] += 1
                page_info = {
                    "url": url,
                    "status": resp.status_code,
                    "size": len(resp.content),
                    "content_type": resp.headers.get("Content-Type", "")[:50],
                    "depth": cur_depth,
                    "content_hash": content_hash,
                    "title": _extract_title(resp.text),
                }
                result["pages"].append(page_info)
                result["content_hashes"][content_hash] = url

                # Extract links
                text = resp.text
                for m in HREF_PATTERN.finditer(text):
                    raw = m.group(1).strip()
                    if not raw or raw.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
                        continue
                    full = urljoin(url, raw).split("#")[0]
                    parsed = urlparse(full)
                    if not parsed.scheme.startswith("http"):
                        continue

                    result["stats"]["total_links"] += 1

                    same = is_same_domain(full, base_url)
                    if same:
                        if full not in visited and cur_depth < depth:
                            queue.append((full, cur_depth + 1))
                        if parsed.query and full not in result["params_found"]:
                            result["params_found"].append(full)
                    else:
                        if not same_domain_only and full not in visited and cur_depth < depth:
                            queue.append((full, cur_depth + 1))
                        if full not in result["external_urls"]:
                            result["external_urls"].append(full)

                # Forms
                for fm in FORM_PATTERN.finditer(text):
                    form_action = urljoin(url, fm.group(1))
                    if form_action not in result["forms_found"]:
                        result["forms_found"].append(form_action)

    except Exception as e:
        result["errors"].append({"url": "global", "error": str(e)})

    result["unique_urls"] = sorted(visited)
    return result


def _extract_title(html: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    return m.group(1).strip()[:100] if m else ""


def analyze_crawl_findings(data: Dict) -> List[ScanResult]:
    findings = []
    target = data.get("target", "")

    findings.append(ScanResult(
        title=f"Crawl Completed — {data['stats']['pages_crawled']} pages",
        severity="INFO",
        description=(
            f"Crawled {data['stats']['pages_crawled']} pages, "
            f"{len(data['params_found'])} parameter URLs, "
            f"{len(data['forms_found'])} forms, "
            f"{data['stats']['broken']} broken links"
        ),
        url=target,
        module="scan_crawl",
    ))

    if data.get("params_found"):
        findings.append(ScanResult(
            title=f"Parameter URLs Discovered ({len(data['params_found'])})",
            severity="LOW",
            description="URL dengan parameter — attack surface untuk SQLi/XSS/SSRF/IDOR",
            url=target,
            evidence="\n".join(data["params_found"][:20]),
            recommendation="Sanitize & validate semua input parameter",
            owasp="A03",
            module="scan_crawl",
        ))

    return findings


# ─── Standalone ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from rich.console import Console
    from rich.table import Table

    console = Console()
    parser = argparse.ArgumentParser(description="AnarkisHunter — Full Web Crawler")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--depth", type=int, default=DEFAULT_MAX_DEPTH)
    parser.add_argument("--max", type=int, default=DEFAULT_MAX_PAGES, dest="max_pages")
    parser.add_argument("--all-domains", action="store_true", help="Crawl external domains too")
    args = parser.parse_args()

    console.print(f"\n[cyan]🕷  Full Crawl: [bold]{args.url}[/bold] (depth={args.depth}, max={args.max_pages})[/cyan]\n")
    data = run_full_crawl(args.url, args.depth, args.max_pages,
                          same_domain_only=not args.all_domains)

    s = data["stats"]
    summary = Table(title="Crawl Statistics", border_style="green")
    summary.add_column("Metric", style="cyan")
    summary.add_column("Value", style="white")
    summary.add_row("Pages crawled", str(s["pages_crawled"]))
    summary.add_row("Unique URLs", str(len(data["unique_urls"])))
    summary.add_row("Total links found", str(s["total_links"]))
    summary.add_row("Forms found", str(len(data["forms_found"])))
    summary.add_row("Parameter URLs", str(len(data["params_found"])))
    summary.add_row("External URLs", str(len(data["external_urls"])))
    summary.add_row("Duplicate content", str(s["duplicates"]))
    summary.add_row("Broken", str(s["broken"]))
    console.print(summary)

    if data["pages"]:
        t = Table(title=f"Sample Pages (showing 20 of {len(data['pages'])})", border_style="cyan")
        t.add_column("Status", style="cyan", width=8)
        t.add_column("Depth", style="dim", width=6)
        t.add_column("URL", style="yellow", overflow="fold")
        t.add_column("Title", style="white", overflow="fold")
        for p in data["pages"][:20]:
            t.add_row(str(p["status"]), str(p["depth"]), p["url"], p["title"])
        console.print(t)
