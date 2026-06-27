"""
AnarkisHunter — recon_email.py
=================================
Email harvesting via regex crawling.
Crawl halaman target & ekstrak alamat email yang ditemukan.

Usage standalone:
    python modules/recon/recon_email.py --url http://target.local --depth 2
"""

import sys
import re
import argparse
from pathlib import Path
from typing import Dict, List, Set
from urllib.parse import urljoin

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from modules.utils.utils_request import (
    HTTPClient, normalize_url, extract_base_url, is_same_domain, get_domain
)
from modules.utils.report import ScanResult


EMAIL_REGEX = re.compile(
    r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}"
)

# Filter false positive (image extensions, version strings)
EMAIL_FALSE_POSITIVES = re.compile(
    r"\.(png|jpg|jpeg|gif|svg|webp|ico|bmp|css|js|woff|ttf)$", re.I
)


def run_email_harvest(target: str, depth: int = 1, max_pages: int = 20, timeout: int = 10) -> Dict:
    """
    Harvest email dari halaman target.

    Args:
        target: URL awal
        depth: Crawl depth
        max_pages: Maksimum halaman yang di-crawl

    Returns:
        Dict berisi email yang ditemukan
    """
    base = extract_base_url(target)
    target_domain = get_domain(base)

    result = {
        "target": target,
        "domain": target_domain,
        "emails": [],
        "emails_by_domain": {},
        "pages_crawled": 0,
        "external_emails": [],
        "internal_emails": [],
        "error": None,
    }

    visited: Set[str] = set()
    queue: List = [(normalize_url(target), 0)]
    found_emails: Set[str] = set()

    try:
        with HTTPClient(timeout=timeout) as client:
            while queue and result["pages_crawled"] < max_pages:
                url, current_depth = queue.pop(0)
                if url in visited or current_depth > depth:
                    continue
                visited.add(url)

                resp = client.get(url)
                if not resp or resp.status_code >= 400:
                    continue

                result["pages_crawled"] += 1
                text = resp.text

                # Ekstrak email
                for match in EMAIL_REGEX.findall(text):
                    email = match.lower().strip()
                    if EMAIL_FALSE_POSITIVES.search(email):
                        continue
                    if len(email) < 6 or len(email) > 100:
                        continue
                    found_emails.add(email)

                # Tambahkan link ke queue (only internal)
                if current_depth < depth:
                    for href in re.findall(r'href=["\']([^"\']+)["\']', text):
                        next_url = urljoin(url, href)
                        if is_same_domain(next_url, base) and next_url not in visited:
                            queue.append((next_url, current_depth + 1))

    except Exception as e:
        result["error"] = str(e)

    # Kategorisasi
    for email in found_emails:
        domain = email.split("@")[-1]
        result["emails_by_domain"].setdefault(domain, []).append(email)
        if domain == target_domain or target_domain.endswith(f".{domain}") or domain.endswith(f".{target_domain}"):
            result["internal_emails"].append(email)
        else:
            result["external_emails"].append(email)

    result["emails"] = sorted(found_emails)
    return result


def analyze_email_findings(data: Dict) -> List[ScanResult]:
    """Analisis hasil harvest email."""
    findings = []
    url = data.get("target", "")

    if data.get("emails"):
        findings.append(ScanResult(
            title=f"Email Addresses Disclosed ({len(data['emails'])} found)",
            severity="LOW",
            description="Email yang tertulis di public page bisa dipakai untuk phishing/social engineering",
            url=url,
            evidence="\n".join(data["emails"][:20]),
            recommendation="Hindari menulis email plain text di public page. Gunakan contact form / obfuscation.",
            owasp="A05",
            module="recon_email",
        ))

    if data.get("internal_emails"):
        findings.append(ScanResult(
            title=f"Internal Email Addresses Found ({len(data['internal_emails'])})",
            severity="LOW",
            description="Internal email yang exposed bisa jadi target spear phishing",
            url=url,
            evidence="\n".join(data["internal_emails"][:10]),
            recommendation="Gunakan generic email (info@, contact@) untuk public exposure",
            owasp="A05",
            module="recon_email",
        ))

    return findings


# ─── Standalone ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from rich.console import Console
    from rich.table import Table

    console = Console()
    parser = argparse.ArgumentParser(description="AnarkisHunter — Email Harvester")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--depth", type=int, default=1, help="Crawl depth")
    parser.add_argument("--max-pages", type=int, default=20)
    args = parser.parse_args()

    console.print(f"\n[cyan]📧 Email Harvest: [bold]{args.url}[/bold] (depth={args.depth})[/cyan]\n")
    data = run_email_harvest(args.url, args.depth, args.max_pages)

    if data.get("error"):
        console.print(f"[yellow]Warning: {data['error']}[/yellow]")

    console.print(f"[green]Pages crawled:[/green] {data['pages_crawled']}")
    console.print(f"[green]Total emails:[/green] {len(data['emails'])}\n")

    if data["emails"]:
        t = Table(title="Found Emails", border_style="cyan")
        t.add_column("Email", style="green")
        t.add_column("Type", style="yellow", width=10)
        for email in data["emails"]:
            etype = "Internal" if email in data["internal_emails"] else "External"
            t.add_row(email, etype)
        console.print(t)

    if data["emails_by_domain"]:
        console.print("\n[bold]Email domains:[/bold]")
        for domain, emails in sorted(data["emails_by_domain"].items(),
                                      key=lambda x: -len(x[1])):
            console.print(f"  [cyan]{domain}[/cyan] ({len(emails)})")
