"""
AnarkisHunter — recon_robots.py
==================================
robots.txt & sitemap.xml parser.
Mengekstrak path yang disallowed (sering kali berisi path sensitif),
sitemap URLs, dan crawl rules.

Usage standalone:
    python modules/recon/recon_robots.py --url http://target.local
"""

import sys
import re
import argparse
from pathlib import Path
from typing import Dict, List
from urllib.parse import urljoin

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from modules.utils.utils_request import HTTPClient, normalize_url, extract_base_url
from modules.utils.report import ScanResult


# Pattern path sensitif dari robots.txt
SENSITIVE_PATH_PATTERNS = [
    r"admin", r"login", r"password", r"backup", r"private", r"secret",
    r"config", r"\.env", r"\.git", r"api", r"internal", r"staff",
    r"upload", r"dashboard", r"panel", r"phpmyadmin", r"db",
]


def run_robots_recon(target: str, timeout: int = 10) -> Dict:
    """
    Parse robots.txt dan sitemap.xml.

    Returns:
        Dict berisi disallow paths, allow paths, sitemap URLs
    """
    base = extract_base_url(target)
    result = {
        "base": base,
        "robots_url": f"{base}/robots.txt",
        "robots_exists": False,
        "robots_content": "",
        "user_agents": [],
        "disallow": [],
        "allow": [],
        "sitemaps": [],
        "crawl_delays": {},
        "sensitive_paths": [],
        "sitemap_urls": [],
        "sitemap_exists": False,
        "sitemap_content_preview": "",
        "error": None,
    }

    try:
        with HTTPClient(timeout=timeout) as client:
            # robots.txt
            resp = client.get(result["robots_url"])
            if resp and resp.status_code == 200:
                result["robots_exists"] = True
                content = resp.text[:30000]
                result["robots_content"] = content[:5000]
                _parse_robots(content, result)
            elif resp:
                result["error"] = f"robots.txt returned {resp.status_code}"

            # sitemap.xml (langsung & dari robots)
            sitemap_urls = [f"{base}/sitemap.xml"] + result["sitemaps"]
            sitemap_urls = list(dict.fromkeys(sitemap_urls))  # dedupe preserve order

            for sm_url in sitemap_urls[:3]:  # batasi 3 sitemap
                sm_resp = client.get(sm_url)
                if sm_resp and sm_resp.status_code == 200:
                    result["sitemap_exists"] = True
                    sm_text = sm_resp.text[:50000]
                    result["sitemap_content_preview"] = sm_text[:2000]
                    # Extract <loc>URL</loc>
                    urls = re.findall(r"<loc>([^<]+)</loc>", sm_text)
                    result["sitemap_urls"].extend(urls)

            # Dedup sitemap_urls
            result["sitemap_urls"] = list(dict.fromkeys(result["sitemap_urls"]))

            # Identifikasi sensitive paths
            for path in result["disallow"] + result["allow"]:
                for pat in SENSITIVE_PATH_PATTERNS:
                    if re.search(pat, path, re.I):
                        result["sensitive_paths"].append(path)
                        break
            result["sensitive_paths"] = list(dict.fromkeys(result["sensitive_paths"]))

    except Exception as e:
        result["error"] = str(e)

    return result


def _parse_robots(content: str, result: Dict) -> None:
    """Parse robots.txt content."""
    current_ua = "*"
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()

        if key == "user-agent":
            current_ua = value
            if current_ua not in result["user_agents"]:
                result["user_agents"].append(current_ua)
        elif key == "disallow" and value:
            result["disallow"].append(value)
        elif key == "allow" and value:
            result["allow"].append(value)
        elif key == "sitemap":
            result["sitemaps"].append(value)
        elif key == "crawl-delay":
            try:
                result["crawl_delays"][current_ua] = float(value)
            except ValueError:
                pass


def analyze_robots_findings(data: Dict) -> List[ScanResult]:
    """Analisis robots.txt & sitemap untuk informasi sensitif."""
    findings = []
    url = data.get("base", "")

    if not data.get("robots_exists"):
        findings.append(ScanResult(
            title="robots.txt Not Found",
            severity="INFO",
            description="File robots.txt tidak ditemukan di root",
            url=data.get("robots_url"),
            module="recon_robots",
        ))
        return findings

    # Sensitive paths di disallow
    if data.get("sensitive_paths"):
        findings.append(ScanResult(
            title="Sensitive Paths Disclosed in robots.txt",
            severity="LOW",
            description=(
                f"robots.txt mengungkap {len(data['sensitive_paths'])} path sensitif. "
                "Attacker bisa langsung tahu path admin/internal."
            ),
            url=data.get("robots_url"),
            evidence="\n".join(data["sensitive_paths"][:20]),
            recommendation=(
                "Jangan letakkan path sensitif di robots.txt. "
                "Gunakan authentication & access control sebagai gantinya."
            ),
            owasp="A01",
            module="recon_robots",
        ))

    # Sitemap menyediakan banyak URL
    if data.get("sitemap_exists") and data.get("sitemap_urls"):
        findings.append(ScanResult(
            title="Sitemap.xml Found",
            severity="INFO",
            description=f"Sitemap berisi {len(data['sitemap_urls'])} URL — bagus untuk attack surface mapping",
            url=f"{data['base']}/sitemap.xml",
            evidence="\n".join(data["sitemap_urls"][:10]),
            module="recon_robots",
        ))

    return findings


# ─── Standalone ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from rich.console import Console
    from rich.table import Table

    console = Console()
    parser = argparse.ArgumentParser(description="AnarkisHunter — robots.txt & sitemap")
    parser.add_argument("--url", required=True, help="Target URL")
    args = parser.parse_args()

    console.print(f"\n[cyan]🤖 robots.txt & sitemap Recon: [bold]{args.url}[/bold][/cyan]\n")
    data = run_robots_recon(args.url)

    if data.get("error"):
        console.print(f"[yellow]Warning: {data['error']}[/yellow]")

    console.print(f"[bold]robots.txt:[/bold] {'✅' if data['robots_exists'] else '❌'} {data['robots_url']}")
    console.print(f"[bold]sitemap.xml:[/bold] {'✅' if data['sitemap_exists'] else '❌'}\n")

    if data["disallow"]:
        t = Table(title=f"Disallow ({len(data['disallow'])})", border_style="red")
        t.add_column("#", style="dim", width=4)
        t.add_column("Path", style="yellow")
        for i, p in enumerate(data["disallow"][:30], 1):
            t.add_row(str(i), p)
        console.print(t)

    if data["allow"]:
        t = Table(title=f"Allow ({len(data['allow'])})", border_style="green")
        t.add_column("Path", style="green")
        for p in data["allow"][:20]:
            t.add_row(p)
        console.print(t)

    if data["sitemap_urls"]:
        t = Table(title=f"Sitemap URLs ({len(data['sitemap_urls'])})", border_style="cyan")
        t.add_column("URL", style="cyan")
        for u in data["sitemap_urls"][:20]:
            t.add_row(u)
        console.print(t)

    if data["sensitive_paths"]:
        console.print(f"\n[red]⚠ Sensitive paths leaked:[/red]")
        for p in data["sensitive_paths"][:15]:
            console.print(f"  [red]→[/red] {p}")
