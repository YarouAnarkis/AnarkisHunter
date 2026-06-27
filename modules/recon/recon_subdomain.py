"""
AnarkisHunter — recon_subdomain.py
=====================================
Subdomain bruteforce via wordlist + Certificate Transparency (crt.sh API).

Usage standalone:
    python modules/recon/recon_subdomain.py --url http://target.local
    python modules/recon/recon_subdomain.py --domain example.com --threads 20
"""

import sys
import argparse
import socket
import threading
from pathlib import Path
from typing import Dict, List, Optional, Set
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from modules.utils.utils_request import HTTPClient, normalize_url, get_domain
from modules.utils.utils_wordlist import wordlist_manager
from modules.utils.report import ScanResult


def run_subdomain_enum(
    target: str,
    wordlist: Optional[List[str]] = None,
    threads: int = 20,
    use_crtsh: bool = True,
    timeout: int = 5,
) -> Dict:
    """
    Enumerate subdomain via bruteforce + crt.sh.

    Returns:
        Dict berisi daftar subdomain yang ditemukan
    """
    if target.startswith("http"):
        domain = get_domain(normalize_url(target))
    else:
        domain = target.strip()
    if domain.startswith("www."):
        domain = domain[4:]

    result = {
        "domain": domain,
        "found": [],        # List subdomain aktif
        "crtsh": [],        # Dari Certificate Transparency
        "bruteforce": [],   # Dari bruteforce
        "total": 0,
        "error": None,
    }

    found_set: Set[str] = set()

    # ── 1. Certificate Transparency via crt.sh ────────────────────────────
    if use_crtsh:
        crtsh_subs = _query_crtsh(domain)
        result["crtsh"] = crtsh_subs
        found_set.update(crtsh_subs)

    # ── 2. Bruteforce via wordlist ────────────────────────────────────────
    words = wordlist or wordlist_manager.load("subdomains")

    lock = threading.Lock()
    active_subs = []

    def check_subdomain(word: str):
        subdomain = f"{word.strip()}.{domain}"
        if subdomain in found_set:
            return
        try:
            ip = socket.gethostbyname(subdomain)
            with lock:
                active_subs.append({"subdomain": subdomain, "ip": ip})
                found_set.add(subdomain)
        except socket.gaierror:
            pass
        except Exception:
            pass

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(check_subdomain, w) for w in words]
        for f in as_completed(futures):
            try:
                f.result()
            except Exception:
                pass

    result["bruteforce"] = active_subs

    # ── 3. Resolve semua dari crt.sh juga ─────────────────────────────────
    crtsh_resolved = []
    for sub in result["crtsh"][:100]:  # Limit untuk kecepatan
        try:
            ip = socket.gethostbyname(sub)
            crtsh_resolved.append({"subdomain": sub, "ip": ip})
        except Exception:
            crtsh_resolved.append({"subdomain": sub, "ip": None})

    # ── 4. Merge semua ───────────────────────────────────────────────────
    all_found = {}
    for item in active_subs + crtsh_resolved:
        sub = item["subdomain"]
        if sub not in all_found:
            all_found[sub] = item["ip"]

    result["found"] = [{"subdomain": k, "ip": v} for k, v in sorted(all_found.items())]
    result["total"] = len(result["found"])
    return result


def _query_crtsh(domain: str) -> List[str]:
    """Query crt.sh Certificate Transparency API."""
    try:
        import requests
        resp = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=15,
            verify=False,
        )
        if resp.status_code != 200:
            return []

        data = resp.json()
        subdomains = set()
        for entry in data:
            name = entry.get("name_value", "")
            for sub in name.splitlines():
                sub = sub.strip().lower()
                if sub.endswith(f".{domain}") or sub == domain:
                    if "*" not in sub:
                        subdomains.add(sub)
        return sorted(subdomains)
    except Exception:
        return []


def _check_takeover(subdomain: str, ip: Optional[str]) -> Optional[ScanResult]:
    """
    Cek potensi subdomain takeover.
    Deteksi CNAME yang mengarah ke layanan cloud yang sudah tidak terdaftar.
    """
    takeover_signatures = {
        "GitHub Pages": ("github.io", "There isn't a GitHub Pages site here"),
        "Heroku": ("herokudns.com", "No such app"),
        "Shopify": ("myshopify.com", "Sorry, this shop is currently unavailable"),
        "Fastly": ("fastly.net", "Fastly error: unknown domain"),
        "AWS S3": ("s3.amazonaws.com", "NoSuchBucket"),
        "Azure": ("azurewebsites.net", "404 Web Site not found"),
        "Pantheon": ("pantheonsite.io", "The gods are wise"),
        "Ghost": ("ghost.io", "The thing you were looking for is no longer here"),
    }

    try:
        import socket
        import requests
        # Cek CNAME
        try:
            import dns.resolver
            answers = dns.resolver.resolve(subdomain, "CNAME")
            cname = str(list(answers)[0].target).lower()
            for service, (signature, error_text) in takeover_signatures.items():
                if signature in cname:
                    resp = requests.get(f"http://{subdomain}", timeout=5, verify=False)
                    if error_text.lower() in resp.text.lower():
                        return ScanResult(
                            title=f"Subdomain Takeover — {subdomain}",
                            severity="CRITICAL",
                            description=f"Subdomain {subdomain} mungkin bisa diambil alih! CNAME mengarah ke {service} yang tidak aktif.",
                            url=f"http://{subdomain}",
                            evidence=f"CNAME: {cname}\nResponse contains: {error_text}",
                            recommendation=f"Hapus DNS record {subdomain} atau klaim kembali resource di {service}",
                            owasp="A01",
                            module="recon_subdomain",
                        )
        except Exception:
            pass
    except Exception:
        pass
    return None


# ─── Standalone ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn

    console = Console()
    parser = argparse.ArgumentParser(description="AnarkisHunter — Subdomain Enumeration")
    parser.add_argument("--url", help="Target URL")
    parser.add_argument("--domain", help="Target domain")
    parser.add_argument("--threads", type=int, default=20)
    parser.add_argument("--wordlist", help="Custom wordlist file")
    parser.add_argument("--no-crtsh", action="store_true", help="Skip crt.sh lookup")
    args = parser.parse_args()

    target = args.url or args.domain
    if not target:
        console.print("[red]Provide --url or --domain[/red]")
        sys.exit(1)

    words = None
    if args.wordlist:
        words = wordlist_manager.get_from_file(args.wordlist)

    console.print(f"\n[cyan]🔎 Subdomain Enumeration: [bold]{target}[/bold][/cyan]")
    console.print(f"[dim]Threads: {args.threads} | crt.sh: {not args.no_crtsh}[/dim]\n")

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        task = progress.add_task("Enumerating subdomains...", total=None)
        result = run_subdomain_enum(
            target, wordlist=words, threads=args.threads,
            use_crtsh=not args.no_crtsh,
        )
        progress.stop()

    if result["found"]:
        table = Table(title=f"Subdomains Found ({result['total']})", border_style="green")
        table.add_column("#", style="dim", width=5)
        table.add_column("Subdomain", style="green")
        table.add_column("IP", style="cyan")
        for i, item in enumerate(result["found"], 1):
            table.add_row(str(i), item["subdomain"], item.get("ip") or "N/A")
        console.print(table)

        console.print(f"\n[green]✅ Total subdomains found: {result['total']}[/green]")
        if result["crtsh"]:
            console.print(f"  └─ From crt.sh : {len(result['crtsh'])}")
        if result["bruteforce"]:
            console.print(f"  └─ From brute  : {len(result['bruteforce'])}")
    else:
        console.print("[yellow]No subdomains found[/yellow]")
