"""
AnarkisHunter — recon_ip.py
==============================
IP Geolocation + ASN lookup via ipapi.co (gratis, no API key).
Resolve domain → IP, lalu lookup geolokasi, ISP, organisasi, ASN.

Usage standalone:
    python modules/recon/recon_ip.py --url http://target.local
    python modules/recon/recon_ip.py --ip 8.8.8.8
"""

import sys
import socket
import argparse
from pathlib import Path
from typing import Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from modules.utils.utils_request import HTTPClient, normalize_url, get_domain
from modules.utils.report import ScanResult


def resolve_to_ip(target: str) -> str:
    """Resolve domain/URL ke IP."""
    if target.startswith("http"):
        host = get_domain(normalize_url(target)).split(":")[0]
    else:
        host = target.strip()
    try:
        # Cek jika sudah IP
        socket.inet_aton(host)
        return host
    except OSError:
        pass
    try:
        return socket.gethostbyname(host)
    except Exception:
        return ""


def run_ip_recon(target: str, timeout: int = 10) -> Dict:
    """
    Geolocation + ASN lookup.

    Returns:
        Dict berisi data IP, lokasi, ISP, ASN
    """
    ip = resolve_to_ip(target)
    result = {
        "target": target,
        "ip": ip,
        "city": None,
        "region": None,
        "country": None,
        "country_code": None,
        "postal": None,
        "timezone": None,
        "latitude": None,
        "longitude": None,
        "asn": None,
        "org": None,
        "isp": None,
        "reverse_dns": None,
        "is_private": False,
        "is_cloudflare": False,
        "error": None,
    }

    if not ip:
        result["error"] = "Failed to resolve hostname to IP"
        return result

    # Cek private IP
    private_prefixes = ("10.", "192.168.", "127.", "172.16.", "172.17.", "172.18.",
                        "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
                        "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
                        "172.29.", "172.30.", "172.31.", "169.254.")
    if any(ip.startswith(p) for p in private_prefixes):
        result["is_private"] = True

    # Reverse DNS
    try:
        result["reverse_dns"] = socket.gethostbyaddr(ip)[0]
    except Exception:
        pass

    # ipapi.co lookup (gratis, no key, rate limit 1000/day)
    if not result["is_private"]:
        try:
            with HTTPClient(timeout=timeout) as client:
                resp = client.get(f"https://ipapi.co/{ip}/json/")
                if resp and resp.status_code == 200:
                    data = resp.json()
                    result["city"] = data.get("city")
                    result["region"] = data.get("region")
                    result["country"] = data.get("country_name")
                    result["country_code"] = data.get("country_code")
                    result["postal"] = data.get("postal")
                    result["timezone"] = data.get("timezone")
                    result["latitude"] = data.get("latitude")
                    result["longitude"] = data.get("longitude")
                    result["asn"] = data.get("asn")
                    result["org"] = data.get("org")
                    result["isp"] = data.get("org")

                    # Detect Cloudflare/CDN
                    org_str = (data.get("org") or "").lower()
                    if "cloudflare" in org_str:
                        result["is_cloudflare"] = True
        except Exception as e:
            result["error"] = f"ipapi lookup failed: {e}"

    return result


def analyze_ip_findings(data: Dict) -> List[ScanResult]:
    """Analisis IP untuk informasi keamanan."""
    findings = []
    url = data.get("target", "")

    if data.get("is_private"):
        findings.append(ScanResult(
            title="Target Resolves to Private IP",
            severity="INFO",
            description=f"Target resolve ke private IP: {data['ip']} (lab/internal network)",
            url=url,
            evidence=f"IP: {data['ip']}",
            module="recon_ip",
        ))

    if data.get("is_cloudflare"):
        findings.append(ScanResult(
            title="Cloudflare CDN Detected",
            severity="INFO",
            description="Target dilindungi Cloudflare. IP asal mungkin disembunyikan.",
            url=url,
            evidence=f"Org: {data.get('org')}",
            recommendation="Cari IP origin via subdomain enumeration / historical DNS",
            module="recon_ip",
        ))

    if data.get("country") and not data.get("is_private"):
        findings.append(ScanResult(
            title="IP Geolocation Information",
            severity="INFO",
            description=f"Server lokasi: {data.get('city')}, {data.get('country')}",
            url=url,
            evidence=f"IP: {data['ip']} | ASN: {data.get('asn')} | Org: {data.get('org')}",
            module="recon_ip",
        ))

    return findings


# ─── Standalone ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from rich.console import Console
    from rich.table import Table

    console = Console()
    parser = argparse.ArgumentParser(description="AnarkisHunter — IP Geolocation")
    parser.add_argument("--url", help="Target URL")
    parser.add_argument("--ip", help="Target IP")
    parser.add_argument("--domain", help="Target domain")
    args = parser.parse_args()

    target = args.url or args.ip or args.domain
    if not target:
        console.print("[red]Provide --url, --ip, or --domain[/red]")
        sys.exit(1)

    console.print(f"\n[cyan]🌍 IP Geolocation: [bold]{target}[/bold][/cyan]\n")
    data = run_ip_recon(target)

    table = Table(title="IP Information", border_style="cyan")
    table.add_column("Field", style="cyan", width=18)
    table.add_column("Value", style="white")
    rows = [
        ("IP Address", data.get("ip")),
        ("Reverse DNS", data.get("reverse_dns")),
        ("City", data.get("city")),
        ("Region", data.get("region")),
        ("Country", data.get("country")),
        ("Country Code", data.get("country_code")),
        ("Postal", data.get("postal")),
        ("Timezone", data.get("timezone")),
        ("Latitude", data.get("latitude")),
        ("Longitude", data.get("longitude")),
        ("ASN", data.get("asn")),
        ("Org/ISP", data.get("org")),
        ("Private IP", data.get("is_private")),
        ("Cloudflare", data.get("is_cloudflare")),
    ]
    for label, val in rows:
        if val is not None and val != "":
            table.add_row(label, str(val))
    console.print(table)

    if data.get("error"):
        console.print(f"\n[yellow]⚠ {data['error']}[/yellow]")
