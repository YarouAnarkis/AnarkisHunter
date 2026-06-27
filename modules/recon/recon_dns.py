"""
AnarkisHunter — recon_dns.py
===============================
DNS enumeration: semua record A, AAAA, MX, NS, TXT, CNAME, SOA, PTR.

Usage standalone:
    python modules/recon/recon_dns.py --url http://target.local
    python modules/recon/recon_dns.py --domain example.com
"""

import sys
import argparse
from pathlib import Path
from typing import Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from modules.utils.utils_request import normalize_url, get_domain
from modules.utils.report import ScanResult


DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR",
                     "SRV", "CAA", "DKIM", "DMARC", "SPF"]


def run_dns_enum(target: str, record_types: Optional[List[str]] = None) -> Dict:
    """
    Enumerate semua DNS record untuk domain.

    Args:
        target: URL atau domain
        record_types: List tipe record (default: semua)

    Returns:
        Dict berisi semua record per tipe
    """
    if target.startswith("http"):
        domain = get_domain(normalize_url(target))
    else:
        domain = target.strip()
    if domain.startswith("www."):
        domain = domain[4:]

    types = record_types or DNS_RECORD_TYPES
    results = {"domain": domain, "records": {}, "ips": [], "error": None}

    try:
        import dns.resolver
        import dns.exception
    except ImportError:
        results["error"] = "dnspython not installed. Run: pip install dnspython"
        return results

    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 10

    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "SRV", "CAA"]:
        if rtype not in types:
            continue
        try:
            query_domain = domain

            # DMARC dan DKIM punya prefix khusus
            if rtype == "DMARC":
                query_domain = f"_dmarc.{domain}"
                rtype_actual = "TXT"
            elif rtype == "DKIM":
                query_domain = f"default._domainkey.{domain}"
                rtype_actual = "TXT"
            elif rtype == "SPF":
                rtype_actual = "TXT"
            else:
                rtype_actual = rtype

            answers = resolver.resolve(query_domain, rtype_actual)
            records = []

            for rdata in answers:
                value = _format_rdata(rtype, rdata)
                if value:
                    records.append(value)
                # Collect IPs
                if rtype == "A":
                    results["ips"].append(str(rdata.address))

            if records:
                results["records"][rtype] = records

        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            pass
        except Exception:
            pass

    # Cek SPF khusus dari TXT records
    txt_records = results["records"].get("TXT", [])
    spf = [r for r in txt_records if "v=spf1" in r.lower()]
    dmarc_txt = [r for r in txt_records if "v=DMARC1" in r]
    if spf:
        results["records"]["SPF"] = spf
    if dmarc_txt:
        results["records"]["DMARC"] = dmarc_txt

    return results


def _format_rdata(rtype: str, rdata) -> Optional[str]:
    """Format rdata menjadi string yang mudah dibaca."""
    try:
        if rtype == "A":
            return rdata.address
        elif rtype == "AAAA":
            return rdata.address
        elif rtype == "MX":
            return f"{rdata.preference} {rdata.exchange}"
        elif rtype == "NS":
            return str(rdata.target)
        elif rtype == "TXT":
            return b"".join(rdata.strings).decode("utf-8", errors="replace")
        elif rtype == "CNAME":
            return str(rdata.target)
        elif rtype == "SOA":
            return f"mname={rdata.mname} rname={rdata.rname} serial={rdata.serial}"
        elif rtype == "SRV":
            return f"priority={rdata.priority} weight={rdata.weight} port={rdata.port} target={rdata.target}"
        elif rtype == "CAA":
            return f"flags={rdata.flags} tag={rdata.tag} value={rdata.value}"
        else:
            return str(rdata)
    except Exception:
        return str(rdata)


def analyze_dns_security(dns_data: Dict) -> List[ScanResult]:
    """Analisis DNS untuk menemukan masalah keamanan."""
    findings = []
    records = dns_data.get("records", {})

    # Zone transfer test (AXFR)
    # Dilakukan secara terpisah karena bisa menyebabkan timeout panjang

    # Cek SPF
    spf_records = records.get("SPF", [])
    if not spf_records:
        findings.append(ScanResult(
            title="Missing SPF Record",
            severity="MEDIUM",
            description="Domain tidak memiliki SPF record. Rentan terhadap email spoofing.",
            recommendation="Tambahkan SPF record: v=spf1 include:your-mail-provider.com ~all",
            owasp="A05",
            module="recon_dns",
        ))
    else:
        for spf in spf_records:
            if "+all" in spf:
                findings.append(ScanResult(
                    title="SPF Record Allows All (Permissive)",
                    severity="HIGH",
                    description=f"SPF record menggunakan '+all' yang memungkinkan semua server mengirim email.",
                    evidence=spf,
                    recommendation="Ganti '+all' dengan '~all' atau '-all'",
                    owasp="A05",
                    module="recon_dns",
                ))

    # Cek DMARC
    dmarc_records = records.get("DMARC", [])
    if not dmarc_records:
        findings.append(ScanResult(
            title="Missing DMARC Record",
            severity="MEDIUM",
            description="Domain tidak memiliki DMARC record. Email phishing lebih mudah dilakukan.",
            recommendation="Tambahkan _dmarc TXT record dengan policy yang sesuai",
            owasp="A05",
            module="recon_dns",
        ))
    else:
        for dmarc in dmarc_records:
            if "p=none" in dmarc.lower():
                findings.append(ScanResult(
                    title="DMARC Policy Set to None",
                    severity="LOW",
                    description="DMARC policy 'p=none' tidak memblok email yang gagal validasi.",
                    evidence=dmarc,
                    recommendation="Ubah ke p=quarantine atau p=reject",
                    owasp="A05",
                    module="recon_dns",
                ))

    # Cek DNSSEC
    # Jika SOA ada tapi tidak ada RRSIG, kemungkinan DNSSEC tidak aktif
    if records.get("SOA") and not records.get("RRSIG"):
        findings.append(ScanResult(
            title="DNSSEC Not Configured",
            severity="LOW",
            description="DNSSEC tampaknya tidak dikonfigurasi. Rentan terhadap DNS spoofing.",
            recommendation="Aktifkan DNSSEC di registrar domain Anda",
            owasp="A05",
            module="recon_dns",
        ))

    # Info: temukan IP
    ips = dns_data.get("ips", [])
    if ips:
        findings.append(ScanResult(
            title="DNS A Records Found",
            severity="INFO",
            description=f"Domain resolve ke IP: {', '.join(ips)}",
            evidence="\n".join(ips),
            module="recon_dns",
        ))

    return findings


# ─── Standalone ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from rich.console import Console
    from rich.table import Table

    console = Console()
    parser = argparse.ArgumentParser(description="AnarkisHunter — DNS Enumeration")
    parser.add_argument("--url", help="Target URL")
    parser.add_argument("--domain", help="Target domain")
    parser.add_argument("--types", nargs="+", help="Record types to query")
    args = parser.parse_args()

    target = args.url or args.domain
    if not target:
        console.print("[red]Provide --url or --domain[/red]")
        sys.exit(1)

    console.print(f"\n[cyan]🌐 DNS Enumeration: [bold]{target}[/bold][/cyan]\n")
    data = run_dns_enum(target, args.types)

    if data.get("error"):
        console.print(f"[red]Error: {data['error']}[/red]")
        sys.exit(1)

    for rtype, records in data["records"].items():
        table = Table(title=f"{rtype} Records", border_style="cyan", show_header=False)
        table.add_column("Record", style="green")
        for r in records:
            table.add_row(r)
        console.print(table)

    if not data["records"]:
        console.print("[yellow]No DNS records found[/yellow]")

    findings = analyze_dns_security(data)
    if findings:
        console.print(f"\n[yellow]Security Analysis — {len(findings)} findings:[/yellow]")
        for f in findings:
            color = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan", "INFO": "blue"}.get(f.severity, "white")
            console.print(f"  [{color}][{f.severity}][/{color}] {f.title}")
