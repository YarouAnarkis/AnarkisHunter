"""
AnarkisHunter — recon_whois.py
=================================
WHOIS lookup lengkap: registrar, owner, tanggal, expiry, nameserver.

Usage standalone:
    python modules/recon/recon_whois.py --url http://target.local
    python modules/recon/recon_whois.py --domain example.com
"""

import sys
import argparse
from pathlib import Path
from typing import Dict, Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from modules.utils.utils_request import normalize_url, get_domain
from modules.utils.report import ScanResult


def run_whois(target: str) -> Dict:
    """
    Lakukan WHOIS lookup pada domain.

    Args:
        target: URL atau domain string

    Returns:
        Dict berisi data WHOIS
    """
    # Ekstrak domain
    if target.startswith("http"):
        domain = get_domain(normalize_url(target))
    else:
        domain = target.strip()

    # Hilangkan www.
    if domain.startswith("www."):
        domain = domain[4:]

    result = {
        "domain": domain,
        "registrar": None,
        "registrar_url": None,
        "creation_date": None,
        "expiration_date": None,
        "updated_date": None,
        "name_servers": [],
        "status": [],
        "emails": [],
        "registrant_name": None,
        "registrant_org": None,
        "registrant_country": None,
        "registrant_email": None,
        "dnssec": None,
        "raw": None,
        "error": None,
    }

    try:
        import whois
        w = whois.whois(domain)

        result["registrar"] = str(w.registrar) if w.registrar else None
        result["registrar_url"] = str(w.registrar_url) if hasattr(w, "registrar_url") and w.registrar_url else None
        result["dnssec"] = str(w.dnssec) if hasattr(w, "dnssec") and w.dnssec else None
        result["raw"] = w.text[:3000] if w.text else None

        # Dates — bisa berupa list atau single value
        def _fmt_date(d):
            if d is None:
                return None
            if isinstance(d, list):
                return str(d[0]) if d else None
            return str(d)

        result["creation_date"] = _fmt_date(w.creation_date)
        result["expiration_date"] = _fmt_date(w.expiration_date)
        result["updated_date"] = _fmt_date(w.updated_date)

        # Name servers
        ns = w.name_servers
        if ns:
            if isinstance(ns, list):
                result["name_servers"] = [str(s).lower() for s in ns]
            else:
                result["name_servers"] = [str(ns).lower()]

        # Status
        st = w.status
        if st:
            if isinstance(st, list):
                result["status"] = [str(s) for s in st]
            else:
                result["status"] = [str(st)]

        # Emails
        em = w.emails
        if em:
            if isinstance(em, list):
                result["emails"] = [str(e) for e in em if e]
            else:
                result["emails"] = [str(em)] if em else []

        # Registrant info (tidak semua TLD menyediakan ini)
        if hasattr(w, "name"):
            result["registrant_name"] = str(w.name) if w.name else None
        if hasattr(w, "org"):
            result["registrant_org"] = str(w.org) if w.org else None
        if hasattr(w, "country"):
            result["registrant_country"] = str(w.country) if w.country else None

    except ImportError:
        result["error"] = "python-whois not installed. Run: pip install python-whois"
    except Exception as e:
        result["error"] = str(e)
        # Fallback: coba via socket/manual
        result.update(_fallback_whois(domain))

    return result


def _fallback_whois(domain: str) -> Dict:
    """Fallback WHOIS via socket jika library gagal."""
    import socket
    try:
        tld = domain.split(".")[-1].lower()
        whois_servers = {
            "com": "whois.verisign-grs.com", "net": "whois.verisign-grs.com",
            "org": "whois.pir.org", "id": "whois.id", "io": "whois.nic.io",
        }
        server = whois_servers.get(tld, f"whois.nic.{tld}")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((server, 43))
        s.send(f"{domain}\r\n".encode())
        raw = b""
        while True:
            data = s.recv(4096)
            if not data:
                break
            raw += data
        s.close()
        return {"raw": raw.decode("utf-8", errors="replace")[:3000]}
    except Exception:
        return {}


def analyze_whois_findings(whois_data: Dict) -> list:
    """Analisis data WHOIS untuk temuan keamanan."""
    findings = []

    # Cek expiry date
    if whois_data.get("expiration_date"):
        import datetime
        try:
            exp_str = whois_data["expiration_date"]
            # Parse berbagai format
            for fmt in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%d-%b-%Y"]:
                try:
                    exp = datetime.datetime.strptime(exp_str[:19], fmt)
                    days_left = (exp - datetime.datetime.now()).days
                    if days_left < 30:
                        findings.append(ScanResult(
                            title="Domain Expiring Soon",
                            severity="HIGH",
                            description=f"Domain akan expired dalam {days_left} hari ({exp_str})",
                            evidence=f"Expiration: {exp_str}",
                            recommendation="Segera perpanjang domain untuk menghindari domain takeover",
                            owasp="A05",
                            module="recon_whois",
                        ))
                    break
                except ValueError:
                    continue
        except Exception:
            pass

    # Cek apakah registrant info tersedia (privacy protection)
    if not whois_data.get("registrant_name") and not whois_data.get("emails"):
        findings.append(ScanResult(
            title="WHOIS Privacy Protection Active",
            severity="INFO",
            description="Data registrant disembunyikan (WHOIS privacy protection aktif)",
            evidence="Registrant info: [REDACTED]",
            module="recon_whois",
        ))

    return findings


def format_output(whois_data: Dict) -> str:
    """Format WHOIS data sebagai string yang rapi."""
    lines = ["", "┌─ WHOIS LOOKUP RESULTS ─────────────────────────────────┐"]
    fields = [
        ("Domain", "domain"), ("Registrar", "registrar"),
        ("Created", "creation_date"), ("Expires", "expiration_date"),
        ("Updated", "updated_date"), ("DNSSEC", "dnssec"),
        ("Registrant", "registrant_name"), ("Org", "registrant_org"),
        ("Country", "registrant_country"),
    ]
    for label, key in fields:
        val = whois_data.get(key)
        if val:
            lines.append(f"│  {label:<14}: {str(val)[:50]}")

    ns = whois_data.get("name_servers", [])
    if ns:
        lines.append(f"│  {'Name Servers':<14}:")
        for s in ns[:5]:
            lines.append(f"│    → {s}")

    emails = whois_data.get("emails", [])
    if emails:
        lines.append(f"│  {'Emails':<14}: {', '.join(emails[:3])}")

    if whois_data.get("error"):
        lines.append(f"│  [!] Error: {whois_data['error']}")

    lines.append("└─────────────────────────────────────────────────────────┘")
    return "\n".join(lines)


# ─── Standalone ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from rich.console import Console
    from rich.table import Table

    console = Console()
    parser = argparse.ArgumentParser(description="AnarkisHunter — WHOIS Lookup")
    parser.add_argument("--url", help="Target URL")
    parser.add_argument("--domain", help="Target domain")
    parser.add_argument("--output", help="Output file")
    parser.add_argument("--format", default="txt", choices=["txt", "json", "html"])
    args = parser.parse_args()

    target = args.url or args.domain
    if not target:
        console.print("[red]Provide --url or --domain[/red]")
        sys.exit(1)

    console.print(f"\n[cyan]🔍 WHOIS Lookup: [bold]{target}[/bold][/cyan]\n")

    data = run_whois(target)

    table = Table(title=f"WHOIS — {data['domain']}", border_style="cyan")
    table.add_column("Field", style="cyan", width=18)
    table.add_column("Value", style="white")

    rows = [
        ("Domain", data.get("domain", "")),
        ("Registrar", data.get("registrar", "N/A")),
        ("Created", data.get("creation_date", "N/A")),
        ("Expires", data.get("expiration_date", "N/A")),
        ("Updated", data.get("updated_date", "N/A")),
        ("DNSSEC", data.get("dnssec", "N/A")),
        ("Registrant", data.get("registrant_name", "N/A")),
        ("Org", data.get("registrant_org", "N/A")),
        ("Country", data.get("registrant_country", "N/A")),
        ("Name Servers", ", ".join(data.get("name_servers", [])[:3]) or "N/A"),
        ("Emails", ", ".join(data.get("emails", [])[:3]) or "N/A"),
    ]
    for label, val in rows:
        if val and val != "N/A":
            table.add_row(label, str(val)[:80])
        else:
            table.add_row(label, f"[dim]{val}[/dim]")

    console.print(table)

    if data.get("error"):
        console.print(f"\n[yellow]⚠ Warning: {data['error']}[/yellow]")

    # Security analysis
    findings = analyze_whois_findings(data)
    if findings:
        console.print(f"\n[yellow]⚠ {len(findings)} security note(s) found[/yellow]")
        for f in findings:
            color = {"HIGH": "red", "MEDIUM": "yellow", "INFO": "blue"}.get(f.severity, "white")
            console.print(f"  [{color}][{f.severity}][/{color}] {f.title}")
