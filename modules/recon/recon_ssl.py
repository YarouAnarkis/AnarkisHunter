"""
AnarkisHunter — recon_ssl.py
==============================
SSL/TLS inspector: certificate info, expiry, protocols, cipher suites,
self-signed detection, weak cipher detection.

Usage standalone:
    python modules/recon/recon_ssl.py --url https://target.local
    python modules/recon/recon_ssl.py --host example.com --port 443
"""

import sys
import ssl
import socket
import argparse
import datetime
from pathlib import Path
from typing import Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from modules.utils.utils_request import normalize_url, get_domain
from modules.utils.report import ScanResult


# Protokol yang sudah deprecated / lemah
WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
STRONG_PROTOCOLS = {"TLSv1.2", "TLSv1.3"}

# Cipher patterns yang lemah
WEAK_CIPHER_PATTERNS = ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon"]


def run_ssl_recon(target: str, port: int = 443, timeout: int = 10) -> Dict:
    """
    Inspeksi SSL/TLS certificate dan konfigurasi.

    Args:
        target: hostname atau URL
        port: port SSL (default 443)
        timeout: timeout koneksi

    Returns:
        Dict berisi detail sertifikat & SSL config
    """
    if target.startswith("http"):
        host = get_domain(normalize_url(target)).split(":")[0]
    else:
        host = target.strip()

    result = {
        "host": host,
        "port": port,
        "valid": False,
        "subject": None,
        "issuer": None,
        "version": None,
        "serial": None,
        "not_before": None,
        "not_after": None,
        "days_until_expiry": None,
        "san": [],
        "signature_algorithm": None,
        "protocol": None,
        "cipher": None,
        "is_self_signed": False,
        "is_expired": False,
        "is_wildcard": False,
        "weak_protocol": False,
        "weak_cipher": False,
        "error": None,
    }

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                cert_bin = ssock.getpeercert(binary_form=True)
                result["protocol"] = ssock.version()
                cipher = ssock.cipher()
                if cipher:
                    result["cipher"] = cipher[0]

                # Reconnect dengan verifikasi untuk validitas
                ctx_strict = ssl.create_default_context()
                try:
                    with socket.create_connection((host, port), timeout=timeout) as s2:
                        with ctx_strict.wrap_socket(s2, server_hostname=host) as ss2:
                            result["valid"] = True
                except Exception:
                    result["valid"] = False
                    result["is_self_signed"] = True

                # Parse certificate dengan cryptography untuk detail lengkap
                try:
                    from cryptography import x509
                    from cryptography.hazmat.backends import default_backend
                    x = x509.load_der_x509_certificate(cert_bin, default_backend())

                    result["subject"] = x.subject.rfc4514_string()
                    result["issuer"] = x.issuer.rfc4514_string()
                    result["serial"] = str(x.serial_number)
                    result["version"] = x.version.name
                    result["not_before"] = x.not_valid_before.strftime("%Y-%m-%d %H:%M:%S")
                    result["not_after"] = x.not_valid_after.strftime("%Y-%m-%d %H:%M:%S")
                    result["signature_algorithm"] = x.signature_algorithm_oid._name

                    delta = x.not_valid_after - datetime.datetime.now()
                    result["days_until_expiry"] = delta.days
                    result["is_expired"] = delta.days < 0

                    # SAN
                    try:
                        san_ext = x.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                        sans = [str(d.value) for d in san_ext.value]
                        result["san"] = sans
                        result["is_wildcard"] = any(s.startswith("*.") for s in sans)
                    except x509.ExtensionNotFound:
                        pass

                    # Self-signed check via issuer == subject
                    if x.issuer == x.subject:
                        result["is_self_signed"] = True
                except Exception as ce:
                    # Fallback ke cert dict
                    if cert:
                        result["subject"] = str(cert.get("subject", ""))
                        result["issuer"] = str(cert.get("issuer", ""))
                        result["not_after"] = cert.get("notAfter")
                        result["not_before"] = cert.get("notBefore")

                # Cek protokol & cipher lemah
                if result["protocol"] in WEAK_PROTOCOLS:
                    result["weak_protocol"] = True
                if result["cipher"]:
                    for pat in WEAK_CIPHER_PATTERNS:
                        if pat in result["cipher"].upper():
                            result["weak_cipher"] = True
                            break

    except socket.timeout:
        result["error"] = "Connection timeout"
    except socket.gaierror:
        result["error"] = "Could not resolve host"
    except ssl.SSLError as se:
        result["error"] = f"SSL Error: {se}"
    except Exception as e:
        result["error"] = str(e)

    return result


def analyze_ssl_findings(data: Dict) -> List[ScanResult]:
    """Analisis SSL/TLS untuk masalah keamanan."""
    findings = []
    url = f"https://{data.get('host', '')}:{data.get('port', 443)}"

    if data.get("error"):
        return findings

    # Expired
    if data.get("is_expired"):
        findings.append(ScanResult(
            title="SSL Certificate Expired",
            severity="CRITICAL",
            description=f"Sertifikat sudah expired pada {data.get('not_after')}",
            url=url,
            evidence=f"Not After: {data.get('not_after')}",
            recommendation="Segera renew sertifikat SSL",
            owasp="A02",
            module="recon_ssl",
        ))
    elif (data.get("days_until_expiry") or 999) < 30:
        findings.append(ScanResult(
            title="SSL Certificate Expiring Soon",
            severity="HIGH",
            description=f"Sertifikat akan expired dalam {data['days_until_expiry']} hari",
            url=url,
            evidence=f"Not After: {data.get('not_after')}",
            recommendation="Renew sertifikat SSL sebelum expired",
            owasp="A02",
            module="recon_ssl",
        ))

    # Self-signed
    if data.get("is_self_signed"):
        findings.append(ScanResult(
            title="Self-Signed SSL Certificate",
            severity="HIGH",
            description="Sertifikat self-signed tidak dipercaya browser",
            url=url,
            evidence=f"Issuer: {data.get('issuer')}",
            recommendation="Gunakan sertifikat dari CA terpercaya (Let's Encrypt gratis)",
            owasp="A02",
            module="recon_ssl",
        ))

    # Weak protocol
    if data.get("weak_protocol"):
        findings.append(ScanResult(
            title=f"Weak SSL/TLS Protocol: {data['protocol']}",
            severity="HIGH",
            description=f"Server mendukung protokol lemah/deprecated: {data['protocol']}",
            url=url,
            evidence=f"Protocol: {data['protocol']}",
            recommendation="Disable SSLv2/v3 dan TLSv1.0/v1.1, gunakan minimal TLSv1.2",
            owasp="A02",
            module="recon_ssl",
        ))

    # Weak cipher
    if data.get("weak_cipher"):
        findings.append(ScanResult(
            title=f"Weak Cipher Suite: {data['cipher']}",
            severity="HIGH",
            description=f"Cipher suite yang digunakan lemah: {data['cipher']}",
            url=url,
            evidence=f"Cipher: {data['cipher']}",
            recommendation="Disable cipher lemah (RC4, DES, 3DES, MD5, NULL)",
            owasp="A02",
            module="recon_ssl",
        ))

    # Wildcard cert info
    if data.get("is_wildcard"):
        findings.append(ScanResult(
            title="Wildcard SSL Certificate",
            severity="INFO",
            description="Sertifikat menggunakan wildcard — kompromi 1 server bisa berdampak ke semua subdomain",
            url=url,
            evidence="\n".join(data.get("san", [])[:5]),
            module="recon_ssl",
        ))

    return findings


# ─── Standalone ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from rich.console import Console
    from rich.table import Table

    console = Console()
    parser = argparse.ArgumentParser(description="AnarkisHunter — SSL/TLS Inspector")
    parser.add_argument("--url", help="Target URL (https://...)")
    parser.add_argument("--host", help="Target hostname")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--timeout", type=int, default=10)
    args = parser.parse_args()

    target = args.url or args.host
    if not target:
        console.print("[red]Provide --url or --host[/red]")
        sys.exit(1)

    console.print(f"\n[cyan]🔐 SSL/TLS Inspection: [bold]{target}:{args.port}[/bold][/cyan]\n")
    data = run_ssl_recon(target, args.port, args.timeout)

    if data.get("error"):
        console.print(f"[red]Error: {data['error']}[/red]")
        sys.exit(1)

    table = Table(title="SSL Certificate Info", border_style="green")
    table.add_column("Field", style="cyan", width=22)
    table.add_column("Value", style="white", overflow="fold")
    for label, key in [
        ("Host", "host"), ("Port", "port"),
        ("Valid (CA trust)", "valid"),
        ("Subject", "subject"), ("Issuer", "issuer"),
        ("Serial", "serial"), ("Version", "version"),
        ("Not Before", "not_before"), ("Not After", "not_after"),
        ("Days until expiry", "days_until_expiry"),
        ("Signature Algo", "signature_algorithm"),
        ("Protocol", "protocol"), ("Cipher", "cipher"),
        ("Self-Signed", "is_self_signed"),
        ("Wildcard", "is_wildcard"),
        ("Weak Protocol", "weak_protocol"),
        ("Weak Cipher", "weak_cipher"),
    ]:
        v = data.get(key)
        if v is not None:
            table.add_row(label, str(v))

    console.print(table)

    if data.get("san"):
        console.print("\n[bold]Subject Alternative Names:[/bold]")
        for s in data["san"][:20]:
            console.print(f"  • {s}")

    findings = analyze_ssl_findings(data)
    if findings:
        console.print(f"\n[yellow]Security Analysis — {len(findings)} findings:[/yellow]")
        for f in findings:
            color = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "INFO": "blue"}.get(f.severity, "white")
            console.print(f"  [{color}][{f.severity}][/{color}] {f.title}")
