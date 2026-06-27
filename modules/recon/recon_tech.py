"""
AnarkisHunter — recon_tech.py
================================
Technology fingerprinting via headers + HTML patterns + meta tags.
Mendeteksi CMS, framework, web server, programming language, JS libraries.

Usage standalone:
    python modules/recon/recon_tech.py --url http://target.local
"""

import sys
import re
import argparse
from pathlib import Path
from typing import Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from modules.utils.utils_request import HTTPClient, normalize_url
from modules.utils.report import ScanResult
from config.settings import CMS_SIGNATURES


# Web server signatures dari Server header
WEB_SERVERS = {
    "Apache": ["apache"],
    "Nginx": ["nginx"],
    "IIS": ["microsoft-iis", "iis"],
    "LiteSpeed": ["litespeed"],
    "Caddy": ["caddy"],
    "Tomcat": ["tomcat", "coyote"],
    "Cloudflare": ["cloudflare"],
}

# Programming languages
LANGUAGES = {
    "PHP": ["php", "phpsessid"],
    "Python": ["python", "wsgi"],
    "Ruby": ["ruby", "rack"],
    "Node.js": ["express", "node"],
    "Java": ["jsessionid", "java"],
    "ASP.NET": ["asp.net", "aspnet"],
}

# JS Library detection patterns (HTML/script src)
JS_LIBRARIES = {
    "jQuery": [r"jquery[.-]\d", r"jquery\.min\.js"],
    "React": [r"react[.-]\d", r"react\.production"],
    "Vue.js": [r"vue[.-]\d", r"vue\.min\.js"],
    "Angular": [r"angular[.-]\d", r"@angular/core"],
    "Bootstrap": [r"bootstrap[.-]\d", r"bootstrap\.min\.css"],
    "Tailwind CSS": [r"tailwind"],
    "Lodash": [r"lodash[.-]\d"],
    "Moment.js": [r"moment[.-]\d"],
    "Font Awesome": [r"fontawesome", r"font-awesome"],
    "Axios": [r"axios[.-]\d"],
    "D3.js": [r"d3[.-]\d", r"d3\.min\.js"],
    "Chart.js": [r"chart\.js"],
    "Three.js": [r"three[.-]\d"],
    "GSAP": [r"gsap", r"TweenMax"],
    "Next.js": [r"_next/static", r"__NEXT_DATA__"],
    "Nuxt.js": [r"_nuxt/", r"__NUXT__"],
}

# Analytics & Tracking
ANALYTICS = {
    "Google Analytics": [r"google-analytics\.com", r"gtag\(", r"ga\(", r"GTM-"],
    "Google Tag Manager": [r"googletagmanager"],
    "Facebook Pixel": [r"connect\.facebook\.net", r"fbq\("],
    "Hotjar": [r"static\.hotjar\.com"],
    "Mixpanel": [r"mixpanel"],
}


def run_tech_recon(target: str, timeout: int = 10) -> Dict:
    """
    Fingerprint teknologi yang dipakai target.

    Returns:
        Dict berisi detected technologies
    """
    url = normalize_url(target)
    result = {
        "url": url,
        "web_server": None,
        "server_version": None,
        "powered_by": None,
        "language": None,
        "cms": [],
        "frameworks": [],
        "js_libraries": [],
        "analytics": [],
        "meta_generator": None,
        "x_powered_by": None,
        "all_headers": {},
        "html_size": 0,
        "error": None,
    }

    try:
        with HTTPClient(timeout=timeout) as client:
            resp = client.get(url)
            if not resp:
                result["error"] = "Connection failed"
                return result

            result["all_headers"] = dict(resp.headers)
            html = resp.text
            result["html_size"] = len(html)

            # Server header
            server = resp.headers.get("Server", "")
            if server:
                result["server_raw"] = server
                for name, patterns in WEB_SERVERS.items():
                    for p in patterns:
                        if p in server.lower():
                            result["web_server"] = name
                            # Extract version
                            m = re.search(rf"{p}[/\s]?([\d.]+)", server, re.I)
                            if m:
                                result["server_version"] = m.group(1)
                            break
                    if result["web_server"]:
                        break

            # X-Powered-By
            powered = resp.headers.get("X-Powered-By", "")
            if powered:
                result["x_powered_by"] = powered
                result["powered_by"] = powered

            # Detect language from headers + cookies
            full_text = (server + " " + powered + " " + " ".join(resp.cookies.keys())).lower()
            for lang, patterns in LANGUAGES.items():
                for p in patterns:
                    if p in full_text:
                        result["language"] = lang
                        break
                if result["language"]:
                    break

            # CMS detection via HTML + headers
            full_haystack = html.lower() + " " + str(resp.headers).lower()
            for cms_name, sigs in CMS_SIGNATURES.items():
                for sig in sigs:
                    if sig.lower() in full_haystack:
                        if cms_name not in result["cms"]:
                            result["cms"].append(cms_name)
                        break

            # Meta generator
            m = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']',
                          html, re.I)
            if m:
                result["meta_generator"] = m.group(1)

            # JS Libraries
            for lib, patterns in JS_LIBRARIES.items():
                for p in patterns:
                    if re.search(p, html, re.I):
                        if lib not in result["js_libraries"]:
                            result["js_libraries"].append(lib)
                        break

            # Analytics
            for an, patterns in ANALYTICS.items():
                for p in patterns:
                    if re.search(p, html, re.I):
                        if an not in result["analytics"]:
                            result["analytics"].append(an)
                        break

    except Exception as e:
        result["error"] = str(e)

    return result


def analyze_tech_findings(data: Dict) -> List[ScanResult]:
    """Analisis fingerprint untuk masalah keamanan."""
    findings = []
    url = data.get("url", "")

    # Server version disclosed
    if data.get("server_version"):
        findings.append(ScanResult(
            title=f"Web Server Version Disclosed: {data['web_server']} {data['server_version']}",
            severity="LOW",
            description="Versi web server terlihat — attacker bisa cari CVE spesifik",
            url=url,
            evidence=f"Server: {data.get('server_raw', '')}",
            recommendation="Samarkan/sembunyikan versi server di konfigurasi",
            owasp="A05",
            module="recon_tech",
        ))

    # X-Powered-By
    if data.get("x_powered_by"):
        findings.append(ScanResult(
            title="Technology Disclosed via X-Powered-By",
            severity="LOW",
            description=f"Header X-Powered-By membocorkan: {data['x_powered_by']}",
            url=url,
            evidence=f"X-Powered-By: {data['x_powered_by']}",
            recommendation="Hapus header X-Powered-By",
            owasp="A05",
            module="recon_tech",
        ))

    # Meta generator
    if data.get("meta_generator"):
        findings.append(ScanResult(
            title="CMS/Generator Disclosed via Meta Tag",
            severity="INFO",
            description=f"Meta generator: {data['meta_generator']}",
            url=url,
            evidence=f"<meta name='generator' content='{data['meta_generator']}'>",
            recommendation="Hapus meta tag generator",
            module="recon_tech",
        ))

    # Tech summary as INFO
    summary_parts = []
    if data.get("web_server"):
        summary_parts.append(f"Server: {data['web_server']}")
    if data.get("language"):
        summary_parts.append(f"Lang: {data['language']}")
    if data.get("cms"):
        summary_parts.append(f"CMS: {', '.join(data['cms'])}")
    if data.get("js_libraries"):
        summary_parts.append(f"JS Libs: {', '.join(data['js_libraries'][:5])}")

    if summary_parts:
        findings.append(ScanResult(
            title="Technology Stack Identified",
            severity="INFO",
            description=" | ".join(summary_parts),
            url=url,
            module="recon_tech",
        ))

    return findings


# ─── Standalone ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from rich.console import Console
    from rich.table import Table

    console = Console()
    parser = argparse.ArgumentParser(description="AnarkisHunter — Technology Fingerprint")
    parser.add_argument("--url", required=True, help="Target URL")
    args = parser.parse_args()

    console.print(f"\n[cyan]🔬 Technology Fingerprint: [bold]{args.url}[/bold][/cyan]\n")
    data = run_tech_recon(args.url)

    if data.get("error"):
        console.print(f"[red]Error: {data['error']}[/red]")
        sys.exit(1)

    table = Table(title="Technology Detection", border_style="green")
    table.add_column("Category", style="cyan", width=18)
    table.add_column("Detected", style="white", overflow="fold")
    rows = [
        ("Web Server", f"{data.get('web_server') or 'Unknown'} {data.get('server_version') or ''}"),
        ("Language", data.get("language") or "Unknown"),
        ("X-Powered-By", data.get("x_powered_by") or "-"),
        ("Meta Generator", data.get("meta_generator") or "-"),
        ("CMS", ", ".join(data.get("cms", [])) or "-"),
        ("JS Libraries", ", ".join(data.get("js_libraries", [])) or "-"),
        ("Analytics", ", ".join(data.get("analytics", [])) or "-"),
        ("HTML Size", f"{data.get('html_size', 0)} bytes"),
    ]
    for label, val in rows:
        table.add_row(label, str(val))
    console.print(table)

    findings = analyze_tech_findings(data)
    console.print(f"\n[bold]Findings: {len(findings)}[/bold]")
