"""
AnarkisHunter — recon_js.py
=============================
JavaScript analysis: download JS files dari halaman, scan untuk
secrets (API keys, tokens), endpoint URLs, dan dependency vulnerabilities.

Usage standalone:
    python modules/recon/recon_js.py --url http://target.local
"""

import sys
import re
import argparse
from pathlib import Path
from typing import Dict, List, Set
from urllib.parse import urljoin

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from modules.utils.utils_request import HTTPClient, normalize_url, extract_base_url, is_same_domain
from modules.utils.report import ScanResult


# Regex pattern untuk secret detection (high-confidence)
SECRET_PATTERNS = {
    "AWS Access Key ID":      r"AKIA[0-9A-Z]{16}",
    "AWS Secret Access Key":  r"(?i)aws[_\-]?secret[_\-]?(?:access)?[_\-]?key[\s:=\"']{1,5}([A-Za-z0-9/+=]{40})",
    "Google API Key":         r"AIza[0-9A-Za-z\-_]{35}",
    "Google OAuth":           r"ya29\.[0-9A-Za-z\-_]+",
    "GitHub Token":           r"gh[pousr]_[A-Za-z0-9]{36,255}",
    "GitHub OAuth":           r"(?i)github[\s:=\"']{1,5}([0-9a-f]{40})",
    "Slack Token":            r"xox[baprs]-[0-9a-zA-Z-]{10,48}",
    "Slack Webhook":          r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
    "Stripe Live Key":        r"sk_live_[0-9a-zA-Z]{24,99}",
    "Stripe Publishable Key": r"pk_live_[0-9a-zA-Z]{24,99}",
    "Heroku API Key":         r"(?i)heroku[\s:=\"']{1,5}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
    "Mailgun API Key":        r"key-[0-9a-zA-Z]{32}",
    "Twilio API Key":         r"SK[0-9a-fA-F]{32}",
    "SendGrid API Key":       r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}",
    "Generic API Key":        r"(?i)api[_\-]?key[\s:=\"']{1,5}[\"']([A-Za-z0-9_\-]{20,64})[\"']",
    "Generic Secret":         r"(?i)secret[_\-]?key[\s:=\"']{1,5}[\"']([A-Za-z0-9_\-]{16,64})[\"']",
    "JWT Token":              r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",
    "Private RSA Key":        r"-----BEGIN RSA PRIVATE KEY-----",
    "Private SSH Key":        r"-----BEGIN OPENSSH PRIVATE KEY-----",
    "Firebase URL":           r"https://[a-zA-Z0-9\-]+\.firebaseio\.com",
}

# Pattern endpoint URL
ENDPOINT_PATTERN = re.compile(
    r"""['"`](\/?[a-zA-Z0-9_\-/]{3,}(?:\.[a-zA-Z]+|\/[a-zA-Z0-9_\-]{2,}))['"`]"""
)
URL_PATTERN = re.compile(r"""['"`](https?://[^\s'"`<>]+)['"`]""")


def run_js_recon(target: str, max_files: int = 30, timeout: int = 10) -> Dict:
    """
    Scan JavaScript files dari halaman target.

    Returns:
        Dict berisi secrets, endpoints, URL ditemukan
    """
    base_url = normalize_url(target)
    result = {
        "target": base_url,
        "js_files": [],
        "secrets": [],
        "endpoints": [],
        "external_urls": [],
        "total_js": 0,
        "total_size": 0,
        "error": None,
    }

    try:
        with HTTPClient(timeout=timeout) as client:
            # Fetch main page
            resp = client.get(base_url)
            if not resp:
                result["error"] = "Failed to fetch target"
                return result

            html = resp.text

            # Ekstrak semua src JS files
            js_urls = set()
            for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I):
                src = m.group(1)
                full = urljoin(base_url, src)
                js_urls.add(full)

            # Juga scan inline script
            inline_scripts = re.findall(r"<script[^>]*>([\s\S]*?)</script>", html, re.I)

            result["total_js"] = len(js_urls) + len(inline_scripts)

            # Scan inline scripts dulu (no HTTP needed)
            for idx, script in enumerate(inline_scripts):
                if not script.strip():
                    continue
                _scan_js_content(script, f"{base_url}#inline-{idx}", result, base_url)

            # Download & scan external JS files
            js_urls = list(js_urls)[:max_files]
            for js_url in js_urls:
                try:
                    js_resp = client.get(js_url)
                    if not js_resp or js_resp.status_code != 200:
                        continue
                    content = js_resp.text
                    result["js_files"].append({
                        "url": js_url,
                        "size": len(content),
                        "status": js_resp.status_code,
                    })
                    result["total_size"] += len(content)
                    _scan_js_content(content, js_url, result, base_url)
                except Exception:
                    continue

            # Dedupe
            result["endpoints"] = list(dict.fromkeys(result["endpoints"]))[:200]
            result["external_urls"] = list(dict.fromkeys(result["external_urls"]))[:100]

    except Exception as e:
        result["error"] = str(e)

    return result


def _scan_js_content(content: str, source: str, result: Dict, base_url: str) -> None:
    """Scan satu blok JS untuk secrets, endpoints, URLs."""
    # Secrets
    for name, pattern in SECRET_PATTERNS.items():
        for m in re.finditer(pattern, content):
            value = m.group(0)
            result["secrets"].append({
                "type": name,
                "value": value[:80] + ("..." if len(value) > 80 else ""),
                "source": source,
            })

    # Endpoints (relative paths)
    for m in ENDPOINT_PATTERN.finditer(content):
        ep = m.group(1)
        if len(ep) > 200:
            continue
        if any(ep.endswith(ext) for ext in (".jpg", ".png", ".gif", ".svg", ".css", ".woff")):
            continue
        result["endpoints"].append(ep)

    # External URLs
    for m in URL_PATTERN.finditer(content):
        url = m.group(1)
        if not is_same_domain(url, base_url):
            result["external_urls"].append(url)


def analyze_js_findings(data: Dict) -> List[ScanResult]:
    """Analisis hasil JS recon."""
    findings = []
    target = data.get("target", "")

    # Secrets — CRITICAL!
    for secret in data.get("secrets", [])[:20]:
        findings.append(ScanResult(
            title=f"Secret Leaked in JavaScript: {secret['type']}",
            severity="CRITICAL",
            description=f"Secret terdeteksi di JS file: {secret['type']}",
            url=secret["source"],
            evidence=f"{secret['type']}: {secret['value']}",
            recommendation=(
                "Pindahkan secret ke backend! Jangan pernah letakkan API key, "
                "token, atau credential di kode frontend."
            ),
            owasp="A02",
            module="recon_js",
        ))

    # Endpoints terungkap
    if data.get("endpoints"):
        findings.append(ScanResult(
            title=f"API Endpoints Discovered in JS ({len(data['endpoints'])})",
            severity="INFO",
            description=f"Ditemukan {len(data['endpoints'])} endpoint dari analisis JS",
            url=target,
            evidence="\n".join(data["endpoints"][:30]),
            module="recon_js",
        ))

    # External URLs
    if data.get("external_urls"):
        findings.append(ScanResult(
            title=f"External URLs Referenced ({len(data['external_urls'])})",
            severity="INFO",
            description="JS me-reference URL eksternal — third-party dependencies",
            url=target,
            evidence="\n".join(data["external_urls"][:20]),
            module="recon_js",
        ))

    return findings


# ─── Standalone ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from rich.console import Console
    from rich.table import Table

    console = Console()
    parser = argparse.ArgumentParser(description="AnarkisHunter — JavaScript Analyzer")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--max-files", type=int, default=30)
    args = parser.parse_args()

    console.print(f"\n[cyan]📜 JavaScript Recon: [bold]{args.url}[/bold][/cyan]\n")
    data = run_js_recon(args.url, args.max_files)

    if data.get("error"):
        console.print(f"[red]Error: {data['error']}[/red]")
        sys.exit(1)

    console.print(f"[green]JS files analyzed:[/green] {len(data['js_files'])}")
    console.print(f"[green]Total size:[/green] {data['total_size']} bytes")
    console.print(f"[green]Endpoints found:[/green] {len(data['endpoints'])}")
    console.print(f"[green]External URLs:[/green] {len(data['external_urls'])}")
    console.print(f"[red]Secrets leaked:[/red] {len(data['secrets'])}\n")

    if data["secrets"]:
        t = Table(title="⚠ Secrets Detected", border_style="red")
        t.add_column("Type", style="red", width=24)
        t.add_column("Value", style="yellow", overflow="fold")
        t.add_column("Source", style="dim", overflow="fold")
        for s in data["secrets"][:20]:
            t.add_row(s["type"], s["value"], s["source"][-50:])
        console.print(t)

    if data["endpoints"]:
        console.print(f"\n[bold]Endpoints sample (showing 20 of {len(data['endpoints'])}):[/bold]")
        for ep in data["endpoints"][:20]:
            console.print(f"  → {ep}")
