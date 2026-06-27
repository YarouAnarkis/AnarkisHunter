"""
AnarkisHunter — utils_regex.py
==================================
Secret & Sensitive Data Finder menggunakan regex patterns.
Temukan API keys, token, password, kredensial dalam response body.

Usage standalone:
    python modules/utils/utils_regex.py --url http://target.local
    python modules/utils/utils_regex.py --file response.txt
"""

import re
import sys
from typing import List, Dict, Optional, Tuple
from pathlib import Path


# ─── Regex Pattern Library ───────────────────────────────────────────────────

SECRET_PATTERNS = {
    # API Keys & Tokens
    "AWS Access Key": re.compile(r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"),
    "AWS Secret Key": re.compile(r"(?i)aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key[\s\"'=:]+([A-Za-z0-9/+]{40})"),
    "AWS Session Token": re.compile(r"AQoXnyc8PIl5\w+"),
    "Google API Key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "Google OAuth": re.compile(r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"),
    "GitHub Token": re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}"),
    "GitHub Personal Token": re.compile(r"github[_\-\s]?token[\s\"'=:]+([A-Za-z0-9_]{40})"),
    "Stripe API Key": re.compile(r"(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{24,}"),
    "Slack Token": re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,48}"),
    "Slack Webhook": re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/+]{44,}"),
    "Twilio Account SID": re.compile(r"AC[a-z0-9]{32}"),
    "Twilio Auth Token": re.compile(r"(?i)twilio[_\-\s]?auth[_\-\s]?token[\s\"'=:]+([a-z0-9]{32})"),
    "SendGrid API Key": re.compile(r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}"),
    "Mailgun API Key": re.compile(r"key-[0-9a-z]{32}"),
    "Firebase API Key": re.compile(r"(?i)firebase[\s\S]{0,20}?(?:api[_\-\s]?key)[\s\"'=:]+([A-Za-z0-9\-_]{39,45})"),
    "Firebase DB URL": re.compile(r"https://[a-z0-9\-]+\.firebaseio\.com"),
    "Heroku API Key": re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
    "Cloudinary": re.compile(r"cloudinary://[0-9]{15}:[A-Za-z0-9\-_]+@[a-z0-9]+"),
    "Shopify Token": re.compile(r"shpat_[a-fA-F0-9]{32}"),
    "Discord Token": re.compile(r"[MN][A-Za-z0-9]{23}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27}"),
    "Discord Webhook": re.compile(r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9\-_]+"),
    "Twitter API Key": re.compile(r"(?i)twitter[_\-\s]?(?:api[_\-\s]?)?(?:key|secret|token)[\s\"'=:]+([A-Za-z0-9]{25,50})"),
    "PayPal Client ID": re.compile(r"A[a-zA-Z0-9_-]{79}"),
    "Telegram Bot Token": re.compile(r"[0-9]{9}:[a-zA-Z0-9_\-]{35}"),
    "NPM Token": re.compile(r"npm_[A-Za-z0-9]{36}"),
    "PyPI Token": re.compile(r"pypi-[A-Za-z0-9_\-]{40,}"),
    "Vault Token": re.compile(r"(?:hvs|s)\.[A-Za-z0-9]{24}"),

    # Credentials & Passwords
    "Generic Password": re.compile(r"(?i)(?:password|passwd|pwd|pass)[\s\"'`]?[=:]\s*[\"']?([^\s\"',;{}()\[\]]{6,50})[\"']?"),
    "Generic Secret": re.compile(r"(?i)(?:secret|token)[\s\"'`]?[=:]\s*[\"']?([a-zA-Z0-9_\-\.]{8,60})[\"']?"),
    "Generic API Key": re.compile(r"(?i)api[_\-\s]?key[\s\"'`]?[=:]\s*[\"']?([a-zA-Z0-9_\-\.]{16,60})[\"']?"),
    "Database URL": re.compile(r"(?i)(?:mysql|postgresql|postgres|mongodb|redis|sqlite)://[^\s\"'<>]+"),
    "Connection String": re.compile(r"(?i)(?:data\s?source|server|uid|pwd|database)=[^;\"']+"),

    # Cryptographic Keys & Certificates
    "Private Key": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    "Certificate": re.compile(r"-----BEGIN CERTIFICATE-----"),
    "PGP Private Key": re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----"),
    "SSH Private Key": re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----"),

    # JWT Tokens
    "JWT Token": re.compile(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"),

    # Credit Card Numbers
    "Credit Card (Visa)": re.compile(r"4[0-9]{12}(?:[0-9]{3})?"),
    "Credit Card (MasterCard)": re.compile(r"5[1-5][0-9]{14}"),
    "Credit Card (Amex)": re.compile(r"3[47][0-9]{13}"),

    # Identity & Personal Info
    "Email Address": re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"),
    "IPv4 Address": re.compile(r"\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b"),  # Private IPs
    "Phone Number": re.compile(r"(?:\+62|0)[0-9]{9,13}"),

    # Hashes (possible passwords)
    "MD5 Hash": re.compile(r"\b[a-f0-9]{32}\b"),
    "SHA1 Hash": re.compile(r"\b[a-f0-9]{40}\b"),
    "SHA256 Hash": re.compile(r"\b[a-f0-9]{64}\b"),
    "bcrypt Hash": re.compile(r"\$2[ayb]\$[0-9]{2}\$[./A-Za-z0-9]{53}"),

    # Hardcoded Credentials Patterns
    "Hardcoded Username": re.compile(r"(?i)(?:username|user_name|login)[\s\"'`]?[=:]\s*[\"']([a-zA-Z0-9_\-\.@]{3,50})[\"']"),
    "Debug Mode": re.compile(r"(?i)(?:debug|DEBUG)\s*[=:]\s*(?:true|True|1|on)"),
    "Stack Trace": re.compile(r"(?:Traceback|Exception|Error).*?(?:File|at)\s+\"?[\w./\\]"),

    # Internal Network & Infrastructure
    "Internal IP": re.compile(r"\b(?:127\.\d+\.\d+\.\d+|localhost|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)\b"),
    "AWS Metadata": re.compile(r"169\.254\.169\.254"),
    "Docker Network": re.compile(r"172\.1[6-9]\.\d+\.\d+|172\.2\d\.\d+\.\d+"),

    # Source Code Indicators
    "PHP Error": re.compile(r"(?:Fatal error|Warning|Notice|Parse error):\s+.+in\s+/.+\.php"),
    "SQL Error": re.compile(r"(?:mysql_fetch|ORA-\d{4,}|SQLSTATE|Syntax error|Column not found|Table .+ doesn't exist)"),
    "Python Traceback": re.compile(r"Traceback \(most recent call last\):"),
    "Debug Comments": re.compile(r"(?i)(?:TODO|FIXME|HACK|BUG|XXX|TEMP|NOCOMMIT):\s*.+"),
}


def scan_text(text: str, patterns: Optional[Dict] = None) -> List[Dict]:
    """
    Scan teks dengan semua secret patterns.
    
    Args:
        text: Teks yang akan di-scan
        patterns: Custom patterns dict (default: SECRET_PATTERNS)
        
    Returns:
        List of findings
    """
    if patterns is None:
        patterns = SECRET_PATTERNS

    findings = []
    seen = set()

    for pattern_name, pattern in patterns.items():
        try:
            matches = pattern.finditer(text)
            for match in matches:
                value = match.group(0)
                # Deduplicate
                key = f"{pattern_name}:{value}"
                if key in seen:
                    continue
                seen.add(key)

                # Dapatkan konteks (30 chars sebelum dan sesudah)
                start = max(0, match.start() - 30)
                end = min(len(text), match.end() + 30)
                context = text[start:end].strip()

                severity = _get_severity(pattern_name)
                findings.append({
                    "type": pattern_name,
                    "value": value[:200],  # Potong jika terlalu panjang
                    "context": context[:300],
                    "severity": severity,
                    "owasp": "A02",
                })
        except Exception:
            continue

    return findings


def scan_url_response(url: str, response_text: str) -> List[Dict]:
    """Scan response dari URL tertentu."""
    findings = scan_text(response_text)
    for f in findings:
        f["source_url"] = url
    return findings


def scan_file(filepath: str) -> List[Dict]:
    """Scan file untuk sensitive data."""
    try:
        content = Path(filepath).read_text(encoding="utf-8", errors="replace")
        findings = scan_text(content)
        for f in findings:
            f["source_file"] = filepath
        return findings
    except Exception as e:
        return [{"error": str(e)}]


def _get_severity(pattern_name: str) -> str:
    """Tentukan severity berdasarkan tipe temuan."""
    critical = ["Private Key", "Certificate", "PGP Private Key", "SSH Private Key",
                "Database URL", "Credit Card", "Generic Password", "AWS Secret Key"]
    high = ["AWS Access Key", "GitHub Token", "Stripe API Key", "JWT Token",
            "Slack Token", "Discord Token", "Firebase API Key"]
    medium = ["Generic API Key", "Generic Secret", "Email Address", "bcrypt Hash",
              "PHP Error", "SQL Error", "Stack Trace"]

    for c in critical:
        if c.lower() in pattern_name.lower():
            return "CRITICAL"
    for h in high:
        if h.lower() in pattern_name.lower():
            return "HIGH"
    for m in medium:
        if m.lower() in pattern_name.lower():
            return "MEDIUM"
    return "LOW"


def extract_endpoints(text: str) -> List[str]:
    """Ekstrak endpoint URL dari JavaScript atau HTML."""
    patterns = [
        re.compile(r"""["'`](/[a-zA-Z0-9_/\-\.?=&]+)["'`]"""),
        re.compile(r"""fetch\(["'`]([^"'`]+)["'`]"""),
        re.compile(r"""axios\.[a-z]+\(["'`]([^"'`]+)["'`]"""),
        re.compile(r"""url:\s*["'`]([^"'`]+)["'`]"""),
        re.compile(r"""href=["']([^"']+)["']"""),
        re.compile(r"""action=["']([^"']+)["']"""),
    ]
    endpoints = set()
    for p in patterns:
        for m in p.finditer(text):
            url = m.group(1)
            if url and not url.startswith("data:") and not url.startswith("javascript:"):
                endpoints.add(url)
    return sorted(endpoints)


# ─── Standalone ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    from rich.console import Console
    from rich.table import Table

    console = Console()
    parser = argparse.ArgumentParser(description="Secret Finder")
    parser.add_argument("--url", help="Scan URL response")
    parser.add_argument("--file", help="Scan local file")
    parser.add_argument("--text", help="Scan raw text")
    args = parser.parse_args()

    findings = []

    if args.url:
        sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
        from modules.utils.utils_request import HTTPClient, normalize_url
        with HTTPClient() as client:
            resp = client.get(normalize_url(args.url))
            if resp:
                findings = scan_url_response(args.url, resp.text)
    elif args.file:
        findings = scan_file(args.file)
    elif args.text:
        findings = scan_text(args.text)
    else:
        console.print("[red]Provide --url, --file, or --text[/red]")
        sys.exit(1)

    if findings:
        table = Table(title=f"🔍 Secrets Found ({len(findings)} items)", border_style="red")
        table.add_column("Severity", width=10)
        table.add_column("Type", style="cyan")
        table.add_column("Value", style="yellow")
        for f in findings:
            if "error" in f:
                continue
            color = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan"}.get(f["severity"], "white")
            table.add_row(
                f"[{color}]{f['severity']}[/{color}]",
                f["type"],
                f["value"][:60] + ("..." if len(f["value"]) > 60 else "")
            )
        console.print(table)
    else:
        console.print("[green]✅ No secrets found[/green]")
