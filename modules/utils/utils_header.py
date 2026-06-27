"""
AnarkisHunter — utils_header.py
=================================
Custom header injection & management.
Support spoofing, X-Forwarded-For, custom User-Agent, Bearer tokens.

Usage standalone:
    python modules/utils/utils_header.py --analyze --url http://target.local
"""

import sys
import random
from typing import Dict, Optional, List

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[2]))
from config.settings import DEFAULT_USER_AGENT, USER_AGENTS


# ─── Security Headers yang harus dianalisis ──────────────────────────────────
REQUIRED_SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Content-Security-Policy",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
]

INFORMATION_DISCLOSURE_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Generator",
    "X-Drupal-Cache",
    "X-Pingback",
    "Via",
    "X-Backend-Server",
    "X-Real-IP",
]

# ─── Populer User Agents ──────────────────────────────────────────────────────
COMMON_USER_AGENTS = {
    "chrome_windows": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "chrome_mac": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "firefox_linux": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "safari_iphone": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "edge_windows": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
    "googlebot": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "burp_suite": "Mozilla/5.0 (compatible; BurpSuite/2024.4)",
    "scanner": "AnarkisHunter/1.0 (Security Scanner; Educational)",
    "curl": "curl/8.7.1",
    "python": "python-requests/2.31.0",
}


class HeaderManager:
    """
    Manager untuk custom headers, spoofing, dan analisis security headers.
    """

    def __init__(
        self,
        user_agent: str = DEFAULT_USER_AGENT,
        custom_headers: Optional[Dict[str, str]] = None,
        cookies_str: Optional[str] = None,
        proxy_headers: bool = False,
        randomize_ua: bool = False,
    ):
        self.base_headers: Dict[str, str] = {}

        # Set User-Agent
        if randomize_ua:
            self.base_headers["User-Agent"] = random.choice(list(COMMON_USER_AGENTS.values()))
        else:
            self.base_headers["User-Agent"] = user_agent

        # Add custom headers
        if custom_headers:
            self.base_headers.update(custom_headers)

        # Parse cookie string "key=val; key2=val2"
        if cookies_str:
            self.base_headers["Cookie"] = cookies_str

        # IP spoofing headers (bypass WAF/IP restriction)
        if proxy_headers:
            spoofed_ip = self._random_ip()
            self.base_headers.update({
                "X-Forwarded-For": spoofed_ip,
                "X-Real-IP": spoofed_ip,
                "X-Originating-IP": spoofed_ip,
                "X-Remote-IP": spoofed_ip,
                "X-Remote-Addr": spoofed_ip,
                "X-Client-IP": spoofed_ip,
            })

    def get_headers(self) -> Dict[str, str]:
        """Return current header dict."""
        return dict(self.base_headers)

    def add_bearer_token(self, token: str) -> None:
        """Tambahkan Bearer token ke Authorization header."""
        self.base_headers["Authorization"] = f"Bearer {token}"

    def add_basic_auth(self, username: str, password: str) -> None:
        """Tambahkan Basic Auth header."""
        import base64
        creds = base64.b64encode(f"{username}:{password}".encode()).decode()
        self.base_headers["Authorization"] = f"Basic {creds}"

    def add_api_key(self, key: str, header_name: str = "X-API-Key") -> None:
        """Tambahkan API Key header."""
        self.base_headers[header_name] = key

    def set_content_json(self) -> None:
        """Set Content-Type ke application/json."""
        self.base_headers["Content-Type"] = "application/json"

    def set_content_form(self) -> None:
        """Set Content-Type ke application/x-www-form-urlencoded."""
        self.base_headers["Content-Type"] = "application/x-www-form-urlencoded"

    def rotate_user_agent(self) -> str:
        """Ganti User-Agent secara acak dan return nilai baru."""
        ua = random.choice(list(COMMON_USER_AGENTS.values()))
        self.base_headers["User-Agent"] = ua
        return ua

    def inject_bypass_headers(self) -> None:
        """
        Inject header untuk bypass WAF dan security controls.
        Berguna untuk test apakah server bisa di-bypass melalui header manipulation.
        """
        bypass_headers = {
            "X-Forwarded-For": "127.0.0.1",
            "X-Real-IP": "127.0.0.1",
            "X-Originating-IP": "127.0.0.1",
            "X-Custom-IP-Authorization": "127.0.0.1",
            "X-Forwarded-Host": "localhost",
            "X-Host": "localhost",
            "X-Rewrite-URL": "/",
            "X-Original-URL": "/",
            "X-Override-URL": "/",
        }
        self.base_headers.update(bypass_headers)

    def parse_header_string(self, header_str: str) -> Dict[str, str]:
        """
        Parse header string format "Key: Value\nKey2: Value2" atau
        "Key: Value; Key2: Value2" menjadi dict.
        """
        headers = {}
        lines = header_str.replace(";", "\n").split("\n")
        for line in lines:
            line = line.strip()
            if ":" in line:
                key, _, val = line.partition(":")
                headers[key.strip()] = val.strip()
        return headers

    def _random_ip(self) -> str:
        """Generate IP acak untuk spoofing."""
        return f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def analyze_security_headers(response_headers: Dict[str, str]) -> List[Dict]:
    """
    Analisis security headers dari response.
    
    Returns:
        List of findings dengan severity dan rekomendasi
    """
    findings = []
    headers_lower = {k.lower(): v for k, v in response_headers.items()}

    # Cek missing security headers
    header_checks = [
        {
            "header": "strict-transport-security",
            "name": "Strict-Transport-Security (HSTS)",
            "severity": "HIGH",
            "description": "Header HSTS tidak ditemukan. Rentan terhadap protocol downgrade attack.",
            "recommendation": "Tambahkan: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            "owasp": "A05",
        },
        {
            "header": "x-content-type-options",
            "name": "X-Content-Type-Options",
            "severity": "MEDIUM",
            "description": "MIME type sniffing tidak dinonaktifkan. Rentan terhadap MIME confusion attack.",
            "recommendation": "Tambahkan: X-Content-Type-Options: nosniff",
            "owasp": "A05",
        },
        {
            "header": "x-frame-options",
            "name": "X-Frame-Options",
            "severity": "MEDIUM",
            "description": "Tidak ada proteksi clickjacking melalui X-Frame-Options.",
            "recommendation": "Tambahkan: X-Frame-Options: SAMEORIGIN",
            "owasp": "A05",
        },
        {
            "header": "content-security-policy",
            "name": "Content-Security-Policy (CSP)",
            "severity": "HIGH",
            "description": "CSP tidak dikonfigurasi. Rentan terhadap XSS dan data injection.",
            "recommendation": "Tambahkan CSP yang restrictive sesuai kebutuhan aplikasi",
            "owasp": "A05",
        },
        {
            "header": "referrer-policy",
            "name": "Referrer-Policy",
            "severity": "LOW",
            "description": "Referrer policy tidak dikonfigurasi. URL sensitif bisa bocor ke third-party.",
            "recommendation": "Tambahkan: Referrer-Policy: strict-origin-when-cross-origin",
            "owasp": "A05",
        },
        {
            "header": "permissions-policy",
            "name": "Permissions-Policy",
            "severity": "LOW",
            "description": "Permissions policy tidak dikonfigurasi.",
            "recommendation": "Tambahkan Permissions-Policy untuk batasi akses fitur browser",
            "owasp": "A05",
        },
    ]

    for check in header_checks:
        if check["header"] not in headers_lower:
            findings.append({
                "type": "missing_header",
                "name": check["name"],
                "severity": check["severity"],
                "description": check["description"],
                "recommendation": check["recommendation"],
                "owasp": check["owasp"],
                "evidence": f"Header '{check['name']}' tidak ditemukan dalam response",
            })

    # Cek information disclosure headers
    for header in INFORMATION_DISCLOSURE_HEADERS:
        if header.lower() in headers_lower:
            findings.append({
                "type": "info_disclosure",
                "name": f"Information Disclosure: {header}",
                "severity": "LOW",
                "description": f"Header '{header}' mengungkapkan informasi teknologi server.",
                "recommendation": f"Hapus atau sembunyikan header '{header}' dari response.",
                "owasp": "A05",
                "evidence": f"{header}: {headers_lower[header.lower()]}",
            })

    return findings


def format_headers_table(headers: Dict[str, str]) -> str:
    """Format headers sebagai string tabel yang bersih."""
    lines = []
    for key, val in sorted(headers.items()):
        lines.append(f"  {key}: {val}")
    return "\n".join(lines)


# ─── Standalone ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    import sys
    sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[2]))

    from rich.console import Console
    from rich.table import Table
    from modules.utils.utils_request import HTTPClient, normalize_url

    console = Console()
    parser = argparse.ArgumentParser(description="Header Analyzer")
    parser.add_argument("--url", required=True)
    args = parser.parse_args()

    url = normalize_url(args.url)
    console.print(f"\n[cyan]Analyzing headers for: [bold]{url}[/bold][/cyan]\n")

    with HTTPClient() as client:
        resp = client.get(url)
        if resp:
            # Response Headers Table
            table = Table(title="Response Headers", border_style="cyan")
            table.add_column("Header", style="cyan", no_wrap=True)
            table.add_column("Value", style="white")
            for k, v in resp.headers.items():
                table.add_row(k, v)
            console.print(table)

            # Security Analysis
            findings = analyze_security_headers(dict(resp.headers))
            if findings:
                ftable = Table(title="Security Header Analysis", border_style="red")
                ftable.add_column("Severity", style="red", width=10)
                ftable.add_column("Header", style="yellow")
                ftable.add_column("Issue", style="white")
                for f in findings:
                    color = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan"}.get(f["severity"], "white")
                    ftable.add_row(
                        f"[{color}]{f['severity']}[/{color}]",
                        f["name"],
                        f["description"][:80]
                    )
                console.print(ftable)
        else:
            console.print("[red]❌ Cannot connect to target[/red]")
