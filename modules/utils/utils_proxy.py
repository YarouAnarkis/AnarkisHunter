"""
AnarkisHunter — utils_proxy.py
=================================
Proxy support: Burp Suite, OWASP ZAP, SOCKS5.
Konfigurasi dan test proxy connection.

Usage standalone:
    python modules/utils/utils_proxy.py --test --proxy http://127.0.0.1:8080
"""

import sys
import socket
import requests
from typing import Optional, Dict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


class ProxyManager:
    """
    Manager untuk konfigurasi proxy.
    Support HTTP/HTTPS proxy (Burp Suite, ZAP) dan SOCKS5.
    """

    def __init__(self, proxy_url: Optional[str] = None):
        self.proxy_url = proxy_url
        self.proxies: Dict[str, str] = {}
        self.socks_host: Optional[str] = None
        self.socks_port: Optional[int] = None

        if proxy_url:
            self._configure(proxy_url)

    def _configure(self, proxy_url: str):
        """Konfigurasi proxy dari URL string."""
        proxy_url = proxy_url.strip()

        if proxy_url.startswith("socks5://") or proxy_url.startswith("socks4://"):
            # SOCKS proxy
            self.proxies = {
                "http": proxy_url,
                "https": proxy_url,
            }
            # Parse host dan port untuk testing
            try:
                from urllib.parse import urlparse
                parsed = urlparse(proxy_url)
                self.socks_host = parsed.hostname
                self.socks_port = parsed.port or 1080
            except Exception:
                pass
        else:
            # HTTP proxy
            if not proxy_url.startswith("http"):
                proxy_url = "http://" + proxy_url
            self.proxies = {
                "http": proxy_url,
                "https": proxy_url,
            }

        self.proxy_url = proxy_url

    def get_proxies(self) -> Dict[str, str]:
        """Return proxy dict untuk requests library."""
        return self.proxies.copy()

    def get_httpx_proxies(self) -> Optional[Dict]:
        """Return proxy config untuk httpx."""
        if not self.proxies:
            return None
        return {
            "http://": self.proxies.get("http", ""),
            "https://": self.proxies.get("https", ""),
        }

    def test_connection(self, timeout: int = 10) -> Dict:
        """
        Test apakah proxy dapat dijangkau.
        
        Returns:
            Dict berisi status dan info proxy
        """
        if not self.proxy_url:
            return {"status": "not_configured", "message": "No proxy configured"}

        try:
            # Parse proxy URL
            from urllib.parse import urlparse
            parsed = urlparse(self.proxy_url if self.proxy_url.startswith("http") else "http://" + self.proxy_url)
            host = parsed.hostname
            port = parsed.port or 8080

            # Test TCP connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()

            if result == 0:
                return {
                    "status": "reachable",
                    "proxy_url": self.proxy_url,
                    "host": host,
                    "port": port,
                    "message": f"✅ Proxy {host}:{port} is reachable",
                }
            else:
                return {
                    "status": "unreachable",
                    "proxy_url": self.proxy_url,
                    "host": host,
                    "port": port,
                    "message": f"❌ Proxy {host}:{port} is NOT reachable",
                    "error_code": result,
                }
        except Exception as e:
            return {
                "status": "error",
                "proxy_url": self.proxy_url,
                "message": str(e),
            }

    def test_via_http(self, test_url: str = "http://httpbin.org/ip", timeout: int = 15) -> Dict:
        """
        Test proxy dengan melakukan request melaluinya.
        
        Returns:
            Dict berisi IP yang terlihat dari luar
        """
        try:
            resp = requests.get(
                test_url,
                proxies=self.proxies,
                timeout=timeout,
                verify=False,
            )
            data = resp.json()
            return {
                "status": "working",
                "origin_ip": data.get("origin", "unknown"),
                "proxy_url": self.proxy_url,
                "message": f"✅ Proxy working. External IP: {data.get('origin', 'unknown')}",
            }
        except requests.exceptions.ProxyError as e:
            return {
                "status": "proxy_error",
                "message": f"Proxy error: {str(e)[:100]}",
            }
        except Exception as e:
            return {
                "status": "error",
                "message": str(e)[:100],
            }

    def enable_burp_interception(self) -> Dict:
        """
        Konfigurasi untuk Burp Suite interception.
        Default: 127.0.0.1:8080
        """
        self._configure("http://127.0.0.1:8080")
        return {
            "proxy_url": "http://127.0.0.1:8080",
            "instructions": [
                "1. Buka Burp Suite",
                "2. Pergi ke Proxy → Options",
                "3. Pastikan listener aktif di 127.0.0.1:8080",
                "4. Turn on Intercept jika ingin menangkap request",
                "5. Semua traffic AnarkisHunter akan melalui Burp",
            ]
        }

    def enable_zap(self) -> Dict:
        """
        Konfigurasi untuk OWASP ZAP.
        Default: 127.0.0.1:8090
        """
        self._configure("http://127.0.0.1:8090")
        return {
            "proxy_url": "http://127.0.0.1:8090",
            "instructions": [
                "1. Buka OWASP ZAP",
                "2. Pergi ke Tools → Options → Local Proxies",
                "3. Pastikan port 8090 aktif",
                "4. Semua traffic AnarkisHunter akan melalui ZAP",
            ]
        }

    def disable(self):
        """Nonaktifkan proxy."""
        self.proxy_url = None
        self.proxies = {}

    def is_configured(self) -> bool:
        """Cek apakah proxy dikonfigurasi."""
        return bool(self.proxy_url)


# ─── Tor Support ─────────────────────────────────────────────────────────────

class TorManager:
    """
    Manager untuk routing traffic melalui Tor network.
    Membutuhkan Tor service berjalan di localhost:9050.
    """

    TOR_SOCKS_PORT = 9050
    TOR_CONTROL_PORT = 9051
    TOR_HOST = "127.0.0.1"

    def __init__(self):
        self.enabled = False
        self._proxy_manager = ProxyManager()

    def enable(self) -> Dict:
        """
        Aktifkan Tor routing.
        
        Returns:
            Dict berisi status dan instruksi
        """
        # Test apakah Tor service berjalan
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((self.TOR_HOST, self.TOR_SOCKS_PORT))
        sock.close()

        if result != 0:
            return {
                "status": "tor_not_running",
                "message": "❌ Tor service tidak berjalan di port 9050",
                "instructions": [
                    "Install Tor: sudo apt install tor (Linux) / brew install tor (macOS)",
                    "Start Tor: sudo service tor start",
                    "Verify: netstat -an | grep 9050",
                ]
            }

        self._proxy_manager._configure(f"socks5://{self.TOR_HOST}:{self.TOR_SOCKS_PORT}")
        self.enabled = True

        return {
            "status": "enabled",
            "socks_proxy": f"socks5://{self.TOR_HOST}:{self.TOR_SOCKS_PORT}",
            "message": "✅ Tor routing enabled",
        }

    def get_proxies(self) -> Dict[str, str]:
        """Return proxy config untuk requests library melalui Tor."""
        if not self.enabled:
            return {}
        return self._proxy_manager.get_proxies()

    def get_current_ip(self) -> Optional[str]:
        """Dapatkan IP publik saat ini melalui Tor."""
        try:
            resp = requests.get(
                "https://check.torproject.org/api/ip",
                proxies=self.get_proxies(),
                timeout=30,
                verify=False,
            )
            data = resp.json()
            return data.get("IP", "unknown")
        except Exception:
            try:
                resp = requests.get(
                    "http://httpbin.org/ip",
                    proxies=self.get_proxies(),
                    timeout=30,
                )
                return resp.json().get("origin", "unknown")
            except Exception:
                return None

    def renew_circuit(self) -> bool:
        """
        Minta Tor untuk membuat circuit baru (IP baru).
        Membutuhkan akses ke Tor control port.
        """
        try:
            import socket
            ctrl_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ctrl_sock.connect((self.TOR_HOST, self.TOR_CONTROL_PORT))
            ctrl_sock.send(b"AUTHENTICATE\r\n")
            ctrl_sock.recv(1024)
            ctrl_sock.send(b"SIGNAL NEWNYM\r\n")
            response = ctrl_sock.recv(1024).decode()
            ctrl_sock.close()
            return "250 OK" in response
        except Exception:
            return False

    def disable(self):
        """Nonaktifkan Tor routing."""
        self.enabled = False
        self._proxy_manager.disable()


# ─── Standalone ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel

    console = Console()
    parser = argparse.ArgumentParser(description="Proxy Manager")
    parser.add_argument("--test", action="store_true", help="Test proxy connection")
    parser.add_argument("--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--tor", action="store_true", help="Test Tor connection")
    args = parser.parse_args()

    if args.tor:
        tor = TorManager()
        console.print("\n[cyan]Testing Tor connection...[/cyan]")
        result = tor.enable()
        console.print(f"Status: {result['status']}")
        console.print(result.get('message', ''))
        if result['status'] == 'enabled':
            console.print("\n[cyan]Getting current IP via Tor...[/cyan]")
            ip = tor.get_current_ip()
            console.print(f"[green]External IP (via Tor): {ip}[/green]")

    elif args.test and args.proxy:
        pm = ProxyManager(args.proxy)
        console.print(f"\n[cyan]Testing proxy: {args.proxy}[/cyan]")
        
        # TCP test
        tcp_result = pm.test_connection()
        console.print(f"TCP Test: {tcp_result['message']}")
        
        # HTTP test
        if tcp_result['status'] == 'reachable':
            console.print("\n[cyan]Testing HTTP request through proxy...[/cyan]")
            http_result = pm.test_via_http()
            console.print(f"HTTP Test: {http_result.get('message', 'Failed')}")
    else:
        # Show proxy setup info
        console.print(Panel(
            "[cyan]Proxy Examples:[/cyan]\n"
            "  Burp Suite: --proxy http://127.0.0.1:8080\n"
            "  OWASP ZAP:  --proxy http://127.0.0.1:8090\n"
            "  SOCKS5:     --proxy socks5://127.0.0.1:1080\n"
            "  Tor:        --tor",
            title="Proxy Configuration", border_style="cyan"
        ))
