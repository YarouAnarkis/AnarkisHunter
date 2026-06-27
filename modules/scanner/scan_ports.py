"""
AnarkisHunter — scan_ports.py
================================
Threaded TCP port scanner (socket-based).
Identifikasi port terbuka & service via banner grabbing.

Usage standalone:
    python modules/scanner/scan_ports.py --host target.local
    python modules/scanner/scan_ports.py --host 192.168.1.1 --ports 1-1000
"""

import sys
import socket
import argparse
from pathlib import Path
from typing import Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from modules.utils.utils_request import normalize_url, get_domain
from modules.utils.report import ScanResult
from config.settings import COMMON_PORTS, PORT_SERVICES


def _scan_one_port(host: str, port: int, timeout: float = 1.0) -> Optional[Dict]:
    """Scan satu port — return dict jika open, None jika closed."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((host, port))
        if result == 0:
            banner = ""
            try:
                # Try grab banner
                s.settimeout(2)
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                data = s.recv(1024)
                banner = data.decode("utf-8", errors="replace")[:300].strip()
            except Exception:
                pass
            s.close()
            return {
                "port": port,
                "service": PORT_SERVICES.get(port, "unknown"),
                "banner": banner,
            }
        s.close()
        return None
    except Exception:
        return None


def parse_port_range(spec: str) -> List[int]:
    """Parse port spec: '80,443,8080' atau '1-1000' atau 'common'."""
    if spec == "common":
        return COMMON_PORTS[:]
    if spec == "all":
        return list(range(1, 65536))
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-")
            ports.update(range(int(lo), int(hi) + 1))
        elif part.isdigit():
            ports.add(int(part))
    return sorted(ports)


def run_port_scan(
    target: str,
    ports: Optional[List[int]] = None,
    threads: int = 100,
    timeout: float = 1.0,
) -> Dict:
    """
    Scan TCP port pada target.

    Args:
        target: hostname / IP / URL
        ports: List port (default: COMMON_PORTS)
        threads: jumlah worker thread

    Returns:
        Dict berisi open ports & banners
    """
    if target.startswith("http"):
        host = get_domain(normalize_url(target)).split(":")[0]
    else:
        host = target.strip()

    # Resolve hostname
    try:
        ip = socket.gethostbyname(host)
    except Exception as e:
        return {"host": host, "ip": "", "error": f"Resolution failed: {e}", "open_ports": []}

    ports = ports or COMMON_PORTS
    result = {
        "host": host,
        "ip": ip,
        "total_ports": len(ports),
        "open_ports": [],
        "closed_count": 0,
        "error": None,
    }

    open_results = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(_scan_one_port, ip, p, timeout): p for p in ports}
        for fut in as_completed(futures):
            try:
                res = fut.result()
                if res:
                    open_results.append(res)
                else:
                    result["closed_count"] += 1
            except Exception:
                result["closed_count"] += 1

    result["open_ports"] = sorted(open_results, key=lambda x: x["port"])
    return result


def analyze_port_findings(data: Dict) -> List[ScanResult]:
    """Analisis hasil port scan."""
    findings = []
    host = data.get("host", "")

    # Risky ports
    RISKY_PORTS = {
        21: ("FTP", "HIGH", "FTP plaintext — gunakan SFTP"),
        23: ("Telnet", "CRITICAL", "Telnet plaintext — DISABLE, gunakan SSH"),
        25: ("SMTP", "MEDIUM", "Verifikasi SMTP tidak open relay"),
        135: ("MSRPC", "MEDIUM", "RPC sebaiknya tidak exposed ke internet"),
        139: ("NetBIOS", "HIGH", "NetBIOS — tutup di internet-facing"),
        445: ("SMB", "HIGH", "SMB — tutup, banyak CVE (EternalBlue dll)"),
        1433: ("MSSQL", "HIGH", "Database tidak boleh exposed ke internet"),
        3306: ("MySQL", "HIGH", "Database tidak boleh exposed ke internet"),
        3389: ("RDP", "HIGH", "RDP target ransomware — VPN saja"),
        5432: ("PostgreSQL", "HIGH", "Database tidak boleh exposed ke internet"),
        5900: ("VNC", "HIGH", "VNC unencrypted — gunakan VPN"),
        6379: ("Redis", "CRITICAL", "Redis open — sering tanpa auth, RCE"),
        27017: ("MongoDB", "CRITICAL", "MongoDB open — sering tanpa auth"),
    }

    for p in data.get("open_ports", []):
        port = p["port"]
        if port in RISKY_PORTS:
            svc, sev, fix = RISKY_PORTS[port]
            findings.append(ScanResult(
                title=f"Risky Port Open: {port}/{svc}",
                severity=sev,
                description=f"Port {port} ({svc}) terbuka — potensi risiko keamanan",
                url=f"{host}:{port}",
                evidence=f"Port {port} OPEN, banner: {p.get('banner', '')[:200]}",
                recommendation=fix,
                owasp="A05",
                module="scan_ports",
            ))
        else:
            findings.append(ScanResult(
                title=f"Port Open: {port}/{p['service']}",
                severity="INFO",
                description=f"Port {port} ({p['service']}) terbuka",
                url=f"{host}:{port}",
                evidence=p.get("banner", "")[:200] if p.get("banner") else f"Port {port}",
                module="scan_ports",
            ))

    return findings


# ─── Standalone ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from rich.console import Console
    from rich.table import Table

    console = Console()
    parser = argparse.ArgumentParser(description="AnarkisHunter — Port Scanner")
    parser.add_argument("--host", required=True, help="Target host/IP/URL")
    parser.add_argument("--ports", default="common", help="Ports (1-1000, 80,443, common, all)")
    parser.add_argument("--threads", type=int, default=100)
    parser.add_argument("--timeout", type=float, default=1.0)
    args = parser.parse_args()

    ports = parse_port_range(args.ports)
    console.print(f"\n[cyan]🔌 Port Scan: [bold]{args.host}[/bold] ({len(ports)} ports, {args.threads} threads)[/cyan]\n")

    data = run_port_scan(args.host, ports, args.threads, args.timeout)

    if data.get("error"):
        console.print(f"[red]Error: {data['error']}[/red]")
        sys.exit(1)

    console.print(f"[green]Host:[/green] {data['host']} ({data['ip']})")
    console.print(f"[green]Open:[/green] {len(data['open_ports'])} / {data['total_ports']}\n")

    if data["open_ports"]:
        t = Table(title="Open Ports", border_style="green")
        t.add_column("Port", style="cyan", width=8)
        t.add_column("Service", style="yellow", width=15)
        t.add_column("Banner", style="white", overflow="fold")
        for p in data["open_ports"]:
            t.add_row(str(p["port"]), p["service"], p.get("banner", "")[:80])
        console.print(t)
    else:
        console.print("[yellow]No open ports found[/yellow]")
