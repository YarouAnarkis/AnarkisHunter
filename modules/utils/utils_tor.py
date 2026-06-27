"""
AnarkisHunter — utils_tor.py
===============================
Modul Tor yang didedikasikan.
Reexport dari utils_proxy.py untuk kemudahan penggunaan standalone.
"""

from modules.utils.utils_proxy import TorManager

__all__ = ["TorManager"]

if __name__ == "__main__":
    import argparse
    from rich.console import Console

    console = Console()
    parser = argparse.ArgumentParser(description="Tor Manager")
    parser.add_argument("--enable", action="store_true", help="Enable Tor routing")
    parser.add_argument("--ip", action="store_true", help="Get current IP via Tor")
    parser.add_argument("--renew", action="store_true", help="Renew Tor circuit")
    args = parser.parse_args()

    tor = TorManager()

    if args.enable or args.ip:
        result = tor.enable()
        console.print(f"\n{result.get('message', '')}")
        if result["status"] == "enabled" and args.ip:
            ip = tor.get_current_ip()
            console.print(f"[green]External IP: {ip}[/green]\n")
    elif args.renew:
        tor.enable()
        success = tor.renew_circuit()
        if success:
            console.print("[green]✅ Tor circuit renewed. New IP assigned.[/green]")
        else:
            console.print("[red]❌ Failed to renew circuit[/red]")
