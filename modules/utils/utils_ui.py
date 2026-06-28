"""
AnarkisHunter — utils_ui.py
=============================
UI components: animated spinner, real-time footer stats,
progress bars, color-coded severity, live findings counter.
"""

import sys
import time
import threading
from typing import Optional, Dict, Any
from contextlib import contextmanager

from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, TaskProgressColumn
from rich.table import Table
from rich.text import Text

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[2]))
from modules.utils.utils_request import get_request_stats


console = Console()

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "orange1",
    "MEDIUM": "yellow",
    "LOW": "green",
    "INFO": "white",
}


def format_severity(severity: str, text: str = "") -> Text:
    """Color-coded severity text."""
    color = SEVERITY_COLORS.get(severity.upper(), "white")
    display = text or severity.upper()
    return Text(display, style=color)


class ScanUI:
    """Real-time scan UI manager."""

    def __init__(self):
        self.findings_count = 0
        self.findings_by_severity: Dict[str, int] = {
            "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0,
        }
        self.current_module = ""
        self._lock = threading.Lock()
        self._live: Optional[Live] = None
        self._progress: Optional[Progress] = None
        self._task_id = None

    def add_finding(self, severity: str = "INFO"):
        with self._lock:
            self.findings_count += 1
            sev = severity.upper()
            self.findings_by_severity[sev] = self.findings_by_severity.get(sev, 0) + 1

    def set_module(self, name: str):
        with self._lock:
            self.current_module = name

    def _build_footer(self) -> Panel:
        stats = get_request_stats().to_dict()
        elapsed = stats.get("elapsed", 0)
        rps = stats.get("requests_per_sec", 0)

        parts = [
            f"[dim]Module:[/dim] [cyan]{self.current_module or 'idle'}[/cyan]",
            f"[dim]Req/s:[/dim] [green]{rps:.1f}[/green]",
            f"[dim]Elapsed:[/dim] [yellow]{elapsed:.0f}s[/yellow]",
            f"[dim]Findings:[/dim] [bold red]{self.findings_count}[/bold red]",
        ]

        sev_parts = []
        for sev, count in self.findings_by_severity.items():
            if count > 0:
                color = SEVERITY_COLORS.get(sev, "white")
                sev_parts.append(f"[{color}]{sev}:{count}[/{color}]")
        if sev_parts:
            parts.append(" | ".join(sev_parts))

        return Panel("  ".join(parts), title="[dim]Stats[/dim]", border_style="dim", height=3)

    @contextmanager
    def spinner(self, message: str = "Working..."):
        """Animated spinner context manager."""
        with console.status(f"[cyan]{message}[/cyan]", spinner="dots"):
            yield

    @contextmanager
    def progress(self, description: str, total: int):
        """Progress bar per module."""
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=40),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=console,
        )
        with progress:
            task = progress.add_task(description, total=total)
            yield lambda advance=1: progress.advance(task, advance)

    def print_module_start(self, module_name: str, phase_color: str = "cyan"):
        self.set_module(module_name)
        console.print(f"  [{phase_color}]▶[/{phase_color}] Running: [bold]{module_name}[/bold]...", end=" ")

    def print_module_done(self, findings: int | list = 0, error: str = ""):
        if isinstance(findings, list):
            count = len(findings)
            titles = []
            for f in findings:
                title = f.title if hasattr(f, "title") else f.get("title", "")
                if title and title not in titles:
                    titles.append(title)
            title_str = f" [dim magenta]({', '.join(titles[:3])})[/dim magenta]" if titles else ""
        else:
            count = findings or 0
            title_str = ""
            
        if error:
            console.print(f"[red]✗ {error[:60]}[/red]")
        elif count > 0:
            console.print(f"[red]✓ {count} finding(s){title_str}[/red]")
        else:
            console.print(f"[green]✓[/green] {count} finding(s)")

    def print_summary_box(self, findings: list):
        """Summary table di akhir scan."""
        console.print()
        console.rule("[bold]📊 FINDINGS SUMMARY[/bold]")

        if not findings:
            console.print("[green]No vulnerabilities found.[/green]")
            return

        table = Table(
            title="All Findings",
            border_style="dim",
            show_lines=True,
            expand=True,
        )
        table.add_column("#", style="dim", width=4)
        table.add_column("Severity", width=10)
        table.add_column("Title", style="white", overflow="fold")
        table.add_column("URL", style="cyan", overflow="fold", max_width=40)
        table.add_column("CVSS", width=6)
        table.add_column("Conf.", width=6)
        table.add_column("OWASP", width=6)

        for i, f in enumerate(findings, 1):
            if hasattr(f, "get"):
                sev = f.get("severity", "INFO")
                title = f.get("title", "")
                url = f.get("url", "")
                cvss = f.get("cvss_score", 0)
                conf = f.get("confidence", "-")
                owasp = f.get("owasp", "")
            else:
                sev = getattr(f, "severity", "INFO")
                title = getattr(f, "title", "")
                url = getattr(f, "url", "")
                cvss = getattr(f, "cvss_score", 0)
                conf = getattr(f, "confidence", "-")
                owasp = getattr(f, "owasp", "")

            sev_text = format_severity(sev)
            table.add_row(
                str(i),
                sev_text,
                title[:80],
                url[:60],
                f"{cvss:.1f}" if cvss else "-",
                f"{conf}%" if isinstance(conf, (int, float)) else str(conf),
                owasp,
            )

        console.print(table)


# Global UI instance
scan_ui = ScanUI()
