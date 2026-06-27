"""
AnarkisHunter — scan_git.py
==============================
Git exposure checker — deteksi .git/ directory exposed,
parse .git/HEAD, .git/config, .git/index untuk informasi repo.

Usage standalone:
    python modules/scanner/scan_git.py --url http://target.local
"""

import sys
import re
import argparse
from pathlib import Path
from typing import Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from modules.utils.utils_request import HTTPClient, normalize_url
from modules.utils.report import ScanResult


GIT_PATHS = [
    ".git/HEAD",
    ".git/config",
    ".git/index",
    ".git/description",
    ".git/COMMIT_EDITMSG",
    ".git/FETCH_HEAD",
    ".git/ORIG_HEAD",
    ".git/packed-refs",
    ".git/refs/heads/main",
    ".git/refs/heads/master",
    ".git/refs/heads/dev",
    ".git/refs/heads/develop",
    ".git/logs/HEAD",
    ".git/logs/refs/heads/main",
    ".git/logs/refs/heads/master",
    ".git/info/exclude",
    ".git/info/refs",
    ".git/hooks/post-commit",
    ".git/objects/info/packs",
]


def run_git_scan(target: str, timeout: int = 8) -> Dict:
    """Cek apakah .git/ exposed & parse data."""
    base_url = normalize_url(target)
    result = {
        "target": base_url,
        "exposed": False,
        "found_paths": [],
        "branch": None,
        "remote": None,
        "config_content": None,
        "head_content": None,
        "git_log": [],
        "error": None,
    }

    try:
        with HTTPClient(timeout=timeout) as client:
            for path in GIT_PATHS:
                url = base_url.rstrip("/") + "/" + path
                resp = client.get(url)
                if not resp or resp.status_code != 200:
                    continue
                content = resp.text[:5000]

                # Lewati custom 404
                if "<html" in content.lower()[:200] and "404" in content[:500]:
                    continue

                info = {
                    "path": path,
                    "url": url,
                    "status": resp.status_code,
                    "size": len(resp.content),
                    "preview": content[:500],
                }
                result["found_paths"].append(info)
                result["exposed"] = True

                # Parse specific files
                if path == ".git/HEAD":
                    result["head_content"] = content.strip()
                    m = re.search(r"ref:\s*refs/heads/(\S+)", content)
                    if m:
                        result["branch"] = m.group(1)

                elif path == ".git/config":
                    result["config_content"] = content
                    # Extract remote URL
                    m = re.search(r"url\s*=\s*(\S+)", content)
                    if m:
                        result["remote"] = m.group(1)

                elif path.endswith("/HEAD") or path.endswith("logs/HEAD"):
                    # Parse log entries
                    for line in content.splitlines()[:20]:
                        parts = line.split()
                        if len(parts) >= 2:
                            result["git_log"].append({
                                "commit": parts[1][:12],
                                "raw": line[:200],
                            })

    except Exception as e:
        result["error"] = str(e)

    return result


def analyze_git_findings(data: Dict) -> List[ScanResult]:
    findings = []
    target = data.get("target", "")

    if data.get("exposed"):
        evidence_lines = [f"{p['path']} ({p['status']}, {p['size']} bytes)" for p in data["found_paths"][:10]]

        findings.append(ScanResult(
            title="🚨 .git Directory Exposed",
            severity="CRITICAL",
            description=(
                "Direktori .git/ accessible publicly. Attacker bisa dump seluruh "
                "source code repository, termasuk credential & history."
            ),
            url=target,
            evidence="\n".join(evidence_lines) + (
                f"\nBranch: {data.get('branch')}\nRemote: {data.get('remote')}"
                if data.get("branch") or data.get("remote") else ""
            ),
            recommendation=(
                "Hapus .git/ dari webroot, atau block via .htaccess/nginx: "
                "Location ~ /\\.git { deny all; }"
            ),
            owasp="A05",
            module="scan_git",
        ))

        if data.get("remote"):
            findings.append(ScanResult(
                title="Git Remote URL Disclosed",
                severity="HIGH",
                description=f"Remote repo URL terungkap: {data['remote']}",
                url=target,
                evidence=f"Remote: {data['remote']}",
                recommendation="Block akses ke .git/config",
                owasp="A05",
                module="scan_git",
            ))

    return findings


# ─── Standalone ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from rich.console import Console
    from rich.table import Table

    console = Console()
    parser = argparse.ArgumentParser(description="AnarkisHunter — Git Exposure Checker")
    parser.add_argument("--url", required=True, help="Target URL")
    args = parser.parse_args()

    console.print(f"\n[cyan]📂 .git Exposure Check: [bold]{args.url}[/bold][/cyan]\n")
    data = run_git_scan(args.url)

    if data.get("error"):
        console.print(f"[yellow]Warning: {data['error']}[/yellow]")

    if data["exposed"]:
        console.print("[bold red]🚨 .git EXPOSED![/bold red]\n")
        if data.get("branch"):
            console.print(f"[green]Branch:[/green] {data['branch']}")
        if data.get("remote"):
            console.print(f"[green]Remote:[/green] {data['remote']}")

        t = Table(title="Exposed Git Files", border_style="red")
        t.add_column("Path", style="yellow", overflow="fold")
        t.add_column("Status", style="cyan", width=8)
        t.add_column("Size", style="white", width=10)
        for p in data["found_paths"]:
            t.add_row(p["path"], str(p["status"]), str(p["size"]))
        console.print(t)

        if data.get("config_content"):
            console.print("\n[bold]Git Config:[/bold]")
            console.print(f"[dim]{data['config_content'][:500]}[/dim]")
    else:
        console.print("[green].git directory not exposed[/green]")
