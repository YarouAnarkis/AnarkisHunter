"""
AnarkisHunter — recon_comments.py
====================================
HTML/JS comment extractor.
Mencari komentar yang sering kali berisi info sensitif:
TODO, FIXME, password hardcoded, credential, debug info.

Usage standalone:
    python modules/recon/recon_comments.py --url http://target.local
"""

import sys
import re
import argparse
from pathlib import Path
from typing import Dict, List
from urllib.parse import urljoin

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from modules.utils.utils_request import HTTPClient, normalize_url
from modules.utils.report import ScanResult


# Pattern komentar HTML & JS
HTML_COMMENT_PATTERN = re.compile(r"<!--(.*?)-->", re.DOTALL)
JS_SINGLE_LINE = re.compile(r"//(.+?)(?:\n|$)")
JS_MULTI_LINE = re.compile(r"/\*([\s\S]*?)\*/")

# Keyword yang menandakan komentar menarik
INTERESTING_KEYWORDS = [
    "todo", "fixme", "xxx", "hack", "bug", "broken", "remove",
    "password", "passwd", "pwd", "secret", "key", "token",
    "api_key", "apikey", "credential", "auth",
    "debug", "test", "temporary", "temp",
    "username", "admin", "root", "user",
    "ip", "url", "endpoint",
    "vulnerable", "exploit", "deprecated",
]


def run_comments_recon(target: str, scan_js: bool = True, timeout: int = 10) -> Dict:
    """
    Ekstrak komentar dari halaman target & JS files.

    Returns:
        Dict berisi komentar yang ditemukan + interesting ones
    """
    base_url = normalize_url(target)
    result = {
        "target": base_url,
        "html_comments": [],
        "js_comments": [],
        "interesting": [],
        "total_comments": 0,
        "error": None,
    }

    try:
        with HTTPClient(timeout=timeout) as client:
            resp = client.get(base_url)
            if not resp:
                result["error"] = "Connection failed"
                return result

            html = resp.text

            # HTML comments
            for m in HTML_COMMENT_PATTERN.finditer(html):
                comment = m.group(1).strip()
                if not comment or len(comment) < 4:
                    continue
                # Skip conditional comments dan empty
                if comment.startswith("[if") or comment.startswith("![endif"):
                    continue
                if len(comment) > 2000:
                    comment = comment[:2000] + "..."
                result["html_comments"].append({
                    "type": "html",
                    "source": base_url,
                    "content": comment,
                })

            # Scan JS files juga
            if scan_js:
                js_urls = set()
                for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I):
                    js_urls.add(urljoin(base_url, m.group(1)))

                # Inline scripts dari main page
                inline = re.findall(r"<script[^>]*>([\s\S]*?)</script>", html, re.I)
                for idx, script in enumerate(inline):
                    _extract_js_comments(script, f"{base_url}#inline-{idx}", result)

                # External JS
                for js_url in list(js_urls)[:20]:
                    try:
                        js_resp = client.get(js_url)
                        if not js_resp or js_resp.status_code != 200:
                            continue
                        _extract_js_comments(js_resp.text, js_url, result)
                    except Exception:
                        continue

            # Cari komentar menarik
            all_comments = result["html_comments"] + result["js_comments"]
            for c in all_comments:
                content_lower = c["content"].lower()
                matched_kw = []
                for kw in INTERESTING_KEYWORDS:
                    if kw in content_lower:
                        matched_kw.append(kw)
                if matched_kw:
                    result["interesting"].append({
                        **c,
                        "keywords": matched_kw,
                    })

            result["total_comments"] = len(all_comments)

    except Exception as e:
        result["error"] = str(e)

    return result


def _extract_js_comments(js_content: str, source: str, result: Dict) -> None:
    """Ekstrak komentar dari JavaScript."""
    # Multi-line /* ... */
    for m in JS_MULTI_LINE.finditer(js_content):
        c = m.group(1).strip()
        if not c or len(c) < 4:
            continue
        if len(c) > 2000:
            c = c[:2000] + "..."
        result["js_comments"].append({
            "type": "js-multi",
            "source": source,
            "content": c,
        })

    # Single line // ...
    for m in JS_SINGLE_LINE.finditer(js_content):
        c = m.group(1).strip()
        if not c or len(c) < 4:
            continue
        # Skip URL fragments (https://)
        if c.startswith("http") and " " not in c[:30]:
            continue
        result["js_comments"].append({
            "type": "js-single",
            "source": source,
            "content": c,
        })


def analyze_comments_findings(data: Dict) -> List[ScanResult]:
    """Analisis komentar untuk info sensitif."""
    findings = []
    target = data.get("target", "")

    # Interesting comments dengan keyword sensitif
    secret_kws = {"password", "passwd", "pwd", "secret", "key", "token", "api_key", "apikey", "credential"}

    for c in data.get("interesting", [])[:30]:
        matched = set(c.get("keywords", []))
        is_secret = bool(matched & secret_kws)
        severity = "HIGH" if is_secret else "LOW"
        title = "Sensitive Keyword in Comment" if is_secret else "Interesting Comment Found"
        findings.append(ScanResult(
            title=title,
            severity=severity,
            description=f"Komentar mengandung keyword: {', '.join(matched)}",
            url=c.get("source", target),
            evidence=c.get("content", "")[:500],
            recommendation="Hapus komentar yang berisi info sensitif sebelum production",
            owasp="A05",
            module="recon_comments",
        ))

    # Summary INFO
    if data.get("total_comments"):
        findings.append(ScanResult(
            title=f"Comments Found ({data['total_comments']})",
            severity="INFO",
            description=f"Total komentar: {data['total_comments']} ({len(data['html_comments'])} HTML, {len(data['js_comments'])} JS)",
            url=target,
            module="recon_comments",
        ))

    return findings


# ─── Standalone ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from rich.console import Console
    from rich.table import Table

    console = Console()
    parser = argparse.ArgumentParser(description="AnarkisHunter — Comment Extractor")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--no-js", action="store_true", help="Skip JS comment scan")
    args = parser.parse_args()

    console.print(f"\n[cyan]💬 Comment Extractor: [bold]{args.url}[/bold][/cyan]\n")
    data = run_comments_recon(args.url, scan_js=not args.no_js)

    if data.get("error"):
        console.print(f"[red]Error: {data['error']}[/red]")
        sys.exit(1)

    console.print(f"[green]HTML comments:[/green] {len(data['html_comments'])}")
    console.print(f"[green]JS comments:[/green] {len(data['js_comments'])}")
    console.print(f"[yellow]Interesting:[/yellow] {len(data['interesting'])}\n")

    if data["interesting"]:
        t = Table(title="⚠ Interesting Comments", border_style="yellow")
        t.add_column("Type", style="cyan", width=10)
        t.add_column("Keywords", style="yellow", width=20)
        t.add_column("Content", style="white", overflow="fold")
        for c in data["interesting"][:25]:
            t.add_row(
                c["type"],
                ", ".join(c["keywords"][:3]),
                c["content"][:120],
            )
        console.print(t)

    if data["html_comments"]:
        console.print("\n[bold]Sample HTML comments:[/bold]")
        for c in data["html_comments"][:5]:
            console.print(f"  [cyan]→[/cyan] {c['content'][:120]}")
