"""
AnarkisHunter — scan_api.py
==============================
API endpoint finder — probe common API path & GraphQL endpoints.

Usage standalone:
    python modules/scanner/scan_api.py --url http://target.local
"""

import sys
import argparse
from pathlib import Path
from typing import Dict, List
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from modules.utils.utils_request import HTTPClient, normalize_url
from modules.utils.report import ScanResult
from config.settings import API_PATHS


def _probe_api(client: HTTPClient, base: str, path: str) -> Dict:
    """Probe satu API path."""
    url = base.rstrip("/") + "/" + path.lstrip("/")
    try:
        resp = client.get(url)
        if not resp:
            return {"path": path, "url": url, "status": None, "found": False}

        found = resp.status_code in {200, 201, 401, 403, 405}
        is_json = "json" in resp.headers.get("Content-Type", "").lower()
        is_graphql = path.endswith("graphql") or path.endswith("graphiql")

        # Cek karakteristik API response
        sample_body = resp.text[:1000]
        looks_like_api = any(t in sample_body for t in ['"message"', '"error"', '"data"', '"status"', '{"'])

        return {
            "path": path,
            "url": url,
            "status": resp.status_code,
            "size": len(resp.content),
            "content_type": resp.headers.get("Content-Type", "")[:60],
            "is_json": is_json,
            "is_graphql": is_graphql,
            "looks_like_api": looks_like_api,
            "found": found,
            "preview": sample_body[:300],
        }
    except Exception:
        return {"path": path, "url": url, "status": None, "found": False}


def run_api_scan(target: str, paths: List[str] = None, threads: int = 15, timeout: int = 8) -> Dict:
    """Scan API endpoints."""
    base_url = normalize_url(target)
    paths = paths or API_PATHS

    result = {
        "target": base_url,
        "total_tested": len(paths),
        "found": [],
        "graphql_endpoints": [],
        "swagger_endpoints": [],
        "error": None,
    }

    try:
        with HTTPClient(timeout=timeout) as client:
            with ThreadPoolExecutor(max_workers=threads) as ex:
                futures = {ex.submit(_probe_api, client, base_url, p): p for p in paths}
                for fut in as_completed(futures):
                    try:
                        res = fut.result()
                        if res.get("found"):
                            result["found"].append(res)
                            if res.get("is_graphql"):
                                result["graphql_endpoints"].append(res["url"])
                            if "swagger" in res["path"].lower() or "openapi" in res["path"].lower():
                                result["swagger_endpoints"].append(res["url"])
                    except Exception:
                        continue
    except Exception as e:
        result["error"] = str(e)

    result["found"].sort(key=lambda x: (x["status"], x["path"]))
    return result


def analyze_api_findings(data: Dict) -> List[ScanResult]:
    findings = []

    # GraphQL exposed
    for url in data.get("graphql_endpoints", []):
        findings.append(ScanResult(
            title="GraphQL Endpoint Exposed",
            severity="MEDIUM",
            description="GraphQL endpoint accessible. Cek apakah introspection enabled (info disclosure).",
            url=url,
            evidence=f"GraphQL: {url}",
            recommendation="Disable introspection di production; rate limit query depth",
            owasp="A05",
            module="scan_api",
        ))

    # Swagger/OpenAPI exposed
    for url in data.get("swagger_endpoints", []):
        findings.append(ScanResult(
            title="API Documentation Exposed (Swagger/OpenAPI)",
            severity="MEDIUM",
            description="Dokumentasi API publicly accessible — info disclosure attack surface",
            url=url,
            evidence=f"Docs: {url}",
            recommendation="Restrict access ke API docs di production (auth / internal only)",
            owasp="A05",
            module="scan_api",
        ))

    # General API endpoints
    for f in data.get("found", []):
        if f["url"] in data.get("graphql_endpoints", []) or f["url"] in data.get("swagger_endpoints", []):
            continue
        if f["status"] == 200 and (f.get("is_json") or f.get("looks_like_api")):
            findings.append(ScanResult(
                title=f"API Endpoint Found: {f['path']}",
                severity="INFO",
                description=f"API endpoint ditemukan dengan HTTP {f['status']}",
                url=f["url"],
                evidence=f"Content-Type: {f['content_type']}\nPreview: {f['preview'][:200]}",
                module="scan_api",
            ))

    return findings


# ─── Standalone ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from rich.console import Console
    from rich.table import Table

    console = Console()
    parser = argparse.ArgumentParser(description="AnarkisHunter — API Endpoint Scanner")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--threads", type=int, default=15)
    args = parser.parse_args()

    console.print(f"\n[cyan]🔌 API Endpoint Scan: [bold]{args.url}[/bold][/cyan]\n")
    data = run_api_scan(args.url, threads=args.threads)

    console.print(f"[green]Tested:[/green] {data['total_tested']} endpoints")
    console.print(f"[green]Found:[/green] {len(data['found'])}")
    console.print(f"[yellow]GraphQL:[/yellow] {len(data['graphql_endpoints'])}")
    console.print(f"[yellow]Swagger:[/yellow] {len(data['swagger_endpoints'])}\n")

    if data["found"]:
        t = Table(title="API Endpoints", border_style="cyan")
        t.add_column("Status", style="cyan", width=8)
        t.add_column("Path", style="yellow", overflow="fold")
        t.add_column("Type", style="white", width=20)
        t.add_column("JSON", style="green", width=6)
        for f in data["found"]:
            t.add_row(
                str(f["status"]), f["path"],
                f["content_type"][:25],
                "✓" if f.get("is_json") else "",
            )
        console.print(t)
