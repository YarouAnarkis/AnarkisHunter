"""
AnarkisHunter — utils_diff.py
================================
Response diff tool: bandingkan dua response untuk deteksi blind vulnerability.
Berguna untuk blind SQLi, blind XSS, timing attack analysis.

Usage standalone:
    python modules/utils/utils_diff.py --url1 http://target.local?id=1
                                        --url2 http://target.local?id=1'
"""

import sys
import time
import hashlib
import difflib
from typing import Optional, Dict, Tuple, List
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


class ResponseDiff:
    """
    Tool untuk membandingkan dua HTTP response dan mendeteksi perbedaan
    yang mengindikasikan kerentanan blind.
    """

    def __init__(self):
        self.baseline: Optional[Dict] = None

    def capture_baseline(self, url: str, client) -> Dict:
        """
        Tangkap response baseline (request normal tanpa payload).
        
        Args:
            url: URL target normal
            client: HTTPClient instance
            
        Returns:
            Dict berisi info response
        """
        start_time = time.time()
        resp = client.get(url)
        elapsed = time.time() - start_time

        if not resp:
            return {}

        self.baseline = {
            "url": url,
            "status_code": resp.status_code,
            "content_length": len(resp.content),
            "body": resp.text,
            "headers": dict(resp.headers),
            "response_time": elapsed,
            "body_hash": hashlib.md5(resp.content).hexdigest(),
        }
        return self.baseline

    def compare(self, url: str, client, label: str = "test") -> Dict:
        """
        Bandingkan response URL baru dengan baseline.
        
        Args:
            url: URL yang akan ditest
            client: HTTPClient instance  
            label: Label untuk identifikasi (misal payload yang digunakan)
            
        Returns:
            Dict berisi analisis perbedaan
        """
        if not self.baseline:
            return {"error": "Baseline not captured. Call capture_baseline() first."}

        start_time = time.time()
        resp = client.get(url)
        elapsed = time.time() - start_time

        if not resp:
            return {
                "label": label,
                "url": url,
                "error": "Connection failed",
                "anomaly": True,
            }

        current = {
            "url": url,
            "status_code": resp.status_code,
            "content_length": len(resp.content),
            "body": resp.text,
            "headers": dict(resp.headers),
            "response_time": elapsed,
            "body_hash": hashlib.md5(resp.content).hexdigest(),
        }

        return self._analyze_diff(self.baseline, current, label)

    def compare_two(self, resp1: Dict, resp2: Dict, label: str = "") -> Dict:
        """Bandingkan dua response dict secara langsung."""
        return self._analyze_diff(resp1, resp2, label)

    def _analyze_diff(self, base: Dict, current: Dict, label: str) -> Dict:
        """Analisis perbedaan antara dua response."""
        result = {
            "label": label,
            "url": current.get("url", ""),
            "anomalies": [],
            "is_different": False,
            "confidence": 0,
        }

        # Status code change
        if base.get("status_code") != current.get("status_code"):
            result["anomalies"].append({
                "type": "status_code_change",
                "baseline": base.get("status_code"),
                "current": current.get("status_code"),
                "severity": "HIGH",
            })
            result["confidence"] += 30

        # Content length change
        base_len = base.get("content_length", 0)
        curr_len = current.get("content_length", 0)
        len_diff = abs(base_len - curr_len)
        len_ratio = len_diff / max(base_len, 1)

        if len_ratio > 0.05:  # >5% perubahan ukuran
            result["anomalies"].append({
                "type": "content_length_change",
                "baseline": base_len,
                "current": curr_len,
                "difference": len_diff,
                "percentage": f"{len_ratio*100:.1f}%",
                "severity": "MEDIUM",
            })
            result["confidence"] += 20

        # Hash change (konten berbeda)
        if base.get("body_hash") != current.get("body_hash"):
            result["anomalies"].append({
                "type": "content_changed",
                "severity": "MEDIUM",
            })
            result["confidence"] += 15

        # Response time anomaly (timing attack)
        base_time = base.get("response_time", 0)
        curr_time = current.get("response_time", 0)
        time_diff = curr_time - base_time

        if time_diff > 4.0:  # >4 detik lebih lambat
            result["anomalies"].append({
                "type": "timing_anomaly",
                "baseline_time": f"{base_time:.2f}s",
                "current_time": f"{curr_time:.2f}s",
                "difference": f"{time_diff:.2f}s",
                "severity": "HIGH",
                "note": "Possible time-based injection (sleep/waitfor detected)",
            })
            result["confidence"] += 40

        # Error keywords in response
        error_keywords = [
            "sql syntax", "mysql error", "ora-", "sqlite", "syntax error",
            "warning:", "fatal error", "exception", "stack trace",
            "undefined variable", "notice:", "postgresql"
        ]
        body_lower = current.get("body", "").lower()
        for kw in error_keywords:
            if kw in body_lower and kw not in base.get("body", "").lower():
                result["anomalies"].append({
                    "type": "error_keyword_detected",
                    "keyword": kw,
                    "severity": "HIGH",
                })
                result["confidence"] += 25
                break

        # Header changes (important headers)
        important_headers = ["set-cookie", "location", "www-authenticate", "x-powered-by"]
        base_headers = {k.lower(): v for k, v in base.get("headers", {}).items()}
        curr_headers = {k.lower(): v for k, v in current.get("headers", {}).items()}

        for h in important_headers:
            if base_headers.get(h) != curr_headers.get(h):
                result["anomalies"].append({
                    "type": "header_changed",
                    "header": h,
                    "baseline": base_headers.get(h),
                    "current": curr_headers.get(h),
                    "severity": "LOW",
                })
                result["confidence"] += 10

        result["is_different"] = len(result["anomalies"]) > 0
        result["confidence"] = min(result["confidence"], 100)

        return result

    def get_text_diff(self, text1: str, text2: str, max_lines: int = 30) -> List[str]:
        """
        Dapatkan unified diff antara dua teks.
        
        Returns:
            List of diff lines
        """
        lines1 = text1.splitlines(keepends=True)
        lines2 = text2.splitlines(keepends=True)
        diff = list(difflib.unified_diff(
            lines1[:200], lines2[:200],
            fromfile="baseline",
            tofile="payload_response",
            n=3,
        ))
        return diff[:max_lines]

    def similarity_ratio(self, text1: str, text2: str) -> float:
        """Hitung similarity ratio antara dua teks (0.0 - 1.0)."""
        return difflib.SequenceMatcher(None, text1[:2000], text2[:2000]).ratio()


def detect_blind_via_time(
    url_normal: str,
    url_payload: str,
    client,
    threshold: float = 4.0,
    repeat: int = 3,
) -> Dict:
    """
    Deteksi blind injection via timing attack.
    
    Args:
        url_normal: URL tanpa payload
        url_payload: URL dengan time-based payload
        client: HTTPClient instance
        threshold: Threshold waktu dalam detik
        repeat: Jumlah pengulangan untuk akurasi
        
    Returns:
        Dict hasil analisis timing
    """
    normal_times = []
    payload_times = []

    for _ in range(repeat):
        start = time.time()
        client.get(url_normal)
        normal_times.append(time.time() - start)

        start = time.time()
        client.get(url_payload)
        payload_times.append(time.time() - start)

    avg_normal = sum(normal_times) / len(normal_times)
    avg_payload = sum(payload_times) / len(payload_times)
    diff = avg_payload - avg_normal

    return {
        "avg_normal_time": round(avg_normal, 3),
        "avg_payload_time": round(avg_payload, 3),
        "time_difference": round(diff, 3),
        "threshold": threshold,
        "vulnerable": diff >= threshold,
        "confidence": min(int((diff / threshold) * 100), 100) if diff > 0 else 0,
    }


# ─── Standalone ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel

    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from modules.utils.utils_request import HTTPClient, normalize_url

    console = Console()
    parser = argparse.ArgumentParser(description="Response Diff Tool")
    parser.add_argument("--url1", required=True, help="Baseline URL")
    parser.add_argument("--url2", required=True, help="Test URL")
    parser.add_argument("--show-diff", action="store_true", help="Show text diff")
    args = parser.parse_args()

    with HTTPClient() as client:
        differ = ResponseDiff()
        console.print(f"\n[cyan]Capturing baseline: {args.url1}[/cyan]")
        baseline = differ.capture_baseline(normalize_url(args.url1), client)

        console.print(f"[cyan]Comparing with: {args.url2}[/cyan]\n")
        result = differ.compare(normalize_url(args.url2), client, label="test")

        if result.get("anomalies"):
            table = Table(title="Response Differences", border_style="red")
            table.add_column("Type", style="cyan")
            table.add_column("Severity", style="red")
            table.add_column("Details", style="white")
            for a in result["anomalies"]:
                atype = a.get("type", "")
                details = str({k: v for k, v in a.items() if k not in ["type", "severity"]})
                table.add_row(atype, a.get("severity", ""), details[:100])
            console.print(table)
            console.print(f"\n[yellow]Confidence: {result['confidence']}%[/yellow]\n")
        else:
            console.print("[green]✅ No significant differences detected[/green]")

        if args.show_diff and baseline:
            diff_lines = differ.get_text_diff(
                baseline.get("body", ""),
                result.get("body", ""),  # Note: result doesn't contain body by default
            )
            if diff_lines:
                console.print(Panel("\n".join(diff_lines[:20]), title="Text Diff", border_style="yellow"))
