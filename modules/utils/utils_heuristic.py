"""
AnarkisHunter — utils_heuristic.py
=====================================
Smart Anti-False-Positive Engine: Baseline comparison, DOM diff analysis,
and time-based anomaly detection to confirm vulnerabilities without
relying solely on error message matching.

Usage standalone:
    python modules/utils/utils_heuristic.py --url http://target.com/page?id=1
"""

import time
import sys
import hashlib
import re
from typing import Optional, Dict, Any, Tuple, List
from dataclasses import dataclass, field

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[2]))

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False


@dataclass
class BaselineResponse:
    """Representasi response baseline untuk perbandingan."""
    url: str
    status_code: int
    content_length: int
    response_time: float
    body_hash: str
    title: str
    form_count: int
    link_count: int
    error_keywords: List[str]
    dom_signature: str  # Hash dari struktur DOM


@dataclass
class ComparisonResult:
    """Hasil perbandingan antara baseline dan response payload."""
    is_anomalous: bool
    confidence: float           # 0.0 - 100.0
    reasons: List[str]
    status_delta: int           # Perbedaan status code
    length_delta: int           # Perbedaan panjang konten
    time_delta: float           # Perbedaan waktu response
    dom_changed: bool           # Apakah DOM berubah signifikan
    error_found: bool           # Apakah ada keyword error baru
    verdict: str                # "CONFIRMED", "POSSIBLE", "FALSE_POSITIVE", "CLEAN"


# ─── Error Signature Database ─────────────────────────────────────────────────

SQLI_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning: mysql_",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"pg_query\(\): query failed",
    r"supplied argument is not a valid mysql",
    r"ORA-\d{4,5}:",
    r"Microsoft OLE DB Provider for SQL Server",
    r"ODBC SQL Server Driver",
    r"Syntax error in string in query expression",
    r"Data type mismatch in criteria expression",
    r"Column count doesn't match value count",
    r"SQLite error",
    r"sqlite3.OperationalError",
    r"psycopg2.errors",
    r"sqlalchemy.exc",
    r"Column.*doesn.t exist",
]

XSS_REFLECTION_PATTERNS = [
    r"<script>",
    r"javascript:",
    r"onerror=",
    r"onload=",
    r"alert\(",
    r"confirm\(",
    r"prompt\(",
    r"<img[^>]+onerror",
]

GENERIC_ERROR_PATTERNS = [
    r"fatal error",
    r"internal server error",
    r"stack trace",
    r"exception in thread",
    r"traceback \(most recent call",
    r"syntax error at or near",
    r"undefined index",
    r"undefined variable",
    r"access denied for user",
    r"permission denied",
    r"file not found",
    r"cannot find module",
    r"NullPointerException",
    r"ArrayIndexOutOfBoundsException",
]


class HeuristicAnalyzer:
    """
    Analisis heuristik untuk validasi temuan dan mengurangi false positive.
    """

    def __init__(self, time_anomaly_threshold: float = 4.5,
                 length_change_threshold: float = 0.15,
                 confidence_threshold: float = 50.0):
        """
        Args:
            time_anomaly_threshold: Perbedaan waktu (detik) yang dianggap anomali
            length_change_threshold: % perubahan panjang yang dianggap signifikan
            confidence_threshold: Skor minimum untuk melaporkan sebagai temuan
        """
        self.time_threshold = time_anomaly_threshold
        self.length_threshold = length_change_threshold
        self.confidence_threshold = confidence_threshold
        self._baselines: Dict[str, BaselineResponse] = {}

    def get_baseline(self, url: str, client=None) -> Optional[BaselineResponse]:
        """
        Ambil dan simpan response baseline dari URL target.
        
        Args:
            url: URL yang akan di-baseline
            client: HTTPClient instance (opsional, gunakan requests jika None)
            
        Returns:
            BaselineResponse object atau None jika gagal
        """
        if url in self._baselines:
            return self._baselines[url]

        try:
            import requests
            start_time = time.time()
            resp = requests.get(url, timeout=10, verify=False,
                              headers={"User-Agent": "Mozilla/5.0"})
            elapsed = time.time() - start_time

            baseline = self._create_baseline(url, resp, elapsed)
            self._baselines[url] = baseline
            return baseline

        except Exception:
            return None

    def _create_baseline(self, url: str, response, elapsed: float) -> BaselineResponse:
        """Buat objek BaselineResponse dari sebuah response."""
        body = ""
        try:
            body = response.text
        except Exception:
            pass

        return BaselineResponse(
            url=url,
            status_code=response.status_code,
            content_length=len(body),
            response_time=elapsed,
            body_hash=hashlib.md5(body.encode(errors="replace")).hexdigest(),
            title=self._extract_title(body),
            form_count=body.lower().count("<form"),
            link_count=body.lower().count("<a "),
            error_keywords=self._find_error_keywords(body),
            dom_signature=self._compute_dom_signature(body),
        )

    def compare_responses(self, baseline: BaselineResponse,
                          payload_body: str, payload_status: int,
                          payload_time: float,
                          vuln_type: str = "sqli") -> ComparisonResult:
        """
        Bandingkan response dengan payload terhadap baseline.
        
        Args:
            baseline: BaselineResponse dari URL normal
            payload_body: Isi response setelah payload dikirim
            payload_status: Status code setelah payload
            payload_time: Waktu response setelah payload
            vuln_type: Tipe kerentanan ("sqli", "xss", "cmdi", dll)
            
        Returns:
            ComparisonResult dengan verdict dan confidence score
        """
        reasons = []
        confidence = 0.0

        # 1. Status code change
        status_delta = payload_status - baseline.status_code
        if abs(status_delta) > 0:
            if payload_status in (500, 502, 503):
                reasons.append(f"Status berubah ke {payload_status} (Server Error)")
                confidence += 35
            elif payload_status == 403:
                reasons.append(f"Status 403 — Mungkin WAF mendeteksi payload")
                confidence += 5  # Ini justru false positive dari WAF
            elif abs(status_delta) >= 100:
                reasons.append(f"Status code berubah drastis: {baseline.status_code} → {payload_status}")
                confidence += 20

        # 2. Time-based anomaly (paling kuat untuk Blind SQLi/CMDi)
        time_delta = payload_time - baseline.response_time
        if time_delta >= self.time_threshold:
            reasons.append(f"Response time anomali: +{time_delta:.1f}s dari baseline")
            confidence += 55  # Sangat strong indicator
        elif time_delta >= 2.0:
            reasons.append(f"Response time meningkat: +{time_delta:.1f}s")
            confidence += 20

        # 3. Content length change
        payload_length = len(payload_body)
        length_delta = payload_length - baseline.content_length
        if baseline.content_length > 0:
            length_pct = abs(length_delta) / baseline.content_length
            if length_pct > self.length_threshold:
                reasons.append(f"Ukuran konten berubah {length_pct:.0%}: {length_delta:+d} bytes")
                confidence += 15

        # 4. Error keyword detection
        new_errors = self._find_error_keywords(payload_body, vuln_type)
        baseline_errors = set(baseline.error_keywords)
        novel_errors = [e for e in new_errors if e not in baseline_errors]
        error_found = bool(novel_errors)
        if novel_errors:
            reasons.append(f"Error keywords baru ditemukan: {', '.join(novel_errors[:3])}")
            confidence += 40

        # 5. DOM structure change
        dom_sig = self._compute_dom_signature(payload_body)
        dom_changed = dom_sig != baseline.dom_signature
        if dom_changed:
            reasons.append("Struktur DOM berubah secara signifikan")
            confidence += 10

        # 6. XSS reflection check
        if vuln_type == "xss":
            for pattern in XSS_REFLECTION_PATTERNS:
                if re.search(pattern, payload_body, re.IGNORECASE):
                    reasons.append(f"Payload XSS ter-reflect di response: {pattern}")
                    confidence += 50
                    break

        # 7. Tentukan verdict
        confidence = min(100.0, confidence)
        is_anomalous = confidence >= self.confidence_threshold

        if confidence >= 75:
            verdict = "CONFIRMED"
        elif confidence >= 50:
            verdict = "POSSIBLE"
        elif confidence >= 25:
            verdict = "INVESTIGATE"
        else:
            verdict = "FALSE_POSITIVE"

        return ComparisonResult(
            is_anomalous=is_anomalous,
            confidence=confidence,
            reasons=reasons,
            status_delta=status_delta,
            length_delta=length_delta,
            time_delta=time_delta,
            dom_changed=dom_changed,
            error_found=error_found,
            verdict=verdict,
        )

    def _find_error_keywords(self, body: str, vuln_type: str = "generic") -> List[str]:
        """Cari keyword error dalam body response."""
        found = []
        body_lower = body.lower()

        patterns = GENERIC_ERROR_PATTERNS.copy()
        if vuln_type in ("sqli", "generic"):
            patterns.extend(SQLI_ERROR_PATTERNS)
        if vuln_type in ("xss", "generic"):
            patterns.extend(XSS_REFLECTION_PATTERNS)

        for pattern in patterns:
            if re.search(pattern, body_lower):
                # Ambil sedikit konteks
                match = re.search(pattern, body_lower)
                if match:
                    start = max(0, match.start() - 10)
                    end = min(len(body_lower), match.end() + 30)
                    found.append(body_lower[start:end].strip()[:50])

        return list(set(found))

    def _extract_title(self, body: str) -> str:
        """Ekstrak judul halaman dari HTML."""
        match = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
        return match.group(1).strip()[:100] if match else ""

    def _compute_dom_signature(self, body: str) -> str:
        """Hitung signature DOM berbasis struktur tag HTML."""
        if not body:
            return ""
        # Ekstrak hanya tag tanpa atribut untuk signature struktural
        tags = re.findall(r"<[a-z]+", body.lower())
        tag_sequence = ",".join(tags[:100])  # Ambil 100 tag pertama
        return hashlib.md5(tag_sequence.encode()).hexdigest()

    def clear_baseline(self, url: Optional[str] = None):
        """Hapus baseline tersimpan."""
        if url:
            self._baselines.pop(url, None)
        else:
            self._baselines.clear()

    def get_cached_baselines(self) -> List[str]:
        """Return daftar URL yang sudah di-baseline."""
        return list(self._baselines.keys())


# Global instance
heuristic_analyzer = HeuristicAnalyzer()


# ─── Standalone ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box

    console = Console()
    parser = argparse.ArgumentParser(description="AnarkisHunter Heuristic Analyzer")
    parser.add_argument("--url", required=True, help="URL untuk baseline")
    parser.add_argument("--test-payload", help="Payload untuk dites (ditambahkan ke URL)")
    args = parser.parse_args()

    console.print(Panel("[bold cyan]Smart Heuristic Analyzer[/bold cyan]"))

    analyzer = HeuristicAnalyzer()
    console.print(f"[dim]Mengambil baseline dari: {args.url}[/dim]")
    baseline = analyzer.get_baseline(args.url)

    if baseline:
        table = Table(title="Baseline Response", border_style="green", box=box.ROUNDED)
        table.add_column("Parameter", style="cyan")
        table.add_column("Value")
        table.add_row("Status Code", str(baseline.status_code))
        table.add_row("Content Length", f"{baseline.content_length:,} bytes")
        table.add_row("Response Time", f"{baseline.response_time:.3f}s")
        table.add_row("Page Title", baseline.title or "[dim]N/A[/dim]")
        table.add_row("Form Count", str(baseline.form_count))
        table.add_row("Link Count", str(baseline.link_count))
        table.add_row("DOM Signature", f"[dim]{baseline.dom_signature[:16]}...[/dim]")
        console.print(table)
    else:
        console.print("[red]Gagal mengambil baseline.[/red]")
