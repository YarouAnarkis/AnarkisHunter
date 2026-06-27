"""
AnarkisHunter — database/db.py
================================
SQLite storage untuk menyimpan hasil scan, findings, dan riwayat target.

Usage standalone:
    python database/db.py --list
    python database/db.py --search target.local
"""

import sys
import sqlite3
import json
import datetime
from pathlib import Path
from typing import Optional, Dict, List, Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from config.settings import DATABASE_DIR


DB_PATH = DATABASE_DIR / "anarkishunter.db"


CREATE_TABLES = """
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target_url  TEXT NOT NULL,
    scan_date   TEXT NOT NULL,
    duration    TEXT,
    modules     TEXT,
    risk_score  TEXT,
    total_findings INTEGER DEFAULT 0,
    created_at  TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER NOT NULL,
    title       TEXT NOT NULL,
    severity    TEXT NOT NULL,
    description TEXT,
    url         TEXT,
    evidence    TEXT,
    payload     TEXT,
    recommendation TEXT,
    owasp       TEXT,
    cvss_score  REAL,
    module      TEXT,
    timestamp   TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS targets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    url         TEXT UNIQUE NOT NULL,
    first_seen  TEXT DEFAULT (datetime('now')),
    last_seen   TEXT DEFAULT (datetime('now')),
    scan_count  INTEGER DEFAULT 0,
    risk_score  TEXT,
    notes       TEXT
);

CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target_url);
"""


class AnarkisDB:
    """SQLite database manager untuk AnarkisHunter."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = Path(db_path) if db_path else DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        """Buat koneksi database dengan row_factory."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_db(self):
        """Inisialisasi schema database."""
        with self._connect() as conn:
            conn.executescript(CREATE_TABLES)

    # ─── Scan Operations ─────────────────────────────────────────────────────

    def save_scan(self, target_url: str, modules: List[str],
                  risk_score: str, total_findings: int,
                  duration: str = "") -> int:
        """
        Simpan record scan baru.
        
        Returns:
            scan_id dari record yang baru disimpan
        """
        scan_date = datetime.datetime.now().isoformat()
        with self._connect() as conn:
            cursor = conn.execute(
                """INSERT INTO scans (target_url, scan_date, duration, modules, risk_score, total_findings)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (target_url, scan_date, duration,
                 json.dumps(modules), risk_score, total_findings)
            )
            scan_id = cursor.lastrowid

            # Update atau insert target
            conn.execute("""
                INSERT INTO targets (url, last_seen, scan_count, risk_score)
                VALUES (?, datetime('now'), 1, ?)
                ON CONFLICT(url) DO UPDATE SET
                    last_seen = datetime('now'),
                    scan_count = scan_count + 1,
                    risk_score = excluded.risk_score
            """, (target_url, risk_score))

            return scan_id

    def save_findings(self, scan_id: int, findings: List[Any]) -> int:
        """
        Simpan semua findings untuk satu scan.
        
        Args:
            scan_id: ID scan yang relevan
            findings: List ScanResult objects
            
        Returns:
            Jumlah findings yang disimpan
        """
        rows = []
        for f in findings:
            rows.append((
                scan_id,
                f.title,
                f.severity,
                f.description,
                f.url,
                f.evidence[:1000] if f.evidence else "",
                f.payload[:500] if f.payload else "",
                f.recommendation,
                f.owasp,
                f.cvss_score,
                f.module,
                f.timestamp,
            ))

        with self._connect() as conn:
            conn.executemany("""
                INSERT INTO findings
                  (scan_id, title, severity, description, url, evidence,
                   payload, recommendation, owasp, cvss_score, module, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, rows)

        return len(rows)

    def save_report(self, report_engine) -> int:
        """
        Shortcut: simpan ReportEngine lengkap ke database.
        
        Returns:
            scan_id
        """
        summary = report_engine._get_summary()
        scan_id = self.save_scan(
            target_url=summary["target"],
            modules=summary["modules_used"],
            risk_score=summary["risk_score"],
            total_findings=summary["total_findings"],
            duration=summary["duration"],
        )
        if report_engine.findings:
            self.save_findings(scan_id, report_engine.findings)
        return scan_id

    # ─── Query Operations ─────────────────────────────────────────────────────

    def get_scans(self, limit: int = 20) -> List[Dict]:
        """Ambil daftar scan terbaru."""
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT id, target_url, scan_date, duration, risk_score, total_findings
                   FROM scans ORDER BY id DESC LIMIT ?""",
                (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    def get_scan_findings(self, scan_id: int) -> List[Dict]:
        """Ambil semua findings untuk scan_id tertentu."""
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT * FROM findings WHERE scan_id = ?
                   ORDER BY CASE severity
                     WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
                     WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END""",
                (scan_id,)
            ).fetchall()
        return [dict(r) for r in rows]

    def get_findings_by_severity(self, severity: str) -> List[Dict]:
        """Ambil findings berdasarkan severity level."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM findings WHERE severity = ? ORDER BY id DESC",
                (severity.upper(),)
            ).fetchall()
        return [dict(r) for r in rows]

    def search_findings(self, keyword: str) -> List[Dict]:
        """Cari findings berdasarkan keyword (title, description, url)."""
        kw = f"%{keyword}%"
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT f.*, s.target_url FROM findings f
                   JOIN scans s ON f.scan_id = s.id
                   WHERE f.title LIKE ? OR f.description LIKE ?
                      OR f.url LIKE ? OR f.module LIKE ?
                   ORDER BY f.id DESC LIMIT 50""",
                (kw, kw, kw, kw)
            ).fetchall()
        return [dict(r) for r in rows]

    def get_targets(self) -> List[Dict]:
        """Ambil semua target yang pernah discan."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM targets ORDER BY last_seen DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    def get_stats(self) -> Dict:
        """Statistik keseluruhan database."""
        with self._connect() as conn:
            total_scans = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
            total_findings = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
            total_targets = conn.execute("SELECT COUNT(*) FROM targets").fetchone()[0]
            by_severity = {}
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                count = conn.execute(
                    "SELECT COUNT(*) FROM findings WHERE severity = ?", (sev,)
                ).fetchone()[0]
                by_severity[sev] = count

            recent_targets = conn.execute(
                "SELECT url, risk_score, scan_count FROM targets ORDER BY last_seen DESC LIMIT 5"
            ).fetchall()

        return {
            "total_scans": total_scans,
            "total_findings": total_findings,
            "total_targets": total_targets,
            "findings_by_severity": by_severity,
            "recent_targets": [dict(r) for r in recent_targets],
        }

    def delete_scan(self, scan_id: int) -> bool:
        """Hapus scan dan findings terkait."""
        with self._connect() as conn:
            conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
            conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        return True

    def export_to_json(self, output_path: Optional[str] = None) -> str:
        """Export seluruh database ke JSON."""
        path = Path(output_path) if output_path else DATABASE_DIR / "export.json"
        data = {
            "exported_at": datetime.datetime.now().isoformat(),
            "stats": self.get_stats(),
            "targets": self.get_targets(),
            "scans": [],
        }
        for scan in self.get_scans(limit=1000):
            scan["findings"] = self.get_scan_findings(scan["id"])
            data["scans"].append(scan)

        path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        return str(path)


# ─── Singleton instance ───────────────────────────────────────────────────────

_db_instance: Optional[AnarkisDB] = None


def get_db() -> AnarkisDB:
    """Get global database instance (singleton)."""
    global _db_instance
    if _db_instance is None:
        _db_instance = AnarkisDB()
    return _db_instance


# ─── Standalone ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    from rich.console import Console
    from rich.table import Table

    console = Console()
    parser = argparse.ArgumentParser(description="AnarkisHunter Database Manager")
    parser.add_argument("--list", action="store_true", help="List all scans")
    parser.add_argument("--stats", action="store_true", help="Show statistics")
    parser.add_argument("--findings", type=int, metavar="SCAN_ID", help="Show findings for scan")
    parser.add_argument("--search", metavar="KEYWORD", help="Search findings")
    parser.add_argument("--export", action="store_true", help="Export to JSON")
    parser.add_argument("--delete", type=int, metavar="SCAN_ID", help="Delete a scan")
    args = parser.parse_args()

    db = AnarkisDB()

    if args.stats:
        stats = db.get_stats()
        console.print("\n[bold cyan]📊 Database Statistics[/bold cyan]")
        console.print(f"  Total Scans    : {stats['total_scans']}")
        console.print(f"  Total Findings : {stats['total_findings']}")
        console.print(f"  Total Targets  : {stats['total_targets']}")
        console.print("\n  By Severity:")
        for sev, count in stats["findings_by_severity"].items():
            color = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow",
                     "LOW": "cyan", "INFO": "blue"}.get(sev, "white")
            if count > 0:
                console.print(f"    [{color}]{sev:<10}[/{color}]: {count}")

    elif args.list:
        scans = db.get_scans()
        table = Table(title="Recent Scans", border_style="cyan")
        table.add_column("ID", style="dim", width=5)
        table.add_column("Target", style="cyan")
        table.add_column("Date", style="white")
        table.add_column("Risk", style="yellow")
        table.add_column("Findings", style="green")
        for s in scans:
            table.add_row(str(s["id"]), s["target_url"][:50],
                         s["scan_date"][:16], s["risk_score"], str(s["total_findings"]))
        console.print(table)

    elif args.findings:
        findings = db.get_scan_findings(args.findings)
        table = Table(title=f"Findings for Scan #{args.findings}", border_style="red")
        table.add_column("Severity", width=10)
        table.add_column("Title", style="yellow")
        table.add_column("URL", style="cyan")
        for f in findings:
            color = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow",
                     "LOW": "cyan", "INFO": "blue"}.get(f["severity"], "white")
            table.add_row(f"[{color}]{f['severity']}[/{color}]",
                         f["title"][:50], f["url"][:60] if f["url"] else "N/A")
        console.print(table)

    elif args.search:
        results = db.search_findings(args.search)
        console.print(f"\n[cyan]Search results for '{args.search}': {len(results)} findings[/cyan]")
        for r in results[:20]:
            color = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow"}.get(r["severity"], "white")
            console.print(f"  [{color}][{r['severity']}][/{color}] {r['title']} — {r.get('target_url', r['url'])[:60]}")

    elif args.export:
        path = db.export_to_json()
        console.print(f"[green]✅ Exported to: {path}[/green]")

    elif args.delete:
        db.delete_scan(args.delete)
        console.print(f"[yellow]Deleted scan #{args.delete}[/yellow]")

    else:
        stats = db.get_stats()
        console.print(f"\n[cyan]AnarkisHunter DB — {stats['total_scans']} scans, "
                      f"{stats['total_findings']} findings, {stats['total_targets']} targets[/cyan]")
        console.print("[dim]Use --help for options[/dim]")
