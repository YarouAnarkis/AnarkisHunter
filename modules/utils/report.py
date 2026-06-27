"""
AnarkisHunter — report.py
============================
Reporting engine: generate laporan ke TXT, HTML, JSON, Markdown, PDF.
Auto-save dengan timestamp, Executive Summary, Risk Matrix, OWASP mapping.
"""

import sys
import json
import datetime
from pathlib import Path
from typing import List, Dict, Optional, Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from config.settings import REPORTS_DIR, TOOL_NAME, TOOL_VERSION, OWASP_TOP10


class ScanResult:
    """Representasi satu temuan kerentanan."""

    def __init__(
        self,
        title: str,
        severity: str,
        description: str,
        url: str = "",
        evidence: str = "",
        payload: str = "",
        recommendation: str = "",
        owasp: str = "",
        cvss_score: float = 0.0,
        module: str = "",
        request: str = "",
        response: str = "",
    ):
        self.title = title
        self.severity = severity.upper()
        self.description = description
        self.url = url
        self.evidence = evidence
        self.payload = payload
        self.recommendation = recommendation
        self.owasp = owasp
        self.cvss_score = cvss_score or self._auto_cvss()
        self.module = module
        self.request = request
        self.response = response
        self.timestamp = datetime.datetime.now().isoformat()

    def _auto_cvss(self) -> float:
        return {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 3.0, "INFO": 0.0}.get(self.severity, 0.0)

    def to_dict(self) -> Dict:
        return {
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "url": self.url,
            "evidence": self.evidence,
            "payload": self.payload,
            "recommendation": self.recommendation,
            "owasp": self.owasp,
            "owasp_name": OWASP_TOP10.get(self.owasp, ""),
            "cvss_score": self.cvss_score,
            "module": self.module,
            "request": self.request,
            "response": self.response[:500] if self.response else "",
            "timestamp": self.timestamp,
        }


class ReportEngine:
    """Engine untuk menggenerate laporan penetration testing."""

    def __init__(self, target_url: str, scan_modules: Optional[List[str]] = None):
        self.target_url = target_url
        self.scan_modules = scan_modules or []
        self.findings: List[ScanResult] = []
        self.scan_start = datetime.datetime.now()
        self.scan_end: Optional[datetime.datetime] = None
        self.metadata: Dict[str, Any] = {}

    def add_finding(self, finding: ScanResult):
        self.findings.append(finding)

    def add_findings(self, findings: List[ScanResult]):
        self.findings.extend(findings)

    def finalize(self):
        self.scan_end = datetime.datetime.now()

    def _get_summary(self) -> Dict:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        duration = (self.scan_end or datetime.datetime.now()) - self.scan_start
        return {
            "target": self.target_url,
            "scan_date": self.scan_start.strftime("%Y-%m-%d %H:%M:%S"),
            "duration": str(duration).split(".")[0],
            "total_findings": len(self.findings),
            "severity_counts": counts,
            "risk_score": self._calc_risk_score(counts),
            "modules_used": self.scan_modules,
        }

    def _calc_risk_score(self, counts: Dict) -> str:
        score = (counts.get("CRITICAL", 0) * 10 +
                 counts.get("HIGH", 0) * 7 +
                 counts.get("MEDIUM", 0) * 4 +
                 counts.get("LOW", 0) * 1)
        if score >= 30: return "CRITICAL"
        elif score >= 15: return "HIGH"
        elif score >= 5: return "MEDIUM"
        elif score > 0: return "LOW"
        return "SECURE"

    def _get_filename(self, fmt: str) -> Path:
        from urllib.parse import urlparse
        domain = urlparse(self.target_url).netloc.replace(":", "_") or "target"
        ts = self.scan_start.strftime("%Y%m%d_%H%M%S")
        return REPORTS_DIR / f"report_{domain}_{ts}.{fmt}"

    # ─── Export to JSON ──────────────────────────────────────────────────────

    def export_json(self, filepath: Optional[str] = None) -> str:
        path = Path(filepath) if filepath else self._get_filename("json")
        data = {
            "tool": TOOL_NAME,
            "version": TOOL_VERSION,
            "summary": self._get_summary(),
            "findings": [f.to_dict() for f in self.findings],
        }
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        return str(path)

    # ─── Export to TXT ──────────────────────────────────────────────────────

    def export_txt(self, filepath: Optional[str] = None) -> str:
        path = Path(filepath) if filepath else self._get_filename("txt")
        summary = self._get_summary()
        lines = [
            f"{'='*70}",
            f"  {TOOL_NAME} v{TOOL_VERSION} — Penetration Testing Report",
            f"{'='*70}",
            f"Target  : {summary['target']}",
            f"Date    : {summary['scan_date']}",
            f"Duration: {summary['duration']}",
            f"Total   : {summary['total_findings']} findings",
            f"Risk    : {summary['risk_score']}",
            "",
            "SEVERITY SUMMARY",
            "-" * 40,
        ]
        for sev, count in summary["severity_counts"].items():
            lines.append(f"  {sev:<10} : {count}")
        lines += ["", "=" * 70, "FINDINGS", "=" * 70, ""]

        for i, f in enumerate(self.findings, 1):
            lines += [
                f"[{i}] {f.title}",
                f"    Severity    : {f.severity}",
                f"    URL         : {f.url}",
                f"    CVSS Score  : {f.cvss_score}",
                f"    OWASP       : {f.owasp} - {OWASP_TOP10.get(f.owasp, '')}",
                f"    Description : {f.description}",
                f"    Evidence    : {f.evidence[:200]}",
                f"    Payload     : {f.payload[:200]}",
                f"    Fix         : {f.recommendation}",
                "-" * 70,
                "",
            ]
        path.write_text("\n".join(lines), encoding="utf-8")
        return str(path)

    # ─── Export to Markdown ──────────────────────────────────────────────────

    def export_markdown(self, filepath: Optional[str] = None) -> str:
        path = Path(filepath) if filepath else self._get_filename("md")
        summary = self._get_summary()
        lines = [
            f"# {TOOL_NAME} — Penetration Testing Report",
            "",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| **Target** | `{summary['target']}` |",
            f"| **Date** | {summary['scan_date']} |",
            f"| **Duration** | {summary['duration']} |",
            f"| **Total Findings** | {summary['total_findings']} |",
            f"| **Overall Risk** | **{summary['risk_score']}** |",
            "",
            "## Severity Summary",
            "",
            "| Severity | Count |",
            "|----------|-------|",
        ]
        for sev, count in summary["severity_counts"].items():
            lines.append(f"| {sev} | {count} |")

        lines += ["", "## Findings", ""]
        for i, f in enumerate(self.findings, 1):
            lines += [
                f"### {i}. {f.title}",
                "",
                f"- **Severity**: `{f.severity}`",
                f"- **URL**: `{f.url}`",
                f"- **CVSS Score**: {f.cvss_score}",
                f"- **OWASP**: {f.owasp} — {OWASP_TOP10.get(f.owasp, '')}",
                f"- **Module**: {f.module}",
                "",
                f"**Description**: {f.description}",
                "",
                f"**Evidence**:",
                f"```",
                f"{f.evidence[:300]}",
                f"```",
                "",
                f"**Payload**: `{f.payload[:200]}`",
                "",
                f"**Recommendation**: {f.recommendation}",
                "",
                "---",
                "",
            ]
        path.write_text("\n".join(lines), encoding="utf-8")
        return str(path)

    # ─── Export to HTML ──────────────────────────────────────────────────────

    def export_html(self, filepath: Optional[str] = None) -> str:
        path = Path(filepath) if filepath else self._get_filename("html")
        summary = self._get_summary()

        sev_colors = {
            "CRITICAL": "#ff2d2d", "HIGH": "#ff6b35",
            "MEDIUM": "#ffd93d", "LOW": "#6bcb77", "INFO": "#4d96ff"
        }
        sev_bg = {
            "CRITICAL": "#2d0000", "HIGH": "#2d1200",
            "MEDIUM": "#2d2800", "LOW": "#002d10", "INFO": "#001a2d"
        }

        findings_html = ""
        for i, f in enumerate(self.findings, 1):
            color = sev_colors.get(f.severity, "#fff")
            bg = sev_bg.get(f.severity, "#1a1a2e")
            owasp_name = OWASP_TOP10.get(f.owasp, "")
            findings_html += f"""
            <div class="finding" style="border-left: 4px solid {color}; background: {bg}; margin: 16px 0; padding: 20px; border-radius: 8px;">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <h3 style="color:{color}; margin:0;">[{i}] {f.title}</h3>
                    <span class="badge" style="background:{color}; color:#000; padding:4px 12px; border-radius:20px; font-weight:bold;">{f.severity}</span>
                </div>
                <table class="info-table" style="margin-top:12px; width:100%; border-collapse:collapse;">
                    <tr><td class="label">URL</td><td><code>{f.url}</code></td></tr>
                    <tr><td class="label">CVSS</td><td>{f.cvss_score}</td></tr>
                    <tr><td class="label">OWASP</td><td>{f.owasp} — {owasp_name}</td></tr>
                    <tr><td class="label">Module</td><td>{f.module}</td></tr>
                </table>
                <p style="margin-top:12px;"><strong>Description:</strong> {f.description}</p>
                {'<div class="evidence"><strong>Evidence:</strong><pre>' + f.evidence[:500] + '</pre></div>' if f.evidence else ''}
                {'<div class="payload"><strong>Payload:</strong><code>' + f.payload[:300] + '</code></div>' if f.payload else ''}
                <div class="recommendation"><strong>🔧 Fix:</strong> {f.recommendation}</div>
            </div>"""

        sev_cards = ""
        for sev, count in summary["severity_counts"].items():
            color = sev_colors.get(sev, "#fff")
            sev_cards += f"""
            <div class="sev-card" style="border:2px solid {color}; border-radius:10px; padding:16px; text-align:center; min-width:120px;">
                <div style="font-size:2em; font-weight:bold; color:{color};">{count}</div>
                <div style="color:{color}; font-size:0.85em;">{sev}</div>
            </div>"""

        risk_color = sev_colors.get(summary["risk_score"], "#fff")
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{TOOL_NAME} Report — {summary['target']}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', sans-serif; background: #0d0d1a; color: #e0e0e0; padding: 30px; }}
  .container {{ max-width: 1100px; margin: 0 auto; }}
  h1 {{ background: linear-gradient(90deg, #00ff88, #0088ff); -webkit-background-clip: text;
        -webkit-text-fill-color: transparent; font-size: 2.2em; text-align: center; padding: 20px 0; }}
  .header-box {{ background: #1a1a2e; border: 1px solid #333; border-radius: 12px; padding: 24px; margin: 20px 0; }}
  .meta-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-top: 16px; }}
  .meta-item {{ background: #252540; border-radius: 8px; padding: 12px; }}
  .meta-item .label {{ color: #888; font-size: 0.8em; margin-bottom: 4px; }}
  .meta-item .value {{ color: #fff; font-size: 1.1em; font-weight: bold; }}
  .sev-grid {{ display: flex; gap: 16px; flex-wrap: wrap; margin: 20px 0; }}
  .risk-badge {{ background: {risk_color}22; border: 2px solid {risk_color}; color: {risk_color};
                 padding: 8px 20px; border-radius: 30px; font-size: 1.3em; font-weight: bold; }}
  .info-table td {{ padding: 4px 12px; font-size: 0.9em; }}
  .info-table .label {{ color: #888; width: 100px; }}
  .evidence {{ background: #111122; border-radius: 6px; padding: 12px; margin: 8px 0; }}
  .evidence pre {{ color: #f0f0f0; white-space: pre-wrap; word-break: break-all; font-size: 0.85em; }}
  .payload {{ background: #111a11; border-radius: 6px; padding: 10px; margin: 8px 0; }}
  .payload code {{ color: #6bcb77; font-size: 0.9em; }}
  .recommendation {{ background: #111a22; border-radius: 6px; padding: 12px; margin: 8px 0; color: #4d96ff; }}
  code {{ background: #252540; padding: 2px 6px; border-radius: 4px; color: #00ff88; word-break: break-all; }}
  footer {{ text-align: center; margin-top: 40px; color: #555; font-size: 0.85em; }}
</style>
</head>
<body>
<div class="container">
  <h1>⚔️ {TOOL_NAME} — Security Report</h1>
  <div class="header-box">
    <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:12px;">
      <div>
        <div style="color:#888; font-size:0.85em;">TARGET</div>
        <div style="color:#00ff88; font-size:1.3em; font-weight:bold;">{summary['target']}</div>
      </div>
      <span class="risk-badge">Risk: {summary['risk_score']}</span>
    </div>
    <div class="meta-grid">
      <div class="meta-item"><div class="label">Scan Date</div><div class="value">{summary['scan_date']}</div></div>
      <div class="meta-item"><div class="label">Duration</div><div class="value">{summary['duration']}</div></div>
      <div class="meta-item"><div class="label">Total Findings</div><div class="value">{summary['total_findings']}</div></div>
      <div class="meta-item"><div class="label">Tool Version</div><div class="value">{TOOL_NAME} v{TOOL_VERSION}</div></div>
    </div>
  </div>
  <h2 style="margin: 24px 0 12px; color:#aaa;">Severity Distribution</h2>
  <div class="sev-grid">{sev_cards}</div>
  <h2 style="margin: 24px 0 12px; color:#aaa;">Findings ({len(self.findings)})</h2>
  {findings_html if findings_html else '<div style="color:#555; padding:40px; text-align:center;">No vulnerabilities found ✅</div>'}
  <footer><p>Generated by {TOOL_NAME} v{TOOL_VERSION} | {summary['scan_date']}</p>
  <p style="color:#333; margin-top:4px;">FOR AUTHORIZED TESTING ONLY</p></footer>
</div>
</body>
</html>"""
        path.write_text(html, encoding="utf-8")
        return str(path)

    # ─── Export to PDF ───────────────────────────────────────────────────────

    def export_pdf(self, filepath: Optional[str] = None) -> str:
        """Export ke PDF via ReportLab."""
        path = Path(filepath) if filepath else self._get_filename("pdf")
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import cm
            from reportlab.lib import colors
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.platypus import HRFlowable

            doc = SimpleDocTemplate(str(path), pagesize=A4,
                                    rightMargin=2*cm, leftMargin=2*cm,
                                    topMargin=2*cm, bottomMargin=2*cm)
            styles = getSampleStyleSheet()
            story = []

            # Title
            title_style = ParagraphStyle("title", parent=styles["Title"],
                                          fontSize=22, textColor=colors.HexColor("#00ff88"))
            story.append(Paragraph(f"{TOOL_NAME} — Security Report", title_style))
            story.append(Spacer(1, 0.5*cm))

            # Summary
            summary = self._get_summary()
            summary_data = [
                ["Target", summary["target"]],
                ["Date", summary["scan_date"]],
                ["Duration", summary["duration"]],
                ["Total Findings", str(summary["total_findings"])],
                ["Overall Risk", summary["risk_score"]],
            ]
            t = Table(summary_data, colWidths=[4*cm, 12*cm])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#1a1a2e")),
                ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#888888")),
                ("TEXTCOLOR", (1, 0), (1, -1), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#333333")),
                ("PADDING", (0, 0), (-1, -1), 6),
            ]))
            story.append(t)
            story.append(Spacer(1, 0.5*cm))

            # Findings
            sev_colors_rl = {
                "CRITICAL": "#ff2d2d", "HIGH": "#ff6b35",
                "MEDIUM": "#ffd93d", "LOW": "#6bcb77", "INFO": "#4d96ff"
            }
            for i, f in enumerate(self.findings, 1):
                story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#333")))
                story.append(Spacer(1, 0.3*cm))
                c = sev_colors_rl.get(f.severity, "#ffffff")
                h_style = ParagraphStyle("fh", parent=styles["Heading2"],
                                          textColor=colors.HexColor(c), fontSize=13)
                story.append(Paragraph(f"[{i}] {f.title}", h_style))
                details = [
                    ["Severity", f.severity], ["URL", f.url[:80]],
                    ["CVSS", str(f.cvss_score)],
                    ["OWASP", f"{f.owasp} — {OWASP_TOP10.get(f.owasp, '')}"],
                ]
                dt = Table(details, colWidths=[3.5*cm, 12.5*cm])
                dt.setStyle(TableStyle([
                    ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#888")),
                    ("TEXTCOLOR", (1, 0), (1, -1), colors.white),
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#1a1a2e")),
                    ("PADDING", (0, 0), (-1, -1), 5),
                ]))
                story.append(dt)
                story.append(Spacer(1, 0.2*cm))
                story.append(Paragraph(f"<b>Description:</b> {f.description}", styles["Normal"]))
                if f.recommendation:
                    story.append(Paragraph(f"<b>Fix:</b> {f.recommendation}", styles["Normal"]))
                story.append(Spacer(1, 0.3*cm))

            doc.build(story)
            return str(path)
        except ImportError:
            # Fallback: generate HTML dan note PDF unavailable
            html_path = self.export_html()
            return f"PDF_UNAVAILABLE:{html_path}"
        except Exception as e:
            return f"PDF_ERROR:{e}"

    # ─── Master Export ───────────────────────────────────────────────────────

    def export(self, fmt: str = "html", filepath: Optional[str] = None) -> str:
        """Export laporan ke format yang diminta."""
        self.finalize()
        exporters = {
            "json": self.export_json,
            "txt": self.export_txt,
            "md": self.export_markdown,
            "html": self.export_html,
            "pdf": self.export_pdf,
        }
        fn = exporters.get(fmt.lower(), self.export_html)
        return fn(filepath)

    def export_all(self) -> Dict[str, str]:
        """Export ke semua format sekaligus."""
        self.finalize()
        results = {}
        for fmt in ["json", "txt", "md", "html"]:
            try:
                results[fmt] = self.export(fmt)
            except Exception as e:
                results[fmt] = f"ERROR: {e}"
        try:
            results["pdf"] = self.export_pdf()
        except Exception as e:
            results["pdf"] = f"ERROR: {e}"
        return results
