"""
AnarkisHunter — utils_template.py
=====================================
YAML Template Engine: Membaca dan mengeksekusi template YAML untuk
deteksi kerentanan, mirip cara kerja Nuclei dari ProjectDiscovery.

Format template YAML didukung:
    id, name, severity, owasp, tags, request, matchers, extractors

Usage standalone:
    python modules/utils/utils_template.py --scan http://target.com --templates templates/
    python modules/utils/utils_template.py --validate templates/wordpress/
    python modules/utils/utils_template.py --list templates/
"""

import sys
import re
import time
import json
from pathlib import Path
from typing import Optional, Dict, List, Any, Tuple
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[2]))

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

BASE_DIR = Path(__file__).resolve().parents[2]
TEMPLATES_DIR = BASE_DIR / "templates"


@dataclass
class TemplateResult:
    """Hasil eksekusi sebuah template."""
    template_id: str
    template_name: str
    severity: str
    owasp: str
    matched: bool
    url: str
    extracted_data: List[str] = field(default_factory=list)
    response_status: int = 0
    response_time: float = 0.0
    matched_pattern: str = ""
    evidence: str = ""


class TemplateEngine:
    """
    Engine eksekusi template YAML untuk vulnerability scanning.
    
    Cara kerja:
    1. Load file .yaml dari folder templates/
    2. Baca instruksi: method, path, headers, body, matchers
    3. Kirim HTTP request sesuai instruksi ke target
    4. Cocokkan response dengan matchers (status, word, regex, size)
    5. Ekstrak data jika ada extractors
    6. Laporkan sebagai finding jika matcher terpenuhi
    """

    def __init__(self, timeout: int = 10, threads: int = 10):
        self.timeout = timeout
        self.threads = threads
        self._session = self._create_session()

    def _create_session(self):
        if not REQUESTS_AVAILABLE:
            return None
        session = requests.Session()
        session.verify = False
        session.headers.update({
            "User-Agent": "AnarkisHunter/3.0 TemplateEngine",
        })
        return session

    def load_template(self, path: str) -> Optional[Dict]:
        """
        Load dan validasi template YAML.
        
        Args:
            path: Path ke file .yaml
            
        Returns:
            Dict template atau None jika invalid
        """
        if not YAML_AVAILABLE:
            return None

        try:
            content = Path(path).read_text(encoding="utf-8")
            template = yaml.safe_load(content)

            # Validasi field wajib
            required = ["id", "name", "severity", "request"]
            for field_name in required:
                if field_name not in template:
                    return None

            return template
        except Exception:
            return None

    def load_templates_from_dir(self, directory: str) -> List[Dict]:
        """Load semua template dari sebuah direktori (rekursif)."""
        templates = []
        base = Path(directory)
        if not base.exists():
            return []

        for yaml_file in base.rglob("*.yaml"):
            tmpl = self.load_template(str(yaml_file))
            if tmpl:
                tmpl["_file"] = str(yaml_file)
                templates.append(tmpl)

        for yaml_file in base.rglob("*.yml"):
            tmpl = self.load_template(str(yaml_file))
            if tmpl:
                tmpl["_file"] = str(yaml_file)
                templates.append(tmpl)

        return templates

    def execute(self, template: Dict, target_url: str,
                variables: Optional[Dict] = None) -> Optional[TemplateResult]:
        """
        Eksekusi satu template terhadap target URL.
        
        Args:
            template: Dict template yang sudah di-load
            target_url: URL target
            variables: Variable substitution ({{username}}, {{password}}, dll)
            
        Returns:
            TemplateResult atau None jika eksekusi gagal
        """
        if not self._session:
            return None

        req_config = template.get("request", {})
        method = req_config.get("method", "GET").upper()
        path = req_config.get("path", "/")
        headers = req_config.get("headers", {})
        body = req_config.get("body", None)
        params = req_config.get("params", {})

        # Substitusi variabel
        if variables:
            path = self._substitute_variables(path, variables)
            if body:
                body = self._substitute_variables(body, variables)

        # Bangun URL lengkap
        target = target_url.rstrip("/")
        if not path.startswith("/"):
            path = "/" + path
        full_url = target + path

        # Kirim request
        try:
            start_time = time.time()
            kwargs = {
                "headers": headers,
                "timeout": self.timeout,
                "allow_redirects": True,
                "params": params,
            }

            if body:
                content_type = headers.get("Content-Type", "").lower()
                if "json" in content_type:
                    try:
                        kwargs["json"] = json.loads(body)
                    except Exception:
                        kwargs["data"] = body
                else:
                    kwargs["data"] = body

            response = self._session.request(method, full_url, **kwargs)
            elapsed = time.time() - start_time

            # Jalankan matchers
            matched, matched_pattern, evidence = self.match_response(
                response, template.get("matchers", [])
            )

            # Ekstrak data jika match
            extracted = []
            if matched and template.get("extractors"):
                extracted = self.extract_data(response, template["extractors"])

            return TemplateResult(
                template_id=template.get("id", "unknown"),
                template_name=template.get("name", "Unknown"),
                severity=template.get("severity", "INFO").upper(),
                owasp=template.get("owasp", ""),
                matched=matched,
                url=full_url,
                extracted_data=extracted,
                response_status=response.status_code,
                response_time=elapsed,
                matched_pattern=matched_pattern,
                evidence=evidence[:200] if evidence else "",
            )

        except Exception:
            return None

    def match_response(self, response, matchers: List[Dict]) -> Tuple[bool, str, str]:
        """
        Cek apakah response cocok dengan semua matchers.
        
        Matcher types: status, word, regex, size, binary
        Condition: and (semua harus cocok), or (salah satu cukup)
        
        Returns:
            Tuple (matched: bool, matched_pattern: str, evidence: str)
        """
        if not matchers:
            return True, "", ""

        results = []
        matched_pattern = ""
        evidence = ""

        for matcher in matchers:
            m_type = matcher.get("type", "word")
            condition = matcher.get("condition", "or").lower()

            if m_type == "status":
                codes = matcher.get("status", [200])
                hit = response.status_code in codes
                results.append(hit)
                if hit:
                    matched_pattern = f"status:{response.status_code}"

            elif m_type == "word":
                words = matcher.get("words", [])
                word_condition = matcher.get("condition", "or").lower()
                body = response.text.lower()
                hits = [w.lower() in body for w in words]

                if word_condition == "and":
                    hit = all(hits)
                else:
                    hit = any(hits)

                results.append(hit)
                if hit:
                    found = [w for w, h in zip(words, hits) if h]
                    matched_pattern = f"words:{found[0]}" if found else ""
                    # Ambil konteks evidence
                    for w in found[:1]:
                        idx = body.find(w.lower())
                        if idx >= 0:
                            evidence = response.text[max(0, idx-30):idx+80]

            elif m_type == "regex":
                patterns = matcher.get("regex", [])
                body = response.text
                regex_condition = matcher.get("condition", "or").lower()
                hits = []
                for pat in patterns:
                    m = re.search(pat, body, re.IGNORECASE)
                    hits.append(bool(m))
                    if m and not evidence:
                        evidence = m.group(0)[:100]

                if regex_condition == "and":
                    hit = all(hits)
                else:
                    hit = any(hits)

                results.append(hit)
                if hit:
                    matched_pattern = f"regex:{patterns[0][:50]}"

            elif m_type == "size":
                expected = matcher.get("size", 0)
                tolerance = matcher.get("tolerance", 100)
                actual = len(response.content)
                hit = abs(actual - expected) <= tolerance
                results.append(hit)
                if hit:
                    matched_pattern = f"size:{actual}"

        # Semua matcher harus terpenuhi (AND logic antar matchers)
        overall = all(results) if results else False
        return overall, matched_pattern, evidence

    def extract_data(self, response, extractors: List[Dict]) -> List[str]:
        """
        Ekstrak data dari response menggunakan extractors.
        
        Extractor types: regex, json, xpath
        """
        extracted = []
        for extractor in extractors:
            e_type = extractor.get("type", "regex")

            if e_type == "regex":
                for pattern in extractor.get("regex", []):
                    for match in re.finditer(pattern, response.text, re.IGNORECASE):
                        val = match.group(1) if match.lastindex else match.group(0)
                        if val and val not in extracted:
                            extracted.append(val[:200])

            elif e_type == "json":
                try:
                    data = response.json()
                    for key in extractor.get("keys", []):
                        val = data.get(key)
                        if val:
                            extracted.append(str(val)[:200])
                except Exception:
                    pass

        return extracted

    def _substitute_variables(self, text: str, variables: Dict) -> str:
        """Substitusi {{variable}} dalam template."""
        for key, value in variables.items():
            text = text.replace(f"{{{{{key}}}}}", str(value))
        return text

    def scan_all(self, target_url: str, templates_dir: str,
                  tags: Optional[List[str]] = None,
                  severity_filter: Optional[List[str]] = None) -> List[TemplateResult]:
        """
        Jalankan semua template terhadap target.
        
        Args:
            target_url: URL target
            templates_dir: Folder berisi template YAML
            tags: Filter berdasarkan tag (opsional)
            severity_filter: Filter berdasarkan severity (opsional)
            
        Returns:
            List TemplateResult yang cocok (matched=True)
        """
        templates = self.load_templates_from_dir(templates_dir)

        # Filter berdasarkan tags
        if tags:
            templates = [
                t for t in templates
                if any(tag in t.get("tags", []) for tag in tags)
            ]

        # Filter berdasarkan severity
        if severity_filter:
            severity_upper = [s.upper() for s in severity_filter]
            templates = [
                t for t in templates
                if t.get("severity", "INFO").upper() in severity_upper
            ]

        results = []
        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = {
                pool.submit(self.execute, t, target_url): t
                for t in templates
            }
            for fut in as_completed(futures):
                result = fut.result()
                if result and result.matched:
                    results.append(result)

        return results

    def list_templates(self, templates_dir: str) -> List[Dict]:
        """Return daftar ringkasan semua template yang tersedia."""
        templates = self.load_templates_from_dir(templates_dir)
        return [
            {
                "id": t.get("id"),
                "name": t.get("name"),
                "severity": t.get("severity", "INFO"),
                "tags": t.get("tags", []),
                "owasp": t.get("owasp", ""),
                "file": t.get("_file", ""),
            }
            for t in templates
        ]


# ─── Standalone ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box

    console = Console()
    parser = argparse.ArgumentParser(description="AnarkisHunter Template Engine")
    parser.add_argument("--scan", help="URL target untuk di-scan")
    parser.add_argument("--templates", default=str(TEMPLATES_DIR), help="Folder template")
    parser.add_argument("--list", action="store_true", help="Tampilkan daftar template")
    parser.add_argument("--validate", help="Validasi template dari folder")
    parser.add_argument("--tags", nargs="+", help="Filter by tags")
    parser.add_argument("--severity", nargs="+", help="Filter by severity")
    args = parser.parse_args()

    engine = TemplateEngine()

    if args.list or args.validate:
        directory = args.validate or args.templates
        templates = engine.list_templates(directory)
        table = Table(title=f"Templates ({len(templates)})", border_style="cyan", box=box.ROUNDED)
        table.add_column("ID", style="bold")
        table.add_column("Name")
        table.add_column("Severity", width=10)
        table.add_column("Tags")
        table.add_column("OWASP", width=6)
        for t in templates:
            sev = t["severity"].upper()
            sev_color = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow",
                         "LOW": "cyan", "INFO": "white"}.get(sev, "white")
            table.add_row(
                t["id"], t["name"],
                f"[{sev_color}]{sev}[/{sev_color}]",
                ", ".join(t["tags"][:3]),
                t["owasp"],
            )
        console.print(table)

    elif args.scan:
        console.print(Panel(f"[bold]Template Scan[/bold]\nTarget: {args.scan}\nTemplates: {args.templates}"))
        results = engine.scan_all(args.scan, args.templates,
                                   tags=args.tags, severity_filter=args.severity)
        if results:
            table = Table(title=f"Hasil ({len(results)} match)", border_style="red")
            table.add_column("Template")
            table.add_column("Severity", width=10)
            table.add_column("URL", overflow="fold")
            table.add_column("Status", width=6)
            table.add_column("Evidence", overflow="fold")
            for r in results:
                table.add_row(r.template_name, r.severity, r.url,
                              str(r.response_status), r.evidence[:60])
            console.print(table)
        else:
            console.print("[green]Tidak ada template yang cocok.[/green]")
