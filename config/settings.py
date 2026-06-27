"""
AnarkisHunter Configuration Settings
=====================================
Global configuration untuk semua modul AnarkisHunter.
Edit file ini sesuai kebutuhan environment Anda.
"""

import os
from pathlib import Path

# ─── Base Paths ──────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent
WORDLISTS_DIR = BASE_DIR / "wordlists"
PAYLOADS_DIR = BASE_DIR / "payloads"
REPORTS_DIR = BASE_DIR / "reports"
LOGS_DIR = BASE_DIR / "logs"
DATABASE_DIR = BASE_DIR / "database"

# Auto-create directories
for _dir in [REPORTS_DIR, LOGS_DIR, DATABASE_DIR]:
    _dir.mkdir(exist_ok=True)

# ─── Tool Info ───────────────────────────────────────────────────────────────
TOOL_NAME = "AnarkisHunter"
TOOL_VERSION = "1.0.0"
TOOL_AUTHOR = "AnarkisHunter Team"
TOOL_DESCRIPTION = "Professional Web Penetration Testing Toolkit"
TOOL_GITHUB = "https://github.com/yourusername/AnarkisHunter"
TOOL_LICENSE = "MIT"

# ─── Default Network Settings ────────────────────────────────────────────────
DEFAULT_TIMEOUT = 10          # detik
DEFAULT_THREADS = 10          # jumlah thread
DEFAULT_DELAY = 0             # detik antar request
DEFAULT_MAX_RETRIES = 3
DEFAULT_FOLLOW_REDIRECTS = True
DEFAULT_VERIFY_SSL = False    # disable untuk lab testing
DEFAULT_MAX_DEPTH = 3         # kedalaman crawl
DEFAULT_MAX_PAGES = 500       # maksimum halaman crawl

# ─── Default User Agent ──────────────────────────────────────────────────────
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/125.0.0.0 Safari/537.36"
)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15",
    "AnarkisHunter/1.0 (Security Scanner)",
]

# ─── Wordlists ────────────────────────────────────────────────────────────────
WORDLIST_COMMON = WORDLISTS_DIR / "common.txt"
WORDLIST_DIRS = WORDLISTS_DIR / "directories.txt"
WORDLIST_SUBDOMAINS = WORDLISTS_DIR / "subdomains.txt"
WORDLIST_PASSWORDS = WORDLISTS_DIR / "passwords.txt"

# ─── Payloads ────────────────────────────────────────────────────────────────
PAYLOAD_SQLI = PAYLOADS_DIR / "sqli.txt"
PAYLOAD_XSS = PAYLOADS_DIR / "xss.txt"
PAYLOAD_LFI = PAYLOADS_DIR / "lfi.txt"
PAYLOAD_CMD = PAYLOADS_DIR / "cmd.txt"

# ─── Database ────────────────────────────────────────────────────────────────
DATABASE_URL = f"sqlite:///{DATABASE_DIR}/results.db"

# ─── Report Settings ─────────────────────────────────────────────────────────
REPORT_FORMATS = ["txt", "html", "json", "md", "pdf"]
DEFAULT_REPORT_FORMAT = "html"

# ─── Port Scanner ────────────────────────────────────────────────────────────
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5900, 8080, 8443, 8888, 9000, 9090, 27017
]

PORT_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    8888: "Jupyter", 9000: "PHP-FPM", 27017: "MongoDB"
}

# ─── Sensitive Files ──────────────────────────────────────────────────────────
SENSITIVE_FILES = [
    ".env", ".env.local", ".env.production", ".env.backup",
    ".git/HEAD", ".git/config", ".git/index", ".gitignore",
    "config.php", "config.yml", "config.yaml", "config.json",
    "database.php", "db.php", "db_config.php",
    "wp-config.php", "settings.py", "settings.php",
    "backup.zip", "backup.tar.gz", "backup.sql", "dump.sql",
    "web.config", "applicationHost.config",
    "id_rsa", "id_rsa.pub", "id_dsa", ".ssh/id_rsa",
    "credentials", "credentials.json", "credentials.xml",
    "phpinfo.php", "info.php", "test.php",
    ".htpasswd", ".htaccess",
    "robots.txt", "sitemap.xml",
    "composer.json", "package.json", "Gemfile", "requirements.txt",
    "README.md", "CHANGELOG.md", "TODO.md",
    "log.txt", "error.log", "access.log", "debug.log",
    "admin.php", "login.php", "panel.php",
]

# ─── Admin Paths ──────────────────────────────────────────────────────────────
ADMIN_PATHS = [
    "/admin", "/admin/", "/admin/login", "/admin/index.php",
    "/administrator", "/administrator/", "/administrator/index.php",
    "/wp-admin", "/wp-admin/", "/wp-login.php",
    "/dashboard", "/dashboard/", "/control", "/control-panel",
    "/panel", "/cpanel", "/webadmin", "/wp-admin/admin-ajax.php",
    "/backend", "/manage", "/management", "/manager",
    "/cms", "/cms/admin", "/admin1", "/admin2", "/admin123",
    "/superadmin", "/super-admin", "/root", "/rootadmin",
    "/phpmyadmin", "/phpmyadmin/", "/pma", "/mysql", "/myadmin",
    "/adminer.php", "/adminer", "/dbadmin",
    "/adminpanel", "/admin_panel", "/admin-panel",
    "/system", "/sysadmin", "/siteadmin", "/webmaster",
    "/portal", "/portal/admin", "/secure", "/secure/admin",
    "/user/login", "/users/login", "/account/login",
    "/login", "/signin", "/sign-in", "/auth", "/authenticate",
    "/config", "/configuration", "/settings", "/setup",
    "/install", "/installation", "/installer",
    "/console", "/terminal", "/shell", "/cmd",
]

# ─── API Paths ────────────────────────────────────────────────────────────────
API_PATHS = [
    "/api", "/api/", "/api/v1", "/api/v2", "/api/v3",
    "/api/v1/users", "/api/v1/login", "/api/v1/auth",
    "/v1", "/v2", "/v3", "/v4",
    "/graphql", "/graphiql", "/graphql/console",
    "/swagger", "/swagger-ui", "/swagger-ui.html", "/swagger.json",
    "/openapi", "/openapi.json", "/openapi.yaml",
    "/docs", "/redoc", "/api-docs", "/api/docs",
    "/rest", "/rest/api", "/rest/v1",
    "/json", "/xml", "/rpc", "/jsonrpc", "/xmlrpc",
    "/webhook", "/webhooks", "/callback",
    "/health", "/healthcheck", "/status", "/ping",
    "/metrics", "/actuator", "/actuator/health",
    "/.well-known", "/.well-known/security.txt",
]

# ─── WAF Signatures ──────────────────────────────────────────────────────────
WAF_SIGNATURES = {
    "Cloudflare": ["cloudflare", "__cfduid", "cf-ray", "cf-request-id"],
    "AWS WAF": ["awswaf", "x-amzn-requestid", "x-amz-cf-id"],
    "ModSecurity": ["mod_security", "modsecurity", "NOYB"],
    "Sucuri": ["sucuri", "x-sucuri-id", "x-sucuri-cache"],
    "Akamai": ["akamai", "x-akamai-transformed", "akamaighost"],
    "Incapsula": ["incapsula", "visid_incap", "incap_ses"],
    "F5 BIG-IP": ["bigipserver", "x-wa-info", "x-cnection"],
    "Barracuda": ["barracuda", "barra_counter_session"],
    "Wordfence": ["wordfence", "wfvt_"],
    "Nginx WAF": ["x-naxsi-sig"],
}

# ─── CMS Signatures ──────────────────────────────────────────────────────────
CMS_SIGNATURES = {
    "WordPress": ["/wp-content/", "/wp-includes/", "wp-json", "wordpress"],
    "Joomla": ["/components/com_", "/administrator/", "joomla"],
    "Drupal": ["/sites/default/", "drupal", "X-Generator: Drupal"],
    "Magento": ["/skin/frontend/", "/js/mage/", "magento"],
    "Laravel": ["laravel_session", "XSRF-TOKEN", "X-Powered-By: PHP"],
    "Django": ["csrfmiddlewaretoken", "django", "X-Frame-Options: SAMEORIGIN"],
    "Ruby on Rails": ["X-Powered-By: Phusion Passenger", "_session_id", "rails"],
    "Symfony": ["sf_redirect", "symfony", "X-Debug-Token"],
    "CodeIgniter": ["ci_session", "codeigniter"],
    "ASP.NET": ["ASP.NET_SessionId", "X-AspNet-Version", "X-Powered-By: ASP.NET"],
    "Spring Boot": ["JSESSIONID", "X-Application-Context"],
    "Express.js": ["X-Powered-By: Express"],
    "Flask": ["session", "werkzeug"],
}

# ─── Security Headers ─────────────────────────────────────────────────────────
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "expected": "max-age=31536000; includeSubDomains",
        "severity": "HIGH",
        "description": "Protects against protocol downgrade attacks (HSTS)"
    },
    "X-Content-Type-Options": {
        "expected": "nosniff",
        "severity": "MEDIUM",
        "description": "Prevents MIME type sniffing"
    },
    "X-Frame-Options": {
        "expected": "SAMEORIGIN",
        "severity": "MEDIUM",
        "description": "Prevents clickjacking attacks"
    },
    "X-XSS-Protection": {
        "expected": "1; mode=block",
        "severity": "LOW",
        "description": "Enables browser XSS filter (deprecated but still useful)"
    },
    "Content-Security-Policy": {
        "expected": None,
        "severity": "HIGH",
        "description": "Prevents XSS and data injection attacks"
    },
    "Referrer-Policy": {
        "expected": "strict-origin-when-cross-origin",
        "severity": "LOW",
        "description": "Controls referrer information"
    },
    "Permissions-Policy": {
        "expected": None,
        "severity": "LOW",
        "description": "Controls browser features and APIs"
    },
}

# ─── Severity Levels ─────────────────────────────────────────────────────────
SEVERITY = {
    "CRITICAL": {"color": "bold red", "score": 9.0},
    "HIGH": {"color": "red", "score": 7.0},
    "MEDIUM": {"color": "yellow", "score": 5.0},
    "LOW": {"color": "cyan", "score": 3.0},
    "INFO": {"color": "blue", "score": 0.0},
}

# ─── OWASP Top 10 2021 Mapping ────────────────────────────────────────────────
OWASP_TOP10 = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery (SSRF)",
}

# ─── Legal Disclaimer ─────────────────────────────────────────────────────────
LEGAL_DISCLAIMER = """
╔══════════════════════════════════════════════════════════════════╗
║                    ⚠️  LEGAL DISCLAIMER ⚠️                        ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  AnarkisHunter adalah tool penetration testing yang dirancang    ║
║  HANYA untuk digunakan pada:                                     ║
║                                                                  ║
║  ✅ Sistem yang Anda miliki sendiri                              ║
║  ✅ Lab lingkungan testing milik sendiri                         ║
║  ✅ Sistem dengan izin tertulis eksplisit dari pemiliknya        ║
║                                                                  ║
║  ❌ DILARANG KERAS digunakan pada sistem tanpa izin              ║
║  ❌ Penggunaan ilegal dapat mengakibatkan tuntutan hukum         ║
║                                                                  ║
║  Dengan melanjutkan, Anda setuju bahwa:                          ║
║  1. Anda hanya akan menggunakan tools ini secara legal           ║
║  2. Developer tidak bertanggung jawab atas penyalahgunaan        ║
║  3. Anda memahami konsekuensi hukum dari penggunaan ilegal       ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
"""
