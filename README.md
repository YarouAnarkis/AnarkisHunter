# ⚔ AnarkisHunter — Web Penetration Testing Framework

[![Python 3.11+](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Kali%20%7C%20Ubuntu%20%7C%20WSL2%20%7C%20macOS-green.svg)]()

> **⚠ LEGAL DISCLAIMER:** This tool is for **authorized penetration testing ONLY**. Use only on systems you have explicit written permission to test. Unauthorized use is illegal.

---

## 📋 Overview

**AnarkisHunter** is a professional-grade, modular web penetration testing CLI framework built in Python 3.11+. Inspired by tools like SQLMap, Nikto, and Gobuster — designed for academic cybersecurity research and controlled lab testing.

### Key Features

- 🔍 **14 Recon modules** — WHOIS, DNS, SSL, subdomain enum, tech detect, wayback, JS analysis
- 🔭 **14 Scanner modules** — Port scan, dir bruteforce, admin panel, CORS, WAF, Git exposure
- 🛡 **22 Vulnerability modules** — SQLi, XSS, LFI, RFI, SSTI, XXE, SSRF, CSRF, JWT, IDOR, upload
- 💉 **15 Exploit modules** — Full exploitation with data extraction and RCE testing
- 🔓 **6 Post-exploitation modules** — Privilege escalation, lateral movement, data exfil, persistence
- 📊 **Multi-format reports** — HTML, JSON, TXT, Markdown, PDF
- 🔐 **Proxy support** — Burp Suite, OWASP ZAP, SOCKS5, Tor

---

## 🚀 Installation

### Linux / macOS / WSL2
```bash
git clone https://github.com/YarouAnarkis/AnarkisHunter
cd AnarkisHunter
chmod +x install.sh && ./install.sh
source .venv/bin/activate
```

### Windows
```cmd
git clone https://github.com/YarouAnarkis/AnarkisHunter
cd AnarkisHunter
install.bat
.venv\Scripts\activate
```

### Manual
```bash
pip install -r requirements.txt
```

---

## 📖 Usage

### Quick Start
```bash
# Run all phases
python webpentest.py --url http://target.local --all

# Specific phases
python webpentest.py --url http://target.local --recon --scan --vuln

# Exploit specific vulnerability
python webpentest.py --url "http://target.local/page.php?id=1" --exploit sqli
python webpentest.py --url "http://target.local/search?q=test" --exploit xss

# Brute force login
python webpentest.py --url http://target.local/login --exploit bruteforce \
  --username admin --wordlist wordlists/passwords.txt

# JWT exploitation
python webpentest.py --url http://target.local/api --exploit jwt \
  --token "eyJhbGciOiJIUzI1NiJ9..."

# Post-exploitation (requires session cookie)
python webpentest.py --url http://target.local --postexploit privesc lateral exfil \
  --cookies "session=abc123"

# Custom report format
python webpentest.py --url http://target.local --all --format html json pdf
```

### Standalone Module Usage
```bash
# WHOIS lookup
python modules/recon/recon_whois.py --domain example.com

# DNS enumeration
python modules/recon/recon_dns.py --domain example.com

# Subdomain enumeration
python modules/recon/recon_subdomain.py --domain example.com --threads 30

# Port scan
python modules/scanner/scan_ports.py --url http://target.local

# SQLi scan
python modules/vuln/vuln_sqli.py --url "http://target.local/page.php?id=1"

# XSS exploit
python modules/exploit/exploit_xss.py --url "http://target.local/search?q=test"

# JWT analyzer
python modules/utils/utils_jwt.py --analyze "eyJ..."

# Proxy through Burp
python webpentest.py --url http://target.local --all --proxy http://127.0.0.1:8080
```

---

## 🗂 Project Structure

```
AnarkisHunter/
├── webpentest.py              # 🚀 Main CLI entry point
├── requirements.txt           # Dependencies
├── install.sh / install.bat   # Setup scripts
├── config/
│   └── settings.py            # Global configuration
├── modules/
│   ├── recon/                 # 14 Reconnaissance modules
│   │   ├── recon_whois.py
│   │   ├── recon_dns.py
│   │   ├── recon_ssl.py
│   │   ├── recon_subdomain.py
│   │   └── ...
│   ├── scanner/               # 14 Scanner modules
│   │   ├── scan_ports.py
│   │   ├── scan_dirs.py
│   │   ├── scan_admin.py
│   │   └── ...
│   ├── vuln/                  # 22 Vulnerability detection modules
│   │   ├── vuln_sqli.py
│   │   ├── vuln_xss.py
│   │   ├── vuln_lfi.py
│   │   └── ...
│   ├── exploit/               # 15 Exploitation modules
│   │   ├── exploit_sqli.py
│   │   ├── exploit_xss.py
│   │   ├── exploit_bruteforce.py
│   │   └── ...
│   ├── postexploit/           # 6 Post-exploitation modules
│   │   ├── post_privesc.py
│   │   ├── post_lateral.py
│   │   ├── post_exfil.py
│   │   └── ...
│   └── utils/                 # 12 Utility modules
│       ├── utils_request.py
│       ├── utils_payload.py
│       ├── utils_jwt.py
│       ├── report.py
│       └── ...
├── payloads/                  # Payload wordlists
│   ├── sqli.txt
│   ├── xss.txt
│   ├── lfi.txt
│   ├── cmd.txt
│   └── ssti.txt
├── wordlists/                 # Wordlists
│   ├── passwords.txt
│   ├── subdomains.txt
│   └── admin_paths.txt
└── reports/                   # Auto-generated reports
```

---

## 📊 Supported Vulnerabilities

| Category | Vulnerabilities |
|----------|----------------|
| **Injection** | SQL Injection, Command Injection, SSTI, XXE, LFI, RFI |
| **Broken Auth** | Brute Force, Session Fixation, JWT Attacks, Weak Credentials |
| **OWASP A01** | IDOR, Privilege Escalation, Mass Assignment |
| **XSS** | Reflected, Stored, DOM-based |
| **CSRF/CORS** | CSRF token bypass, CORS misconfiguration |
| **Misconfig** | Open redirect, WAF detection, Admin panel exposure |
| **Cryptographic** | Weak JWT secrets, None algorithm, Missing HTTPS |
| **Components** | Git exposure, Backup files, PHP info leaks |

---

## ⚙ Configuration

Edit `config/settings.py` to customize:
- Request timeout, threads, delay
- Custom User-Agent
- WAF bypass headers
- OWASP mapping

---

## 📝 Report Output

Reports are auto-saved to `reports/` directory:
```
reports/report_target.local_20240101_120000.html
reports/report_target.local_20240101_120000.json
reports/report_target.local_20240101_120000.md
```

---

## ⚖ Legal & Ethics

This tool is intended for:
- ✅ Authorized penetration testing
- ✅ Academic cybersecurity research
- ✅ Testing your own systems
- ✅ Controlled lab environments

**NOT for:**
- ❌ Unauthorized access to systems
- ❌ Any illegal activities
- ❌ Malicious use against production systems

---

## 🔮 Roadmap / Future Development

Ke depannya, proyek ini dapat dikembangkan menjadi *Enterprise-grade Security Tool* dengan menambahkan fitur-fitur mutakhir berikut:

1. **Migrasi Asynchronous (Performa Maksimal):** 
   Berpindah dari `Multithreading` (sinkron) ke arsitektur *Asynchronous* (`asyncio` + `aiohttp`) untuk menembakkan ribuan *request* per detik tanpa membebani CPU, mirip kinerja *ffuf* atau *nuclei*.
2. **Mekanisme Anti "False Positive" Cerdas:** 
   Alih-alih sekadar mencocokkan pola teks (regex), tool akan menganalisis secara heuristik struktur DOM HTML antara respons normal vs respons *error* untuk menembus WAF secara lebih akurat.
3. **Payload Berbasis Template (YAML):** 
   Mengadopsi format YAML untuk memisahkan logika pendeteksian dari kode Python murni. Pengguna dapat menambah CVE baru hanya dengan membuat *file template* tanpa perlu menulis kode (seperti cara kerja Nuclei).
4. **Integrasi Burp Suite / OWASP ZAP:** 
   Menambahkan fitur ekspor tangkapan data ke `.xml` atau `.json` yang bisa langsung diimpor ke dalam proksi keamanan profesional.
5. **Deteksi "Out-of-Band" (OOB / Blind Vulnerabilities) 📡:** 
   Mendeteksi celah *Blind* (seperti Blind SQLi / Blind SSRF) dengan memaksa server target melakukan *ping* atau *DNS request* balik ke *server monitoring* eksternal untuk verifikasi celah 100% tanpa respon layar.
6. **Auto-Login & Session Maintenance 🤖:** 
   Mekanisme otomatis (*headless*) yang bisa menavigasi ke halaman login, melewati proteksi CSRF, mengambil token/cookie JWT, dan menjaga sesi tetap hidup selama proses *Post-Exploitation*.

---

## 📚 References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)

---

*Made with ❤ for cybersecurity education*
