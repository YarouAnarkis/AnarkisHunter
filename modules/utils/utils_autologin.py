"""
AnarkisHunter — utils_autologin.py
======================================
Auto-Login & Session Manager: Otomatis mendeteksi form login,
mengekstrak CSRF token, melakukan login, dan menjaga sesi aktif
untuk semua fase scan selanjutnya.

Usage standalone:
    python modules/utils/utils_autologin.py --url http://target.com/login --user admin --pass admin123
    python modules/utils/utils_autologin.py --url http://wp-target.com/wp-login.php --user admin --pass pass123 --detect
"""

import sys
import re
import time
from typing import Optional, Dict, List, Tuple, Any
from urllib.parse import urljoin, urlparse
from dataclasses import dataclass, field

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[2]))

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False


# ─── Login Form Patterns ──────────────────────────────────────────────────────

USERNAME_FIELD_NAMES = [
    "username", "user", "email", "login", "user_login", "log",
    "name", "uname", "userid", "user_id", "user_name", "user_email",
    "account", "membername", "loginid", "uid", "user[email]",
    "user[username]", "session[email]", "session[username]",
]

PASSWORD_FIELD_NAMES = [
    "password", "pass", "passwd", "pwd", "user_password", "userpass",
    "passw", "user_pass", "user_pwd", "password1", "pass1",
    "passwort", "senha", "sifre", "user[password]", "session[password]",
]

SUCCESS_INDICATORS = [
    "dashboard", "logout", "profile", "welcome", "berhasil", "success",
    "logged in", "log out", "sign out", "akun", "my account", "hello",
    "hi ", "selamat datang", "control panel", "panel kontrol",
]

FAILURE_INDICATORS = [
    "invalid", "incorrect", "wrong", "error", "failed", "gagal",
    "salah", "tidak valid", "login failed", "authentication failed",
    "bad credentials", "unauthorized", "access denied",
    "username or password", "password you entered",
]


@dataclass
class LoginForm:
    """Representasi form login yang terdeteksi."""
    action: str
    method: str
    username_field: str
    password_field: str
    csrf_field: Optional[str]
    csrf_value: Optional[str]
    extra_fields: Dict[str, str] = field(default_factory=dict)
    form_html: str = ""


@dataclass
class LoginResult:
    """Hasil percobaan login."""
    success: bool
    session_cookies: Dict[str, str]
    session_headers: Dict[str, str]
    redirect_url: Optional[str]
    error_message: Optional[str]
    auth_token: Optional[str]  # JWT/Bearer token jika ada
    csrf_token: Optional[str]  # CSRF token untuk request selanjutnya
    confidence: float  # 0-100, seberapa yakin login berhasil


class AutoLoginHandler:
    """
    Handler untuk otomasi proses login.
    
    Mendukung:
    - Form-based login (aplikasi web standar)
    - WordPress login
    - API-based login (JSON body)
    - Login dengan CSRF protection
    """

    def __init__(self, timeout: int = 10, verify_ssl: bool = False):
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self._session = self._create_session()
        self._login_result: Optional[LoginResult] = None

    def _create_session(self) -> Optional[Any]:
        """Buat requests Session dengan retry."""
        if not REQUESTS_AVAILABLE:
            return None

        session = requests.Session()
        retry = Retry(total=3, backoff_factor=0.5, status_forcelist=[500, 502, 503])
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.verify = self.verify_ssl
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        })
        return session

    def detect_login_form(self, url: str) -> Optional[LoginForm]:
        """
        Deteksi form login secara otomatis dari halaman.
        
        Args:
            url: URL halaman login
            
        Returns:
            LoginForm jika ditemukan, None jika tidak
        """
        if not self._session or not BS4_AVAILABLE:
            return None

        try:
            resp = self._session.get(url, timeout=self.timeout,
                                     allow_redirects=True)
            soup = BeautifulSoup(resp.text, "html.parser")

            # Cari semua form di halaman
            forms = soup.find_all("form")
            for form in forms:
                login_form = self._analyze_form(form, url)
                if login_form:
                    return login_form

            return None

        except Exception:
            return None

    def _analyze_form(self, form, base_url: str) -> Optional[LoginForm]:
        """Analisis apakah form ini adalah form login."""
        inputs = form.find_all("input")

        username_field = None
        password_field = None
        csrf_field = None
        csrf_value = None
        extra_fields = {}

        for inp in inputs:
            inp_type = inp.get("type", "text").lower()
            inp_name = (inp.get("name") or inp.get("id") or "").lower()
            inp_value = inp.get("value", "")

            if inp_type == "password":
                password_field = inp.get("name") or inp.get("id")

            elif inp_type in ("text", "email") or inp_name in USERNAME_FIELD_NAMES:
                # Cek apakah ini username field
                for pattern in USERNAME_FIELD_NAMES:
                    if pattern in inp_name:
                        username_field = inp.get("name") or inp.get("id")
                        break
                if not username_field and inp_type in ("text", "email"):
                    username_field = inp.get("name") or inp.get("id")

            elif inp_type == "hidden":
                # Kemungkinan CSRF token
                if any(csrf_kw in inp_name for csrf_kw in
                       ["csrf", "token", "_token", "nonce", "authenticity"]):
                    csrf_field = inp.get("name")
                    csrf_value = inp_value
                else:
                    if inp.get("name"):
                        extra_fields[inp.get("name")] = inp_value

            elif inp_type == "submit":
                extra_fields[inp.get("name", "submit")] = inp_value

        # Harus ada setidaknya password field
        if not password_field:
            return None

        # Ambil action URL
        action = form.get("action", "")
        if action:
            action = urljoin(base_url, action)
        else:
            action = base_url

        method = form.get("method", "post").lower()

        return LoginForm(
            action=action,
            method=method,
            username_field=username_field or "username",
            password_field=password_field,
            csrf_field=csrf_field,
            csrf_value=csrf_value,
            extra_fields=extra_fields,
            form_html=str(form)[:500],
        )

    def attempt_login(self, url: str, username: str, password: str,
                      form: Optional[LoginForm] = None,
                      api_mode: bool = False) -> LoginResult:
        """
        Lakukan percobaan login.
        
        Args:
            url: URL halaman login
            username: Username/email untuk login
            password: Password untuk login
            form: LoginForm yang sudah dideteksi (opsional, akan auto-detect)
            api_mode: Jika True, kirim sebagai JSON body (untuk REST API)
            
        Returns:
            LoginResult dengan status dan session cookies
        """
        if not self._session:
            return LoginResult(
                success=False, session_cookies={}, session_headers={},
                redirect_url=None, error_message="requests tidak tersedia",
                auth_token=None, csrf_token=None, confidence=0
            )

        # Auto-detect form jika belum disediakan
        if not form and not api_mode:
            form = self.detect_login_form(url)

        if api_mode:
            return self._login_api(url, username, password)
        elif form:
            return self._login_form(form, username, password)
        else:
            # Fallback: coba submit POST dengan field default
            return self._login_generic(url, username, password)

    def _login_form(self, form: LoginForm, username: str,
                    password: str) -> LoginResult:
        """Submit form login yang sudah diidentifikasi."""
        payload = {
            form.username_field: username,
            form.password_field: password,
        }

        # Tambahkan CSRF token jika ada
        if form.csrf_field and form.csrf_value:
            payload[form.csrf_field] = form.csrf_value

        # Tambahkan hidden fields lainnya
        payload.update(form.extra_fields)

        try:
            if form.method == "post":
                resp = self._session.post(
                    form.action, data=payload,
                    timeout=self.timeout, allow_redirects=True
                )
            else:
                resp = self._session.get(
                    form.action, params=payload,
                    timeout=self.timeout, allow_redirects=True
                )

            return self._evaluate_login_response(resp)

        except Exception as e:
            return LoginResult(
                success=False, session_cookies={}, session_headers={},
                redirect_url=None, error_message=str(e),
                auth_token=None, csrf_token=None, confidence=0
            )

    def _login_api(self, url: str, username: str, password: str) -> LoginResult:
        """Login via REST API dengan JSON body."""
        # Coba berbagai format JSON yang umum
        payloads_to_try = [
            {"username": username, "password": password},
            {"email": username, "password": password},
            {"user": username, "pass": password},
            {"login": username, "password": password},
        ]

        for payload in payloads_to_try:
            try:
                resp = self._session.post(
                    url, json=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=self.timeout, allow_redirects=True
                )
                result = self._evaluate_login_response(resp)
                if result.success or result.auth_token:
                    return result
            except Exception:
                continue

        return LoginResult(
            success=False, session_cookies={}, session_headers={},
            redirect_url=None, error_message="Semua format payload API gagal",
            auth_token=None, csrf_token=None, confidence=0
        )

    def _login_generic(self, url: str, username: str, password: str) -> LoginResult:
        """Fallback: POST ke URL dengan field umum."""
        common_payloads = [
            {"username": username, "password": password},
            {"user": username, "pass": password},
            {"email": username, "password": password},
            {"log": username, "pwd": password},  # WordPress format
            {"user_login": username, "user_pass": password},
        ]

        for payload in common_payloads:
            try:
                resp = self._session.post(
                    url, data=payload,
                    timeout=self.timeout, allow_redirects=True
                )
                result = self._evaluate_login_response(resp)
                if result.success:
                    return result
            except Exception:
                continue

        return LoginResult(
            success=False, session_cookies={}, session_headers={},
            redirect_url=None, error_message="Login gagal dengan semua format",
            auth_token=None, csrf_token=None, confidence=0
        )

    def _evaluate_login_response(self, response) -> LoginResult:
        """Evaluasi apakah login berhasil dari response."""
        body = ""
        try:
            body = response.text.lower()
        except Exception:
            pass

        cookies = dict(response.cookies)
        headers = dict(response.headers)
        confidence = 0.0
        reasons = []

        # Cek JWT/Bearer token di response JSON
        auth_token = None
        csrf_token = None
        try:
            json_data = response.json()
            for key in ["token", "access_token", "jwt", "auth_token",
                        "authorization", "bearer"]:
                if key in json_data:
                    auth_token = json_data[key]
                    confidence += 60
                    reasons.append(f"JWT/token ditemukan di response JSON ({key})")
                    break
        except Exception:
            pass

        # Cek Authorization header
        if "Authorization" in headers:
            auth_token = headers["Authorization"]
            confidence += 50

        # Cek cookies yang menandakan session aktif
        session_cookie_names = ["session", "sessionid", "PHPSESSID", "laravel_session",
                                  "JSESSIONID", "connect.sid", "token", "auth"]
        for name in session_cookie_names:
            if any(name.lower() in k.lower() for k in cookies):
                confidence += 30
                reasons.append(f"Session cookie ditemukan: {name}")
                break

        # Cek indikator sukses di body
        for indicator in SUCCESS_INDICATORS:
            if indicator in body:
                confidence += 25
                reasons.append(f"Indikator sukses: '{indicator}'")
                break

        # Cek indikator gagal di body (kurangi confidence)
        for indicator in FAILURE_INDICATORS:
            if indicator in body:
                confidence -= 40
                reasons.append(f"Indikator gagal: '{indicator}'")
                break

        # Redirect setelah login biasanya tanda berhasil
        redirect_url = str(response.url) if response.history else None
        if response.history and response.status_code == 200:
            confidence += 15
            reasons.append("Redirect berhasil setelah submit")

        # Cek status code
        if response.status_code in (200, 302):
            confidence += 5
        elif response.status_code in (401, 403):
            confidence -= 30

        confidence = max(0, min(100, confidence))
        success = confidence >= 50 or bool(auth_token)

        # Ambil CSRF token dari halaman setelah login
        if BS4_AVAILABLE and body:
            csrf_match = re.search(
                r'(?:csrf|_token|nonce)["\s]*[=:]["\s]*([a-zA-Z0-9_\-\.]+)',
                response.text, re.IGNORECASE
            )
            if csrf_match:
                csrf_token = csrf_match.group(1)

        self._login_result = LoginResult(
            success=success,
            session_cookies=cookies,
            session_headers={"Cookie": "; ".join(f"{k}={v}" for k, v in cookies.items())},
            redirect_url=redirect_url,
            error_message=None if success else "Login tidak berhasil terdeteksi",
            auth_token=auth_token,
            csrf_token=csrf_token,
            confidence=confidence,
        )
        return self._login_result

    def get_session_headers(self) -> Dict[str, str]:
        """Return headers siap pakai dengan session aktif."""
        if not self._login_result or not self._login_result.success:
            return {}

        headers = {}
        if self._login_result.session_cookies:
            headers["Cookie"] = "; ".join(
                f"{k}={v}" for k, v in self._login_result.session_cookies.items()
            )
        if self._login_result.auth_token:
            token = self._login_result.auth_token
            if not token.startswith("Bearer "):
                token = f"Bearer {token}"
            headers["Authorization"] = token
        if self._login_result.csrf_token:
            headers["X-CSRF-Token"] = self._login_result.csrf_token
            headers["X-CSRFToken"] = self._login_result.csrf_token

        return headers

    def get_cookie_string(self) -> str:
        """Return cookie string untuk dipakai di argumen --cookies."""
        if not self._login_result:
            return ""
        return "; ".join(
            f"{k}={v}" for k, v in self._login_result.session_cookies.items()
        )


# ─── Standalone ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel

    console = Console()
    parser = argparse.ArgumentParser(description="AnarkisHunter Auto-Login Handler")
    parser.add_argument("--url", required=True, help="URL halaman login")
    parser.add_argument("--user", required=True, help="Username/email")
    parser.add_argument("--pass", dest="password", required=True, help="Password")
    parser.add_argument("--detect", action="store_true", help="Hanya deteksi form, tidak login")
    parser.add_argument("--api", action="store_true", help="Mode API (JSON body)")
    args = parser.parse_args()

    handler = AutoLoginHandler()
    console.print(Panel(f"[bold cyan]Auto-Login Handler[/bold cyan]\nTarget: {args.url}"))

    if args.detect:
        form = handler.detect_login_form(args.url)
        if form:
            table = Table(title="Form Login Terdeteksi", border_style="green")
            table.add_column("Field", style="cyan")
            table.add_column("Value")
            table.add_row("Action", form.action)
            table.add_row("Method", form.method.upper())
            table.add_row("Username Field", form.username_field)
            table.add_row("Password Field", form.password_field)
            table.add_row("CSRF Field", form.csrf_field or "[dim]Tidak ada[/dim]")
            table.add_row("Extra Fields", str(list(form.extra_fields.keys())))
            console.print(table)
        else:
            console.print("[red]Tidak dapat mendeteksi form login di halaman ini.[/red]")
    else:
        console.print(f"[dim]Mencoba login sebagai '{args.user}'...[/dim]")
        result = handler.attempt_login(args.url, args.user, args.password,
                                        api_mode=args.api)
        if result.success:
            console.print(f"\n[bold green]✓ LOGIN BERHASIL[/bold green] (Confidence: {result.confidence:.0f}%)")
            if result.auth_token:
                console.print(f"  Token: [yellow]{result.auth_token[:60]}...[/yellow]")
            if result.session_cookies:
                console.print(f"  Cookies: [cyan]{handler.get_cookie_string()[:100]}[/cyan]")
            if result.csrf_token:
                console.print(f"  CSRF Token: [dim]{result.csrf_token}[/dim]")
        else:
            console.print(f"\n[bold red]✗ LOGIN GAGAL[/bold red] (Confidence: {result.confidence:.0f}%)")
            console.print(f"  Pesan: {result.error_message}")
