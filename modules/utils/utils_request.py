"""
AnarkisHunter — utils_request.py
==================================
Base HTTP client module menggunakan httpx + asyncio.
Menyediakan session management, proxy support, custom headers,
retry logic, dan rate limiting.

Usage standalone:
    python modules/utils/utils_request.py --url http://target.local
"""

import asyncio
import time
import sys
import httpx
import requests
from typing import Optional, Dict, Any, List
from urllib.parse import urlparse, urljoin

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[2]))
from config.settings import (
    DEFAULT_TIMEOUT, DEFAULT_USER_AGENT, DEFAULT_VERIFY_SSL,
    DEFAULT_MAX_RETRIES, DEFAULT_DELAY, DEFAULT_FOLLOW_REDIRECTS
)


class HTTPClient:
    """
    Sync & Async HTTP client dengan fitur lengkap:
    - Session reuse
    - Custom headers & cookies
    - Proxy support (Burp/ZAP/Tor)
    - Retry logic dengan exponential backoff
    - Rate limiting dengan delay
    - SSL verification control
    """

    def __init__(
        self,
        timeout: int = DEFAULT_TIMEOUT,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        proxy: Optional[str] = None,
        user_agent: str = DEFAULT_USER_AGENT,
        verify_ssl: bool = DEFAULT_VERIFY_SSL,
        follow_redirects: bool = DEFAULT_FOLLOW_REDIRECTS,
        delay: float = DEFAULT_DELAY,
        max_retries: int = DEFAULT_MAX_RETRIES,
    ):
        self.timeout = timeout
        self.delay = delay
        self.max_retries = max_retries
        self.follow_redirects = follow_redirects

        # Build default headers
        self.headers = {
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        }
        if headers:
            self.headers.update(headers)

        self.cookies = cookies or {}
        self.verify_ssl = verify_ssl

        # Proxy configuration
        self.proxies = {}
        if proxy:
            self.proxies = {
                "http://": proxy,
                "https://": proxy,
            }

        # Build sync session (requests)
        self._session = requests.Session()
        self._session.headers.update(self.headers)
        self._session.cookies.update(self.cookies)
        self._session.verify = verify_ssl
        if proxy:
            self._session.proxies = {"http": proxy, "https": proxy}

    # ─── Sync Methods ────────────────────────────────────────────────────────

    def get(self, url: str, params: Optional[Dict] = None, **kwargs) -> Optional[requests.Response]:
        """Sync GET request dengan retry logic."""
        return self._request("GET", url, params=params, **kwargs)

    def post(self, url: str, data: Optional[Dict] = None,
             json: Optional[Dict] = None, **kwargs) -> Optional[requests.Response]:
        """Sync POST request."""
        return self._request("POST", url, data=data, json=json, **kwargs)

    def put(self, url: str, data: Optional[Dict] = None, **kwargs) -> Optional[requests.Response]:
        """Sync PUT request."""
        return self._request("PUT", url, data=data, **kwargs)

    def delete(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Sync DELETE request."""
        return self._request("DELETE", url, **kwargs)

    def head(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Sync HEAD request."""
        return self._request("HEAD", url, **kwargs)

    def options(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Sync OPTIONS request."""
        return self._request("OPTIONS", url, **kwargs)

    def _request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """Internal retry-aware request sender."""
        if self.delay > 0:
            time.sleep(self.delay)

        for attempt in range(self.max_retries):
            try:
                response = self._session.request(
                    method,
                    url,
                    timeout=self.timeout,
                    allow_redirects=self.follow_redirects,
                    **kwargs
                )
                return response
            except requests.exceptions.SSLError:
                # Retry without SSL verification
                try:
                    old_verify = self._session.verify
                    self._session.verify = False
                    response = self._session.request(
                        method, url, timeout=self.timeout,
                        allow_redirects=self.follow_redirects, **kwargs
                    )
                    self._session.verify = old_verify
                    return response
                except Exception:
                    pass
            except requests.exceptions.ConnectionError as e:
                if attempt == self.max_retries - 1:
                    return None
                time.sleep(2 ** attempt)  # exponential backoff
            except requests.exceptions.Timeout:
                if attempt == self.max_retries - 1:
                    return None
                time.sleep(1)
            except Exception:
                return None
        return None

    def close(self):
        """Tutup session."""
        self._session.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    # ─── Async Methods ───────────────────────────────────────────────────────

    async def async_get(self, url: str, params: Optional[Dict] = None) -> Optional[httpx.Response]:
        """Async GET request."""
        return await self._async_request("GET", url, params=params)

    async def async_post(self, url: str, data: Optional[Dict] = None,
                         json_data: Optional[Dict] = None) -> Optional[httpx.Response]:
        """Async POST request."""
        kwargs = {}
        if data:
            kwargs["data"] = data
        if json_data:
            kwargs["json"] = json_data
        return await self._async_request("POST", url, **kwargs)

    async def _async_request(self, method: str, url: str, **kwargs) -> Optional[httpx.Response]:
        """Async request dengan httpx."""
        if self.delay > 0:
            await asyncio.sleep(self.delay)

        transport = None
        if not self.verify_ssl:
            transport = httpx.AsyncHTTPTransport(verify=False)

        async with httpx.AsyncClient(
            headers=self.headers,
            cookies=self.cookies,
            timeout=self.timeout,
            follow_redirects=self.follow_redirects,
            proxies=self.proxies if self.proxies else None,
            transport=transport,
        ) as client:
            for attempt in range(self.max_retries):
                try:
                    response = await client.request(method, url, **kwargs)
                    return response
                except (httpx.ConnectError, httpx.TimeoutException):
                    if attempt == self.max_retries - 1:
                        return None
                    await asyncio.sleep(2 ** attempt)
                except Exception:
                    return None
        return None


async def async_batch_get(
    urls: List[str],
    client: HTTPClient,
    semaphore_limit: int = 20,
) -> List[Dict[str, Any]]:
    """
    Batch async GET requests dengan semaphore untuk kontrol concurrency.
    
    Args:
        urls: List URL yang akan ditest
        client: HTTPClient instance
        semaphore_limit: Maksimum concurrent requests
        
    Returns:
        List of dicts berisi url, status_code, response
    """
    semaphore = asyncio.Semaphore(semaphore_limit)
    results = []

    async def _fetch(url: str):
        async with semaphore:
            resp = await client.async_get(url)
            if resp:
                return {
                    "url": url,
                    "status_code": resp.status_code,
                    "content_length": len(resp.content),
                    "headers": dict(resp.headers),
                    "body": resp.text[:2000],  # Batasi ukuran body
                }
            return {"url": url, "status_code": None, "error": "Connection failed"}

    tasks = [_fetch(url) for url in urls]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    return [r for r in results if isinstance(r, dict)]


def normalize_url(url: str) -> str:
    """Normalisasi URL — pastikan ada scheme."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")


def extract_base_url(url: str) -> str:
    """Ekstrak base URL (scheme + host)."""
    parsed = urlparse(normalize_url(url))
    return f"{parsed.scheme}://{parsed.netloc}"


def build_url(base: str, path: str) -> str:
    """Gabungkan base URL dengan path."""
    return urljoin(normalize_url(base), path)


def get_domain(url: str) -> str:
    """Ekstrak domain dari URL."""
    parsed = urlparse(normalize_url(url))
    return parsed.netloc


def is_same_domain(url1: str, url2: str) -> bool:
    """Cek apakah dua URL berasal dari domain yang sama."""
    return get_domain(url1) == get_domain(url2)


# ─── Standalone Test ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    from rich.console import Console
    from rich.table import Table

    console = Console()
    parser = argparse.ArgumentParser(description="HTTP Client Test")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--method", default="GET", help="HTTP Method")
    parser.add_argument("--timeout", type=int, default=10)
    args = parser.parse_args()

    url = normalize_url(args.url)
    console.print(f"\n[cyan]Testing HTTP Client → [bold]{url}[/bold][/cyan]\n")

    with HTTPClient(timeout=args.timeout) as client:
        resp = client.get(url)
        if resp:
            table = Table(title="Response Info", border_style="green")
            table.add_column("Field", style="cyan")
            table.add_column("Value", style="white")
            table.add_row("Status Code", str(resp.status_code))
            table.add_row("Content-Type", resp.headers.get("Content-Type", "N/A"))
            table.add_row("Content-Length", str(len(resp.content)))
            table.add_row("Response Time", f"{resp.elapsed.total_seconds():.2f}s")
            table.add_row("Final URL", resp.url)
            console.print(table)
        else:
            console.print("[red]❌ Connection failed[/red]")
