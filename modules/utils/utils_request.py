"""
AnarkisHunter — utils_request.py
==================================
Async-first HTTP client menggunakan httpx + asyncio.
Connection pooling, retry dengan exponential backoff, rate-limit handling,
dan sync wrapper untuk backward compatibility dengan modul existing.

Usage standalone:
    python modules/utils/utils_request.py --url http://target.local
"""

import asyncio
import time
import sys
import threading
from typing import Optional, Dict, Any, List, Callable, Union
from urllib.parse import urlparse, urljoin

import httpx

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[2]))
from config.settings import (
    DEFAULT_TIMEOUT, DEFAULT_USER_AGENT, DEFAULT_VERIFY_SSL,
    DEFAULT_MAX_RETRIES, DEFAULT_DELAY, DEFAULT_FOLLOW_REDIRECTS, DEFAULT_THREADS,
)


class RequestStats:
    """Real-time request statistics tracker."""

    def __init__(self):
        self._lock = threading.Lock()
        self.total_requests = 0
        self.successful = 0
        self.failed = 0
        self.retries = 0
        self.rate_limited = 0
        self.start_time = time.time()

    def record(self, success: bool = True, retry: bool = False, rate_limited: bool = False):
        with self._lock:
            self.total_requests += 1
            if success:
                self.successful += 1
            else:
                self.failed += 1
            if retry:
                self.retries += 1
            if rate_limited:
                self.rate_limited += 1

    @property
    def elapsed(self) -> float:
        return time.time() - self.start_time

    @property
    def requests_per_sec(self) -> float:
        elapsed = self.elapsed
        return self.total_requests / elapsed if elapsed > 0 else 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_requests": self.total_requests,
            "successful": self.successful,
            "failed": self.failed,
            "retries": self.retries,
            "rate_limited": self.rate_limited,
            "elapsed": round(self.elapsed, 2),
            "requests_per_sec": round(self.requests_per_sec, 2),
        }


# Global stats instance (shared across scan session)
_global_stats = RequestStats()


def get_request_stats() -> RequestStats:
    return _global_stats


def reset_request_stats() -> RequestStats:
    global _global_stats
    _global_stats = RequestStats()
    return _global_stats


def _run_sync(coro):
    """Run async coroutine from sync context."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    else:
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(asyncio.run, coro).result()


class HTTPResponse:
    """Unified response wrapper compatible with requests-like API."""

    def __init__(self, response: httpx.Response, elapsed: float = 0.0):
        self._response = response
        self.status_code = response.status_code
        self.headers = response.headers
        self.content = response.content
        self.text = response.text
        self.url = str(response.url)
        self.elapsed = type("Elapsed", (), {"total_seconds": lambda s=elapsed: elapsed})()
        self.cookies = response.cookies

    def json(self):
        return self._response.json()


class HTTPClient:
    """
    Async-first HTTP client dengan connection pooling.
    Sync methods (get/post/...) wrap async untuk backward compatibility.
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
        threads: int = DEFAULT_THREADS,
        stats: Optional[RequestStats] = None,
    ):
        self.timeout = timeout
        self.delay = delay
        self.max_retries = max_retries
        self.follow_redirects = follow_redirects
        self.verify_ssl = verify_ssl
        self.threads = threads
        self.stats = stats or _global_stats

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
        self.proxy = proxy

        self._limits = httpx.Limits(
            max_connections=threads,
            max_keepalive_connections=min(threads, 20),
        )
        self._timeout = httpx.Timeout(float(timeout), connect=float(timeout))
        self._async_client: Optional[httpx.AsyncClient] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._closed = False

    def _build_client(self) -> httpx.AsyncClient:
        transport = None
        if not self.verify_ssl:
            transport = httpx.AsyncHTTPTransport(verify=False)

        kwargs: Dict[str, Any] = {
            "headers": self.headers,
            "cookies": self.cookies,
            "timeout": self._timeout,
            "follow_redirects": self.follow_redirects,
            "limits": self._limits,
        }
        if self.proxy:
            kwargs["proxy"] = self.proxy
        if transport:
            kwargs["transport"] = transport

        return httpx.AsyncClient(**kwargs)

    async def _ensure_client(self) -> httpx.AsyncClient:
        if self._async_client is None or self._closed:
            self._async_client = self._build_client()
            self._closed = False
        return self._async_client

    async def _async_request(
        self,
        method: str,
        url: str,
        **kwargs,
    ) -> Optional[HTTPResponse]:
        if self.delay > 0:
            await asyncio.sleep(self.delay)

        client = await self._ensure_client()

        for attempt in range(self.max_retries):
            start = time.time()
            try:
                response = await client.request(method, url, **kwargs)
                elapsed = time.time() - start

                if response.status_code == 429:
                    self.stats.record(success=False, rate_limited=True)
                    wait = min(2 ** (attempt + 1), 30)
                    await asyncio.sleep(wait)
                    self.stats.record(retry=True)
                    continue

                self.stats.record(success=True)
                return HTTPResponse(response, elapsed)

            except httpx.TimeoutException:
                self.stats.record(success=False)
                if attempt == self.max_retries - 1:
                    return None
                await asyncio.sleep(2 ** attempt)
                self.stats.record(retry=True)

            except httpx.ConnectError:
                self.stats.record(success=False)
                if attempt == self.max_retries - 1:
                    return None
                await asyncio.sleep(2 ** attempt)
                self.stats.record(retry=True)

            except httpx.HTTPStatusError:
                self.stats.record(success=False)
                return None

            except Exception:
                self.stats.record(success=False)
                if attempt == self.max_retries - 1:
                    return None
                await asyncio.sleep(2 ** attempt)
                self.stats.record(retry=True)

        return None

    # ─── Async Methods ───────────────────────────────────────────────────────

    async def aget(self, url: str, params: Optional[Dict] = None, **kwargs) -> Optional[HTTPResponse]:
        return await self._async_request("GET", url, params=params, **kwargs)

    async def apost(
        self, url: str, data: Optional[Dict] = None,
        json: Optional[Dict] = None, **kwargs,
    ) -> Optional[HTTPResponse]:
        req_kwargs = {}
        if data is not None:
            req_kwargs["data"] = data
        if json is not None:
            req_kwargs["json"] = json
        req_kwargs.update(kwargs)
        return await self._async_request("POST", url, **req_kwargs)

    async def aput(self, url: str, data: Optional[Dict] = None, **kwargs) -> Optional[HTTPResponse]:
        return await self._async_request("PUT", url, data=data, **kwargs)

    async def adelete(self, url: str, **kwargs) -> Optional[HTTPResponse]:
        return await self._async_request("DELETE", url, **kwargs)

    async def ahead(self, url: str, **kwargs) -> Optional[HTTPResponse]:
        return await self._async_request("HEAD", url, **kwargs)

    async def aoptions(self, url: str, **kwargs) -> Optional[HTTPResponse]:
        return await self._async_request("OPTIONS", url, **kwargs)

    # Backward-compat aliases
    async def async_get(self, url: str, params: Optional[Dict] = None) -> Optional[HTTPResponse]:
        return await self.aget(url, params=params)

    async def async_post(
        self, url: str, data: Optional[Dict] = None,
        json_data: Optional[Dict] = None,
    ) -> Optional[HTTPResponse]:
        return await self.apost(url, data=data, json=json_data)

    # ─── Sync Methods (backward compatibility) ───────────────────────────────

    def get(self, url: str, params: Optional[Dict] = None, **kwargs) -> Optional[HTTPResponse]:
        return _run_sync(self.aget(url, params=params, **kwargs))

    def post(
        self, url: str, data: Optional[Dict] = None,
        json: Optional[Dict] = None, **kwargs,
    ) -> Optional[HTTPResponse]:
        return _run_sync(self.apost(url, data=data, json=json, **kwargs))

    def put(self, url: str, data: Optional[Dict] = None, **kwargs) -> Optional[HTTPResponse]:
        return _run_sync(self.aput(url, data=data, **kwargs))

    def delete(self, url: str, **kwargs) -> Optional[HTTPResponse]:
        return _run_sync(self.adelete(url, **kwargs))

    def head(self, url: str, **kwargs) -> Optional[HTTPResponse]:
        return _run_sync(self.ahead(url, **kwargs))

    def options(self, url: str, **kwargs) -> Optional[HTTPResponse]:
        return _run_sync(self.aoptions(url, **kwargs))

    async def aclose(self):
        if self._async_client and not self._closed:
            await self._async_client.aclose()
            self._async_client = None
            self._closed = True

    def close(self):
        _run_sync(self.aclose())

    async def __aenter__(self):
        await self._ensure_client()
        return self

    async def __aexit__(self, *args):
        await self.aclose()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


async def async_batch_request(
    urls: List[str],
    client: HTTPClient,
    method: str = "GET",
    semaphore_limit: int = 20,
    callback: Optional[Callable[[str, Optional[HTTPResponse]], Any]] = None,
) -> List[Dict[str, Any]]:
    """
    Batch async HTTP requests dengan semaphore untuk kontrol concurrency.
    """
    semaphore = asyncio.Semaphore(semaphore_limit)

    async def _fetch(url: str) -> Dict[str, Any]:
        async with semaphore:
            if method.upper() == "GET":
                resp = await client.aget(url)
            elif method.upper() == "HEAD":
                resp = await client.ahead(url)
            else:
                resp = await client._async_request(method.upper(), url)

            if callback:
                result = callback(url, resp)
                if result is not None:
                    return result

            if resp:
                return {
                    "url": url,
                    "status_code": resp.status_code,
                    "content_length": len(resp.content),
                    "headers": dict(resp.headers),
                    "body": resp.text[:2000],
                }
            return {"url": url, "status_code": None, "error": "Connection failed"}

    tasks = [_fetch(url) for url in urls]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    return [r for r in results if isinstance(r, dict)]


async def async_batch_get(
    urls: List[str],
    client: HTTPClient,
    semaphore_limit: int = 20,
) -> List[Dict[str, Any]]:
    """Backward-compatible batch GET."""
    return await async_batch_request(urls, client, "GET", semaphore_limit)


def normalize_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")


def extract_base_url(url: str) -> str:
    parsed = urlparse(normalize_url(url))
    return f"{parsed.scheme}://{parsed.netloc}"


def build_url(base: str, path: str) -> str:
    return urljoin(normalize_url(base), path)


def get_domain(url: str) -> str:
    parsed = urlparse(normalize_url(url))
    return parsed.netloc


def is_same_domain(url1: str, url2: str) -> bool:
    return get_domain(url1) == get_domain(url2)


if __name__ == "__main__":
    import argparse
    from rich.console import Console
    from rich.table import Table

    console = Console()
    parser = argparse.ArgumentParser(description="HTTP Client Test")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--method", default="GET", help="HTTP Method")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--threads", type=int, default=10)
    args = parser.parse_args()

    url = normalize_url(args.url)
    console.print(f"\n[cyan]Testing HTTP Client → [bold]{url}[/bold][/cyan]\n")

    reset_request_stats()
    with HTTPClient(timeout=args.timeout, threads=args.threads) as client:
        resp = client.get(url)
        if resp:
            table = Table(title="Response Info", border_style="green")
            table.add_column("Field", style="cyan")
            table.add_column("Value", style="white")
            table.add_row("Status Code", str(resp.status_code))
            table.add_row("Content-Type", resp.headers.get("Content-Type", "N/A"))
            table.add_row("Content-Length", str(len(resp.content)))
            table.add_row("Final URL", resp.url)
            stats = get_request_stats().to_dict()
            table.add_row("Requests/sec", str(stats["requests_per_sec"]))
            console.print(table)
        else:
            console.print("[red]Connection failed[/red]")
