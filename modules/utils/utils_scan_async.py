"""
AnarkisHunter — utils_scan_async.py
=====================================
Async parallel scanning helpers untuk modul scanner.
"""

import asyncio
import inspect
from typing import Any, Callable, Dict, List, Optional, TypeVar

from modules.utils.utils_request import HTTPClient, async_batch_request

T = TypeVar("T")


async def async_parallel_scan(
    items: List[Any],
    scan_fn: Callable,
    client: HTTPClient,
    threads: int = 20,
    progress_callback: Optional[Callable[[int, int], None]] = None,
) -> List[Any]:
    """
    Generic async parallel scanner.
    scan_fn(item, client) → result dict or None
    """
    semaphore = asyncio.Semaphore(threads)
    results = []
    completed = 0
    total = len(items)
    lock = asyncio.Lock()

    async def _scan_one(item):
        nonlocal completed
        async with semaphore:
            try:
                if inspect.iscoroutinefunction(scan_fn):
                    result = await scan_fn(item, client)
                else:
                    loop = asyncio.get_event_loop()
                    result = await loop.run_in_executor(None, scan_fn, item, client)
            except Exception:
                result = None

            async with lock:
                completed += 1
                if progress_callback:
                    progress_callback(completed, total)

            return result

    tasks = [_scan_one(item) for item in items]
    raw = await asyncio.gather(*tasks, return_exceptions=True)
    return [r for r in raw if r is not None and not isinstance(r, Exception)]


async def async_url_scan(
    urls: List[str],
    client: HTTPClient,
    threads: int = 20,
    method: str = "GET",
    filter_fn: Optional[Callable[[Dict], bool]] = None,
) -> List[Dict]:
    """
    Scan list of URLs in parallel, optionally filter results.
    """
    results = await async_batch_request(urls, client, method, threads)
    if filter_fn:
        return [r for r in results if filter_fn(r)]
    return results


def run_async(coro):
    """Run async coroutine from sync context."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    else:
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(asyncio.run, coro).result()
