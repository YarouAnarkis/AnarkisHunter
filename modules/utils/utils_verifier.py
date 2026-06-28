"""
AnarkisHunter — utils_verifier.py
===================================
Baseline capture, double verification, confidence scoring,
dan false-positive filtering untuk vulnerability detection.
"""

import hashlib
import time
from typing import Optional, Dict, Any, Callable, List

from modules.utils.utils_diff import ResponseDiff


class FindingVerifier:
    """
    Verifikasi temuan kerentanan dengan:
    1. Baseline request (response normal)
    2. Double verification (2x konfirmasi)
    3. Confidence score 0-100%
    4. Skip jika response identik dengan baseline
    """

    def __init__(self, client, url: str):
        self.client = client
        self.url = url
        self.differ = ResponseDiff()
        self.baseline: Optional[Dict] = None
        self._verified_cache: Dict[str, bool] = {}

    def capture_baseline(self) -> Optional[Dict]:
        """Rekam response baseline sebelum scan."""
        self.baseline = self.differ.capture_baseline(self.url, self.client)
        return self.baseline

    @property
    def baseline_hash(self) -> str:
        if not self.baseline:
            return ""
        return self.baseline.get("body_hash", "")

    def _response_fingerprint(self, resp) -> str:
        if not resp:
            return ""
        return hashlib.md5(resp.content).hexdigest()

    def is_same_as_baseline(self, resp) -> bool:
        """True jika response identik dengan baseline → bukan vulnerability."""
        if not self.baseline or not resp:
            return False
        return self._response_fingerprint(resp) == self.baseline_hash

    def verify_finding(
        self,
        test_url: str,
        check_fn: Callable[[Any, Any], Optional[Dict]],
        min_confidence: int = 50,
    ) -> Optional[Dict]:
        """
        Verifikasi temuan dengan 2x konfirmasi.

        Args:
            test_url: URL dengan payload
            check_fn: (baseline_resp, test_resp) → finding dict atau None
            min_confidence: Minimum confidence untuk dilaporkan

        Returns:
            Finding dict dengan confidence score, atau None jika false positive
        """
        cache_key = hashlib.md5(test_url.encode()).hexdigest()
        if cache_key in self._verified_cache:
            return None if not self._verified_cache[cache_key] else {"cached": True}

        if not self.baseline:
            self.capture_baseline()

        base_resp = self.client.get(self.url)
        if not base_resp:
            return None

        # Verifikasi 1
        resp1 = self.client.get(test_url)
        if not resp1 or self.is_same_as_baseline(resp1):
            self._verified_cache[cache_key] = False
            return None

        finding1 = check_fn(base_resp, resp1)
        if not finding1:
            self._verified_cache[cache_key] = False
            return None

        # Verifikasi 2 (konfirmasi ulang)
        time.sleep(0.3)
        resp2 = self.client.get(test_url)
        if not resp2 or self.is_same_as_baseline(resp2):
            self._verified_cache[cache_key] = False
            return None

        finding2 = check_fn(base_resp, resp2)
        if not finding2:
            self._verified_cache[cache_key] = False
            return None

        # Hitung confidence dari diff analysis
        diff_result = self.differ.compare(test_url, self.client, label="verify")
        confidence = diff_result.get("confidence", 0)

        if finding1.get("type") == "Error-based":
            confidence = max(confidence, 85)
        elif finding1.get("type") == "Time-based":
            confidence = max(confidence, 90)
        elif finding1.get("type") == "Boolean-based":
            confidence = max(confidence, 60)

        if confidence < min_confidence:
            self._verified_cache[cache_key] = False
            return None

        self._verified_cache[cache_key] = True
        finding1["confidence"] = min(confidence, 100)
        finding1["verified"] = True
        finding1["verification_count"] = 2
        return finding1

    async def async_verify_finding(
        self,
        test_url: str,
        check_fn: Callable[[Any, Any], Optional[Dict]],
        min_confidence: int = 50,
    ) -> Optional[Dict]:
        """Async version of verify_finding."""
        cache_key = hashlib.md5(test_url.encode()).hexdigest()
        if cache_key in self._verified_cache:
            return None if not self._verified_cache[cache_key] else {"cached": True}

        if not self.baseline:
            self.capture_baseline()

        base_resp = await self.client.aget(self.url)
        if not base_resp:
            return None

        resp1 = await self.client.aget(test_url)
        if not resp1 or self.is_same_as_baseline(resp1):
            self._verified_cache[cache_key] = False
            return None

        finding1 = check_fn(base_resp, resp1)
        if not finding1:
            self._verified_cache[cache_key] = False
            return None

        import asyncio
        await asyncio.sleep(0.3)

        resp2 = await self.client.aget(test_url)
        if not resp2 or self.is_same_as_baseline(resp2):
            self._verified_cache[cache_key] = False
            return None

        finding2 = check_fn(base_resp, resp2)
        if not finding2:
            self._verified_cache[cache_key] = False
            return None

        diff_result = self.differ.compare(test_url, self.client, label="verify")
        confidence = diff_result.get("confidence", 0)

        if finding1.get("type") == "Error-based":
            confidence = max(confidence, 85)
        elif finding1.get("type") == "Time-based":
            confidence = max(confidence, 90)

        if confidence < min_confidence:
            self._verified_cache[cache_key] = False
            return None

        self._verified_cache[cache_key] = True
        finding1["confidence"] = min(confidence, 100)
        finding1["verified"] = True
        return finding1


def confidence_to_severity(confidence: int, base_severity: str = "MEDIUM") -> str:
    """Adjust severity based on confidence score."""
    if confidence >= 90:
        return base_severity
    elif confidence >= 70:
        severity_map = {"CRITICAL": "HIGH", "HIGH": "HIGH", "MEDIUM": "MEDIUM"}
        return severity_map.get(base_severity, base_severity)
    elif confidence >= 50:
        severity_map = {"CRITICAL": "MEDIUM", "HIGH": "MEDIUM", "MEDIUM": "LOW"}
        return severity_map.get(base_severity, "LOW")
    return "INFO"
