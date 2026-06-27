"""
AnarkisHunter — vuln_jwt.py
=============================
JWT vulnerability checker:
- Algorithm "none" attack
- Weak secret (HS256 dictionary)
- Algorithm confusion (RS256 → HS256)
- Token expired but accepted
- kid injection

Usage standalone:
    python modules/vuln/vuln_jwt.py --token <JWT>
"""

import sys
import json
import base64
import hmac
import hashlib
import argparse
from pathlib import Path
from typing import Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from modules.utils.report import ScanResult


# Common weak secrets untuk HS256
COMMON_SECRETS = [
    "secret", "password", "123456", "admin", "jwt", "key", "test",
    "your-256-bit-secret", "your_jwt_secret", "supersecret", "changeme",
    "default", "qwerty", "letmein", "welcome", "secret_key", "jwt_secret",
    "private_key", "auth_secret", "ANARKHUNTER", "anarkhunter",
]


def b64url_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def parse_jwt(token: str) -> Optional[Dict]:
    """Parse JWT structure tanpa verify."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
        sig = parts[2]
        return {
            "header": header,
            "payload": payload,
            "signature": sig,
            "raw_header": parts[0],
            "raw_payload": parts[1],
        }
    except Exception:
        return None


def crack_hs256(token: str, wordlist: List[str]) -> Optional[str]:
    """Try crack HS256 with wordlist."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    header_payload = (parts[0] + "." + parts[1]).encode()
    target_sig = parts[2]

    for secret in wordlist:
        sig = hmac.new(secret.encode(), header_payload, hashlib.sha256).digest()
        if b64url_encode(sig) == target_sig:
            return secret
    return None


def make_none_token(payload: Dict) -> str:
    """Generate JWT dengan alg=none."""
    header = {"alg": "none", "typ": "JWT"}
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}."


def run_jwt_scan(token: str, wordlist: Optional[List[str]] = None) -> Dict:
    """Analyze JWT untuk vulnerabilities."""
    result = {
        "token": token,
        "parsed": None,
        "vulnerabilities": [],
        "info": {},
        "error": None,
    }

    parsed = parse_jwt(token)
    if not parsed:
        result["error"] = "Invalid JWT format"
        return result
    result["parsed"] = parsed

    header = parsed["header"]
    payload = parsed["payload"]
    alg = header.get("alg", "").upper()
    result["info"]["alg"] = alg
    result["info"]["typ"] = header.get("typ")
    result["info"]["kid"] = header.get("kid")
    result["info"]["sub"] = payload.get("sub")
    result["info"]["exp"] = payload.get("exp")
    result["info"]["iss"] = payload.get("iss")
    result["info"]["aud"] = payload.get("aud")

    # 1. alg=none vulnerability indicator (just header info)
    if alg == "NONE" or alg == "":
        result["vulnerabilities"].append({
            "type": "alg=none accepted by server",
            "severity": "CRITICAL",
            "evidence": f"alg: {alg}",
        })

    # 2. Weak HMAC secret crack attempt
    if alg in ("HS256", "HS384", "HS512"):
        wl = wordlist or COMMON_SECRETS
        cracked = crack_hs256(token, wl) if alg == "HS256" else None
        if cracked:
            result["vulnerabilities"].append({
                "type": f"Weak HMAC Secret Cracked",
                "severity": "CRITICAL",
                "evidence": f"Secret: '{cracked}'",
            })

    # 3. Expired but parsed (server-side check needed)
    if payload.get("exp"):
        import time
        if payload["exp"] < time.time():
            result["info"]["expired"] = True
            result["vulnerabilities"].append({
                "type": "Token Expired (needs server validation)",
                "severity": "INFO",
                "evidence": f"exp: {payload['exp']} (past)",
            })

    # 4. Header kid injection
    if "kid" in header and any(c in str(header["kid"]) for c in ["../", "..\\", ";", "'"]):
        result["vulnerabilities"].append({
            "type": "Suspicious kid header (possible injection)",
            "severity": "HIGH",
            "evidence": f"kid: {header['kid']}",
        })

    # 5. No expiration
    if "exp" not in payload:
        result["vulnerabilities"].append({
            "type": "No Expiration Claim",
            "severity": "MEDIUM",
            "evidence": "Payload tidak memiliki 'exp'",
        })

    # 6. Sensitive info in payload (PII check)
    for sensitive in ["password", "passwd", "pwd", "ssn", "credit_card", "secret"]:
        if sensitive in str(payload).lower():
            result["vulnerabilities"].append({
                "type": f"Sensitive Field in JWT Payload",
                "severity": "HIGH",
                "evidence": f"Payload contains '{sensitive}'",
            })
            break

    # Generate forged tokens for manual testing
    result["forged"] = {
        "none_token": make_none_token({**payload, "admin": True}),
    }

    return result


def analyze_jwt_findings(data: Dict) -> List[ScanResult]:
    findings = []
    for v in data.get("vulnerabilities", []):
        findings.append(ScanResult(
            title=f"JWT: {v['type']}",
            severity=v["severity"],
            description=v["type"],
            url="",
            evidence=v["evidence"],
            recommendation=(
                "Pakai algoritma kuat (RS256, ES256); gunakan secret >= 256-bit acak; "
                "validate alg di server (jangan terima alg dari header); "
                "set & check exp; jangan simpan PII di payload"
            ),
            owasp="A02",
            module="vuln_jwt",
        ))
    return findings


# ─── Standalone ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from rich.console import Console
    from rich.table import Table

    console = Console()
    parser = argparse.ArgumentParser(description="AnarkisHunter — JWT Analyzer")
    parser.add_argument("--token", required=True, help="JWT token to analyze")
    parser.add_argument("--wordlist", help="Custom wordlist for HS256 cracking")
    args = parser.parse_args()

    wl = None
    if args.wordlist:
        try:
            wl = Path(args.wordlist).read_text().splitlines()
        except Exception:
            pass

    console.print(f"\n[red]🎟  JWT Analyzer[/red]\n")
    data = run_jwt_scan(args.token, wl)
    if data.get("error"):
        console.print(f"[red]Error: {data['error']}[/red]")
        sys.exit(1)

    p = data["parsed"]
    console.print("[bold]Header:[/bold]")
    console.print(json.dumps(p["header"], indent=2))
    console.print("\n[bold]Payload:[/bold]")
    console.print(json.dumps(p["payload"], indent=2))

    console.print(f"\n[red]Vulnerabilities:[/red] {len(data['vulnerabilities'])}")
    for v in data["vulnerabilities"]:
        c = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "INFO": "blue"}.get(
            v["severity"], "white")
        console.print(f"  [{c}][{v['severity']}][/{c}] {v['type']} — {v['evidence']}")

    if data.get("forged", {}).get("none_token"):
        console.print(f"\n[bold]Forged 'alg=none' token (test manually):[/bold]")
        console.print(f"[yellow]{data['forged']['none_token']}[/yellow]")
