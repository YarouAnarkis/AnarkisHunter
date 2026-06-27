"""
AnarkisHunter — utils_encode.py
==================================
Encoder/Decoder: URL, Base64, HTML Entity, Hex, Unicode, ROT13.
Digunakan untuk manipulasi payload dan decode hasil eksploitasi.

Usage standalone:
    python modules/utils/utils_encode.py --encode base64 --input "hello world"
    python modules/utils/utils_encode.py --decode url --input "hello%20world"
"""

import sys
import base64
import urllib.parse
import html
import binascii
import codecs
import json
from typing import Optional


def url_encode(text: str, full: bool = False) -> str:
    """
    URL encode sebuah string.
    
    Args:
        text: String yang akan diencoding
        full: Jika True, encode semua karakter termasuk safe chars
    """
    if full:
        return "".join(f"%{ord(c):02X}" for c in text)
    return urllib.parse.quote(text, safe="")


def url_decode(text: str) -> str:
    """URL decode sebuah string."""
    try:
        return urllib.parse.unquote(text)
    except Exception:
        return text


def double_url_encode(text: str) -> str:
    """Double URL encode — berguna untuk WAF bypass."""
    return url_encode(url_encode(text))


def base64_encode(text: str, url_safe: bool = False) -> str:
    """
    Base64 encode.
    
    Args:
        text: String yang akan diencoding
        url_safe: Gunakan URL-safe Base64 (- dan _ bukan + dan /)
    """
    encoded = text.encode("utf-8")
    if url_safe:
        return base64.urlsafe_b64encode(encoded).decode("utf-8")
    return base64.b64encode(encoded).decode("utf-8")


def base64_decode(text: str, url_safe: bool = False) -> str:
    """Base64 decode dengan padding otomatis."""
    try:
        # Tambah padding jika perlu
        text = text.strip()
        padding = 4 - len(text) % 4
        if padding != 4:
            text += "=" * padding
        if url_safe:
            return base64.urlsafe_b64decode(text).decode("utf-8", errors="replace")
        return base64.b64decode(text).decode("utf-8", errors="replace")
    except Exception as e:
        return f"[Error decoding Base64: {e}]"


def html_encode(text: str, full: bool = False) -> str:
    """
    HTML entity encode.
    
    Args:
        text: String yang akan diencoding
        full: Jika True, encode semua karakter ke &#decimal;
    """
    if full:
        return "".join(f"&#{ord(c)};" for c in text)
    return html.escape(text, quote=True)


def html_decode(text: str) -> str:
    """HTML entity decode."""
    return html.unescape(text)


def hex_encode(text: str, prefix: str = "") -> str:
    """
    Hex encode.
    
    Args:
        text: String yang akan diencoding
        prefix: Prefix per byte (misal "\\x" atau "0x")
    """
    hex_bytes = binascii.hexlify(text.encode("utf-8")).decode()
    if prefix:
        return "".join(prefix + hex_bytes[i:i+2] for i in range(0, len(hex_bytes), 2))
    return hex_bytes


def hex_decode(text: str) -> str:
    """Hex decode — bersihkan prefix \\x, 0x, atau spasi otomatis."""
    text = text.replace("\\x", "").replace("0x", "").replace(" ", "").replace(",", "")
    try:
        return binascii.unhexlify(text).decode("utf-8", errors="replace")
    except Exception as e:
        return f"[Error decoding Hex: {e}]"


def unicode_encode(text: str) -> str:
    """Unicode escape encode (\u0041 format)."""
    return text.encode("unicode_escape").decode("ascii")


def unicode_decode(text: str) -> str:
    """Unicode escape decode."""
    try:
        return text.encode("ascii").decode("unicode_escape")
    except Exception:
        return text


def rot13_encode(text: str) -> str:
    """ROT13 encode/decode (simetris)."""
    return codecs.encode(text, "rot_13")


def ascii_encode(text: str) -> str:
    """Encode ke ASCII decimal per karakter (misal: 65 66 67)."""
    return " ".join(str(ord(c)) for c in text)


def ascii_decode(text: str) -> str:
    """Decode dari ASCII decimal."""
    try:
        parts = text.split()
        return "".join(chr(int(p)) for p in parts)
    except Exception as e:
        return f"[Error: {e}]"


def binary_encode(text: str) -> str:
    """Encode ke binary string."""
    return " ".join(format(ord(c), "08b") for c in text)


def binary_decode(text: str) -> str:
    """Decode dari binary string."""
    try:
        parts = text.split()
        return "".join(chr(int(p, 2)) for p in parts)
    except Exception as e:
        return f"[Error: {e}]"


def jwt_decode_parts(token: str) -> dict:
    """
    Decode JWT tanpa verifikasi signature.
    Returns: dict berisi header, payload, signature_raw
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {"error": "Invalid JWT format"}

        header = json.loads(base64_decode(parts[0], url_safe=True))
        payload = json.loads(base64_decode(parts[1], url_safe=True))

        return {
            "header": header,
            "payload": payload,
            "signature": parts[2],
        }
    except Exception as e:
        return {"error": str(e)}


def encode_for_sqli(payload: str) -> dict:
    """
    Return berbagai encoding dari SQLi payload untuk bypass.
    """
    return {
        "original": payload,
        "url_encoded": url_encode(payload),
        "double_url": double_url_encode(payload),
        "hex": hex_encode(payload, prefix="0x"),
        "html_entity": html_encode(payload),
        "unicode": unicode_encode(payload),
    }


def encode_for_xss(payload: str) -> dict:
    """
    Return berbagai encoding dari XSS payload untuk bypass WAF.
    """
    return {
        "original": payload,
        "url_encoded": url_encode(payload),
        "double_url": double_url_encode(payload),
        "html_entity": html_encode(payload),
        "unicode": unicode_encode(payload),
        "hex_chars": "".join(f"&#x{ord(c):02X};" for c in payload),
        "decimal_chars": "".join(f"&#{ord(c)};" for c in payload),
    }


# ─── Standalone ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    from rich.console import Console
    from rich.table import Table

    console = Console()
    parser = argparse.ArgumentParser(description="AnarkisHunter Encoder/Decoder")
    parser.add_argument("--encode", choices=["url", "base64", "html", "hex", "unicode", "rot13", "ascii", "binary"])
    parser.add_argument("--decode", choices=["url", "base64", "html", "hex", "unicode", "ascii", "binary"])
    parser.add_argument("--input", required=True, help="Input string")
    parser.add_argument("--all", action="store_true", help="Encode to all formats")
    args = parser.parse_args()

    text = args.input

    if args.all:
        table = Table(title=f"All Encodings for: {text[:50]}", border_style="cyan")
        table.add_column("Format", style="cyan")
        table.add_column("Encoded Value", style="green")
        table.add_row("URL Encode", url_encode(text))
        table.add_row("Double URL", double_url_encode(text))
        table.add_row("Base64", base64_encode(text))
        table.add_row("Base64 URL-Safe", base64_encode(text, url_safe=True))
        table.add_row("HTML Entity", html_encode(text))
        table.add_row("HTML Full", html_encode(text, full=True))
        table.add_row("Hex", hex_encode(text))
        table.add_row("Hex (\\x)", hex_encode(text, prefix="\\x"))
        table.add_row("Unicode", unicode_encode(text))
        table.add_row("ROT13", rot13_encode(text))
        table.add_row("ASCII Decimal", ascii_encode(text))
        table.add_row("Binary", binary_encode(text))
        console.print(table)

    elif args.encode:
        ops = {
            "url": url_encode, "base64": base64_encode, "html": html_encode,
            "hex": hex_encode, "unicode": unicode_encode,
            "rot13": rot13_encode, "ascii": ascii_encode, "binary": binary_encode,
        }
        result = ops[args.encode](text)
        console.print(f"\n[green]Encoded ({args.encode}):[/green] {result}\n")

    elif args.decode:
        ops = {
            "url": url_decode, "base64": base64_decode, "html": html_decode,
            "hex": hex_decode, "unicode": unicode_decode,
            "ascii": ascii_decode, "binary": binary_decode,
        }
        result = ops[args.decode](text)
        console.print(f"\n[cyan]Decoded ({args.decode}):[/cyan] {result}\n")
