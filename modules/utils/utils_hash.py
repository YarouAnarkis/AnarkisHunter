"""
AnarkisHunter — utils_hash.py
================================
Hash identifier dan cracker sederhana via wordlist.
Support MD5, SHA1, SHA256, SHA512, bcrypt, NTLM.

Usage standalone:
    python modules/utils/utils_hash.py --identify "5f4dcc3b5aa765d61d8327deb882cf99"
    python modules/utils/utils_hash.py --crack "5f4dcc3b5aa765d61d8327deb882cf99" --wordlist passwords.txt
"""

import sys
import re
import hashlib
import hmac
from typing import Optional, List, Tuple, Dict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


# ─── Hash Signatures ─────────────────────────────────────────────────────────

HASH_PATTERNS = {
    "MD5": re.compile(r"^[a-f0-9]{32}$", re.IGNORECASE),
    "SHA1": re.compile(r"^[a-f0-9]{40}$", re.IGNORECASE),
    "SHA224": re.compile(r"^[a-f0-9]{56}$", re.IGNORECASE),
    "SHA256": re.compile(r"^[a-f0-9]{64}$", re.IGNORECASE),
    "SHA384": re.compile(r"^[a-f0-9]{96}$", re.IGNORECASE),
    "SHA512": re.compile(r"^[a-f0-9]{128}$", re.IGNORECASE),
    "NTLM": re.compile(r"^[a-f0-9]{32}$", re.IGNORECASE),  # Same as MD5 length
    "MySQL323": re.compile(r"^[a-f0-9]{16}$", re.IGNORECASE),
    "MySQL41": re.compile(r"^\*[a-f0-9]{40}$", re.IGNORECASE),
    "bcrypt": re.compile(r"^\$2[ayb]\$[0-9]{2}\$[./A-Za-z0-9]{53}$"),
    "MD5Crypt": re.compile(r"^\$1\$[a-zA-Z0-9./]{1,8}\$[a-zA-Z0-9./]{22}$"),
    "SHA512Crypt": re.compile(r"^\$6\$[a-zA-Z0-9./]{1,8}\$[a-zA-Z0-9./]{86}$"),
    "SHA256Crypt": re.compile(r"^\$5\$[a-zA-Z0-9./]{1,8}\$[a-zA-Z0-9./]{43}$"),
    "Argon2": re.compile(r"^\$argon2[id][i]?\$"),
    "PBKDF2": re.compile(r"^pbkdf2_sha[0-9]+\$"),
    "Django PBKDF2": re.compile(r"^pbkdf2_sha256\$[0-9]+\$"),
    "CRC32": re.compile(r"^[a-f0-9]{8}$", re.IGNORECASE),
    "LM Hash": re.compile(r"^[a-f0-9]{32}:[a-f0-9]{32}$", re.IGNORECASE),  # NTLM format
    "Base64": re.compile(r"^[A-Za-z0-9+/]{4,}={0,2}$"),
    "JWT": re.compile(r"^eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+$"),
    "UUID": re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE),
}


def identify_hash(hash_str: str) -> List[str]:
    """
    Identifikasi tipe hash berdasarkan pattern.
    
    Args:
        hash_str: Hash string yang akan diidentifikasi
        
    Returns:
        List of possible hash types
    """
    hash_str = hash_str.strip()
    possible = []

    for hash_type, pattern in HASH_PATTERNS.items():
        if pattern.match(hash_str):
            possible.append(hash_type)

    # Disambiguate MD5 vs NTLM (keduanya 32 hex chars)
    if "NTLM" in possible and "MD5" in possible:
        possible = [t for t in possible if t != "NTLM"]  # Default ke MD5
        possible.append("NTLM (possible)")

    return possible if possible else ["Unknown"]


def crack_hash(
    hash_str: str,
    hash_type: str = "auto",
    wordlist: Optional[List[str]] = None,
    wordlist_file: Optional[str] = None,
    verbose: bool = False,
) -> Optional[str]:
    """
    Coba crack hash via dictionary attack.
    
    Args:
        hash_str: Hash yang akan di-crack
        hash_type: Tipe hash ('md5', 'sha1', 'sha256', dll) atau 'auto'
        wordlist: List kata-kata untuk dicoba
        wordlist_file: Path ke file wordlist
        verbose: Tampilkan progress
        
    Returns:
        Plaintext jika berhasil, None jika gagal
    """
    hash_str = hash_str.strip()

    # Auto-detect hash type
    if hash_type == "auto":
        identified = identify_hash(hash_str)
        if identified and identified[0] != "Unknown":
            hash_type = identified[0].lower().replace(" ", "_")
        else:
            return None

    # Load wordlist
    words = []
    if wordlist:
        words.extend(wordlist)
    if wordlist_file and Path(wordlist_file).exists():
        try:
            lines = Path(wordlist_file).read_text(encoding="utf-8", errors="replace").splitlines()
            words.extend(l.strip() for l in lines if l.strip())
        except Exception:
            pass

    if not words:
        # Coba common passwords sebagai fallback
        from config.settings import WORDLIST_PASSWORDS
        if Path(WORDLIST_PASSWORDS).exists():
            lines = Path(WORDLIST_PASSWORDS).read_text(encoding="utf-8", errors="replace").splitlines()
            words = [l.strip() for l in lines if l.strip()]

    # Hash functions
    hash_funcs = {
        "md5": lambda w: hashlib.md5(w.encode()).hexdigest(),
        "sha1": lambda w: hashlib.sha1(w.encode()).hexdigest(),
        "sha224": lambda w: hashlib.sha224(w.encode()).hexdigest(),
        "sha256": lambda w: hashlib.sha256(w.encode()).hexdigest(),
        "sha384": lambda w: hashlib.sha384(w.encode()).hexdigest(),
        "sha512": lambda w: hashlib.sha512(w.encode()).hexdigest(),
        "ntlm": lambda w: _ntlm_hash(w),
        "mysql323": lambda w: _mysql323_hash(w),
    }

    hash_func = hash_funcs.get(hash_type.lower())
    if not hash_func:
        return None

    target_hash = hash_str.lower()

    for i, word in enumerate(words):
        try:
            computed = hash_func(word).lower()
            if computed == target_hash:
                return word
            # Juga coba uppercase
            computed_upper = hash_func(word.upper()).lower()
            if computed_upper == target_hash:
                return word.upper()
        except Exception:
            continue

    return None


def compute_hash(text: str, algorithm: str = "md5") -> str:
    """
    Hitung hash dari sebuah teks.
    
    Args:
        text: Teks yang akan di-hash
        algorithm: 'md5', 'sha1', 'sha256', 'sha512', dll
        
    Returns:
        Hash string dalam format hex
    """
    algo_map = {
        "md5": hashlib.md5,
        "sha1": hashlib.sha1,
        "sha224": hashlib.sha224,
        "sha256": hashlib.sha256,
        "sha384": hashlib.sha384,
        "sha512": hashlib.sha512,
    }
    func = algo_map.get(algorithm.lower(), hashlib.md5)
    return func(text.encode("utf-8")).hexdigest()


def _ntlm_hash(password: str) -> str:
    """Hitung NTLM hash."""
    try:
        import hashlib
        h = hashlib.new("md4", password.encode("utf-16-le"))
        return h.hexdigest()
    except Exception:
        # MD4 mungkin tidak tersedia di semua platform
        return hashlib.md5(password.encode()).hexdigest()


def _mysql323_hash(password: str) -> str:
    """Hitung MySQL 3.23 OLD_PASSWORD hash."""
    nr = 1345345333
    add = 7
    nr2 = 0x12345671

    for c in password:
        if c in (' ', '\t'):
            continue
        tmp = ord(c)
        nr ^= (((nr & 63) + add) * tmp) + (nr << 8)
        nr2 += (nr2 << 8) ^ nr
        add += tmp

    result1 = nr & ((1 << 31) - 1)
    result2 = nr2 & ((1 << 31) - 1)
    return f"{result1:08x}{result2:08x}"


def is_hashed_password(value: str) -> Tuple[bool, List[str]]:
    """
    Cek apakah string adalah hash password.
    
    Returns:
        (is_hash, possible_types)
    """
    types = identify_hash(value)
    is_hash = types != ["Unknown"] and any(
        t in types for t in ["MD5", "SHA1", "SHA256", "SHA512", "bcrypt", "NTLM", "MySQL41"]
    )
    return is_hash, types


# ─── Standalone ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    from rich.console import Console
    from rich.table import Table

    console = Console()
    parser = argparse.ArgumentParser(description="Hash Identifier & Cracker")
    parser.add_argument("--identify", help="Hash string to identify")
    parser.add_argument("--crack", help="Hash to crack")
    parser.add_argument("--hash", help="Compute hash of text")
    parser.add_argument("--algorithm", default="md5", help="Hash algorithm (for --hash)")
    parser.add_argument("--wordlist", help="Wordlist file for cracking")
    parser.add_argument("--type", default="auto", help="Hash type for cracking")
    args = parser.parse_args()

    if args.identify:
        types = identify_hash(args.identify)
        console.print(f"\n[cyan]Hash:[/cyan] {args.identify}")
        console.print(f"[green]Possible types:[/green] {', '.join(types)}\n")

    elif args.crack:
        console.print(f"\n[cyan]Cracking:[/cyan] {args.crack}")
        console.print("[yellow]Loading wordlist...[/yellow]")
        result = crack_hash(args.crack, args.type, wordlist_file=args.wordlist)
        if result:
            console.print(f"[bold green]✅ CRACKED! Plaintext: {result}[/bold green]\n")
        else:
            console.print("[red]❌ Hash could not be cracked[/red]\n")

    elif args.hash:
        result = compute_hash(args.hash, args.algorithm)
        console.print(f"\n[cyan]{args.algorithm.upper()}([/cyan]{args.hash}[cyan])[/cyan] = [green]{result}[/green]\n")

    else:
        # Interactive demo
        console.print("\n[bold cyan]Hash Examples:[/bold cyan]")
        table = Table(border_style="cyan")
        table.add_column("Algorithm")
        table.add_column("Hash of 'password'")
        for algo in ["md5", "sha1", "sha256", "sha512"]:
            table.add_row(algo.upper(), compute_hash("password", algo))
        console.print(table)
