"""
AnarkisHunter — utils_wordlist.py
====================================
Wordlist manager: load, merge, deduplicate, filter, preview wordlists.

Usage standalone:
    python modules/utils/utils_wordlist.py --list directories
    python modules/utils/utils_wordlist.py --preview --file /path/to/list.txt
"""

import sys
import random
from pathlib import Path
from typing import List, Optional, Iterator

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from config.settings import (
    WORDLIST_COMMON, WORDLIST_DIRS, WORDLIST_SUBDOMAINS, WORDLIST_PASSWORDS
)

# ─── Built-in mini wordlists ─────────────────────────────────────────────────

BUILTIN_DIRS = [
    "admin", "administrator", "login", "dashboard", "panel", "cpanel",
    "wp-admin", "phpmyadmin", "api", "v1", "v2", "test", "backup",
    "config", "upload", "uploads", "files", "images", "img", "css",
    "js", "static", "assets", "vendor", "lib", "libs", "includes",
    "inc", "src", "dist", "public", "private", "secret", "hidden",
    "docs", "documentation", "help", "support", "contact", "about",
    "index", "home", "main", "default", "old", "new", "dev", "staging",
    "prod", "production", "temp", "tmp", "cache", "logs", "log",
    "data", "db", "database", "sql", "dump", "export", "import",
    "user", "users", "account", "accounts", "profile", "profiles",
    "register", "signup", "signin", "logout", "auth", "token",
    "shop", "cart", "checkout", "product", "products", "category",
    "search", "filter", "sort", "order", "orders", "payment",
    "portal", "secure", "ssl", "www", "ftp", "mail", "email",
    "wp-content", "wp-includes", "wordpress", "joomla", "drupal",
    "laravel", "symfony", "django", "flask", "spring", "rails",
    "server-status", "server-info", ".git", ".svn", ".env",
    "phpinfo.php", "info.php", "test.php", "shell.php",
    "robots.txt", "sitemap.xml", "crossdomain.xml",
    "web.config", ".htaccess", ".htpasswd",
]

BUILTIN_SUBDOMAINS = [
    "www", "mail", "email", "ftp", "admin", "administrator",
    "api", "api2", "dev", "development", "staging", "test",
    "demo", "beta", "alpha", "preview", "sandbox",
    "blog", "shop", "store", "forum", "wiki", "docs",
    "support", "help", "status", "monitor", "dashboard",
    "app", "mobile", "m", "cdn", "static", "assets",
    "vpn", "remote", "ssh", "sftp", "backup",
    "db", "database", "mysql", "postgres", "mongodb",
    "redis", "cache", "queue", "worker", "cron",
    "jenkins", "gitlab", "github", "jira", "confluence",
    "grafana", "kibana", "elastic", "prometheus",
    "portal", "intranet", "internal", "private", "secure",
    "ns1", "ns2", "mx1", "mx2", "smtp", "pop", "imap",
    "media", "video", "img", "images", "upload", "uploads",
    "old", "legacy", "v1", "v2", "v3",
    "aws", "gcp", "azure", "cloud",
]

BUILTIN_PASSWORDS = [
    "123456", "password", "12345678", "qwerty", "123456789",
    "12345", "1234567", "password123", "1234567890", "0987654321",
    "abc123", "letmein", "monkey", "1234", "dragon",
    "master", "iloveyou", "sunshine", "princess", "admin",
    "root", "toor", "pass", "test", "guest", "changeme",
    "default", "welcome", "login", "user", "administrator",
    "P@ssw0rd", "P@$$w0rd", "Admin@123", "Admin1234",
    "password1", "Password1", "Password123!", "Passw0rd!",
    "qwerty123", "111111", "123123", "000000", "654321",
    "666666", "888888", "987654321", "pass123", "test123",
    "admin123", "root123", "user123", "superuser", "superman",
    "batman", "spider", "hello", "world", "secret", "security",
    "hacker", "crack", "hack", "system", "network", "server",
]

BUILTIN_COMMON = BUILTIN_DIRS + [
    "index.php", "index.html", "index.htm", "index.asp", "index.aspx",
    "login.php", "login.html", "register.php", "signup.php",
    "admin.php", "administrator.php", "panel.php", "dashboard.php",
    "config.php", "settings.php", "setup.php", "install.php",
    "phpinfo.php", "info.php", "test.php", "upload.php",
    "backup.zip", "backup.tar.gz", "backup.sql", "dump.sql",
    "db.php", "database.php", "connect.php", "connection.php",
    ".env", ".env.local", ".env.production", ".env.backup",
    "composer.json", "package.json", "requirements.txt",
    "README.md", "CHANGELOG.md", "TODO",
    "error.log", "access.log", "debug.log",
]


class WordlistManager:
    """
    Manager untuk loading dan manipulasi wordlists.
    """

    def __init__(self):
        self._builtin = {
            "common": BUILTIN_COMMON,
            "directories": BUILTIN_DIRS,
            "subdomains": BUILTIN_SUBDOMAINS,
            "passwords": BUILTIN_PASSWORDS,
        }

    def load(self, wordlist_type: str = "common", filepath: Optional[str] = None) -> List[str]:
        """
        Load wordlist dari file atau built-in.
        
        Args:
            wordlist_type: 'common', 'directories', 'subdomains', 'passwords'
            filepath: Path ke file custom (opsional)
            
        Returns:
            List of words
        """
        # Prioritas: file custom > file wordlist > built-in
        if filepath and Path(filepath).exists():
            return self._load_file(filepath)

        file_map = {
            "common": WORDLIST_COMMON,
            "directories": WORDLIST_DIRS,
            "subdomains": WORDLIST_SUBDOMAINS,
            "passwords": WORDLIST_PASSWORDS,
        }

        if wordlist_type in file_map and Path(file_map[wordlist_type]).exists():
            words = self._load_file(str(file_map[wordlist_type]))
            if words:
                return words

        # Fallback ke built-in
        return self._builtin.get(wordlist_type, BUILTIN_COMMON).copy()

    def _load_file(self, filepath: str) -> List[str]:
        """Load wordlist dari file teks."""
        try:
            content = Path(filepath).read_text(encoding="utf-8", errors="replace")
            words = [
                line.strip()
                for line in content.splitlines()
                if line.strip() and not line.startswith("#")
            ]
            return self._deduplicate(words)
        except Exception:
            return []

    def _deduplicate(self, words: List[str]) -> List[str]:
        """Hilangkan duplikasi sambil menjaga urutan."""
        seen = set()
        result = []
        for w in words:
            if w not in seen:
                seen.add(w)
                result.append(w)
        return result

    def merge(self, *wordlists: List[str]) -> List[str]:
        """Merge beberapa wordlist dan deduplicate."""
        merged = []
        for wl in wordlists:
            merged.extend(wl)
        return self._deduplicate(merged)

    def filter(self, words: List[str], min_length: int = 1,
               max_length: int = 100, pattern: Optional[str] = None) -> List[str]:
        """
        Filter wordlist berdasarkan kriteria.
        
        Args:
            words: Input wordlist
            min_length: Minimum panjang kata
            max_length: Maximum panjang kata
            pattern: Regex pattern filter (opsional)
        """
        import re
        result = [w for w in words if min_length <= len(w) <= max_length]
        if pattern:
            try:
                regex = re.compile(pattern)
                result = [w for w in result if regex.search(w)]
            except Exception:
                pass
        return result

    def shuffle(self, words: List[str]) -> List[str]:
        """Shuffle wordlist secara acak."""
        shuffled = words.copy()
        random.shuffle(shuffled)
        return shuffled

    def chunk(self, words: List[str], size: int) -> Iterator[List[str]]:
        """Split wordlist menjadi chunks untuk threading."""
        for i in range(0, len(words), size):
            yield words[i:i + size]

    def preview(self, words: List[str], n: int = 20) -> List[str]:
        """Preview n kata pertama dan terakhir."""
        if len(words) <= n * 2:
            return words
        return words[:n] + ["... ({} more) ...".format(len(words) - n * 2)] + words[-n:]

    def add_extensions(self, words: List[str], extensions: List[str]) -> List[str]:
        """
        Tambahkan ekstensi file ke setiap word.
        Berguna untuk directory bruteforce dengan extension.
        
        Example: "admin" + [".php", ".html"] → ["admin", "admin.php", "admin.html"]
        """
        result = []
        for word in words:
            result.append(word)
            for ext in extensions:
                if not ext.startswith("."):
                    ext = "." + ext
                result.append(word + ext)
        return self._deduplicate(result)

    def generate_mutations(self, word: str) -> List[str]:
        """
        Generate mutasi dari sebuah kata untuk password testing.
        
        Example: "admin" → ["admin1", "Admin", "ADMIN", "admin@123", ...]
        """
        mutations = [word]
        mutations.extend([
            word + "1", word + "123", word + "1234", word + "12345",
            word + "!", word + "123!", word + "@123", word + "#123",
            word.capitalize(), word.upper(), word.lower(),
            word.capitalize() + "1", word.capitalize() + "123",
            word.capitalize() + "!", word.capitalize() + "@123",
            word + "2024", word + "2025", word + "2023",
            "1" + word, "123" + word, word + "000",
        ])
        return self._deduplicate(mutations)


# Global instance
wordlist_manager = WordlistManager()


# ─── Standalone ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    from rich.console import Console
    from rich.table import Table

    console = Console()
    parser = argparse.ArgumentParser(description="Wordlist Manager")
    parser.add_argument("--list", choices=["common", "directories", "subdomains", "passwords"])
    parser.add_argument("--file", help="Custom wordlist file")
    parser.add_argument("--preview", action="store_true")
    parser.add_argument("--count", action="store_true")
    parser.add_argument("--stats", action="store_true")
    args = parser.parse_args()

    wm = WordlistManager()

    if args.stats:
        table = Table(title="Built-in Wordlist Stats", border_style="cyan")
        table.add_column("Wordlist", style="cyan")
        table.add_column("Count", style="green")
        for name, wl in wm._builtin.items():
            table.add_row(name.capitalize(), str(len(wl)))
        console.print(table)

    elif args.list or args.file:
        wtype = args.list or "common"
        words = wm.load(wtype, args.file)

        if args.count:
            console.print(f"\n[green]Total words: {len(words)}[/green]\n")
        elif args.preview:
            preview_words = wm.preview(words, 15)
            for i, w in enumerate(preview_words, 1):
                console.print(f"  [dim]{i:4d}[/dim] {w}")
        else:
            for w in words:
                print(w)
