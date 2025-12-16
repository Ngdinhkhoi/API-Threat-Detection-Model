# utils_clean.py
import math
from collections import Counter
import urllib.parse
import html
import re

# ============================================
# BASIC FEATURE FUNCTIONS
# ============================================

def calc_entropy(s: str) -> float:
    """Entropy đo mức độ encode/obfuscate."""
    if not s:
        return 0.0
    s = str(s)
    total = len(s)
    counts = Counter(s)
    ent = 0.0
    for c in counts.values():
        p = c / total
        ent -= p * math.log2(p)
    return ent


def normalize_for_tfidf(text: str, max_decode_rounds: int = 3) -> str:
    """Normalize mạnh để lộ payload encode."""
    if text is None:
        return ""
    s = str(text)

    # Multi URL decode
    for _ in range(max_decode_rounds):
        try:
            new_s = urllib.parse.unquote_plus(s)
        except Exception:
            break
        if new_s == s:
            break
        s = new_s

    s = html.unescape(s)
    s = s.lower()

    # Replace whitespace
    s = s.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    s = re.sub(r"\s+", " ", s).strip()

    return s


def count_special_chars(s: str) -> int:
    if not s:
        return 0
    return sum(1 for ch in s if not ch.isalnum() and not ch.isspace())


def longest_special_run(s: str) -> int:
    if not s:
        return 0
    cur = 0
    max_run = 0
    for ch in s:
        if not ch.isalnum() and not ch.isspace():
            cur += 1
            max_run = max(max_run, cur)
        else:
            cur = 0
    return max_run


# ============================================
# CMD / SHELL FEATURE FUNCTIONS
# ============================================

_CMD_KEYWORDS = [
    "ls", "cat", "wget", "curl", "chmod", "chown",
    "rm ", "rm -rf", "mv ", "cp ", "echo ", "id", "whoami",
    "uname", "ping", "nc ", "netcat", "bash", "sh ", "/bin/sh",
    "/bin/bash", "nohup", "python", "perl", "php ", "nc -e",
]

def find_cmd_keyword_count(s: str) -> int:
    if not s:
        return 0
    s = s.lower()
    return sum(s.count(k) for k in _CMD_KEYWORDS)


def count_cmd_special(s: str) -> int:
    """Các ký tự mạnh cho CMD injection."""
    if not s:
        return 0
    s = s.lower()
    patterns = [";", "&&", "||", "|", "`", "$(", ")", ">>", "<", "&"]
    return sum(s.count(p) for p in patterns)


def count_shell_patterns(s: str) -> int:
    if not s:
        return 0
    s = s.lower()
    pats = ["sh -c", "/bin/sh", "/bin/bash",
            "$(whoami", "$(id", "$(uname", "$(curl", "$(wget"]
    return sum(s.count(p) for p in pats)


def count_path_traversal(s: str) -> int:
    if not s:
        return 0
    s = s.lower()
    pats = ["../", "..\\", "%2e%2e%2f", "%2e%2e\\",
            "..%2f", "%252e%252e%252f"]
    return sum(s.count(p) for p in pats)


def count_sensitive_files(s: str) -> int:
    if not s:
        return 0
    s = s.lower()
    targets = [
        "/etc/passwd", "/etc/shadow", "/etc/hosts",
        "id_rsa", "id_dsa", "authorized_keys",
        "web.config", "config.php", "settings.py",
        ".htaccess", "wp-config.php",
    ]
    return sum(s.count(t) for t in targets)


# ============================================
# SQL FEATURE FUNCTIONS (UPGRADED)
# ============================================

_SQL_KEYWORDS = [
    "select", "union", "insert", "update", "delete",
    "drop", "truncate", "alter", "create",
    "from", "where", "group by", "order by",
    "having", "limit", "offset",
    "into", "values", "join", "inner join", "outer join",
    "sleep", "benchmark",
]

_SQL_HEX_RE = re.compile(r"0x[0-9a-f]{4,}", re.IGNORECASE)
_SQL_OBFUSCATE_RE = re.compile(r"/\*![0-9]*\s*select", re.IGNORECASE)
_SQL_UNION_OBFUS_RE = re.compile(r"union(?:/\*.*?\*/|\s+)+select", re.IGNORECASE)
_SQL_OR_TRUE_RE = re.compile(r"\bor\s*[/\*\)\(+\s]*1\s*=\s*1", re.IGNORECASE)
_SQL_UNICODE_QUOTE_RE = re.compile(r"\\u0*0*27", re.IGNORECASE)

_SQL_FUNC_RE = re.compile(
    r"\b(?:ascii|char|count|sum|avg|min|max|substr|substring|md5|sha1|"
    r"concat|database|schema|version|sleep|benchmark|if|pg_sleep|pg_read_file|"
    r"json_extract|extractvalue|updatexml)\s*\(",
    re.IGNORECASE,
)

_SQL_LOGIC_RE = re.compile(
    r"(?:\bor\b|\band\b|\bxor\b)\s+[0-9a-z_'\"]+\s*=\s*[0-9a-z_'\"]+",
    re.IGNORECASE,
)

_SQL_URL_SIGNS = [
    "%27", "%22", "%23", "%20or%20", "%20and%20",
    "%2527", "%2520", "%255c", "%253d",
]


def count_sql_keywords(s: str) -> int:
    if not s:
        return 0
    s = s.lower()
    score = 0
    score += sum(s.count(k) for k in _SQL_KEYWORDS)
    score += len(_SQL_HEX_RE.findall(s))
    score += len(_SQL_OBFUSCATE_RE.findall(s))
    score += len(_SQL_UNION_OBFUS_RE.findall(s)) * 2
    return score


def count_sql_comments(s: str) -> int:
    if not s:
        return 0
    s = s.lower()
    base = sum(s.count(p) for p in ["--", "/*", "*/", "#", "--+", "#+"])
    bypass = len(re.findall(r"/\*.*?\*/", s))
    return base + bypass


def count_sql_boolean_ops(s: str) -> int:
    if not s:
        return 0
    return len(_SQL_LOGIC_RE.findall(s.lower()))


def count_sql_funcs(s: str) -> int:
    if not s:
        return 0
    return len(_SQL_FUNC_RE.findall(s))


def count_sql_logic_patterns(s: str) -> int:
    if not s:
        return 0
    s = s.lower()
    score = 0

    common = ["1=1", "1 = 1", "1=2", "1 = 2",
              "true", "false", "is null", "is not null",
              "like '%", 'like "%']
    score += sum(s.count(p) for p in common)

    score += sum(s.count(sig) for sig in _SQL_URL_SIGNS)

    if re.search(r"%[0-9a-f]{2}%[0-9a-f]{2}", s):
        score += 2

    score += len(_SQL_UNION_OBFUS_RE.findall(s)) * 2
    score += len(_SQL_OR_TRUE_RE.findall(s)) * 2

    if _SQL_UNICODE_QUOTE_RE.search(s):
        if any(k in s for k in ("select", "union", " or ", " and ")):
            score += 2

    return score


# ============================================
# BROKEN AUTHENTICATION DETECTION (NEW)
# ============================================

_BA_KEYS = [
    "login", "signin", "signup", "register",
    "username=", "user=", "userid=",
    "password=", "pwd=", "pass=", "passwd=",
    "token=", "access_token=", "refresh_token=",
    "jwt=", "authorization", "bearer ",
    "api_key=", "apikey=", "key=",
    "session=", "sessionid=", "sessid=",
]

_WEAK_PASS = ["123", "1234", "12345", "123456", "password", "admin", "root"]
_JWT_NONE = ['"alg":"none"', '"alg": "none"', "'alg':'none'"]
_WEAK_OTP = ["otp=000000", "otp=111111", "pin=0000"]


def count_broken_auth_patterns(s: str) -> int:
    if not s:
        return 0

    s = s.lower()
    score = 0

    # Keyword login/token/password
    score += sum(s.count(k) for k in _BA_KEYS)

    # Weak password signs
    for wp in _WEAK_PASS:
        if wp in s:
            score += 2

    # JWT ALG=none
    for j in _JWT_NONE:
        if j in s:
            score += 3

    # Weak OTP/PIN
    for otp in _WEAK_OTP:
        if otp in s:
            score += 2

    # common auth endpoints
    if any(x in s for x in ["/login", "/auth", "/session", "/reset", "/forgot"]):
        score += 1

    return score


# ============================================
# XSS FEATURES
# ============================================

_XSS_TAG_RE = re.compile(
    r"<\s*(script|img|svg|math|iframe|object|embed|video|audio|details|marquee|body|input|textarea|button)\b",
    re.IGNORECASE
)

def count_xss_tags(s: str) -> int:
    if not s:
        return 0
    return len(_XSS_TAG_RE.findall(s))


_XSS_EVENT_RE = re.compile(r"\bon\w+\s*=", re.IGNORECASE)

def count_xss_events(s: str) -> int:
    if not s:
        return 0
    return len(_XSS_EVENT_RE.findall(s))


def count_js_protocols(s: str) -> int:
    if not s:
        return 0
    s = s.lower()
    pats = ["javascript:", "vbscript:", "data:text/html", "data:text/javascript"]
    return sum(s.count(p) for p in pats)


def count_xss_js_uri(s: str) -> int:
    if not s:
        return 0
    s = s.lower()
    pats = ["href=javascript:", "src=javascript:", "xlink:href=javascript:"]
    return sum(s.count(p) for p in pats)


_RARE_TAG_RE = re.compile(
    r"<\s*(svg|math|details|marquee|embed|object|video|audio)\b",
    re.IGNORECASE
)

def count_rare_html_tags(s: str) -> int:
    if not s:
        return 0
    return len(_RARE_TAG_RE.findall(s))


_UNICODE_ESC_RE = re.compile(r"\\u[0-9a-f]{4}")

def count_unicode_escapes(s: str) -> int:
    if not s:
        return 0
    return len(_UNICODE_ESC_RE.findall(s))


_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")

def count_base64_chunks(s: str) -> int:
    if not s:
        return 0
    return len(_BASE64_RE.findall(s))
