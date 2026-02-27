# utils_clean.py
"""
TOC
[S00] Imports
[S01] Basic text features
[S02] Normalization / Canonicalization
[S03] Structural / balance features
[S04] URL / query features
[S05] CMD / Shell features
[S06] SQLi features
[S07] Broken Auth (payload) features
[S08] XSS features
[S09] Behavioral features (STATEFUL rolling window)
[S10] Feature group lists (for train/infer consistency)
"""

# ============================================================
# [S00] IMPORTS
# ============================================================
import math
import re
import html
import hashlib
import urllib.parse
from collections import Counter, deque
from datetime import timedelta

import pandas as pd


# ============================================================
# [S01] BASIC TEXT FEATURES
# ============================================================
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


def ratio_alpha(s: str) -> float:
    """
    Tỷ lệ ký tự chữ cái (a-z) + khoảng trắng / tổng độ dài.
    Giúp phân biệt text tự nhiên vs payload/code (nhiều ký tự đặc biệt).
    """
    if not s:
        return 0.0
    s = str(s)
    alpha_space = sum(1 for c in s if c.isalpha() or c.isspace())
    return alpha_space / max(len(s), 1)


# ============================================================
# [S02] NORMALIZATION / CANONICALIZATION
# ============================================================
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


def canonicalize_text(text: str) -> str:
    """
    Biến đổi văn bản thô thành 'khung xương' (structure tokens) để giảm học thuộc lòng.
    Ví dụ:
      "UNION SELECT 1, 'admin'" -> "KW_UNION KW_SELECT LIT_INT LIT_STR"
    """
    if not text:
        return ""

    # 1) Normalize cơ bản trước
    s = normalize_for_tfidf(text)

    # 2) Thay thế số (integer/hex) -> LIT_INT
    s = re.sub(r"\b0x[0-9a-f]+\b", " LIT_INT ", s, flags=re.IGNORECASE)
    s = re.sub(r"\b\d+\b", " LIT_INT ", s)

    # 3) Thay thế chuỗi trong nháy đơn/kép -> LIT_STR
    s = re.sub(r"(['\"])(?:\\.|(?!\1).)*\1", " LIT_STR ", s)

    # 4) Thay các từ khóa SQL cấu trúc thành token
    structural_keywords = [
        "select", "union", "from", "where", "and", "or",
        "order by", "group by", "limit", "offset",
        "insert", "update", "delete", "drop", "truncate",
        "values", "into", "table", "database", "schema",
        "sleep", "benchmark",
    ]

    for kw in sorted(structural_keywords, key=len, reverse=True):
        token = " KW_" + kw.replace(" ", "_").upper() + " "
        s = re.sub(r"\b" + re.escape(kw) + r"\b", token, s)

    return " ".join(s.split())


# ============================================================
# [S03] STRUCTURAL / BALANCE FEATURES
# ============================================================
def count_unbalanced_quotes(text: str) -> int:
    """Đếm số dấu nháy đơn/kép không có cặp (0..2)."""
    if not text:
        return 0
    s = str(text)
    single = s.count("'") % 2
    double = s.count('"') % 2
    return single + double


def count_unbalanced_parentheses(text: str) -> int:
    """Đếm mức độ mất cân bằng ngoặc tròn () (abs(balance) + underflow)."""
    if not text:
        return 0
    s = str(text)
    bal = 0
    under = 0
    for ch in s:
        if ch == "(":
            bal += 1
        elif ch == ")":
            if bal == 0:
                under += 1
            else:
                bal -= 1
    return abs(bal) + under


def count_unbalanced_brackets(text: str) -> int:
    """Mất cân bằng ngoặc vuông [] và ngoặc nhọn {} (abs(balance)+underflow cho mỗi loại)."""
    if not text:
        return 0
    s = str(text)

    def _score_pair(open_ch: str, close_ch: str) -> int:
        bal = 0
        under = 0
        for ch in s:
            if ch == open_ch:
                bal += 1
            elif ch == close_ch:
                if bal == 0:
                    under += 1
                else:
                    bal -= 1
        return abs(bal) + under

    return _score_pair("[", "]") + _score_pair("{", "}")


def calc_local_entropy_max(s: str, window: int = 32, step: int = 8) -> float:
    """Entropy cục bộ: lấy entropy lớn nhất trong sliding window."""
    if not s:
        return 0.0
    s = str(s)
    n = len(s)
    if n <= window:
        return calc_entropy(s)

    best = 0.0
    for i in range(0, n - window + 1, step):
        chunk = s[i:i + window]
        e = calc_entropy(chunk)
        if e > best:
            best = e
    return best


# ============================================================
# [S04] URL / QUERY FEATURES
# ============================================================
def extract_query_string(url: str) -> str:
    """Lấy phần query sau dấu '?' (không decode)."""
    if not url:
        return ""
    s = str(url)
    qpos = s.find("?")
    return s[qpos + 1:] if qpos != -1 else ""


def max_query_value_length(url: str) -> int:
    """Độ dài value lớn nhất trong query string."""
    qs = extract_query_string(url)
    if not qs:
        return 0
    max_len = 0
    for part in qs.split("&"):
        if not part:
            continue
        if "=" in part:
            _, v = part.split("=", 1)
            max_len = max(max_len, len(v))
        else:
            max_len = max(max_len, len(part))
    return max_len


# ============================================================
# [S05] CMD / SHELL FEATURES
# ============================================================
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
    patterns = [";", "&&", "||", "|", "`", "$(", ">>", "&"]
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


# ============================================================
# [S06] SQLi FEATURES (UPGRADED)
# ============================================================
_SQL_KEYWORDS = [
    # core verbs
    "select", "union", "insert", "update", "delete",
    "drop", "truncate", "alter", "create", "replace",

    # clauses
    "from", "where", "group by", "order by", "having",
    "limit", "offset", "into", "values", "join", "inner join", "outer join",

    # boolean / control
    "or", "and", "xor", "case when", "if(", "elseif", "then", "else", "end",

    # time-based / delay
    "sleep", "benchmark", "pg_sleep", "dbms_lock.sleep",

    # info schema / metadata
    "information_schema", "pg_catalog", "sysobjects", "syscolumns", "dual",

    # common leakage funcs
    "database()", "schema()", "version()", "@@version", "user()", "current_user",
    "current_database", "current_schema",

    # file / dangerous funcs
    "load_file", "pg_read_file", "pg_ls_dir", "xp_cmdshell", "utl_http", "utl_inaddr",

    # xml / error-based
    "extractvalue", "updatexml",

    # casting / string tricks
    "concat", "concat_ws", "char(", "ascii(", "substr", "substring", "left(", "right(",
    "hex(", "unhex(", "to_char", "to_number", "convert(", "cast(", "coalesce",

    # json paths
    "json_extract", "json_value",
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


# ============================================================
# [S07] BROKEN AUTH (PAYLOAD) FEATURES (UPGRADED)
# ============================================================
_BA_KEYS = [
    "login", "signin", "signup", "register",
    "username=", "user=", "userid=", "email=",
    "password=", "pwd=", "pass=", "passwd=",
    "token=", "access_token=", "refresh_token=", "id_token=",
    "jwt=", "authorization", "bearer ",
    "api_key=", "apikey=", "key=",
    "session=", "sessionid=", "sessid=", "jsessionid=",
    "otp=", "mfa", "2fa", "totp",
]

_WEAK_PASS = ["123", "1234", "12345", "123456", "password", "welcome", "admin", "root", "changeme", "qwerty"]
_WEAK_USER = ["admin", "administrator", "root", "sysadmin", "operator", "test", "demo", "guest", "service"]

_JWT_NONE = ['"alg":"none"', '"alg": "none"', "'alg':'none'", "'alg': 'none'"]

_WEAK_OTP = ["otp=000000", "otp=111111", "pin=0000", "pin=1234", "code=000000"]

_BA_BYPASS = [
    "mfa=false", "2fa=false", "otp=000000",
    "remember_me=true", "remember=true",
    "next=/admin", "redirect=/admin", "redirect_uri=",
    "returnurl=", "continue=", "callback=", "state=",
]

_JWT_LIKE_RE = re.compile(r"\beyj[a-z0-9_\-]{10,}\.[a-z0-9_\-]{10,}\.[a-z0-9_\-]{5,}\b", re.IGNORECASE)
_BEARER_RE = re.compile(r"\bbearer\s+[a-z0-9_\-\.=]{10,}\b", re.IGNORECASE)
_BASIC_RE = re.compile(r"\bbasic\s+[a-z0-9+/]{10,}={0,2}\b", re.IGNORECASE)
_SESSION_RE = re.compile(r"\b(jsessionid|sessionid|sessid|session)\s*=\s*[a-z0-9\-_]{6,}\b", re.IGNORECASE)
_BRUTE_HINTS = ["wrongpass", "invalidtoken", "doesnotexist", "failed login", "too many", "rate limit"]


def count_broken_auth_patterns(s: str) -> int:
    """
    Trả về điểm BrokenAuth:
    - keyword auth (login/token/session/otp...)
    - JWT/bearer/basic/session id patterns
    - weak creds / weak otp
    - bypass params (mfa=false, next=/admin, redirect...)
    - brute-force hints
    """
    if not s:
        return 0

    s = s.lower()
    score = 0

    # 1) keyword login/token/password
    score += sum(s.count(k) for k in _BA_KEYS)

    # 2) weak username/password hints
    for u in _WEAK_USER:
        if f"username={u}" in s or f"user={u}" in s or f"email={u}" in s:
            score += 3
        elif u in s:
            score += 1

    for p in _WEAK_PASS:
        if f"password={p}" in s or f"pwd={p}" in s or f"pass={p}" in s:
            score += 3
        elif p in s:
            score += 1

    # 3) JWT ALG=none
    for j in _JWT_NONE:
        if j in s:
            score += 5

    # 4) JWT-like token / bearer / basic
    if _JWT_LIKE_RE.search(s):
        score += 4
    if _BEARER_RE.search(s):
        score += 4
    if _BASIC_RE.search(s):
        score += 3

    # 5) session fixation / session id
    if _SESSION_RE.search(s):
        score += 3
    if "jsessionid" in s:
        score += 1

    # 6) weak otp/pin
    for otp in _WEAK_OTP:
        if otp in s:
            score += 3

    # 7) auth bypass params
    for b in _BA_BYPASS:
        if b in s:
            score += 3

    # 8) common auth endpoints
    if any(x in s for x in ["/login", "/auth", "/session", "/reset", "/forgot", "/token", "/oauth"]):
        score += 2

    # 9) brute-force hints
    for h in _BRUTE_HINTS:
        if h in s:
            score += 1

    return score


# ============================================================
# [S08] XSS FEATURES
# ============================================================
_XSS_TAG_RE = re.compile(
    r"<\s*(script|img|svg|math|iframe|object|embed|video|audio|details|marquee|body|input|textarea|button)\b",
    re.IGNORECASE
)

_XSS_EVENT_RE = re.compile(r"\bon\w+\s*=", re.IGNORECASE)

_RARE_TAG_RE = re.compile(r"<\s*(svg|math|details|marquee|embed|object|video|audio)\b", re.IGNORECASE)

_UNICODE_ESC_RE = re.compile(r"\\u[0-9a-f]{4}")

_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")

_XSS_SINK_RE = re.compile(
    r"\b(?:alert|prompt|confirm|eval|settimeout|setinterval|function|fetch|xmlhttprequest|"
    r"document\.cookie|document\.domain|document\.write|window\.location|location\.href|"
    r"innerhtml|outerhtml|onerror|onload)\b",
    re.IGNORECASE,
)

_XSS_OBFUS_RE = re.compile(
    r"(?:string\.fromcharcode|atob\s*\(|\\x[0-9a-f]{2}|\\u[0-9a-f]{4})",
    re.IGNORECASE,
)

_HTML_ENTITY_RE = re.compile(r"&#x?[0-9a-f]+;", re.IGNORECASE)


def count_xss_tags(s: str) -> int:
    if not s:
        return 0
    return len(_XSS_TAG_RE.findall(s))


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


def count_rare_html_tags(s: str) -> int:
    if not s:
        return 0
    return len(_RARE_TAG_RE.findall(s))


def count_unicode_escapes(s: str) -> int:
    if not s:
        return 0
    return len(_UNICODE_ESC_RE.findall(s))


def count_base64_chunks(s: str) -> int:
    if not s:
        return 0
    return len(_BASE64_RE.findall(s))


def count_xss_sinks(s: str) -> int:
    """Đếm JS sinks/keywords kiểu alert(), document.cookie, eval..."""
    if not s:
        return 0
    return len(_XSS_SINK_RE.findall(s))


def count_xss_obfuscation(s: str) -> int:
    """Đếm dấu hiệu obfuscation hay gặp trong XSS."""
    if not s:
        return 0
    return len(_XSS_OBFUS_RE.findall(s))


def count_html_entities(s: str) -> int:
    """Đếm HTML entities (&#x3c;script&#x3e;) thường dùng để né filter."""
    if not s:
        return 0
    return len(_HTML_ENTITY_RE.findall(s))


# ============================================================
# [S09] BEHAVIORAL FEATURES (STATEFUL, for Auth/AuthZ)
# ============================================================
_INV_RE = re.compile(r"^/api/inventory/(\d+)$", re.IGNORECASE)


def _token_hash(auth_token: str) -> str:
    """Không lưu token thô. Hash để phát hiện reuse/behavior."""
    if not auth_token:
        return ""
    t = str(auth_token).strip()
    t = t.replace("Bearer", "").strip()
    if not t:
        return ""
    return hashlib.sha256(t.encode("utf-8", errors="ignore")).hexdigest()[:16]


def _extract_inv_id(url: str):
    """/api/inventory/123 -> 123"""
    if not url:
        return None
    m = _INV_RE.match(str(url).strip())
    return int(m.group(1)) if m else None


class BehaviorFeaturizer:
    """
    Rolling-window behavior features theo remote_ip (hoặc key khác).
    Dùng cho phát hiện behavior Auth/AuthZ (binary suspicious).
    """

    def __init__(self, window_sec: int = 60, window10_sec: int = 10):
        self.window = timedelta(seconds=window_sec)
        self.window10 = timedelta(seconds=window10_sec)
        self.by_key = {}  # key(ip/user/token) -> deque[events]

    def _cleanup(self, dq, now):
        cutoff = now - self.window
        while dq and dq[0]["ts"] < cutoff:
            dq.popleft()

    def update_and_extract(self, event: dict, key_field: str = "remote_ip") -> dict:
        """
        event cần có:
          - ts: datetime (UTC) hoặc timestamp ISO string ("timestamp")
          - remote_ip
          - method
          - url
          - status
          - auth_token
        """

        # key
        key = str(event.get(key_field, "") or "")
        if not key:
            key = "UNKNOWN"

        # timestamp
        ts = event.get("ts")
        if ts is None:
            t = event.get("timestamp")
            if t is None:
                raise ValueError("Event thiếu 'ts' (datetime) hoặc 'timestamp' (ISO string).")
            ts = pd.to_datetime(t, utc=True).to_pydatetime()

        dq = self.by_key.setdefault(key, deque())

        url = str(event.get("url", "") or "")
        method = str(event.get("method", "") or "").upper()
        status = int(event.get("status", 0) or 0)

        auth_token = str(event.get("auth_token", "") or "")
        token_present = 1 if auth_token.strip() else 0
        token_h = _token_hash(auth_token)

        inv_id = _extract_inv_id(url)
        is_inv = 1 if inv_id is not None else 0
        is_update = 1 if url.strip() == "/api/inventory/update" else 0

        dq.append({
            "ts": ts,
            "url": url,
            "method": method,
            "status": status,
            "token_present": token_present,
            "token_h": token_h,
            "inv_id": inv_id,
            "is_inv": is_inv,
            "is_update": is_update,
        })

        self._cleanup(dq, ts)

        # 60s window
        req_cnt_60s = len(dq)
        unique_url_60s = len({e["url"] for e in dq}) if dq else 0
        token_ratio_60s = (sum(e["token_present"] for e in dq) / (req_cnt_60s + 1e-9)) if dq else 0.0
        update_cnt_60s = sum(e["is_update"] for e in dq)

        status_401_60s = sum(1 for e in dq if e["status"] == 401)
        status_403_60s = sum(1 for e in dq if e["status"] == 403)
        fail_ratio_60s = (status_401_60s + status_403_60s) / (req_cnt_60s + 1e-9)

        # 10s subwindow
        cutoff10 = ts - self.window10
        last10 = [e for e in dq if e["ts"] >= cutoff10]
        req_cnt_10s = len(last10)
        inv_req_10s = sum(e["is_inv"] for e in last10)

        # inventory scan behavior
        inv_ids = [e["inv_id"] for e in dq if e["inv_id"] is not None]
        inv_unique_60s = len(set(inv_ids)) if inv_ids else 0

        inv_seq_score_60s = 0.0
        if len(inv_ids) >= 2:
            pairs = 0
            good = 0
            for a, b in zip(inv_ids[:-1], inv_ids[1:]):
                pairs += 1
                if b == a + 1:
                    good += 1
            inv_seq_score_60s = good / (pairs + 1e-9)

        token_first_seen_sec_ago = 9999.0
        if token_h:
            for e in dq:
                if e["token_h"] == token_h and e["token_h"] != "":
                    token_first_seen_sec_ago = (ts - e["ts"]).total_seconds()
                    break

        return {
            "req_cnt_10s": req_cnt_10s,
            "req_cnt_60s": req_cnt_60s,
            "unique_url_60s": unique_url_60s,

            "token_present": token_present,
            "token_ratio_60s": token_ratio_60s,
            "token_first_seen_sec_ago": token_first_seen_sec_ago,

            "inv_req_10s": inv_req_10s,
            "inv_unique_60s": inv_unique_60s,
            "inv_seq_score_60s": inv_seq_score_60s,

            "update_cnt_60s": update_cnt_60s,

            "status_401_60s": status_401_60s,
            "status_403_60s": status_403_60s,
            "fail_ratio_60s": fail_ratio_60s,
        }


# ============================================================
# [S10] FEATURE GROUP LISTS (for train/infer consistency)
# ============================================================
# Nhóm “text/structure” (không phụ thuộc loại attack cụ thể)
META_TEXT_COLS = [
    "url_length",
    "entropy",
    "num_special",
    "special_ratio",
    "ratio_alpha",
    "longest_special_seq",
    "unbalanced_quotes",
    "unbalanced_parens",
    "unbalanced_brackets",
    "local_entropy_max",
    "entropy_spike",
    "max_query_value_len",
]

# Nhóm “payload signature” (SQL/XSS/CMD/BrokenAuth scoring)
META_PAYLOAD_COLS = [
    "cmd_keyword_count",
    "sql_comment_count",
    "cmd_special_count",
    "sql_keyword_count",
    "sql_boolean_ops",
    "sql_func_count",
    "xss_tag_count",
    "xss_event_count",
    "js_proto_count",
    "xss_sink_count",
    "xss_obfus_count",
    "html_entity_count",
    "path_traversal_count",
    "sensitive_file_count",
    "shell_pattern_count",
    "xss_js_uri_count",
    "xss_rare_tag_count",
    "unicode_escape_count",
    "base64_chunk_count",
    "sql_logic_count",
    "broken_auth_score",
]

# Nhóm “behavior rolling window” (Auth/AuthZ)
META_BEHAVIOR_COLS = [
    "req_cnt_10s",
    "req_cnt_60s",
    "unique_url_60s",
    "token_present",
    "token_ratio_60s",
    "token_first_seen_sec_ago",
    "inv_req_10s",
    "inv_unique_60s",
    "inv_seq_score_60s",
    "update_cnt_60s",
    "status_401_60s",
    "status_403_60s",
    "fail_ratio_60s",
]