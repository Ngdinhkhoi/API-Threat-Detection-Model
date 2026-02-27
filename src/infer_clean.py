#!/usr/bin/env python3
# infer_clean.py
import warnings
warnings.filterwarnings("ignore")

import joblib
import os
import json
import csv
from datetime import datetime

from scipy.sparse import csr_matrix, hstack
from rich.console import Console
from rich.table import Table
from rich import box

from src.utils_clean import (
    normalize_for_tfidf,
    calc_entropy,
    calc_local_entropy_max,
    count_special_chars,
    longest_special_run,
    find_cmd_keyword_count,
    count_sql_comments,
    count_cmd_special,
    count_sql_keywords,
    count_sql_boolean_ops,
    count_sql_funcs,
    count_sql_logic_patterns,
    count_unbalanced_quotes,
    count_unbalanced_parentheses,
    count_unbalanced_brackets,
    max_query_value_length,
    count_xss_tags,
    count_xss_events,
    count_js_protocols,
    count_xss_js_uri,
    count_rare_html_tags,
    count_xss_sinks,
    count_xss_obfuscation,
    count_html_entities,
    count_unicode_escapes,
    count_base64_chunks,
    count_path_traversal,
    count_sensitive_files,
    count_shell_patterns,
    count_broken_auth_patterns,

    ratio_alpha,
)

console = Console()

# ✅ 4-class default map
DEFAULT_LABEL_MAP = {
    0: "Benign",
    1: "SQL Injection",
    2: "XSS",
    3: "Broken Authentication",
}

# ✅ Alert thresholds per class (percent)
SAFE_THRESHOLD = 75.0  # production threshold (percent)

CLASS_THRESH = {
    "SQL Injection": 97.0,
    "XSS": 95.0,
    "Broken Authentication": 90.0,
}

# Alert priority (highest first)
ALERT_PRIORITY = ["SQL Injection", "XSS", "Broken Authentication"]

# IMPORTANT:
# - Prefer meta_cols saved in model bundle (models/model_clean.pkl).
# - DEFAULT_META_COLS is only a fallback for older bundles.
DEFAULT_META_COLS = [
    "url_length",
    "entropy",
    "num_special",
    "special_ratio",
    "ratio_alpha",
    "longest_special_seq",

    # NEW structural + local entropy + query features
    "unbalanced_quotes",
    "unbalanced_parens",
    "unbalanced_brackets",
    "local_entropy_max",
    "entropy_spike",
    "max_query_value_len",

    "cmd_keyword_count",
    "sql_comment_count",
    "cmd_special_count",
    "sql_keyword_count",
    "sql_boolean_ops",
    "sql_func_count",
    "sql_logic_count",

    "xss_tag_count",
    "xss_event_count",
    "js_proto_count",
    "xss_js_uri_count",
    "xss_rare_tag_count",
    "xss_sink_count",
    "xss_obfus_count",
    "html_entity_count",

    "path_traversal_count",
    "sensitive_file_count",
    "shell_pattern_count",

    "unicode_escape_count",
    "base64_chunk_count",

    "broken_auth_score",

    
]

MODEL_BUNDLE = None


def load_model():
    global MODEL_BUNDLE
    if MODEL_BUNDLE is None:
        MODEL_BUNDLE = joblib.load("models/model_clean.pkl")
        console.print("[green]📘 Model loaded[/]")
        console.print("[yellow]classes_ =[/]", getattr(MODEL_BUNDLE["model"], "classes_", None))
        console.print("[yellow]meta_cols =[/]", MODEL_BUNDLE.get("meta_cols", None))
    return MODEL_BUNDLE


def preprocess(url, body=""):
    # text normalized (same as preprocess_clean.py)
    text = normalize_for_tfidf(str(url) + " " + str(body))

    # NOTE: features should match preprocess_clean.py columns as close as possible
    url_str = str(url or "")

    ent = calc_entropy(text)
    local_ent = calc_local_entropy_max(text)
    meta = {
        "url_length": len(text),
        "entropy": ent,
        "num_special": count_special_chars(text),
        "special_ratio": count_special_chars(text) / (len(text) + 1),

        "ratio_alpha": ratio_alpha(text),

        "longest_special_seq": longest_special_run(text),

        # NEW: structure break signals
        "unbalanced_quotes": count_unbalanced_quotes(text),
        "unbalanced_parens": count_unbalanced_parentheses(text),
        "unbalanced_brackets": count_unbalanced_brackets(text),

        # NEW: local entropy spike
        "local_entropy_max": local_ent,
        "entropy_spike": max(0.0, local_ent - ent),

        # NEW: query param size (compute from raw URL, not normalized text)
        "max_query_value_len": max_query_value_length(url_str),

        "cmd_keyword_count": find_cmd_keyword_count(text),
        "cmd_special_count": count_cmd_special(text),
        "path_traversal_count": count_path_traversal(text),
        "sensitive_file_count": count_sensitive_files(text),
        "shell_pattern_count": count_shell_patterns(text),

        "sql_comment_count": count_sql_comments(text),
        "sql_keyword_count": count_sql_keywords(text),
        "sql_boolean_ops": count_sql_boolean_ops(text),
        "sql_func_count": count_sql_funcs(text),
        "sql_logic_count": count_sql_logic_patterns(text),

        "xss_tag_count": count_xss_tags(text),
        "xss_event_count": count_xss_events(text),
        "js_proto_count": count_js_protocols(text),
        "xss_js_uri_count": count_xss_js_uri(text),
        "xss_rare_tag_count": count_rare_html_tags(text),
        "xss_sink_count": count_xss_sinks(text),
        "xss_obfus_count": count_xss_obfuscation(text),
        "html_entity_count": count_html_entities(text),

        "unicode_escape_count": count_unicode_escapes(text),
        "base64_chunk_count": count_base64_chunks(text),

        "broken_auth_score": count_broken_auth_patterns(text),
    }

    return text, meta


def predict(url, body=""):
    bundle = load_model()
    model = bundle["model"]
    tfidf = bundle["tfidf"]
    meta_cols = bundle.get("meta_cols") or DEFAULT_META_COLS
    label_map = bundle.get("label_map") or DEFAULT_LABEL_MAP

    text, meta = preprocess(url, body)

    X_text = tfidf.transform([text])

    # Robust: if a meta col is missing (older bundle / mismatch), fill with 0.0
    meta_row = [float(meta.get(c, 0.0)) for c in meta_cols]
    X_meta = csr_matrix([meta_row])

    X = hstack([X_text, X_meta])

    probs = model.predict_proba(X)[0]

    # Map prob -> label name (percent)
    label_probs = {label_map[i]: float(probs[i] * 100) for i in range(len(probs))}

    # ---------- Optional rule gate: reduce false positives for SQLi on auth/users ----------
    url_s = str(url or "")
    is_auth_endpoint = ("/api/auth" in url_s) or ("/api/users" in url_s)

    sql_signal = (
        meta.get("sql_keyword_count", 0)
        + meta.get("sql_comment_count", 0)
        + meta.get("sql_logic_count", 0)
        + meta.get("sql_func_count", 0)
        + meta.get("sql_boolean_ops", 0)
    )

    if is_auth_endpoint and sql_signal == 0:
        label_probs["SQL Injection"] = 0.0

    # --------- NEW LOGIC: choose top class (no hard threshold blocking) ---------
    top_label = max(label_probs, key=label_probs.get)
    top_score = float(label_probs[top_label])

    # broaden auth endpoint detection to match your real logs (e.g. /auth?id=...)
    is_auth_endpoint = any(k in url_s for k in ["/auth", "/login", "/signin", "/session", "/token", "/oauth", "/api/auth", "/api/users"])

    # keep SQL signal definition
    sql_signal = (
        meta.get("sql_keyword_count", 0)
        + meta.get("sql_comment_count", 0)
        + meta.get("sql_logic_count", 0)
        + meta.get("sql_func_count", 0)
        + meta.get("sql_boolean_ops", 0)
    )

    # Rule gate: reduce false positives for SQLi on auth endpoints when no real SQL signal
    if top_label == "SQL Injection" and is_auth_endpoint and sql_signal == 0:
        return "Benign", float(label_probs.get("Benign", 0.0))

    # If top score is meaningful -> alert
    if top_score > 50.0:
        return top_label, top_score

    # Otherwise low confidence benign
    return "Benign (Low Conf)", float(label_probs.get("Benign", 0.0))


def load_jsonl(path):
    """Đọc JSONL: chỉ cần url/body. time/ip thiếu vẫn OK."""
    arr = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            item = json.loads(line)
            arr.append({
                "time": item.get("time") or item.get("timestamp") or item.get("ts"),
                "ip": item.get("ip") or item.get("client_ip") or item.get("remote_ip"),
                "url": item.get("url", ""),
                "body": item.get("body", ""),
            })
    return arr


def save_jsonl(records, out):
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        for r in records:
            json.dump(r, f, ensure_ascii=False)
            f.write("\n")
    console.print(f"[green]✔ JSONL saved → {out}[/]")


def save_csv(results, out):
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    with open(out, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["label", "probability", "url", "body"])
        for label, prob, url, body in results:
            w.writerow([label, f"{prob:.2f}", url, body])
    console.print(f"[green]✔ CSV saved → {out}[/]")


def main():
    FILES = {
        "1": "payloads/benign.jsonl",
        "2": "payloads/sqli.jsonl",
        "3": "payloads/xss.jsonl",
        "4": "payloads/brokenAuth.jsonl",
        "5": "payloads/mixed.jsonl",
    }

    console.print("[cyan]=== PAYLOAD TESTER (local mode, không WebSocket) ===[/]")
    print("1. Test benign.jsonl")
    print("2. Test sqli.jsonl")
    print("3. Test xss.jsonl")
    print("4. Test brokenAuth.jsonl")
    print("5. Test mixed.jsonl")
    print("6. Test 1 JSON log thủ công")
    print("7. Exit\n")

    choice = input("Select: ").strip()
    if choice == "7":
        return

    # ----- manual JSON log -----
    if choice == "6":
        raw = input("Nhập JSON log: ").strip()
        try:
            obj = json.loads(raw)
            url = obj.get("url", "")
            body = obj.get("body", "")
            t = obj.get("time") or obj.get("timestamp") or datetime.utcnow().isoformat()
            ip = obj.get("ip") or obj.get("client_ip") or obj.get("remote_ip") or "0.0.0.0"
        except Exception:
            console.print("[red]JSON không hợp lệ[/]")
            return

        label, prob = predict(url, body)
        record = {
            "time": t,
            "ip": ip,
            "attack": label,
            "score": round(prob, 2),
            "url": url,
            "body": body,
        }
        console.print(f"\n[bold green]→ {label} ({prob:.2f}%)")
        print(json.dumps(record, ensure_ascii=False, indent=2))
        return

    # ----- file mode -----
    if choice not in FILES:
        console.print("[red]Lựa chọn không hợp lệ[/]")
        return

    path = FILES[choice]
    payloads = load_jsonl(path)

    results = []
    jsonl_records = []

    for item in payloads:
        url = item.get("url", "")
        body = item.get("body", "")

        label, prob = predict(url, body)

        t = item.get("time") or datetime.utcnow().isoformat()
        ip = item.get("ip") or "0.0.0.0"

        rec = {
            "time": t,
            "ip": ip,
            "attack": label,
            "score": round(prob, 2),
            "url": url,
            "body": body,
        }

        jsonl_records.append(rec)
        results.append((label, prob, url, body))

    # 1) Full results
    save_jsonl(jsonl_records, out="results/infer_result.jsonl")

    # 2) Suspects BrokenAuth
    suspects = [r for r in jsonl_records if r["attack"] == "Broken Authentication"]
    save_jsonl(suspects, out="results/suspect_broken_auth.jsonl")
    console.print(f"[yellow]⚠ Suspects saved: {len(suspects)}[/]")

    # 3) (optional) CSV full
    # save_csv(results, out="results/infer_result.csv")

    # show top table
    results.sort(key=lambda x: -x[1])
    table = Table(title="TOP PAYLOADS", header_style="bold magenta", box=box.HEAVY_EDGE)
    table.add_column("Label")
    table.add_column("%")
    table.add_column("URL")
    for l, p, u, _b in results[:20]:
        table.add_row(l, f"{p:.2f}", u)
    console.print(table)




def predict_one(payload: dict, model_path: str = "models/model_clean.pkl"):
    """Helper for smoke tests.
    payload: {"url": "...", "body": "..."} (optionally has other keys)
    Returns: (label, score, label_probs)
    """
    url = str(payload.get("url", "") or "")
    body = str(payload.get("body", "") or "")
    return predict(url=url, body=body)

if __name__ == "__main__":
    main()
