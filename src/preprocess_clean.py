#!/usr/bin/env python3
# preprocess_clean.py

import os
import csv
import re
import pandas as pd

from src.utils_clean import (
    normalize_for_tfidf,
    calc_entropy,
    count_special_chars,
    longest_special_run,
    find_cmd_keyword_count,
    count_sql_comments,
    count_cmd_special,
    count_sql_keywords,
    count_sql_boolean_ops,
    count_sql_funcs,
    count_xss_tags,
    count_xss_events,
    count_js_protocols,
    count_xss_sinks,
    count_xss_obfuscation,
    count_html_entities,
    count_path_traversal,
    count_sensitive_files,
    count_shell_patterns,
    count_xss_js_uri,
    count_rare_html_tags,
    count_unicode_escapes,
    count_base64_chunks,
    count_sql_logic_patterns,
    count_broken_auth_patterns,

    # ✅ NEW FEATURES
    ratio_alpha,
    count_unbalanced_quotes,
    count_unbalanced_parentheses,
    count_unbalanced_brackets,
    calc_local_entropy_max,
    max_query_value_length,

    # ✅ OPTIONAL
    canonicalize_text,
)

INPUT_DIR = "data"

# =========================
# SOURCE -> LABEL (multi-class tạm)
# Sau đó sẽ convert về binary 0/1
# =========================
DESIRED_LABEL = {
    "bai.csv": 0,
    "SQL.csv": 1,
    "XSS.csv": 2,
    "XSS_cus.csv": 2,
    "XSS_train_2.csv":2,
    "brokenAuth.csv": 3,
    "BOLA_train.csv": 4,
    "BOLA_test.csv": 4,
}

NORMALIZE_LABEL = {str(i): i for i in range(5)}
NORMALIZE_LABEL.update({i: i for i in range(5)})
NORMALIZE_LABEL.update({"5": 2, 5: 2, "6": 3, 6: 3})

USE_CANONICALIZE_TEXT = True

META_COLS = [
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

# =========================
# BOLA labeling (rule-based)
# =========================
_CART_RE = re.compile(r"/api/cart/(\d+)", re.IGNORECASE)

def _safe_int(x):
    try:
        return int(str(x).strip())
    except Exception:
        return None

def label_bola_df(df: pd.DataFrame) -> pd.DataFrame:
    """
    Auto-label BOLA:
      - label=1 (attack) nếu requested_resource có id và user_id != id (và không phải admin)
      - label=0 (benign) còn lại
    """
    # chuẩn hóa tên cột từ file BOLA của em
    # header em show: user_id, user_role, requested_resource, request_method...
    if "requested_resource" not in df.columns:
        # fallback nếu file dùng cột khác
        if "url" in df.columns:
            df["requested_resource"] = df["url"]
        elif "requested_url" in df.columns:
            df["requested_resource"] = df["requested_url"]
        else:
            df["requested_resource"] = ""

    if "user_id" not in df.columns:
        df["user_id"] = ""

    if "user_role" not in df.columns:
        df["user_role"] = ""

    def _row_label(r):
        role = str(r.get("user_role", "")).strip().lower()
        if role == "admin":
            return 0

        uid = _safe_int(r.get("user_id"))
        rr = str(r.get("requested_resource", "")).strip()

        m = _CART_RE.search(rr)
        rid = _safe_int(m.group(1)) if m else None

        if uid is not None and rid is not None:
            return 1 if uid != rid else 0

        # không parse được -> benign (đỡ bẩn label)
        return 0

    df["label"] = df.apply(_row_label, axis=1)
    return df


def parse_broken_auth(path: str) -> pd.DataFrame:
    rows = []
    with open(path, "r", encoding="utf-8", errors="ignore", newline="") as f:
        reader = csv.reader(f, delimiter=",", quotechar='"', escapechar="\\")
        first = next(reader, None)
        if first is None:
            return pd.DataFrame(columns=["id","method","user_agent","url","referer","body","label"])

        first_lower = [c.strip().lower() for c in first]
        has_header = ("id" in first_lower and "method" in first_lower and ("label" in first_lower or "lable" in first_lower))

        def normalize_row(row):
            if len(row) > 7:
                body = ",".join(row[5:-1])
                row = row[:5] + [body, row[-1]]
            return row

        if not has_header:
            row = normalize_row(first)
            if len(row) == 7:
                rows.append(row)

        for row in reader:
            row = normalize_row(row)
            if len(row) != 7:
                print("⚠️ Skip malformed:", row[:3], "... (cols=", len(row), ")")
                continue
            rows.append(row)

    return pd.DataFrame(rows, columns=["id","method","user_agent","url","referer","body","label"])


def assign_label(df: pd.DataFrame, fname: str) -> pd.DataFrame:
    # BOLA xử lý riêng bằng rule
    if fname == "BOLA.csv":
        return label_bola_df(df)

    if "lable" in df.columns:
        df["lable"] = df["lable"].astype(str).str.strip()
        df["label"] = df["lable"].map(NORMALIZE_LABEL)
        invalid = df["label"].isna().sum()
        if invalid > 0:
            print(f"⚠️ {fname}: {invalid} label invalid → fallback by filename")
            df.loc[df["label"].isna(), "label"] = DESIRED_LABEL[fname]
    else:
        df["label"] = DESIRED_LABEL[fname]

    df["label"] = pd.to_numeric(df["label"], errors="coerce").fillna(DESIRED_LABEL[fname]).astype(int)
    return df


def read_csv_auto(path: str) -> pd.DataFrame:
    # đọc UTF-8 trước, fail thì latin1
    try:
        return pd.read_csv(path, on_bad_lines="skip", engine="python", encoding="utf-8")
    except UnicodeDecodeError:
        print(f"⚠️ {os.path.basename(path)} not utf-8 → fallback to latin1")
        return pd.read_csv(path, on_bad_lines="skip", engine="python", encoding="latin1")


def build_dataset():
    dfs = []

    for fname in DESIRED_LABEL:
        path = os.path.join(INPUT_DIR, fname)
        print(f"📂 Loading {path}")

        if fname == "brokenAuth.csv":
            df = parse_broken_auth(path)
        else:
            df = read_csv_auto(path)

        # Chuẩn hóa field chung
        if "id" not in df.columns: df["id"] = ""
        if "url" not in df.columns: df["url"] = ""
        if "body" not in df.columns: df["body"] = ""
        if "refer" not in df.columns and "referer" not in df.columns:
            df["refer"] = ""

        df["id"] = df["id"].astype(str)
        df["url"] = df["url"].astype(str)
        df["body"] = df["body"].astype(str)
        df["source"] = fname

        # TEXT cho TF-IDF: ưu tiên URL + body (BOLA thì body có thể rỗng)
        df["text"] = df.apply(
            lambda r: (
                canonicalize_text(r["url"] + " " + r["body"])
                if USE_CANONICALIZE_TEXT
                else normalize_for_tfidf(r["url"] + " " + r["body"])
            ),
            axis=1,
        )

        # Gán nhãn (BOLA: rule-based)
        df = assign_label(df, fname)

        # normalize multi-class (phòng trường hợp label bẩn)
        REMAP = {0: 0, 1: 1, 2: 2, 3: 3, 4: 4, 5: 2, 6: 3}
        df["label"] = df["label"].map(REMAP).fillna(df["label"]).astype(int)

        # =========================
        # ✅ Convert to BINARY here
        # 0 = benign, 1 = attack
        # =========================
        df["label"] = (df["label"] != 0).astype(int)

        # META FEATURES
        df["url_length"] = df["text"].str.len()
        df["entropy"] = df["text"].apply(calc_entropy)
        df["num_special"] = df["text"].apply(count_special_chars)
        df["special_ratio"] = df["num_special"] / (df["url_length"] + 1)
        df["ratio_alpha"] = df["text"].apply(ratio_alpha)
        df["longest_special_seq"] = df["text"].apply(longest_special_run)

        df["cmd_keyword_count"] = df["text"].apply(find_cmd_keyword_count)
        df["cmd_special_count"] = df["text"].apply(count_cmd_special)
        df["path_traversal_count"] = df["text"].apply(count_path_traversal)
        df["sensitive_file_count"] = df["text"].apply(count_sensitive_files)
        df["shell_pattern_count"] = df["text"].apply(count_shell_patterns)

        df["sql_comment_count"] = df["text"].apply(count_sql_comments)
        df["sql_keyword_count"] = df["text"].apply(count_sql_keywords)
        df["sql_boolean_ops"] = df["text"].apply(count_sql_boolean_ops)
        df["sql_func_count"] = df["text"].apply(count_sql_funcs)
        df["sql_logic_count"] = df["text"].apply(count_sql_logic_patterns)

        df["xss_tag_count"] = df["text"].apply(count_xss_tags)
        df["xss_event_count"] = df["text"].apply(count_xss_events)
        df["js_proto_count"] = df["text"].apply(count_js_protocols)
        df["xss_js_uri_count"] = df["text"].apply(count_xss_js_uri)
        df["xss_rare_tag_count"] = df["text"].apply(count_rare_html_tags)
        df["xss_sink_count"] = df["text"].apply(count_xss_sinks)
        df["xss_obfus_count"] = df["text"].apply(count_xss_obfuscation)
        df["html_entity_count"] = df["text"].apply(count_html_entities)

        df["unicode_escape_count"] = df["text"].apply(count_unicode_escapes)
        df["base64_chunk_count"] = df["text"].apply(count_base64_chunks)
        df["broken_auth_score"] = df["text"].apply(count_broken_auth_patterns)

        df["unbalanced_quotes"] = df["text"].apply(count_unbalanced_quotes)
        df["unbalanced_parens"] = df["text"].apply(count_unbalanced_parentheses)
        df["unbalanced_brackets"] = df["text"].apply(count_unbalanced_brackets)

        df["local_entropy_max"] = df["text"].apply(calc_local_entropy_max)
        df["entropy_spike"] = (df["local_entropy_max"] - df["entropy"]).clip(lower=0.0)

        df["max_query_value_len"] = df["url"].apply(max_query_value_length)

        dfs.append(df)

    out_df = pd.concat(dfs, ignore_index=True)
    out_df = out_df.sample(frac=1.0, random_state=42).reset_index(drop=True)

    os.makedirs("dataset", exist_ok=True)
    out_df.to_parquet("dataset/train_df_clean.parquet", index=False)

    print("✔ DONE → dataset/train_df_clean.parquet")
    print("📊 Shape:", out_df.shape)
    print("📌 Label counts (binary):\n", out_df["label"].value_counts())
    print("📌 Source counts:\n", out_df["source"].value_counts())


if __name__ == "__main__":
    build_dataset()