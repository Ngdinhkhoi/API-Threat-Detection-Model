#!/usr/bin/env python3
# preprocess_clean.py (FINAL 5-CLASS EDITION — FULL SAFE PARSER)

import os
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
    count_path_traversal,
    count_sensitive_files,
    count_shell_patterns,
    count_xss_js_uri,
    count_rare_html_tags,
    count_unicode_escapes,
    count_base64_chunks,
    count_sql_logic_patterns,
)

INPUT_DIR = "data"

# ==================================================================
# 5-CLASS — Broken Authentication thêm class 4
# ==================================================================
DESIRED_LABEL = {
    "bai.csv": 0,             # Benign
    "SQL.csv": 1,             # SQL Injection
    "XSS.csv": 2,             # XSS
    "commmand.csv": 3,        # Command Injection
    "brokenAuth.csv": 6       # NEW — Broken Authentication
}

NORMALIZE_LABEL = {str(i): i for i in range(5)}
NORMALIZE_LABEL.update({i: i for i in range(5)})

# META FEATURES — phải trùng 100% với train_clean.py + infer_clean.py
META_COLS = [
    "url_length", "entropy", "num_special", "special_ratio",
    "longest_special_seq",
    "cmd_keyword_count", "sql_comment_count", "cmd_special_count",
    "sql_keyword_count", "sql_boolean_ops", "sql_func_count",
    "xss_tag_count", "xss_event_count", "js_proto_count",
    "path_traversal_count", "sensitive_file_count", "shell_pattern_count",
    "xss_js_uri_count", "xss_rare_tag_count",
    "unicode_escape_count", "base64_chunk_count",
    "sql_logic_count",
]



# ==================================================================
# SPECIAL PARSER — dành cho brokenAuth.csv (CSV lỗi)
# ==================================================================
def parse_broken_auth(path):
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            parts = line.split(",", 6)   # split đúng 7 trường
            if len(parts) != 7:
                print("⚠️ Skip malformed:", line)
                continue
            rows.append(parts)

    df = pd.DataFrame(
        rows,
        columns=["id", "method", "user_agent", "url", "referer", "body", "label"]
    )
    return df



# ==================================================================
# ASSIGN LABEL
# ==================================================================
def assign_label(df: pd.DataFrame, fname: str) -> pd.DataFrame:
    if "lable" in df.columns:
        df["lable"] = df["lable"].astype(str).str.strip()
        df["label"] = df["lable"].map(NORMALIZE_LABEL)
        invalid = df["label"].isna().sum()
        if invalid > 0:
            print(f"⚠️ {fname}: {invalid} label invalid → auto-fix")
            df.loc[df["label"].isna(), "label"] = DESIRED_LABEL[fname]
    else:
        df["label"] = DESIRED_LABEL[fname]

    df["label"] = df["label"].astype(int)
    return df



# ==================================================================
# BUILD DATASET
# ==================================================================
def build_dataset():
    dfs = []

    for fname in DESIRED_LABEL:
        path = os.path.join(INPUT_DIR, fname)
        print(f"📂 Loading {path}")

        # BrokenAuth.csv cần parser đặc biệt
        if fname == "brokenAuth.csv":
            df = parse_broken_auth(path)
        else:
            df = pd.read_csv(path, on_bad_lines="skip")

        # Chuẩn hóa field
        df["id"] = df["id"].astype(str) if "id" in df.columns else ""
        df["url"] = df["url"] if "url" in df.columns else ""
        df["body"] = df["body"] if "body" in df.columns else ""

        # TEXT cho TF-IDF
        df["text"] = df.apply(
            lambda r: normalize_for_tfidf(str(r["url"]) + " " + str(r["body"])),
            axis=1,
        )

        # Gán nhãn
        df = assign_label(df, fname)

        # META FEATURES
        df["url_length"] = df["text"].str.len()
        df["entropy"] = df["text"].apply(calc_entropy)
        df["num_special"] = df["text"].apply(count_special_chars)
        df["special_ratio"] = df["num_special"] / (df["url_length"] + 1)
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

        df["unicode_escape_count"] = df["text"].apply(count_unicode_escapes)
        df["base64_chunk_count"] = df["text"].apply(count_base64_chunks)

        dfs.append(df)

    out_df = pd.concat(dfs, ignore_index=True)
    out_df = out_df.sample(frac=1.0, random_state=42).reset_index(drop=True)

    os.makedirs("dataset", exist_ok=True)
    out_df.to_parquet("dataset/train_df_clean.parquet", index=False)

    print("✔ DONE → dataset/train_df_clean.parquet")
    print("📊 Shape:", out_df.shape)
    print("📌 Label counts:\n", out_df["label"].value_counts())


if __name__ == "__main__":
    build_dataset()
