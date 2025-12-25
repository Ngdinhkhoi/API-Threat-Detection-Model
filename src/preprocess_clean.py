#!/usr/bin/env python3
# preprocess_clean.py (FIXED — BROKENAUTOH CSV MULTILINE SAFE)

import os
import csv
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

DESIRED_LABEL = {
    "bai.csv": 0,             # Benign
    "SQL.csv": 1,             # SQL Injection
    "XSS.csv": 2,             # XSS
    "commmand.csv": 3,        # Command Injection
    "brokenAuth.csv": 6       # Broken Authentication
}

# map cho label dạng string "0"..."6" (nếu có cột lable)
NORMALIZE_LABEL = {str(i): i for i in range(7)}
NORMALIZE_LABEL.update({i: i for i in range(7)})

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
# FIXED PARSER — dành cho brokenAuth.csv (multiline JSON body)
# ==================================================================
def parse_broken_auth(path: str) -> pd.DataFrame:
    rows = []

    # newline="" rất quan trọng để csv.reader xử lý multiline field đúng
    with open(path, "r", encoding="utf-8", newline="") as f:
        reader = csv.reader(f, delimiter=",", quotechar='"', escapechar="\\")

        first = next(reader, None)
        if first is None:
            return pd.DataFrame(columns=["id","method","user_agent","url","referer","body","label"])

        # Detect header
        first_lower = [c.strip().lower() for c in first]
        has_header = ("id" in first_lower and "method" in first_lower and ("label" in first_lower or "lable" in first_lower))

        def normalize_row(row):
            # Mong muốn 7 cột: id,method,user_agent,url,referer,body,label
            # Nếu body chứa dấu phẩy và file không quote chuẩn → row có thể > 7 cột
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
                # bỏ những record thực sự hỏng (rất hiếm sau khi dùng csv.reader)
                print("⚠️ Skip malformed:", row[:3], "... (cols=", len(row), ")")
                continue
            rows.append(row)

    df = pd.DataFrame(rows, columns=["id","method","user_agent","url","referer","body","label"])
    return df

# ==================================================================
# ASSIGN LABEL
# ==================================================================
def assign_label(df: pd.DataFrame, fname: str) -> pd.DataFrame:
    # Nếu file có cột 'lable' (sai chính tả) thì ưu tiên dùng nó
    if "lable" in df.columns:
        df["lable"] = df["lable"].astype(str).str.strip()
        df["label"] = df["lable"].map(NORMALIZE_LABEL)
        invalid = df["label"].isna().sum()
        if invalid > 0:
            print(f"⚠️ {fname}: {invalid} label invalid → auto-fix")
            df.loc[df["label"].isna(), "label"] = DESIRED_LABEL[fname]
    else:
        # Nếu không có label/lable → gán label theo file
        df["label"] = DESIRED_LABEL[fname]

    df["label"] = pd.to_numeric(df["label"], errors="coerce").fillna(DESIRED_LABEL[fname]).astype(int)
    return df

# ==================================================================
# BUILD DATASET
# ==================================================================
def build_dataset():
    dfs = []

    for fname in DESIRED_LABEL:
        path = os.path.join(INPUT_DIR, fname)
        print(f"📂 Loading {path}")

        if fname == "brokenAuth.csv":
            df = parse_broken_auth(path)
        else:
            # engine="python" đôi khi đọc “bẩn” tốt hơn
            df = pd.read_csv(path, on_bad_lines="skip", engine="python")

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
