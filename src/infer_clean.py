#!/usr/bin/env python3
import warnings
warnings.filterwarnings("ignore")

import joblib
import os
import json
import csv
from scipy.sparse import csr_matrix, hstack
from rich.console import Console
from rich.table import Table
from rich import box

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

console = Console()

DEFAULT_LABEL_MAP = {
    0: "Benign",
    1: "SQL Injection",
    2: "XSS",
    3: "Command Injection",
    6: "Broken Authentication"
}

DEFAULT_META_COLS = [
    "url_length","entropy","num_special","special_ratio","longest_special_seq",
    "cmd_keyword_count","sql_comment_count","cmd_special_count",
    "sql_keyword_count","sql_boolean_ops","sql_func_count",
    "xss_tag_count","xss_event_count","js_proto_count",
    "path_traversal_count","sensitive_file_count","shell_pattern_count",
    "xss_js_uri_count","xss_rare_tag_count",
    "unicode_escape_count","base64_chunk_count","sql_logic_count",
]

MODEL_BUNDLE = None


def load_model():
    global MODEL_BUNDLE
    if MODEL_BUNDLE is None:
        MODEL_BUNDLE = joblib.load("models/model_clean.pkl")
        console.print("[green]📘 Model loaded[/]")
    return MODEL_BUNDLE


def preprocess(url, body=""):
    text = normalize_for_tfidf(str(url) + " " + str(body))

    meta = {
        "url_length": len(text),
        "entropy": calc_entropy(text),
        "num_special": count_special_chars(text),
        "special_ratio": count_special_chars(text) / (len(text) + 1),
        "longest_special_seq": longest_special_run(text),

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

        "unicode_escape_count": count_unicode_escapes(text),
        "base64_chunk_count": count_base64_chunks(text),
    }

    return text, meta


def predict(url, body=""):
    bundle = load_model()

    model = bundle["model"]
    tfidf = bundle["tfidf"]
    meta_cols = bundle.get("meta_cols", DEFAULT_META_COLS)
    label_map = bundle.get("label_map", DEFAULT_LABEL_MAP)

    text, meta = preprocess(url, body)
    X_text = tfidf.transform([text])
    X_meta = csr_matrix([[meta[c] for c in meta_cols]])
    X = hstack([X_text, X_meta])

    probs = model.predict_proba(X)[0]
    idx_model = int(probs.argmax())
    idx_label = 6 if idx_model == 4 else idx_model
    prob = float(probs[idx_model] * 100)

    return label_map[idx_label], prob


def load_jsonl(path):
    arr = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip(): 
                    continue
                item = json.loads(line)
                arr.append((item.get("url",""), item.get("body","")))
    except:
        pass
    return arr


def save_csv(results):
    os.makedirs("results", exist_ok=True)
    out = "results/infer_result.csv"
    with open(out,"w",encoding="utf-8",newline="") as f:
        w = csv.writer(f)
        w.writerow(["label","probability","url","body"])
        for label, prob, url, body in results:
            w.writerow([label, f"{prob:.2f}", url, body])
    console.print(f"[green]✔ CSV saved → {out}[/]")


def main():

    FILES = {
        "1": "payloads/benign.jsonl",
        "2": "payloads/sqli.jsonl",
        "3": "payloads/command.jsonl",
        "4": "payloads/xss.jsonl",
        "5": "payloads/brokenAuth.jsonl"
    }

    console.print("[cyan]=== PAYLOAD TESTER (local mode, không WebSocket) ===[/]")
    print("1. Test benign.jsonl")
    print("2. Test sqli.jsonl")
    print("3. Test command.jsonl")
    print("4. Test xss.jsonl")
    print("5. Test brokenAuth.jsonl")
    print("6. Test 1 JSON log thủ công")
    print("7. Exit\n")

    choice = input("Select: ").strip()

    if choice == "7":
        return

    # manual JSON log
    if choice == "6":
        raw = input("Nhập JSON log: ").strip()
        try:
            obj = json.loads(raw)
            url = obj.get("url","")
            body = obj.get("body","")
        except:
            console.print("[red]JSON không hợp lệ[/]")
            return

        label, prob = predict(url, body)

        console.print(f"\n[bold green]→ {label} ({prob:.2f}%)")
        print("URL :", url)
        print("BODY:", body)
        return

    # file mode
    if choice not in FILES:
        console.print("[red]Lựa chọn không hợp lệ[/]")
        return

    payloads = load_jsonl(FILES[choice])
    results = []

    for url, body in payloads:
        label, prob = predict(url, body)
        results.append((label, prob, url, body))

    save_csv(results)

    results.sort(key=lambda x: -x[1])
    table = Table(title="TOP PAYLOADS", header_style="bold magenta", box=box.HEAVY_EDGE)
    table.add_column("Label")
    table.add_column("%")
    table.add_column("URL")

    for l,p,u,b in results[:20]:
        table.add_row(l, f"{p:.2f}", u)

    console.print(table)


if __name__ == "__main__":
    main()
