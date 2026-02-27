#!/usr/bin/env python3
# train_clean.py

import os
import joblib
import pandas as pd
import json

from pathlib import Path
from datetime import datetime
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from scipy.sparse import hstack, csr_matrix
from sklearn.metrics import classification_report, confusion_matrix
from lightgbm import LGBMClassifier, early_stopping, log_evaluation
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
)


# ========== Feature groups (for train/infer consistency) ==========
META_TEXT_COLS = [
    "url_length", "entropy", "num_special", "special_ratio", "ratio_alpha", "longest_special_seq",
    "unbalanced_quotes", "unbalanced_parens", "unbalanced_brackets",
    "local_entropy_max", "entropy_spike", "max_query_value_len",
]

META_PAYLOAD_COLS = [
    "cmd_keyword_count", "cmd_special_count", "shell_pattern_count",
    "sql_comment_count", "sql_keyword_count", "sql_boolean_ops", "sql_func_count", "sql_logic_count",
    "xss_tag_count", "xss_event_count", "js_proto_count", "xss_js_uri_count", "xss_rare_tag_count",
    "xss_sink_count", "xss_obfus_count", "html_entity_count", "unicode_escape_count", "base64_chunk_count",
    "path_traversal_count", "sensitive_file_count",
    "broken_auth_score",
]

META_BEHAVIOR_COLS = [
    "req_cnt_10s", "req_cnt_60s", "unique_url_60s",
    "token_present", "token_ratio_60s", "token_first_seen_sec_ago",
    "inv_req_10s", "inv_unique_60s", "inv_seq_score_60s",
    "update_cnt_60s",
    "status_401_60s", "status_403_60s", "fail_ratio_60s",
]

USE_BEHAVIOR = False  # <-- thêm dòng này

META_COLS = META_TEXT_COLS + META_PAYLOAD_COLS
if USE_BEHAVIOR:
    META_COLS = META_COLS + META_BEHAVIOR_COLS


# =========================
# CONFIG FLAGS
# =========================
USE_SOURCE_SPLIT = True   # True: split theo file/source (OOD test)
USE_META_ONLY    = False  # True: chỉ dùng META features, không dùng TF-IDF

TRAIN_SOURCES = {"bai.csv", "SQL.csv", "XSS.csv", "BOLA_train.csv"}
TEST_SOURCES  = {"XSS_cus.csv", "brokenAuth.csv", "BOLA_test.csv"}


def train(random_state: int = 42):
    # ============================================================
    # 1. LOAD DATA
    # ============================================================
    df = pd.read_parquet("dataset/train_df_clean.parquet")

    print(f"📘 Shape gốc: {df.shape}")

    # ✅ Xóa trùng lặp theo cột text (URL + Body đã gộp)
    if "text" not in df.columns:
        raise ValueError("❌ Dataset missing required column: 'text'")

    before = len(df)
    df = df.drop_duplicates(subset=["text"]).reset_index(drop=True)
    after = len(df)
    print(f"🧹 Xóa duplicate theo 'text': {before} -> {after} rows")

    print("📊 Label distribution:\n", df["label"].value_counts())

    # ✅ safety check: label phải nằm trong 0..3
    labels = df["label"].astype(int)
    y_bin = (labels != 0).astype(int)
    print("📊 Binary distribution:\n", y_bin.value_counts())
    bad = sorted(set(labels.unique()) - {0, 1, 2, 3})
    if bad:
        raise ValueError(
            f"❌ Found unexpected labels (must be 0..3): {bad}. "
            f"Please re-run preprocess_clean.py."
        )

    missing_meta = [c for c in META_COLS if c not in df.columns]
    if missing_meta:
        raise ValueError(f"❌ Missing META_COLS in dataset: {missing_meta}")

    # ============================================================
    # 2. TRAIN / VAL / TEST SPLIT 
    # ============================================================
    # ============================================================
    # 2. SPLIT
    #   - Nếu USE_SOURCE_SPLIT=True: hold-out theo source (OOD test)
    #   - Nếu False: random split như cũ
    # ============================================================
    if USE_SOURCE_SPLIT:
        if "source" not in df.columns:
            raise ValueError("❌ Dataset missing 'source'. Hãy chạy lại preprocess_clean.py sau khi thêm df['source']=fname")

        idx_trainval = df.index[df["source"].isin(TRAIN_SOURCES)].to_numpy()
        idx_test     = df.index[df["source"].isin(TEST_SOURCES)].to_numpy()

        if len(idx_trainval) == 0 or len(idx_test) == 0:
            raise ValueError(
                f"❌ Split theo source bị rỗng. Kiểm tra TRAIN_SOURCES/TEST_SOURCES.\n"
                f"Trainval={len(idx_trainval)}, Test={len(idx_test)}"
            )

        # VAL lấy từ trainval (25% của trainval)
        idx_train, idx_val = train_test_split(
            idx_trainval,
            test_size=0.25,
            stratify=y_bin.loc[idx_trainval],
            random_state=random_state,
        )
    else:
        idx = df.index.to_numpy()

        idx_trainval, idx_test = train_test_split(
            idx,
            test_size=0.10,
            stratify=y_bin.loc[idx],
            random_state=random_state,
        )

        idx_train, idx_val = train_test_split(
            idx_trainval,
            test_size=0.1111,
            stratify=y_bin.loc[idx_trainval],
            random_state=random_state,
        )

    print("📦 Split sizes (train/val/test):")
    print(f"  Training Set  : {len(idx_train)} samples")
    print(f"  Validation Set: {len(idx_val)} samples")
    print(f"  Test Set      : {len(idx_test)} samples")

    # Lấy text/label theo index
    X_train_txt = df.loc[idx_train, "text"].astype(str)
    X_val_txt   = df.loc[idx_val, "text"].astype(str)
    X_test_txt  = df.loc[idx_test, "text"].astype(str)

    y_train = y_bin.loc[idx_train]
    y_val   = y_bin.loc[idx_val]
    y_test  = y_bin.loc[idx_test]

    # ============================================================
    # 3. TF-IDF VECTORIZE (FIT CHỈ TRÊN TRAIN) - GIẢM HỌC THUỘC LÒNG
    # ============================================================
    print("🔧 TF-IDF fitting (char-level TF-IDF) [TRAIN ONLY]...")

    tfidf = TfidfVectorizer(
        analyzer="word",
        token_pattern=r"(?u)\b\w+\b",
        ngram_range=(1, 2),      
        lowercase=False,
        sublinear_tf=True,
        min_df=5,
        max_df=0.9,
        max_features=1_000,      
    )

    X_train_text = tfidf.fit_transform(X_train_txt)
    X_val_text   = tfidf.transform(X_val_txt)
    X_test_text  = tfidf.transform(X_test_txt)

    print("📐 X_train_text shape:", X_train_text.shape)
    print("📐 X_val_text   shape:", X_val_text.shape)
    print("📐 X_test_text  shape:", X_test_text.shape)

    # Meta theo đúng split
    X_train_meta = csr_matrix(df.loc[idx_train, META_COLS].astype(float).values)
    X_val_meta   = csr_matrix(df.loc[idx_val, META_COLS].astype(float).values)
    X_test_meta  = csr_matrix(df.loc[idx_test, META_COLS].astype(float).values)

    print("📐 X_train_meta shape:", X_train_meta.shape)
    print("📐 X_val_meta   shape:", X_val_meta.shape)
    print("📐 X_test_meta  shape:", X_test_meta.shape)

    # Ghép từng tập
    if USE_META_ONLY:
        print("🧪 META-ONLY mode: bỏ TF-IDF, chỉ dùng META_COLS")
        X_train = X_train_meta
        X_val   = X_val_meta
        X_test  = X_test_meta

        feature_names = META_COLS
        tfidf = None  # để bundle vẫn save nhưng infer phải handle
    else:
        # Ghép từng tập
        X_train = hstack([X_train_text, X_train_meta])
        X_val   = hstack([X_val_text, X_val_meta])
        X_test  = hstack([X_test_text, X_test_meta])

        feature_names = tfidf.get_feature_names_out().tolist() + META_COLS

    print("📐 X_train:", X_train.shape)
    print("📐 X_val  :", X_val.shape)
    print("📐 X_test :", X_test.shape)

    

    # ============================================================
    # 4. LIGHTGBM MODEL TRAINING (4 CLASSES) - REGULARIZATION
    # ============================================================
    print("Training LightGBM (BINARY: benign vs attack)")

    model = LGBMClassifier(
        objective="binary",
        

        n_estimators=2000,
        learning_rate=0.05,

        num_leaves=30,
        max_depth=-1,
        min_child_samples=200,

        feature_fraction=0.8,
        bagging_fraction=0.8,
        bagging_freq=5,

        reg_alpha=1.0,
        reg_lambda=50.0,

        class_weight="balanced",
        random_state=random_state,
        n_jobs=-1,
        verbose=-1,
    )

    model.fit(
        X_train,
        y_train,
        feature_name=feature_names,
        eval_set=[(X_val, y_val)],
        eval_metric="binary_logloss",
        callbacks=[
            early_stopping(120),
            log_evaluation(200),
        ],
    )

    # ============================================================
    # 5. EVAL
    # ============================================================
    def _ts():
        return datetime.now().strftime("%Y%m%d-%H%M%S")

    def save_run_report(run_dir: str, payload: dict):
        Path(run_dir).mkdir(parents=True, exist_ok=True)
        # json (đọc lại dễ)
        with open(os.path.join(run_dir, "report.json"), "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        # txt (đọc nhanh)
        with open(os.path.join(run_dir, "report.txt"), "w", encoding="utf-8") as f:
            f.write(payload["text_report"])

    print("\n📊 Evaluation on TEST set:")

    thresholds = [0.5, 0.3, 0.2]
    proba_test = model.predict_proba(X_test)[:, 1]  # P(attack)
    auc = roc_auc_score(y_test, proba_test)

    run_id = _ts()
    run_dir = os.path.join("results", f"run_{run_id}")

    summary = {
        "run_id": run_id,
        "time": datetime.now().isoformat(timespec="seconds"),
        "random_state": random_state,
        "use_source_split": USE_SOURCE_SPLIT,
        "use_meta_only": USE_META_ONLY,
        "split_sizes": {
            "train": int(len(idx_train)),
            "val": int(len(idx_val)),
            "test": int(len(idx_test)),
        },
        "sources": {
            "train_sources": sorted(list(TRAIN_SOURCES)) if USE_SOURCE_SPLIT else None,
            "test_sources": sorted(list(TEST_SOURCES)) if USE_SOURCE_SPLIT else None,
        },
        "auc_roc": float(auc),
        "threshold_results": [],
    }

    # txt report builder
    lines = []
    lines.append(f"Run ID: {run_id}")
    lines.append(f"Time: {summary['time']}")
    lines.append(f"Random state: {random_state}")
    lines.append(f"USE_SOURCE_SPLIT: {USE_SOURCE_SPLIT}")
    lines.append(f"USE_META_ONLY: {USE_META_ONLY}")
    lines.append(f"Split (train/val/test): {len(idx_train)}/{len(idx_val)}/{len(idx_test)}")
    if USE_SOURCE_SPLIT:
        lines.append(f"TRAIN_SOURCES: {sorted(list(TRAIN_SOURCES))}")
        lines.append(f"TEST_SOURCES : {sorted(list(TEST_SOURCES))}")
    lines.append(f"AUC-ROC: {auc:.6f}")
    lines.append("")

    for threshold in thresholds:
        pred_test = (proba_test >= threshold).astype(int)

        acc = accuracy_score(y_test, pred_test)
        prec = precision_score(y_test, pred_test, zero_division=0)
        rec  = recall_score(y_test, pred_test, zero_division=0)
        f1   = f1_score(y_test, pred_test, zero_division=0)

        cm = confusion_matrix(y_test, pred_test)
        rep = classification_report(y_test, pred_test, digits=4, zero_division=0)

        # console
        print(f"\n==== THRESHOLD = {threshold} ====")
        print(f"Accuracy : {acc:.6f}")
        print(f"Precision: {prec:.6f}")
        print(f"Recall   : {rec:.6f}")
        print(f"F1-score : {f1:.6f}")
        print(f"AUC-ROC  : {auc:.6f}")
        print("🧩 Confusion matrix:\n", cm)
        print(rep)

        # json
        summary["threshold_results"].append({
            "threshold": float(threshold),
            "accuracy": float(acc),
            "precision": float(prec),
            "recall": float(rec),
            "f1": float(f1),
            "confusion_matrix": cm.tolist(),
            "classification_report": rep,
        })

        # txt
        lines.append(f"==== THRESHOLD = {threshold} ====")
        lines.append(f"Accuracy : {acc:.6f}")
        lines.append(f"Precision: {prec:.6f}")
        lines.append(f"Recall   : {rec:.6f}")
        lines.append(f"F1-score : {f1:.6f}")
        lines.append("Confusion matrix:")
        lines.append(str(cm))
        lines.append("Classification report:")
        lines.append(rep)
        lines.append("")

    summary["text_report"] = "\n".join(lines)
    save_run_report(run_dir, summary)

    print(f"📝 Saved report → {run_dir}/report.txt & report.json")

    # ============================================================
    # 6. SAVE MODEL (save 1 lần, không nằm trong loop)
    # ============================================================
    os.makedirs("models", exist_ok=True)
    bundle = {
        "model": model,
        "tfidf": tfidf,
        "meta_cols": META_COLS,
        "label_map": {
            0: "Benign",
            1: "Attack",
        },
        "thresholds": [0.5, 0.3, 0.2],
    }

    joblib.dump(bundle, "models/model_clean.pkl")

    print("\n💾 Saved → models/model_clean.pkl")
    print("✅ META_COLS saved.")
    print("🚀 Ready for infer_clean.py")

if __name__ == "__main__":
    train()
