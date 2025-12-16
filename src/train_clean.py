#!/usr/bin/env python3
# train_clean.py (5-CLASS READY)

import os
import joblib
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from scipy.sparse import hstack, csr_matrix
from sklearn.metrics import classification_report, confusion_matrix
from lightgbm import LGBMClassifier, early_stopping, log_evaluation

# ============================================================
# PHẢI KHỚP với preprocess_clean.py & infer_clean.py
# ============================================================
META_COLS = [
    "url_length",
    "entropy",
    "num_special",
    "special_ratio",
    "longest_special_seq",
    "cmd_keyword_count",
    "sql_comment_count",
    "cmd_special_count",
    "sql_keyword_count",
    "sql_boolean_ops",
    "sql_func_count",
    "xss_tag_count",
    "xss_event_count",
    "js_proto_count",
    "path_traversal_count",
    "sensitive_file_count",
    "shell_pattern_count",
    "xss_js_uri_count",
    "xss_rare_tag_count",
    "unicode_escape_count",
    "base64_chunk_count",
    "sql_logic_count",
]


def train(random_state: int = 42):

    # ============================================================
    # 1. LOAD DATA
    # ============================================================
    df = pd.read_parquet("dataset/train_df_clean.parquet")

    print("📘 Loaded dataset:", df.shape)
    print("📊 Label distribution:\n", df["label"].value_counts())

    texts = df["text"].astype(str)
    labels = df["label"].astype(int)

    # ============================================================
    # 2. TF-IDF VECTORIZE
    # ============================================================
    print("🔧 TF-IDF fitting (char-level TF-IDF)...")

    tfidf = TfidfVectorizer(
        analyzer="char",
        ngram_range=(2, 6),
        lowercase=True,
        sublinear_tf=True,
        min_df=3,
        max_features=80_000,
    )

    X_text = tfidf.fit_transform(texts)
    print("📐 X_text shape:", X_text.shape)

    missing_meta = [c for c in META_COLS if c not in df.columns]
    if missing_meta:
        raise ValueError(f"❌ Missing META_COLS in dataset: {missing_meta}")

    X_meta = csr_matrix(df[META_COLS].astype(float).values)
    print("📐 X_meta shape:", X_meta.shape)

    X = hstack([X_text, X_meta])
    print("📐 X (TF-IDF + META) shape:", X.shape)

    # ============================================================
    # 3. TRAIN / VAL / TEST SPLIT
    # ============================================================
    X_train_full, X_test, y_train_full, y_test = train_test_split(
        X,
        labels,
        test_size=0.2,
        stratify=labels,
        random_state=random_state,
    )

    X_train, X_val, y_train, y_val = train_test_split(
        X_train_full,
        y_train_full,
        test_size=0.2,  # 64% train, 16% val, 20% test
        stratify=y_train_full,
        random_state=random_state,
    )

    print("📐 X_train:", X_train.shape)
    print("📐 X_val  :", X_val.shape)
    print("📐 X_test :", X_test.shape)

    # ============================================================
    # 4. LIGHTGBM MODEL TRAINING (UPDATED TO 5 CLASSES)
    # ============================================================
    print("🚀 Training LightGBM with 5 classes...")

    model = LGBMClassifier(
        objective="multiclass",
        num_class=5,   # 🔥 UPDATE TO 5 CLASSES
        n_estimators=2000,
        learning_rate=0.03,
        num_leaves=160,
        max_depth=-1,
        min_data_in_leaf=20,
        feature_fraction=0.8,
        bagging_fraction=0.8,
        reg_alpha=1.0,
        reg_lambda=1.0,
        class_weight="balanced",
        random_state=random_state,
        n_jobs=-1,
        verbose=-1,
    )

    model.fit(
        X_train,
        y_train,
        eval_set=[(X_val, y_val)],
        eval_metric="multi_logloss",
        callbacks=[
            early_stopping(120),
            log_evaluation(200),
        ],
    )

    # ============================================================
    # 5. EVAL
    # ============================================================
    print("\n📊 Evaluation on TEST set:")
    pred_test = model.predict(X_test)

    print(classification_report(y_test, pred_test, digits=4))
    print("🧩 Confusion matrix:\n", confusion_matrix(y_test, pred_test))

    # ============================================================
    # 6. SAVE MODEL
    # ============================================================
    os.makedirs("models", exist_ok=True)
    bundle = {
        "model": model,
        "tfidf": tfidf,
        "meta_cols": META_COLS,
        "label_map": {
            0: "Benign",
            1: "SQL Injection",
            2: "XSS",
            3: "Command Injection",
            6: "Broken Authentication",   # 🔥 NEW CLASS
        },
    }

    joblib.dump(bundle, "models/model_clean.pkl")

    print("\n💾 Saved → models/model_clean.pkl")
    print("✅ META_COLS saved.")
    print("🚀 Ready for infer_clean.py")


if __name__ == "__main__":
    train()
