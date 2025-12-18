# 🚨 AI Web Attack Detection System (Model Clean)

An AI-based web attack detection system using **Machine Learning (LightGBM + TF-IDF + Meta-features)**. The system supports:

* SQL Injection
* XSS
* Command Injection
* Broken Authentication
* Benign traffic

It can run in **offline mode (CLI)** or **realtime mode (WebSocket + Dashboard)**.

---

## 1️⃣ Environment Setup

### Install dependencies

```bash
pip install -r requirements.txt
```

### Main libraries

* scikit-learn
* lightgbm
* pandas
* scipy
* rich
* fastapi
* uvicorn

---

## 2️⃣ Project Structure

```text
MODEL_OFFICIAL/
├─ data/
│  ├─ bai.csv
│  ├─ SQL.csv
│  ├─ XSS.csv
│  ├─ commmand.csv
│  └─ brokenAuth.csv
│
├─ dataset/
│  └─ train_df_clean.parquet        # artifact generated after preprocessing
│
├─ models/
│  └─ model_clean.pkl               # trained model (Git LFS recommended)
│
├─ payloads/
│  ├─ benign.csv
│  ├─ command.csv
│  ├─ xss.csv
│  ├─ sqli.jsonl
│  ├─ brokenAuth.jsonl
│  └─ test_log.jsonl
│
├─ results/
│  ├─ infer_result.csv
│  ├─ infer_result.jsonl
│  ├─ alert_results.csv
│  └─ alert_results.jsonl
│
├─ src/
│  ├─ preprocess_clean.py
│  ├─ train_clean.py
│  ├─ infer_clean.py
│  ├─ alert_parser.py
│  ├─ alert_ws_server.py
│  ├─ dashboard_api.py
│  └─ utils_clean.py
│
├─ web/
│  └─ dashboard.html
│
└─ README.md
```

---

## 3️⃣ Data Preprocessing

**Script:** `src/preprocess_clean.py`

```bash
python src/preprocess_clean.py
```

### Responsibilities

* Load datasets from `data/`
* Normalize URL + BODY (multi-layer decoding, HTML unescape)
* Label mapping:

  * 0: Benign
  * 1: SQL Injection
  * 2: XSS
  * 3: Command Injection
  * 6: Broken Authentication
* Extract **22+ advanced meta-features**
* Shuffle dataset
* Save cleaned dataset

📦 Output:

```
dataset/train_df_clean.parquet
```

---

## 4️⃣ Model Training

**Script:** `src/train_clean.py`

```bash
python src/train_clean.py
```

### Training Pipeline

* Character-level TF-IDF (2–6 grams)
* Merge TF-IDF features with meta-features → sparse matrix
* Data split:

  * 64% training
  * 16% validation
  * 20% testing
* Train LightGBM (5 classes)
* Early stopping

📦 Output:

```
models/model_clean.pkl
```

### Training Output

* Classification report
* Confusion matrix
* Training logs (loss per iteration)

---

## 5️⃣ Payload Testing (CLI)

**Script:** `src/infer_clean.py`

```bash
python src/infer_clean.py
```

### Features

* Load trained model + TF-IDF
* Test payloads from JSONL / CSV files
* Rich-based interactive terminal UI
* Rank payloads by risk level
* Export results:

  * `results/infer_result.jsonl`
  * `results/infer_result.csv`

---

## 6️⃣ Alert Engine (Log Analysis)

**Script:** `src/alert_parser.py`

```bash
python src/alert_parser.py
```

### Capabilities

* Read JSON / JSONL logs
* Auto-parse inconsistent or incomplete log formats
* Run inference + meta-feature analysis
* Compute **Severity score (0–100)**
* Severity levels:

  * SAFE / LOW / MEDIUM / HIGH / CRITICAL
* Export alerts:

  * `results/alert_results.csv`
  * `results/alert_results.jsonl`

---

## 7️⃣ Realtime WebSocket & Dashboard

### WebSocket Server

```bash
uvicorn src.alert_ws_server:app --reload
```

* Endpoint: `/ws/alerts`
* Receive realtime logs
* Broadcast alerts to dashboard & attack tester

### Dashboard API

```bash
uvicorn src.dashboard_api:app --reload
```

* Dashboard: `http://127.0.0.1:8000`
* APIs:

  * `/api/stats`
  * `/api/events`

---

## 8️⃣ How the Model Works

### 1. TF-IDF (Character-level)

Captures malicious patterns such as:

* `' or 1=1 --`
* `<script>alert(1)</script>`
* `; ls -la`
* `../../etc/passwd`
* Multi-encoded payloads

### 2. Meta-features (Critical signals)

* `entropy`, `base64_chunk_count` → detect obfuscation / encoding
* `xss_event_count`, `rare_tag_count` → advanced XSS detection
* `cmd_special_count`, `shell_pattern_count` → command injection
* `sql_logic_count`, `sql_boolean_ops` → logic-based SQL injection

---

## 9️⃣ Microservice Integration

Recommended flow:

```
Client → API Gateway → Security Model → Backend Services
```

Example usage:

```python
label, confidence = predict(url, body)
if label != "Benign":
    block / log / alert
```

---

## 🔟 Quick Commands

```bash
# Preprocess data
python src/preprocess_clean.py

# Train model
python src/train_clean.py

# Test payloads
python src/infer_clean.py

# Run alert engine
python src/alert_parser.py

