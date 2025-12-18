# 🚨 Hệ thống phát hiện tấn công Web bằng AI (Model Clean)

Đây là hệ thống phát hiện tấn công web sử dụng **Machine Learning (LightGBM + TF-IDF + Meta-features)**, hỗ trợ các loại tấn công phổ biến trong môi trường web/API:

* SQL Injection
* XSS (Cross-Site Scripting)
* Command Injection
* Broken Authentication
* Benign (lưu lượng hợp lệ)

Hệ thống có thể chạy ở chế độ **offline (CLI)** hoặc **realtime (WebSocket + Dashboard)**, phù hợp cho SOC, WAF, API Gateway hoặc microservice security.

👉 **English version:** [README.md](README.md)

---

## 1️⃣ Chuẩn bị môi trường

### Cài đặt dependencies

```bash
pip install -r requirements.txt
```

### Các thư viện chính

* scikit-learn
* lightgbm
* pandas
* scipy
* rich
* fastapi
* uvicorn

---

## 2️⃣ Cấu trúc thư mục

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
│  └─ train_df_clean.parquet        # file sinh ra sau bước preprocess
│
├─ models/
│  └─ model_clean.pkl               # model đã train (khuyến nghị dùng Git LFS)
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

## 3️⃣ Tiền xử lý dữ liệu

**Script:** `src/preprocess_clean.py`

```bash
python src/preprocess_clean.py
```

### Chức năng chính

* Load dữ liệu từ thư mục `data/`
* Chuẩn hóa URL + BODY (multi-decode, HTML unescape)
* Ánh xạ nhãn:

  * 0: Benign
  * 1: SQL Injection
  * 2: XSS
  * 3: Command Injection
  * 6: Broken Authentication
* Trích xuất **22+ meta-features nâng cao**
* Shuffle dữ liệu
* Lưu dataset đã chuẩn hóa

📦 Output:

```
dataset/train_df_clean.parquet
```

---

## 4️⃣ Huấn luyện mô hình

**Script:** `src/train_clean.py`

```bash
python src/train_clean.py
```

### Pipeline huấn luyện

* TF-IDF ở mức **character-level (2–6 grams)**
* Kết hợp TF-IDF + meta-features → sparse matrix
* Chia dữ liệu:

  * 64% train
  * 16% validation
  * 20% test
* Huấn luyện LightGBM với 5 lớp
* Early stopping

📦 Output:

```
models/model_clean.pkl
```

### Kết quả hiển thị

* Classification report
* Confusion matrix
* Log huấn luyện (loss theo epoch)

---

## 5️⃣ Kiểm thử payload (CLI)

**Script:** `src/infer_clean.py`

```bash
python src/infer_clean.py
```

### Tính năng

* Load model + TF-IDF
* Test payload từ file JSONL / CSV
* Giao diện terminal bằng **Rich**
* Sắp xếp payload theo độ nguy hiểm
* Xuất kết quả:

  * `results/infer_result.jsonl`
  * `results/infer_result.csv`

---

## 6️⃣ Alert Engine (Phân tích log)

**Script:** `src/alert_parser.py`

```bash
python src/alert_parser.py
```

### Chức năng

* Đọc log JSON / JSONL
* Tự động parse log thiếu field (IP, time, method…)
* Chạy inference kết hợp meta-feature
* Tính **Severity (0–100)**
* Phân cấp mức độ:

  * SAFE / LOW / MEDIUM / HIGH / CRITICAL
* Xuất kết quả alert:

  * `results/alert_results.csv`
  * `results/alert_results.jsonl`

---

## 7️⃣ Realtime WebSocket & Dashboard

### WebSocket Server

```bash
uvicorn src.alert_ws_server:app --reload
```

* Endpoint: `/ws/alerts`
* Nhận log realtime
* Broadcast alert tới dashboard & attack tester

### Dashboard API

```bash
uvicorn src.dashboard_api:app --reload
```

* Dashboard: `http://127.0.0.1:8000`
* API:

  * `/api/stats`
  * `/api/events`

---

## 8️⃣ Mô hình hoạt động như thế nào?

### 1. TF-IDF (character-level)

Bắt các pattern nguy hiểm:

* `' or 1=1 --`
* `<script>alert(1)</script>`
* `; ls -la`
* `../../etc/passwd`
* Payload encode nhiều lớp

### 2. Meta-features (rất quan trọng)

* `entropy`, `base64_chunk_count` → phát hiện encode / obfuscation
* `xss_event_count`, `rare_tag_count` → XSS nâng cao
* `cmd_special_count`, `shell_pattern_count` → Command Injection
* `sql_logic_count`, `sql_boolean_ops` → SQL Injection dựa trên logic

---

## 9️⃣ Tích hợp Microservice

Luồng khuyến nghị:

```
Client → API Gateway → Security Model → Backend Services
```

Cách sử dụng:

```python
label, confidence = predict(url, body)
if label != "Benign":
    block / log / alert
```

---

## 🔟 Lệnh nhanh

```bash
# Tiền xử lý dữ liệu
python src/preprocess_clean.py

# Huấn luyện model
python src/train_clean.py

# Test payload
python src/infer_clean.py

# Chạy alert engine
python src/alert_parser.py
```


