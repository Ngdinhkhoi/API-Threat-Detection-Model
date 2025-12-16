#!/usr/bin/env python3
# alert_parser.py — FULL ALERT ENGINE FOR MODEL_CLEAN

import os
import json
import csv
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich import box

# Import predict + preprocess từ infer_clean.py
from src.infer_clean import predict, preprocess, load_model

console = Console()


# ============================================================
# PARSER FIX — HOẠT ĐỘNG VỚI MỌI DẠNG LOG
# ============================================================
def parse_log_item(item):
    """
    Chuẩn hoá log item từ mọi định dạng:
    ✔ JSON log đầy đủ
    ✔ Log thiếu field (chỉ có url/body)
    ✔ Log không có ip/method/time
    """

    # ----- TIME -----
    time = (
        item.get("time")
        or item.get("timestamp")
        or item.get("ts")
        or datetime.utcnow().isoformat()   # fallback: time hiện tại
    )

    # convert unix timestamp → ISO
    if isinstance(time, (int, float)):
        try:
            time = datetime.utcfromtimestamp(time).isoformat()
        except:
            time = str(time)

    # ----- IP -----
    ip = (
        item.get("ip")
        or item.get("remote_ip")
        or item.get("client_ip")
        or item.get("source_ip")
        or item.get("host")
        or item.get("ip_address")
        or item.get("src_ip")
        or ""
    )

    # fallback: search trong headers
    if not ip and "headers" in item:
        hdr = item["headers"]
        ip = (
            hdr.get("x-forwarded-for")
            or hdr.get("x-real-ip")
            or ""
        )

    # fallback cuối cùng: regex tìm IP trong cả log
    if not ip:
        import re
        m = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", json.dumps(item))
        ip = m.group(0) if m else "0.0.0.0"

    # ----- METHOD -----
    method = item.get("method") or item.get("http_method") or "GET"

    # ----- URL -----
    url = item.get("url") or item.get("path") or ""

    # ----- BODY -----
    body = item.get("body") or item.get("data") or ""

    return {
        "time": str(time),
        "ip": str(ip),
        "method": str(method),
        "url": str(url),
        "body": str(body)
    }


# ============================================================
# SEVERITY (0–100)
# ============================================================
def compute_severity(meta, attack_label):
    BASE = {
        "Benign": 0,
        "SQL Injection": 85,
        "XSS": 50,
        "Command Injection": 95,
        "Broken Authentication": 70,
    }

    score = BASE.get(attack_label, 0)
    score += 10 if meta["entropy"] > 4 else 0
    score += 5 if meta["base64_chunk_count"] > 0 else 0
    score += 10 if meta["shell_pattern_count"] > 0 else 0
    score += 10 if meta["path_traversal_count"] > 0 else 0
    score += 5 if meta["xss_event_count"] > 0 else 0
    score += 5 if meta["cmd_special_count"] > 0 else 0
    score += 5 if meta["sql_comment_count"] > 0 else 0

    return min(score, 100)


def severity_level(score):
    if score >= 90: return "CRITICAL"
    if score >= 70: return "HIGH"
    if score >= 40: return "MEDIUM"
    if score >= 10: return "LOW"
    return "SAFE"


# ============================================================
# LOAD JSON hoặc JSONL file
# ============================================================
def load_logs(path):
    logs = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read().strip()

        # JSON array
        if content.startswith("["):
            for item in json.loads(content):
                logs.append(parse_log_item(item))
            return logs

        # JSONL
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    logs.append(parse_log_item(json.loads(line)))
                except:
                    continue

    except Exception as e:
        console.print(f"[red]❌ Không đọc được log {path}: {e}[/]")

    return logs


# ============================================================
# SAVE CSV + JSONL
# ============================================================
def save_results(results):
    os.makedirs("results", exist_ok=True)

    # CSV
    csv_path = "results/alert_results.csv"
    with open(csv_path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["time", "ip", "method", "url", "body",
                    "attack", "confidence", "severity", "level"])
        for r in results:
            w.writerow([
                r["time"], r["ip"], r["method"], r["url"], r["body"],
                r["attack"], f"{r['confidence']:.2f}",
                r["severity"], r["level"]
            ])

    # JSONL
    jsonl_path = "results/alert_results.jsonl"
    with open(jsonl_path, "w", encoding="utf-8") as f:
        for r in results:
            json.dump(r, f)
            f.write("\n")

    console.print(f"[green]✔ Saved →[/] {csv_path}, {jsonl_path}")


# ============================================================
# MAIN
# ============================================================
def main():
    console.print("[cyan]=== ALERT ENGINE — AI SECURITY MODEL ===[/]")

    path = input("📄 Nhập đường dẫn log JSON/JSONL: ").strip()

    # auto detect in payloads folder
    if not os.path.exists(path):
        guess = os.path.join("payloads", path)
        if os.path.exists(guess):
            path = guess

    logs = load_logs(path)
    if not logs:
        console.print("[red]❌ Không có dữ liệu[/]")
        return

    console.print(f"[yellow]→ Loaded {len(logs)} log entries[/]")

    load_model()

    results = []

    table = Table(
        title="🚨 ALERT REPORT — TOP DANGEROUS EVENTS",
        header_style="bold magenta",
        box=box.HEAVY_EDGE
    )
    table.add_column("Attack")
    table.add_column("Level")
    table.add_column("Score")
    table.add_column("Confidence")
    table.add_column("IP")
    table.add_column("Time")
    table.add_column("URL")

    for item in logs:
        text, meta = preprocess(item["url"], item["body"])
        attack_label, confidence = predict(item["url"], item["body"])
        severity = compute_severity(meta, attack_label)
        level = severity_level(severity)

        result = {
            "time": item["time"],
            "ip": item["ip"],
            "method": item["method"],
            "url": item["url"],
            "body": item["body"],
            "attack": attack_label,
            "confidence": confidence,
            "severity": severity,
            "level": level,
        }
        results.append(result)

        if severity >= 40:
            table.add_row(
                attack_label, level, str(severity),
                f"{confidence:.2f}%", item["ip"],
                item["time"], item["url"]
            )

    console.print(table)
    save_results(results)


if __name__ == "__main__":
    main()
