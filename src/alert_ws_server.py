#!/usr/bin/env python3
# alert_ws_server.py — Realtime alert WebSocket server

import os
from typing import Any, Dict, List

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse

# Import model pipeline
from src.infer_clean import preprocess, predict, load_model
from src.alert_parser import compute_severity, severity_level, parse_log_item

app = FastAPI()

# ============================================================
# DANH SÁCH TẤT CẢ CLIENT WEBSOCKET (DASHBOARD + ATTACK TESTER)
# ============================================================
clients: List[WebSocket] = []


# ============================================================
# STARTUP → LOAD MODEL 1 LẦN
# ============================================================
@app.on_event("startup")
def _startup():
    load_model()
    print("📘 Model loaded")


# ============================================================
# TRẢ GIAO DIỆN DASHBOARD
# ============================================================
@app.get("/")
def dashboard():
    base_dir = os.path.dirname(os.path.dirname(__file__))
    html_path = os.path.join(base_dir, "web", "alert_dashboard.html")

    if not os.path.exists(html_path):
        return HTMLResponse("<h1>Không tìm thấy alert_dashboard.html</h1>", 404)

    with open(html_path, "r", encoding="utf-8") as f:
        return HTMLResponse(f.read())


# ============================================================
# TRẢ GIAO DIỆN ATTACK TESTER
# ============================================================
@app.get("/attack")
def attack_ui():
    base_dir = os.path.dirname(os.path.dirname(__file__))
    html_path = os.path.join(base_dir, "web", "attack_tester.html")

    if not os.path.exists(html_path):
        return HTMLResponse("<h1>Không tìm thấy attack_tester.html</h1>", 404)

    with open(html_path, "r", encoding="utf-8") as f:
        return HTMLResponse(f.read())


# ============================================================
# HÀM PHÁT ALERT CHO TẤT CẢ CLIENT
# ============================================================
async def broadcast(alert: dict):
    dead_clients = []

    for ws in clients:
        try:
            await ws.send_json(alert)
        except:
            dead_clients.append(ws)

    # remove client bị rớt
    for ws in dead_clients:
        clients.remove(ws)


# ============================================================
# WEBSOCKET CHÍNH: nhận log từ whook + attack tester + infer
# ============================================================
@app.websocket("/ws/alerts")
async def ws_alerts(ws: WebSocket):
    await ws.accept()
    clients.append(ws)
    print("🔌 Client connected. Total:", len(clients))

    try:
        while True:
            data: Dict[str, Any] = await ws.receive_json()

            # Chuẩn hóa log
            item = parse_log_item(data)

            # Model inference
            _, meta = preprocess(item["url"], item["body"])
            attack_label, confidence = predict(item["url"], item["body"])
            severity = compute_severity(meta, attack_label)
            level = severity_level(severity)

            alert = {
                "time": item["time"],
                "ip": item["ip"],
                "method": item["method"],
                "url": item["url"],
                "body": item["body"],
                "attack": attack_label,
                "confidence": confidence,
                "severity": severity,
                "level": level
            }

            # gửi alert cho tất cả client khác
            await broadcast(alert)

    except WebSocketDisconnect:
        print("❌ Client disconnected")
        if ws in clients:
            clients.remove(ws)
        return
