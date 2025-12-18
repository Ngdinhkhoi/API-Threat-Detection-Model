from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from datetime import datetime
from collections import Counter
import json, os

APP_FILE = os.getenv("ALERT_FILE", "results/infer_result.jsonl")

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def read_jsonl(path: str, limit: int = 5000):
    if not os.path.exists(path):
        return []

    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                pass

    return rows[-limit:]


@app.get("/")
def dashboard():
    # serve file HTML luôn (để khỏi phải mở file thủ công)
    return FileResponse("web/dashboard.html")


@app.get("/api/stats")
def stats():
    rows = read_jsonl(APP_FILE)

    counts = Counter(r.get("attack") or "Unknown" for r in rows)

    return {
        "file": APP_FILE,
        "total": len(rows),
        "counts": dict(counts),   # ✅ đếm động mọi attack
        "updated_at": datetime.utcnow().isoformat() + "Z",
    }


@app.get("/api/events")
def events(limit: int = 100):
    rows = read_jsonl(APP_FILE)

    rows = sorted(rows, key=lambda r: r.get("time", ""), reverse=True)

    out = []
    for r in rows[:limit]:
        out.append({
            "time": r.get("time") or "",
            "ip": r.get("ip") or "",
            "attack": r.get("attack") or "Unknown",
            "score": r.get("score") if r.get("score") is not None else "",
            "url": r.get("url") or "",
        })
    return out
