import os, json
from collections import Counter

IN_PATH = "results/infer_result.jsonl"   # đổi nếu file nằm chỗ khác
OUT_DIR = "results/by_attack"

os.makedirs(OUT_DIR, exist_ok=True)

counts = Counter()
writers = {}

def get_writer(label):
    safe = label.replace("/", "_")
    path = os.path.join(OUT_DIR, f"{safe}.jsonl")
    if path not in writers:
        writers[path] = open(path, "w", encoding="utf-8")
    return writers[path]

with open(IN_PATH, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        obj = json.loads(line)
        label = obj.get("attack", "UNKNOWN")
        counts[label] += 1
        w = get_writer(label)
        w.write(json.dumps(obj, ensure_ascii=False) + "\n")

for w in writers.values():
    w.close()

print("DONE. Split files in:", OUT_DIR)
print("Counts:")
for k,v in counts.most_common():
    print(f"- {k}: {v}")
