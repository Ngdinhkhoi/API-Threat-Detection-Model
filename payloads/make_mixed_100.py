import json, random

def load_jsonl(path):
    data = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                data.append(json.loads(line))
    return data

def sample(items, k, name):
    if len(items) < k:
        raise ValueError(f"{name}: need {k} but only have {len(items)}")
    return random.sample(items, k)

random.seed(42)

sqli = load_jsonl("payloads/sqli.jsonl")
xss  = load_jsonl("payloads/xss.jsonl")
ba   = load_jsonl("payloads/brokenAuth.jsonl")
ben  = load_jsonl("payloads/benign.jsonl")

mixed = []
mixed += sample(sqli, 10, "SQLi")
mixed += sample(xss, 10, "XSS")
mixed += sample(ba, 10, "BrokenAuth")
mixed += sample(ben, 70, "Benign")

random.shuffle(mixed)

with open("payloads/mixed.jsonl", "w", encoding="utf-8") as out:
    for obj in mixed:
        out.write(json.dumps(obj, ensure_ascii=False) + "\n")

print("✔ created payloads/mixed.jsonl with", len(mixed), "logs")
