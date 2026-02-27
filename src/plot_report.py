#!/usr/bin/env python3
# src/plot_report.py

import json
import os
from glob import glob

import numpy as np
import matplotlib.pyplot as plt


def find_latest_run(results_dir="results"):
    runs = sorted(glob(os.path.join(results_dir, "run_*")))
    if not runs:
        raise FileNotFoundError("Không tìm thấy results/run_*")
    return runs[-1]


def plot_metrics(threshold_results, out_dir):
    # threshold_results: list[{threshold, accuracy, precision, recall, f1, ...}]
    thresholds = [x["threshold"] for x in threshold_results]
    acc = [x.get("accuracy", 0) for x in threshold_results]
    prec = [x.get("precision", 0) for x in threshold_results]
    rec = [x.get("recall", 0) for x in threshold_results]
    f1 = [x.get("f1", 0) for x in threshold_results]

    x = np.arange(len(thresholds))
    w = 0.2

    plt.figure(figsize=(10, 5))
    plt.bar(x - 1.5*w, acc,  width=w, label="Accuracy")
    plt.bar(x - 0.5*w, prec, width=w, label="Precision")
    plt.bar(x + 0.5*w, rec,  width=w, label="Recall")
    plt.bar(x + 1.5*w, f1,   width=w, label="F1")

    plt.xticks(x, [str(t) for t in thresholds])
    plt.ylim(0, 1.0)
    plt.title("Metrics by Threshold")
    plt.xlabel("Threshold")
    plt.ylabel("Score")
    plt.legend()
    plt.tight_layout()

    out_path = os.path.join(out_dir, "metrics_by_threshold.png")
    plt.savefig(out_path, dpi=200)
    plt.close()
    return out_path


def plot_confusion_matrix(cm, out_path, title="Confusion Matrix"):
    cm = np.array(cm, dtype=float)

    plt.figure(figsize=(5, 4))
    plt.imshow(cm, interpolation="nearest")
    plt.title(title)
    plt.colorbar()
    plt.xticks([0, 1], ["Pred 0", "Pred 1"])
    plt.yticks([0, 1], ["True 0", "True 1"])

    # annotate numbers
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            plt.text(j, i, int(cm[i, j]), ha="center", va="center")

    plt.tight_layout()
    plt.savefig(out_path, dpi=200)
    plt.close()
    return out_path


def main():
    run_dir = find_latest_run("results")
    report_path = os.path.join(run_dir, "report.json")
    if not os.path.exists(report_path):
        raise FileNotFoundError(f"Không thấy {report_path}")

    with open(report_path, "r", encoding="utf-8") as f:
        report = json.load(f)

    thr_results = report.get("threshold_results", [])
    if not thr_results:
        raise ValueError("report.json không có threshold_results")

    # 1) bar chart metrics
    p1 = plot_metrics(thr_results, run_dir)

    # 2) confusion matrix per threshold
    cm_paths = []
    for x in thr_results:
        t = x["threshold"]
        cm = x.get("confusion_matrix")
        if cm is None:
            continue
        out_cm = os.path.join(run_dir, f"confusion_matrix_t{t}.png")
        cm_paths.append(plot_confusion_matrix(cm, out_cm, title=f"Confusion Matrix (t={t})"))

    print("✅ Saved plots:")
    print(" -", p1)
    for p in cm_paths:
        print(" -", p)


if __name__ == "__main__":
    main()