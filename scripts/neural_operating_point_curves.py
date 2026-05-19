#!/usr/bin/env python3
"""Create threshold operating-point curves from saved neural predictions."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
import sys

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
import conduct_detector_aging as aging  # noqa: E402


def read_jsonl(path: Path) -> list[dict]:
    rows = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def auroc(y: list[int], scores: list[float]) -> float:
    pos = [(s, i) for i, (s, label) in enumerate(zip(scores, y)) if label == 1]
    neg = [(s, i) for i, (s, label) in enumerate(zip(scores, y)) if label == 0]
    if not pos or not neg:
        return 0.0
    wins = 0.0
    for ps, _ in pos:
        for ns, _ in neg:
            if ps > ns:
                wins += 1.0
            elif ps == ns:
                wins += 0.5
    return wins / (len(pos) * len(neg))


def auprc(y: list[int], scores: list[float]) -> float:
    total_pos = sum(y)
    if total_pos == 0:
        return 0.0
    ordered = sorted(zip(scores, y), reverse=True)
    tp = 0
    fp = 0
    prev_recall = 0.0
    area = 0.0
    for _, label in ordered:
        if label == 1:
            tp += 1
        else:
            fp += 1
        recall = tp / total_pos
        precision = tp / max(1, tp + fp)
        area += precision * max(0.0, recall - prev_recall)
        prev_recall = recall
    return area


def summarize_at_threshold(rows: list[dict], threshold: float) -> dict:
    y = [int(r["target"]) for r in rows]
    scores = [float(r["score"]) for r in rows]
    preds = [int(score >= threshold) for score in scores]
    return aging.classification_metrics(y, preds, scores)


def best_row(rows: list[dict], key_fields: tuple[str, ...]) -> dict:
    return max(rows, key=lambda r: tuple(r[k] for k in key_fields))


def choose_precision_floor(rows: list[dict], floor: float) -> dict:
    feasible = [r for r in rows if r["precision"] >= floor and r["tp"] > 0]
    if feasible:
        return max(feasible, key=lambda r: (r["recall"], r["f1"], -r["false_positive_rate"]))
    # If no threshold satisfies the precision floor with a positive prediction,
    # report the highest-precision non-empty operating point so the failure is visible.
    nonempty = [r for r in rows if r["tp"] + r["fp"] > 0]
    return max(nonempty or rows, key=lambda r: (r["precision"], r["recall"], r["f1"]))


def choose_youden_j(rows: list[dict]) -> dict:
    return max(rows, key=lambda r: (r["recall"] + r["specificity"] - 1.0, r["f1"], r["recall"]))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--prediction", action="append", required=True, type=Path)
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--step", type=float, default=0.01)
    parser.add_argument("--precision-floor", type=float, default=0.50)
    args = parser.parse_args()

    curve_rows = []
    summary_rows = []
    for path in args.prediction:
        rows = read_jsonl(path)
        if not rows:
            continue
        model = rows[0].get("model", path.stem)
        thresholds = np.arange(0.0, 1.0 + args.step / 2, args.step)
        for threshold in thresholds:
            metrics = summarize_at_threshold(rows, float(threshold))
            curve_rows.append({"dataset": args.dataset, "model": model, "threshold": round(float(threshold), 4), **metrics})
        y = [int(r["target"]) for r in rows]
        scores = [float(r["score"]) for r in rows]
        model_curve = curve_rows[-len(thresholds) :]
        best_f1 = max(model_curve, key=lambda r: (r["f1"], r["recall"]))
        fpr20 = [r for r in model_curve if r["false_positive_rate"] <= 0.20]
        best_fpr20 = max(fpr20, key=lambda r: (r["recall"], r["f1"])) if fpr20 else min(model_curve, key=lambda r: r["false_positive_rate"])
        precision_floor = choose_precision_floor(model_curve, args.precision_floor)
        youden_j = choose_youden_j(model_curve)
        summary_rows.append(
            {
                "dataset": args.dataset,
                "model": model,
                "rows": len(rows),
                "positives": sum(y),
                "auroc": auroc(y, scores),
                "auprc": auprc(y, scores),
                "best_f1_threshold": best_f1["threshold"],
                "best_f1": best_f1["f1"],
                "best_f1_recall": best_f1["recall"],
                "best_f1_precision": best_f1["precision"],
                "fpr20_threshold": best_fpr20["threshold"],
                "fpr20_recall": best_fpr20["recall"],
                "fpr20_precision": best_fpr20["precision"],
                "fpr20_f1": best_fpr20["f1"],
                "fpr20_fpr": best_fpr20["false_positive_rate"],
                "precision_floor": args.precision_floor,
                "precision_floor_threshold": precision_floor["threshold"],
                "precision_floor_precision": precision_floor["precision"],
                "precision_floor_recall": precision_floor["recall"],
                "precision_floor_f1": precision_floor["f1"],
                "precision_floor_fpr": precision_floor["false_positive_rate"],
                "youden_j_threshold": youden_j["threshold"],
                "youden_j": youden_j["recall"] + youden_j["specificity"] - 1.0,
                "youden_j_precision": youden_j["precision"],
                "youden_j_recall": youden_j["recall"],
                "youden_j_f1": youden_j["f1"],
                "youden_j_fpr": youden_j["false_positive_rate"],
            }
        )

    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_csv(args.output_dir / "neural_operating_point_curves.csv", curve_rows)
    write_csv(args.output_dir / "neural_operating_point_summary.csv", summary_rows)
    print(json.dumps({"output": str(args.output_dir), "curves": len(curve_rows), "summaries": summary_rows}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
