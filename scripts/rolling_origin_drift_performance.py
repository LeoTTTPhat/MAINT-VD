#!/usr/bin/env python3
"""Pair rolling-origin drift signals with downstream performance."""

from __future__ import annotations

import argparse
import csv
import json
import math
from pathlib import Path
import random
import statistics
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import conduct_detector_aging as aging  # noqa: E402


def write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def parse_cutoff(text: str) -> tuple[int, int, int, int, int]:
    parts = [int(p) for p in text.split(":")]
    if len(parts) != 5:
        raise argparse.ArgumentTypeError("cutoff must be train_start:train_end:validation_year:test_start:test_end")
    return tuple(parts)  # type: ignore[return-value]


def sample_balanced(rows: list[dict], limit: int, seed: int) -> list[dict]:
    if not limit or len(rows) <= limit:
        return rows
    rng = random.Random(seed)
    pos = [r for r in rows if int(r["target"]) == 1]
    neg = [r for r in rows if int(r["target"]) == 0]
    selected = []
    selected.extend(rng.sample(pos, min(len(pos), limit // 2)))
    selected.extend(rng.sample(neg, min(len(neg), limit - len(selected))))
    if len(selected) < limit:
        used = {r["idx"] for r in selected}
        rest = [r for r in rows if r["idx"] not in used]
        selected.extend(rng.sample(rest, min(len(rest), limit - len(selected))))
    return sorted(selected, key=lambda row: (int(row["year"]), str(row["idx"])))


def fisher_ci(r: float, n: int) -> tuple[float, float]:
    if n <= 3 or abs(r) >= 1:
        return (r, r)
    z = 0.5 * math.log((1 + r) / (1 - r))
    se = 1 / math.sqrt(n - 3)
    lo = math.tanh(z - 1.96 * se)
    hi = math.tanh(z + 1.96 * se)
    return lo, hi


def permutation_p(xs: list[float], ys: list[float], seed: int, iterations: int) -> float:
    observed = abs(aging.pearson(xs, ys))
    rng = random.Random(seed)
    hits = 0
    shuffled = list(ys)
    for _ in range(iterations):
        rng.shuffle(shuffled)
        if abs(aging.pearson(xs, shuffled)) >= observed:
            hits += 1
    return (hits + 1) / (iterations + 1)


def holm_adjust(rows: list[dict]) -> list[dict]:
    ordered = sorted(rows, key=lambda r: float(r["permutation_p"]))
    m = len(ordered)
    running = 0.0
    for rank, row in enumerate(ordered, start=1):
        adjusted = min(1.0, (m - rank + 1) * float(row["permutation_p"]))
        running = max(running, adjusted)
        row["holm_p"] = running
    return rows


def run_dataset(
    rows: list[dict],
    dataset: str,
    cutoffs: list[tuple[int, int, int, int, int]],
    args: argparse.Namespace,
) -> tuple[list[dict], list[dict]]:
    pair_rows: list[dict] = []
    correlation_rows: list[dict] = []

    for cutoff_index, cutoff in enumerate(cutoffs, start=1):
        train_start, train_end, validation_year, test_start, test_end = cutoff
        windows = aging.build_windows(
            rows,
            train_start=train_start,
            train_end=train_end,
            validation_year=validation_year,
            test_start=test_start,
            test_end=test_end,
            min_train_samples=args.min_train_samples,
            min_eval_samples=args.min_eval_samples,
            min_pos=args.min_pos,
            min_neg=args.min_neg,
        )
        if windows["split_warnings"]:
            continue

        train_rows_full = aging.rows_for_years(windows, windows["train_years"])
        train_rows = sample_balanced(train_rows_full, args.max_train_rows, args.seed + cutoff_index)
        validation_rows = windows["by_year"][windows["validation_year"]]
        space = aging.fit_space_like(args.model, train_rows)
        model = aging.fit_model(space, train_rows, validation_rows)
        first_recall = None

        for year in windows["test_years"]:
            test_rows = windows["by_year"][year]
            metrics, _ = aging.evaluate_model(space, model, test_rows)
            if first_recall is None:
                first_recall = float(metrics["recall"])
            drift = aging.compute_drift(train_rows_full, test_rows, year)
            pair_rows.append(
                {
                    "dataset": dataset,
                    "cutoff": f"{train_start}-{train_end}/{validation_year}/{test_start}-{test_end}",
                    "replicate_id": f"{dataset}_c{cutoff_index}_{year}",
                    "model": args.model,
                    "test_year": year,
                    "train_rows": len(train_rows_full),
                    "train_rows_used": len(train_rows),
                    "validation_rows": len(validation_rows),
                    "test_rows": len(test_rows),
                    "recall": metrics["recall"],
                    "f1": metrics["f1"],
                    "false_positive_rate": metrics["false_positive_rate"],
                    "recall_drop_from_first_window": first_recall - float(metrics["recall"]),
                    **{k: v for k, v in drift.items() if k != "year"},
                }
            )

    dataset_pairs = [row for row in pair_rows if row["dataset"] == dataset]
    if not dataset_pairs:
        return pair_rows, correlation_rows
    signals = [
        key
        for key in dataset_pairs[0]
        if key
        not in {
            "dataset",
            "cutoff",
            "replicate_id",
            "model",
            "test_year",
            "train_rows",
            "train_rows_used",
            "validation_rows",
            "test_rows",
            "recall",
            "f1",
            "false_positive_rate",
            "recall_drop_from_first_window",
        }
    ]
    for signal in signals:
        xs = [float(row[signal]) for row in dataset_pairs]
        ys = [float(row["recall_drop_from_first_window"]) for row in dataset_pairs]
        r = aging.pearson(xs, ys)
        lo, hi = fisher_ci(r, len(xs))
        correlation_rows.append(
            {
                "dataset": dataset,
                "model": args.model,
                "signal": signal,
                "n_pairs": len(xs),
                "pearson_with_recall_drop": r,
                "fisher_ci_low": lo,
                "fisher_ci_high": hi,
                "permutation_p": permutation_p(xs, ys, args.seed + sum(map(ord, dataset + signal)), args.permutations),
                "holm_p": "",
            }
        )
    holm_adjust(correlation_rows)
    return pair_rows, correlation_rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cvefixes-input", type=Path, required=True)
    parser.add_argument("--diversevul-input", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--model", default="char4_hash_logreg")
    parser.add_argument("--cvefixes-cutoff", action="append", type=parse_cutoff, required=True)
    parser.add_argument("--diversevul-cutoff", action="append", type=parse_cutoff, required=True)
    parser.add_argument("--max-func-chars", type=int, default=8000)
    parser.add_argument("--max-train-rows", type=int, default=6000)
    parser.add_argument("--min-train-samples", type=int, default=1000)
    parser.add_argument("--min-eval-samples", type=int, default=100)
    parser.add_argument("--min-pos", type=int, default=10)
    parser.add_argument("--min-neg", type=int, default=10)
    parser.add_argument("--permutations", type=int, default=2000)
    parser.add_argument("--seed", type=int, default=73)
    args = parser.parse_args()

    all_pairs: list[dict] = []
    all_correlations: list[dict] = []
    meta = {
        "model": args.model,
        "max_func_chars": args.max_func_chars,
        "max_train_rows": args.max_train_rows,
        "permutations": args.permutations,
        "datasets": {},
    }

    for label, path, cutoffs in [
        ("CVEfixes", args.cvefixes_input, args.cvefixes_cutoff),
        ("DiverseVul recovered-date", args.diversevul_input, args.diversevul_cutoff),
    ]:
        raw_rows = aging.read_jsonl(path)
        rows, warnings = aging.normalize_rows(raw_rows, label)
        truncated = 0
        for row in rows:
            if args.max_func_chars and len(row["func"]) > args.max_func_chars:
                row["func"] = row["func"][: args.max_func_chars]
                truncated += 1
        pair_rows, correlation_rows = run_dataset(rows, label, cutoffs, args)
        all_pairs.extend(pair_rows)
        all_correlations.extend(correlation_rows)
        meta["datasets"][label] = {
            "input": str(path),
            "rows": len(rows),
            "normalization_warnings": len(warnings),
            "truncated_functions": truncated,
            "cutoffs": [":".join(map(str, cutoff)) for cutoff in cutoffs],
            "paired_replicates": len([row for row in pair_rows if row["dataset"] == label]),
        }

    args.output_dir.mkdir(parents=True, exist_ok=True)
    all_correlations.sort(key=lambda row: (row["dataset"], -abs(float(row["pearson_with_recall_drop"]))))
    write_csv(args.output_dir / "rolling_origin_drift_performance_pairs.csv", all_pairs)
    write_csv(args.output_dir / "rolling_origin_drift_performance_correlations.csv", all_correlations)
    aging.write_json(args.output_dir / "rolling_origin_drift_performance_meta.json", meta)

    summary = [
        {
            "dataset": dataset,
            "paired_replicates": meta["datasets"][dataset]["paired_replicates"],
            "strongest_signal": next((row["signal"] for row in all_correlations if row["dataset"] == dataset), ""),
            "strongest_r": next((row["pearson_with_recall_drop"] for row in all_correlations if row["dataset"] == dataset), ""),
            "strongest_holm_p": next((row["holm_p"] for row in all_correlations if row["dataset"] == dataset), ""),
        }
        for dataset in meta["datasets"]
    ]
    write_csv(args.output_dir / "rolling_origin_drift_performance_summary.csv", summary)
    print(json.dumps({"output": str(args.output_dir), "rows": len(all_pairs), "summary": summary}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
