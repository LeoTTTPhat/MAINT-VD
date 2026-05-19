#!/usr/bin/env python3
"""Near-duplicate and drift-statistics validity analysis."""

from __future__ import annotations

import argparse
from collections import defaultdict
import csv
import json
from pathlib import Path
import random
import statistics

import conduct_detector_aging as aging


def write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    columns = list(rows[0].keys())
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)


def simhash(tokens: list[str]) -> int:
    weights = [0] * 64
    for token, count in aging.Counter(tokens).items():
        digest = aging.hashlib.blake2b(token.encode("utf-8"), digest_size=8).digest()
        value = int.from_bytes(digest, "big")
        for bit in range(64):
            weights[bit] += count if (value >> bit) & 1 else -count
    out = 0
    for bit, weight in enumerate(weights):
        if weight >= 0:
            out |= 1 << bit
    return out


def split_name(row: dict, train_years: set[int], validation_year: int, test_years: set[int]) -> str:
    year = int(row["year"])
    if year in train_years:
        return "train"
    if year == validation_year:
        return "validation"
    if year in test_years:
        return "test"
    return "unused"


def near_duplicate_summary(rows: list[dict], windows: dict, max_pairs_per_bucket: int) -> dict:
    train_years = set(windows["train_years"])
    test_years = set(windows["test_years"])
    buckets = defaultdict(list)
    prepared = []
    for row in rows:
        split = split_name(row, train_years, windows["validation_year"], test_years)
        if split == "unused":
            continue
        toks = aging.tokenize(row["func"])
        sh = simhash(toks)
        item = {
            "idx": row["idx"],
            "year": row["year"],
            "split": split,
            "target": row["target"],
            "simhash": sh,
            "token_count": max(1, len(toks)),
        }
        prepared.append(item)
        for block in range(4):
            buckets[(block, (sh >> (block * 16)) & 0xFFFF)].append(item)

    seen_pairs = set()
    counts = defaultdict(int)
    examples = []
    for bucket_rows in buckets.values():
        if len(bucket_rows) > max_pairs_per_bucket:
            bucket_rows = random.Random(7).sample(bucket_rows, max_pairs_per_bucket)
        for i in range(len(bucket_rows)):
            a = bucket_rows[i]
            for b in bucket_rows[i + 1 :]:
                if a["split"] == b["split"]:
                    continue
                ratio = a["token_count"] / b["token_count"]
                if ratio < 0.75 or ratio > 1.33:
                    continue
                key = tuple(sorted([a["idx"], b["idx"]]))
                if key in seen_pairs:
                    continue
                seen_pairs.add(key)
                dist = (a["simhash"] ^ b["simhash"]).bit_count()
                if dist <= 3:
                    pair_type = f"{a['split']}-{b['split']}"
                    counts[pair_type] += 1
                    if len(examples) < 30:
                        examples.append(
                            {
                                "idx_a": a["idx"],
                                "split_a": a["split"],
                                "year_a": a["year"],
                                "target_a": a["target"],
                                "idx_b": b["idx"],
                                "split_b": b["split"],
                                "year_b": b["year"],
                                "target_b": b["target"],
                                "hamming_distance": dist,
                            }
                        )
    by_split = aging.Counter(item["split"] for item in prepared)
    return {
        "rows_by_split": dict(by_split),
        "near_duplicate_pairs_by_split": dict(counts),
        "near_duplicate_pairs_total": sum(counts.values()),
        "examples": examples,
    }


def permutation_pvalue(xs: list[float], ys: list[float], observed: float, iterations: int) -> float:
    rng = random.Random(13)
    hits = 0
    ys_perm = ys[:]
    for _ in range(iterations):
        rng.shuffle(ys_perm)
        if abs(aging.pearson(xs, ys_perm)) >= abs(observed):
            hits += 1
    return (hits + 1) / (iterations + 1)


def drift_statistics(results_dir: Path, primary_model: str, iterations: int) -> list[dict]:
    drift_rows = list(csv.DictReader(open(results_dir / "phase_5_drift_metrics.csv", encoding="utf-8")))
    aging_rows = list(csv.DictReader(open(results_dir / "phase_3_4_fixed_origin_aging_metrics.csv", encoding="utf-8")))
    model_rows = [
        r for r in aging_rows
        if r["model"] == primary_model and r["phase"] == "fixed_origin_test"
    ]
    by_year = {int(r["year"]): float(r["recall"]) for r in model_rows}
    if not by_year:
        return []
    first_recall = by_year[min(by_year)]
    out = []
    for signal in drift_rows[0]:
        if signal == "year":
            continue
        xs, drops = [], []
        for row in drift_rows:
            year = int(row["year"])
            if year not in by_year:
                continue
            xs.append(float(row[signal]))
            drops.append(first_recall - by_year[year])
        r = aging.pearson(xs, drops)
        out.append(
            {
                "signal": signal,
                "n_years": len(xs),
                "pearson_with_recall_drop": r,
                "permutation_p_value": permutation_pvalue(xs, drops, r, iterations),
            }
        )
    out.sort(key=lambda row: abs(row["pearson_with_recall_drop"]), reverse=True)
    return out


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--source-name", default="temporal_dataset")
    parser.add_argument("--results-dir", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--train-start", type=int, required=True)
    parser.add_argument("--train-end", type=int, required=True)
    parser.add_argument("--validation-year", type=int, required=True)
    parser.add_argument("--test-start", type=int, required=True)
    parser.add_argument("--test-end", type=int, required=True)
    parser.add_argument("--max-func-chars", type=int, default=8000)
    parser.add_argument("--primary-model", default="char4_hash_logreg")
    parser.add_argument("--permutations", type=int, default=2000)
    parser.add_argument("--max-pairs-per-bucket", type=int, default=800)
    args = parser.parse_args()

    raw_rows = aging.read_jsonl(args.input)
    rows, warnings = aging.normalize_rows(raw_rows, args.source_name)
    if args.max_func_chars:
        for row in rows:
            if len(row["func"]) > args.max_func_chars:
                row["func"] = row["func"][: args.max_func_chars]
    rows, dedupe = aging.deduplicate_rows(rows)
    windows = aging.build_windows(
        rows,
        train_start=args.train_start,
        train_end=args.train_end,
        validation_year=args.validation_year,
        test_start=args.test_start,
        test_end=args.test_end,
    )
    near_dups = near_duplicate_summary(rows, windows, args.max_pairs_per_bucket)
    stats = drift_statistics(args.results_dir, args.primary_model, args.permutations)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    aging.write_json(
        args.output_dir / "near_duplicate_summary.json",
        {
            "input": str(args.input),
            "dedupe": dedupe,
            "normalization_warnings": len(warnings),
            "split": {
                "train_years": windows["train_years"],
                "validation_year": windows["validation_year"],
                "test_years": windows["test_years"],
            },
            **near_dups,
        },
    )
    write_csv(args.output_dir / "near_duplicate_examples.csv", near_dups["examples"])
    write_csv(args.output_dir / "drift_permutation_statistics.csv", stats)
    print(json.dumps({"output": str(args.output_dir), "near_duplicate_pairs": near_dups["near_duplicate_pairs_total"], "drift_rows": len(stats)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
