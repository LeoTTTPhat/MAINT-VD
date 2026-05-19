#!/usr/bin/env python3
"""Create a temporal dataset with cross-split near duplicates removed.

The script keeps the fixed-origin training split intact, then removes
validation/test records that are near-duplicates of earlier training or
validation records. It is intentionally conservative for temporal evaluation:
past data is preserved and future evaluation rows are filtered.
"""

from __future__ import annotations

import argparse
from collections import defaultdict
import json
from pathlib import Path
import random

import conduct_detector_aging as aging
from temporal_validity_analysis import simhash, split_name


def bucket_keys(sh: int) -> list[tuple[int, int]]:
    return [(block, (sh >> (block * 16)) & 0xFFFF) for block in range(4)]


def prepare_items(rows: list[dict], windows: dict) -> list[dict]:
    train_years = set(windows["train_years"])
    test_years = set(windows["test_years"])
    items = []
    for row in rows:
        split = split_name(row, train_years, windows["validation_year"], test_years)
        toks = aging.tokenize(row["func"])
        items.append(
            {
                "row": row,
                "idx": row["idx"],
                "split": split,
                "year": int(row["year"]),
                "target": int(row["target"]),
                "simhash": simhash(toks),
                "token_count": max(1, len(toks)),
            }
        )
    return items


def should_remove(item: dict, prior_buckets: dict, max_distance: int, min_ratio: float, max_ratio: float) -> tuple[bool, dict | None]:
    candidates = []
    seen = set()
    for key in bucket_keys(item["simhash"]):
        for other in prior_buckets.get(key, []):
            if other["idx"] in seen:
                continue
            seen.add(other["idx"])
            candidates.append(other)
    for other in candidates:
        ratio = item["token_count"] / other["token_count"]
        if ratio < min_ratio or ratio > max_ratio:
            continue
        dist = (item["simhash"] ^ other["simhash"]).bit_count()
        if dist <= max_distance:
            return True, {
                "idx": item["idx"],
                "split": item["split"],
                "year": item["year"],
                "target": item["target"],
                "matched_idx": other["idx"],
                "matched_split": other["split"],
                "matched_year": other["year"],
                "matched_target": other["target"],
                "hamming_distance": dist,
            }
    return False, None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--summary", required=True, type=Path)
    parser.add_argument("--source-name", default="temporal_dataset")
    parser.add_argument("--max-func-chars", type=int, default=8000)
    parser.add_argument("--train-start", type=int, required=True)
    parser.add_argument("--train-end", type=int, required=True)
    parser.add_argument("--validation-year", type=int, required=True)
    parser.add_argument("--test-start", type=int, required=True)
    parser.add_argument("--test-end", type=int, required=True)
    parser.add_argument("--max-distance", type=int, default=3)
    parser.add_argument("--min-ratio", type=float, default=0.75)
    parser.add_argument("--max-ratio", type=float, default=1.33)
    args = parser.parse_args()

    raw_rows = aging.read_jsonl(args.input)
    rows, warnings = aging.normalize_rows(raw_rows, args.source_name)
    truncated = 0
    for row in rows:
        if args.max_func_chars and len(row["func"]) > args.max_func_chars:
            row["func"] = row["func"][: args.max_func_chars]
            truncated += 1
    rows, exact_dedupe = aging.deduplicate_rows(rows)
    windows = aging.build_windows(
        rows,
        train_start=args.train_start,
        train_end=args.train_end,
        validation_year=args.validation_year,
        test_start=args.test_start,
        test_end=args.test_end,
    )
    items = prepare_items(rows, windows)
    split_order = {"unused": 0, "train": 1, "validation": 2, "test": 3}
    items.sort(key=lambda item: (split_order[item["split"]], item["year"], item["idx"]))
    prior_buckets = defaultdict(list)
    kept = []
    removed = []
    for item in items:
        if item["split"] == "unused":
            kept.append(item["row"])
            continue
        remove = False
        match = None
        if item["split"] in {"validation", "test"}:
            remove, match = should_remove(item, prior_buckets, args.max_distance, args.min_ratio, args.max_ratio)
        if remove and match is not None:
            removed.append(match)
            continue
        kept.append(item["row"])
        if item["split"] in {"train", "validation"}:
            for key in bucket_keys(item["simhash"]):
                prior_buckets[key].append(item)

    aging.write_jsonl(args.output, kept)
    by_split_removed = aging.Counter(row["split"] for row in removed)
    summary = {
        "input": str(args.input),
        "output": str(args.output),
        "source_name": args.source_name,
        "max_func_chars": args.max_func_chars,
        "truncated_functions": truncated,
        "normalization_warnings": len(warnings),
        "exact_dedupe": exact_dedupe,
        "near_duplicate_control": {
            "max_distance": args.max_distance,
            "min_ratio": args.min_ratio,
            "max_ratio": args.max_ratio,
            "removed_rows": len(removed),
            "removed_by_split": dict(by_split_removed),
            "examples": removed[:30],
        },
        "rows_before_near_duplicate_control": len(rows),
        "rows_after_near_duplicate_control": len(kept),
    }
    args.summary.parent.mkdir(parents=True, exist_ok=True)
    args.summary.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
