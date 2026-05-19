#!/usr/bin/env python3
"""Run fixed-origin temporal cutoff sensitivity for detector-aging study."""

from __future__ import annotations

import argparse
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


def parse_cutoff(text: str) -> tuple[int, int, int, int, int]:
    parts = [int(p) for p in text.split(":")]
    if len(parts) != 5:
        raise argparse.ArgumentTypeError("cutoff must be train_start:train_end:validation_year:test_start:test_end")
    return tuple(parts)  # type: ignore[return-value]


def run_cutoff(rows: list[dict], cutoff: tuple[int, int, int, int, int], args: argparse.Namespace) -> list[dict]:
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
        return [
            {
                "cutoff": f"{train_start}-{train_end}/{validation_year}/{test_start}-{test_end}",
                "model": "SPLIT_INVALID",
                "train_years": "|".join(map(str, windows["train_years"])),
                "validation_year": validation_year,
                "test_years": "|".join(map(str, windows["test_years"])),
                "first_test_recall": "",
                "last_test_recall": "",
                "absolute_recall_decay": "",
                "worst_recall": "",
                "mean_recall": "",
                "mean_f1": "",
                "split_warnings": "; ".join(windows["split_warnings"]),
            }
        ]
    output_stub = args.output_dir / "artifacts" / f"cutoff_{train_start}_{train_end}_{validation_year}"
    metrics, _, _ = aging.run_fixed_origin(windows, output_stub)
    rows_out = []
    for model in sorted({r["model"] for r in metrics}):
        model_rows = [r for r in metrics if r["model"] == model and r["phase"] == "fixed_origin_test"]
        recalls = [r["recall"] for r in model_rows]
        f1s = [r["f1"] for r in model_rows]
        rows_out.append(
            {
                "cutoff": f"{train_start}-{train_end}/{validation_year}/{test_start}-{test_end}",
                "model": model,
                "train_years": "|".join(map(str, windows["train_years"])),
                "validation_year": validation_year,
                "test_years": "|".join(map(str, windows["test_years"])),
                "first_test_recall": recalls[0],
                "last_test_recall": recalls[-1],
                "absolute_recall_decay": recalls[0] - recalls[-1],
                "worst_recall": min(recalls),
                "mean_recall": statistics.mean(recalls),
                "mean_f1": statistics.mean(f1s),
                "split_warnings": "",
            }
        )
    return rows_out


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--source-name", default="temporal_dataset")
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--max-func-chars", type=int, default=8000)
    parser.add_argument("--dedupe", action="store_true")
    parser.add_argument("--cutoff", action="append", type=parse_cutoff, required=True)
    parser.add_argument("--min-train-samples", type=int, default=1000)
    parser.add_argument("--min-eval-samples", type=int, default=500)
    parser.add_argument("--min-pos", type=int, default=50)
    parser.add_argument("--min-neg", type=int, default=50)
    args = parser.parse_args()

    raw_rows = aging.read_jsonl(args.input)
    rows, warnings = aging.normalize_rows(raw_rows, args.source_name)
    truncated = 0
    if args.max_func_chars:
        for row in rows:
            if len(row["func"]) > args.max_func_chars:
                row["func"] = row["func"][: args.max_func_chars]
                truncated += 1
    dedupe_summary = {}
    if args.dedupe:
        rows, dedupe_summary = aging.deduplicate_rows(rows)

    all_rows = []
    for cutoff in args.cutoff:
        all_rows.extend(run_cutoff(rows, cutoff, args))
    write_csv(args.output_dir / "cutoff_sensitivity_summary.csv", all_rows)
    meta = {
        "input": str(args.input),
        "source_name": args.source_name,
        "valid_rows": len(rows),
        "normalization_warnings": len(warnings),
        "truncated_functions": truncated,
        "dedupe": dedupe_summary,
        "cutoffs": [":".join(map(str, c)) for c in args.cutoff],
    }
    aging.write_json(args.output_dir / "cutoff_sensitivity_meta.json", meta)
    print(json.dumps({"output": str(args.output_dir), "rows": len(all_rows), **meta}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
