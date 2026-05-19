#!/usr/bin/env python3
"""Evaluate temporal detectors on an independent clean-only challenge set."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
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


def fit_spaces(train_rows: list[dict]) -> list[aging.FeatureSpace]:
    return [
        aging.fit_token_space(train_rows),
        aging.fit_char_space(train_rows),
        aging.fit_metric_space(train_rows),
        aging.fit_frozen_embedding_space(train_rows),
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--temporal-input", required=True, type=Path)
    parser.add_argument("--source-name", required=True)
    parser.add_argument("--clean-input", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--train-start", type=int, required=True)
    parser.add_argument("--train-end", type=int, required=True)
    parser.add_argument("--validation-year", type=int, required=True)
    parser.add_argument("--test-start", type=int, required=True)
    parser.add_argument("--test-end", type=int, required=True)
    parser.add_argument("--max-func-chars", type=int, default=8000)
    parser.add_argument("--dedupe", action="store_true")
    args = parser.parse_args()

    raw_rows = aging.read_jsonl(args.temporal_input)
    rows, warnings = aging.normalize_rows(raw_rows, args.source_name)
    for row in rows:
        if args.max_func_chars and len(row["func"]) > args.max_func_chars:
            row["func"] = row["func"][: args.max_func_chars]
    dedupe_summary = {}
    if args.dedupe:
        rows, dedupe_summary = aging.deduplicate_rows(rows)
    windows = aging.build_windows(
        rows,
        train_start=args.train_start,
        train_end=args.train_end,
        validation_year=args.validation_year,
        test_start=args.test_start,
        test_end=args.test_end,
    )
    train_rows = aging.rows_for_years(windows, windows["train_years"])
    val_rows = windows["by_year"][windows["validation_year"]]

    clean_rows = aging.read_jsonl(args.clean_input)
    for row in clean_rows:
        row["target"] = 0
        row.setdefault("year", 0)
        row.setdefault("project", row.get("source_dataset", "independent_clean"))
        row.setdefault("cwe", "independent_clean")
        if args.max_func_chars and len(row["func"]) > args.max_func_chars:
            row["func"] = row["func"][: args.max_func_chars]

    result_rows = []
    pred_rows = []
    for space in fit_spaces(train_rows):
        model = aging.fit_model(space, train_rows, val_rows)
        metrics, preds = aging.evaluate_model(space, model, clean_rows)
        result_rows.append(
            {
                "source_name": args.source_name,
                "model": space.name,
                "threshold": model.threshold,
                "clean_rows": len(clean_rows),
                "specificity": metrics["specificity"],
                "false_positive_rate": metrics["false_positive_rate"],
                "accuracy": metrics["accuracy"],
                "fp": metrics["fp"],
                "tn": metrics["tn"],
            }
        )
        for pred in preds:
            pred_rows.append({"model": space.name, **pred})

    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_csv(args.output_dir / "independent_clean_specificity.csv", result_rows)
    aging.write_jsonl(args.output_dir / "independent_clean_predictions.jsonl", pred_rows)
    aging.write_json(
        args.output_dir / "independent_clean_meta.json",
        {
            "temporal_input": str(args.temporal_input),
            "clean_input": str(args.clean_input),
            "source_name": args.source_name,
            "normalization_warnings": len(warnings),
            "dedupe": dedupe_summary,
            "train_years": windows["train_years"],
            "validation_year": windows["validation_year"],
            "test_years": windows["test_years"],
            "clean_rows": len(clean_rows),
        },
    )
    print(json.dumps({"output": str(args.output_dir), "rows": result_rows}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
