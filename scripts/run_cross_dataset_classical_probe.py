#!/usr/bin/env python3
"""Run the manuscript's cross-dataset temporal probe for the char-4 model."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path
import statistics
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import conduct_detector_aging as aging  # noqa: E402


DATASETS = {
    "CVEfixes": {
        "path": Path("data/raw/cvefixes_full_temporal_ndcontrol.jsonl"),
        "train_start": 2010,
        "train_end": 2016,
        "validation_year": 2017,
        "test_start": 2018,
        "test_end": 2024,
    },
    "DiverseVul recovered": {
        "path": Path("data/raw/diversevul_recovered_commit_dates_only.jsonl"),
        "train_start": 2012,
        "train_end": 2015,
        "validation_year": 2016,
        "test_start": 2017,
        "test_end": 2022,
    },
    "PrimeVul recovered": {
        "path": Path("data/raw/primevul_paired_commit_dates.jsonl"),
        "train_start": 2012,
        "train_end": 2016,
        "validation_year": 2017,
        "test_start": 2018,
        "test_end": 2022,
    },
}

PAIRS = [
    ("CVEfixes", "DiverseVul recovered"),
    ("CVEfixes", "PrimeVul recovered"),
    ("DiverseVul recovered", "PrimeVul recovered"),
    ("PrimeVul recovered", "DiverseVul recovered"),
]


def write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def load_dataset(name: str, root: Path, max_func_chars: int | None) -> dict:
    spec = DATASETS[name]
    raw = aging.read_jsonl(root / spec["path"])
    rows, _ = aging.normalize_rows(raw, name)
    rows, _ = aging.deduplicate_rows(rows)
    if max_func_chars:
        rows = [{**row, "func": row["func"][:max_func_chars]} for row in rows]
    return aging.build_windows(
        rows,
        train_start=spec["train_start"],
        train_end=spec["train_end"],
        validation_year=spec["validation_year"],
        test_start=spec["test_start"],
        test_end=spec["test_end"],
    )


def fit_source(windows: dict, model_name: str) -> tuple[aging.FeatureSpace, aging.LinearModel]:
    train_rows = aging.rows_for_years(windows, windows["train_years"])
    val_rows = windows["by_year"][windows["validation_year"]]
    space = aging.fit_space_like(model_name, train_rows)
    return space, aging.fit_model(space, train_rows, val_rows)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--output-dir", type=Path, default=Path("results/cross_dataset_classical_probe"))
    parser.add_argument("--model", default="char4_hash_logreg")
    parser.add_argument("--max-func-chars", type=int, default=8000)
    args = parser.parse_args()

    windows = {name: load_dataset(name, args.root, args.max_func_chars) for name in DATASETS}
    fitted = {name: fit_source(win, args.model) for name, win in windows.items()}

    metric_rows = []
    for train_name, test_name in PAIRS:
        space, model = fitted[train_name]
        test_windows = windows[test_name]
        for year in test_windows["test_years"]:
            test_rows = test_windows["by_year"][year]
            metrics, _ = aging.evaluate_model(space, model, test_rows)
            metric_rows.append(
                {
                    "train_source": train_name,
                    "test_source": test_name,
                    "test_year": year,
                    "test_rows": len(test_rows),
                    "recall": metrics["recall"],
                    "f1": metrics["f1"],
                    "false_positive_rate": metrics["false_positive_rate"],
                }
            )

    summary_rows = []
    for train_name, test_name in PAIRS:
        rows = [r for r in metric_rows if r["train_source"] == train_name and r["test_source"] == test_name]
        summary_rows.append(
            {
                "train_source": train_name,
                "test_source": test_name,
                "windows": len(rows),
                "mean_recall": statistics.mean(float(r["recall"]) for r in rows),
                "mean_f1": statistics.mean(float(r["f1"]) for r in rows),
                "mean_fpr": statistics.mean(float(r["false_positive_rate"]) for r in rows),
                "mean_test_rows": statistics.mean(float(r["test_rows"]) for r in rows),
            }
        )

    write_csv(args.output_dir / "cross_dataset_metrics.csv", metric_rows)
    write_csv(args.output_dir / "cross_dataset_summary.csv", summary_rows)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
