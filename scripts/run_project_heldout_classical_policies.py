#!/usr/bin/env python3
"""Run classical maintenance policies under unseen-project temporal testing."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
import random
import statistics
import sys

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
import conduct_detector_aging as aging  # noqa: E402


ORIGINAL_TRAIN_LOGREG = aging.train_logreg


def write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def bootstrap_ci(values: list[float], seed: int, iterations: int = 1000) -> tuple[float, float]:
    if not values:
        return (0.0, 0.0)
    rng = random.Random(seed)
    draws = []
    for _ in range(iterations):
        draws.append(statistics.mean(rng.choice(values) for _ in values))
    draws.sort()
    return draws[int(0.025 * len(draws))], draws[int(0.975 * len(draws))]


def mean_or_zero(values: list[float]) -> float:
    return statistics.mean(values) if values else 0.0


def filter_unseen(rows: list[dict], train_rows: list[dict]) -> list[dict]:
    return filter_unseen_projects(rows, {row["project"] for row in train_rows})


def filter_unseen_projects(rows: list[dict], train_projects: set[str]) -> list[dict]:
    return [row for row in rows if row["project"] not in train_projects]


def sample_rows(rows: list[dict], limit: int, seed: int) -> list[dict]:
    if not limit or len(rows) <= limit:
        return rows
    rng = random.Random(seed)
    pos = [r for r in rows if int(r["target"]) == 1]
    neg = [r for r in rows if int(r["target"]) == 0]
    half = limit // 2
    selected = []
    selected.extend(rng.sample(pos, min(len(pos), half)))
    selected.extend(rng.sample(neg, min(len(neg), limit - len(selected))))
    if len(selected) < limit:
        used = {r["idx"] for r in selected}
        rest = [r for r in rows if r["idx"] not in used]
        selected.extend(rng.sample(rest, min(len(rest), limit - len(selected))))
    selected.sort(key=lambda row: (int(row["year"]), str(row["idx"])))
    return selected


def choose_fallback_validation(windows: dict, train_projects: set[str], candidate_year: int) -> list[dict]:
    validation_rows = filter_unseen_projects(windows["by_year"][candidate_year], train_projects)
    if validation_rows:
        return validation_rows
    # If the previous year has no unseen-project examples, keep the project
    # holdout on the test side and use all previous-year labels only to avoid an
    # empty calibration set. The row is flagged in the output.
    return windows["by_year"][candidate_year]


def evaluate_policy(policy: str, train_years: list[int] | str, validation_year: int | str, labeled_samples_used: int, train_rows: list[dict], validation_rows: list[dict], test_rows: list[dict], model_name: str) -> dict:
    space = aging.fit_space_like(model_name, train_rows)
    model = aging.fit_model(space, train_rows, validation_rows)
    metrics, _ = aging.evaluate_model(space, model, test_rows)
    return {
        "policy": policy,
        "test_year": int(test_rows[0]["year"]) if test_rows else "",
        "train_years": train_years if isinstance(train_years, str) else "|".join(map(str, train_years)),
        "validation_year": validation_year,
        "labeled_samples_used": labeled_samples_used,
        "train_rows": len(train_rows),
        "validation_rows": len(validation_rows),
        "test_rows": len(test_rows),
        "test_projects": len({r["project"] for r in test_rows}),
        **metrics,
    }


def run(args: argparse.Namespace) -> dict:
    def bounded_train_logreg(x, y, epochs=240, lr=0.18, l2=1e-3):
        return ORIGINAL_TRAIN_LOGREG(x, y, epochs=args.logreg_epochs, lr=lr, l2=l2)

    aging.train_logreg = bounded_train_logreg

    raw_rows = aging.read_jsonl(args.input)
    rows, warnings = aging.normalize_rows(raw_rows, args.source_name)
    for row in rows:
        if args.max_func_chars and len(row["func"]) > args.max_func_chars:
            row["func"] = row["func"][: args.max_func_chars]
    windows = aging.build_windows(
        rows,
        train_start=args.train_start,
        train_end=args.train_end,
        validation_year=args.validation_year,
        test_start=args.test_start,
        test_end=args.test_end,
        min_train_samples=args.min_train_samples,
        min_eval_samples=args.min_eval_samples,
        min_pos=args.min_pos,
        min_neg=args.min_neg,
    )
    fixed_reference_rows = aging.rows_for_years(windows, windows["train_years"])
    fixed_train_projects = {row["project"] for row in fixed_reference_rows}
    fixed_train_rows = sample_rows(fixed_reference_rows, args.max_policy_train_rows, args.seed)
    fixed_validation_rows = filter_unseen_projects(windows["by_year"][windows["validation_year"]], fixed_train_projects)
    if not fixed_validation_rows:
        fixed_validation_rows = windows["by_year"][windows["validation_year"]]

    fixed_space = aging.fit_space_like(args.primary_model, fixed_train_rows)
    fixed_model = aging.fit_model(fixed_space, fixed_train_rows, fixed_validation_rows)

    results = []
    for year in windows["test_years"]:
        year_index = windows["years"].index(year)
        previous_year = windows["years"][year_index - 1]

        # P0: deploy the fixed-origin model to future projects unseen in the
        # original training window.
        fixed_test_rows = filter_unseen_projects(windows["by_year"][year], fixed_train_projects)
        if fixed_test_rows:
            metrics, _ = aging.evaluate_model(fixed_space, fixed_model, fixed_test_rows)
            results.append(
                {
                    "policy": "P0_no_refresh",
                    "test_year": year,
                    "train_years": "|".join(map(str, windows["train_years"])),
                    "validation_year": windows["validation_year"],
                    "labeled_samples_used": 0,
                    "train_rows": len(fixed_train_rows),
                    "validation_rows": len(fixed_validation_rows),
                    "test_rows": len(fixed_test_rows),
                    "test_projects": len({r["project"] for r in fixed_test_rows}),
                    **metrics,
                }
            )

        cumulative_years = [y for y in windows["years"] if y <= year - 2]
        if cumulative_years:
            reference_rows = aging.rows_for_years(windows, cumulative_years)
            reference_projects = {row["project"] for row in reference_rows}
            train_rows = sample_rows(reference_rows, args.max_policy_train_rows, args.seed + year * 10 + 1)
            validation_rows = choose_fallback_validation(windows, reference_projects, previous_year)
            test_rows = filter_unseen_projects(windows["by_year"][year], reference_projects)
            if test_rows:
                results.append(evaluate_policy("P1_cumulative_retrain", cumulative_years, previous_year, len(validation_rows), train_rows, validation_rows, test_rows, args.primary_model))

        sliding_years = [y for y in windows["years"] if year - 4 <= y <= year - 2]
        if sliding_years:
            reference_rows = aging.rows_for_years(windows, sliding_years)
            reference_projects = {row["project"] for row in reference_rows}
            train_rows = sample_rows(reference_rows, args.max_policy_train_rows, args.seed + year * 10 + 2)
            validation_rows = choose_fallback_validation(windows, reference_projects, previous_year)
            test_rows = filter_unseen_projects(windows["by_year"][year], reference_projects)
            if test_rows:
                results.append(evaluate_policy("P2_sliding_3yr_retrain", sliding_years, previous_year, len(validation_rows), train_rows, validation_rows, test_rows, args.primary_model))

        validation_rows = choose_fallback_validation(windows, fixed_train_projects, previous_year)
        test_rows = filter_unseen_projects(windows["by_year"][year], fixed_train_projects)
        if test_rows:
            scores = aging.predict_scores(fixed_model, fixed_space.transform(validation_rows))
            threshold = aging.choose_threshold(scores, np.array([r["target"] for r in validation_rows], dtype=np.float64))
            calibrated = aging.LinearModel(fixed_model.weights, fixed_model.mean, fixed_model.std, threshold)
            metrics, _ = aging.evaluate_model(fixed_space, calibrated, test_rows)
            results.append(
                {
                    "policy": "P3_calibration_only",
                    "test_year": year,
                    "train_years": "|".join(map(str, windows["train_years"])),
                    "validation_year": previous_year,
                    "labeled_samples_used": len(validation_rows),
                    "train_rows": len(fixed_train_rows),
                    "validation_rows": len(validation_rows),
                    "test_rows": len(test_rows),
                    "test_projects": len({r["project"] for r in test_rows}),
                    **metrics,
                }
            )

        recent = choose_fallback_validation(windows, fixed_train_projects, previous_year)
        pos = [r for r in recent if r["target"] == 1][: args.small_update_pos]
        neg = [r for r in recent if r["target"] == 0][: args.small_update_neg]
        train_rows = fixed_train_rows + pos + neg
        validation_rows = recent
        small_update_projects = fixed_train_projects | {row["project"] for row in pos + neg}
        test_rows = filter_unseen_projects(windows["by_year"][year], small_update_projects)
        if test_rows and pos and neg:
            results.append(
                evaluate_policy(
                    "P4_small_recent_update",
                    f"{windows['train_years'][0]}-{windows['train_years'][-1]}+{previous_year}_small",
                    previous_year,
                    len(pos) + len(neg),
                    train_rows,
                    validation_rows,
                    test_rows,
                    args.primary_model,
                )
            )

    summary = []
    for policy in sorted({row["policy"] for row in results}):
        policy_rows = [row for row in results if row["policy"] == policy]
        recalls = [float(row["recall"]) for row in policy_rows]
        f1s = [float(row["f1"]) for row in policy_rows]
        fprs = [float(row["false_positive_rate"]) for row in policy_rows]
        lo, hi = bootstrap_ci(recalls, args.seed + sum(map(ord, policy)))
        summary.append(
            {
                "source_name": args.source_name,
                "model": args.primary_model,
                "policy": policy,
                "windows": len(policy_rows),
                "mean_recall": mean_or_zero(recalls),
                "mean_f1": mean_or_zero(f1s),
                "mean_fpr": mean_or_zero(fprs),
                "recall_ci_low": lo,
                "recall_ci_high": hi,
                "mean_labeled_samples_used": mean_or_zero([float(row["labeled_samples_used"]) for row in policy_rows]),
                "mean_test_rows": mean_or_zero([float(row["test_rows"]) for row in policy_rows]),
                "mean_test_projects": mean_or_zero([float(row["test_projects"]) for row in policy_rows]),
            }
        )

    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_csv(args.output_dir / "project_heldout_policy_metrics.csv", results)
    write_csv(args.output_dir / "project_heldout_policy_summary.csv", summary)
    aging.write_json(
        args.output_dir / "project_heldout_policy_meta.json",
        {
            "input": str(args.input),
            "source_name": args.source_name,
            "normalization_warnings": len(warnings),
            "train_years": windows["train_years"],
            "validation_year": windows["validation_year"],
            "test_years": windows["test_years"],
            "primary_model": args.primary_model,
            "policy_count": len(results),
        },
    )
    return {"output": str(args.output_dir), "rows": len(results), "summary": summary}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--source-name", required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--train-start", type=int, required=True)
    parser.add_argument("--train-end", type=int, required=True)
    parser.add_argument("--validation-year", type=int, required=True)
    parser.add_argument("--test-start", type=int, required=True)
    parser.add_argument("--test-end", type=int, required=True)
    parser.add_argument("--primary-model", default="char4_hash_logreg")
    parser.add_argument("--max-func-chars", type=int, default=8000)
    parser.add_argument("--min-train-samples", type=int, default=1)
    parser.add_argument("--min-eval-samples", type=int, default=1)
    parser.add_argument("--min-pos", type=int, default=1)
    parser.add_argument("--min-neg", type=int, default=1)
    parser.add_argument("--small-update-pos", type=int, default=20)
    parser.add_argument("--small-update-neg", type=int, default=20)
    parser.add_argument("--seed", type=int, default=29)
    parser.add_argument("--logreg-epochs", type=int, default=80)
    parser.add_argument("--max-policy-train-rows", type=int, default=6000)
    args = parser.parse_args()
    print(json.dumps(run(args), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
