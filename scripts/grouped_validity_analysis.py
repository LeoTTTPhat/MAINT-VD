#!/usr/bin/env python3
"""Project and CVE/commit-style grouped validity analysis for temporal runs."""

from __future__ import annotations

import argparse
from collections import defaultdict
import csv
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import conduct_detector_aging as aging  # noqa: E402


CVEFIXES_RE = re.compile(r"^cvefixes-(?P<commit>.+)-(?P<kind>vuln|fix)-(?P<pair>\d+)$")
DIVERSEVUL_RE = re.compile(r"^diversevul-(?P<commit>[0-9a-fA-F]+)-(?P<pair>\d+)$")


def split_name(row: dict, train_years: set[int], validation_year: int, test_years: set[int]) -> str:
    year = int(row["year"])
    if year in train_years:
        return "train"
    if year == validation_year:
        return "validation"
    if year in test_years:
        return "test"
    return "unused"


def group_ids(row: dict) -> dict:
    idx = str(row["idx"])
    match = CVEFIXES_RE.match(idx)
    if match:
        return {
            "commit_group": f"commit:{match.group('commit')}",
            "pair_group": f"cvefixes_pair:{match.group('commit')}:{match.group('pair')}",
        }
    match = DIVERSEVUL_RE.match(idx)
    if match:
        return {
            "commit_group": f"commit:{match.group('commit')}",
            "pair_group": f"diversevul_row:{match.group('commit')}:{match.group('pair')}",
        }
    return {"commit_group": f"idx:{idx}", "pair_group": f"idx:{idx}"}


def write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def read_predictions(path: Path) -> list[dict]:
    rows = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def grouped_metrics(rows: list[dict], predictions_dir: Path, train_projects: set[str]) -> list[dict]:
    row_by_idx = {str(row["idx"]): row for row in rows}
    out = []
    for path in sorted(predictions_dir.glob("fixed_origin_*.jsonl")):
        pred_rows = read_predictions(path)
        by_subset = defaultdict(list)
        for pred in pred_rows:
            original = row_by_idx.get(str(pred["idx"]))
            if not original:
                continue
            subset = "seen_project" if original["project"] in train_projects else "unseen_project"
            by_subset[subset].append((original, pred))
        for subset, pairs in sorted(by_subset.items()):
            targets = [int(orig["target"]) for orig, _ in pairs]
            preds = [int(pred["pred"]) for _, pred in pairs]
            scores = [float(pred["score"]) for _, pred in pairs]
            metrics = aging.classification_metrics(targets, preds, scores)
            out.append(
                {
                    "model": pred_rows[0].get("model", path.stem.replace("fixed_origin_", "")) if pred_rows else path.stem,
                    "subset": subset,
                    **metrics,
                }
            )
    return out


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()

    split_manifest = json.loads((args.run_dir / "phase_2_temporal_splits.json").read_text(encoding="utf-8"))
    fixed = split_manifest["fixed_origin"]
    train_years = set(map(int, fixed["train_years"]))
    validation_year = int(fixed["validation_year"])
    test_years = set(map(int, fixed["test_years"]))
    rows = aging.read_jsonl(args.run_dir / "artifacts" / "normalized_temporal_dataset.jsonl")

    train_rows = [row for row in rows if int(row["year"]) in train_years]
    train_projects = {row["project"] for row in train_rows}
    summaries = []
    for group_name in ["project", "commit_group", "pair_group"]:
        groups_by_split = defaultdict(set)
        for row in rows:
            split = split_name(row, train_years, validation_year, test_years)
            if split == "unused":
                continue
            gids = group_ids(row)
            value = row["project"] if group_name == "project" else gids[group_name]
            groups_by_split[split].add(value)
        train_groups = groups_by_split["train"]
        for split in ["validation", "test"]:
            split_groups = groups_by_split[split]
            overlap = train_groups & split_groups
            summaries.append(
                {
                    "group": group_name,
                    "comparison": f"train_vs_{split}",
                    "train_groups": len(train_groups),
                    "comparison_groups": len(split_groups),
                    "overlap_groups": len(overlap),
                    "comparison_overlap_rate": aging.safe_div(len(overlap), len(split_groups)),
                }
            )

    unseen_rows = []
    for row in rows:
        split = split_name(row, train_years, validation_year, test_years)
        if split not in {"validation", "test"}:
            continue
        gids = group_ids(row)
        unseen_rows.append(
            {
                "idx": row["idx"],
                "split": split,
                "year": row["year"],
                "target": row["target"],
                "project": row["project"],
                "seen_project": row["project"] in train_projects,
                **gids,
            }
        )

    metrics = grouped_metrics(rows, args.run_dir / "artifacts" / "predictions", train_projects)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_csv(args.output_dir / "group_overlap_summary.csv", summaries)
    write_csv(args.output_dir / "seen_unseen_project_metrics.csv", metrics)
    aging.write_jsonl(args.output_dir / "future_group_annotations.jsonl", unseen_rows)
    aging.write_json(
        args.output_dir / "grouped_validity_meta.json",
        {
            "run_dir": str(args.run_dir),
            "train_years": sorted(train_years),
            "validation_year": validation_year,
            "test_years": sorted(test_years),
            "rows": len(rows),
            "future_rows_annotated": len(unseen_rows),
        },
    )
    print(json.dumps({"output": str(args.output_dir), "summaries": summaries}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
