#!/usr/bin/env python3
"""Summarize independent clean false positives by source, project, and language."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
import re
from collections import defaultdict
import math


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


def infer_language(code: str, project: str) -> str:
    text = code[:4000]
    if re.search(r"\b(public|private|protected)\s+(class|interface)\b|\bSystem\.out\b", text):
        return "Java"
    if re.search(r"\bdef\s+\w+\s*\(|\bimport\s+[a-zA-Z_][\w.]*\b", text) and "{" not in text[:500]:
        return "Python"
    if re.search(r"\btemplate\s*<|::|std::|\bclass\s+\w+\s*[:{]", text):
        return "C/C++"
    if re.search(r"#include\s*<|->|\bsizeof\s*\(|\bstatic\s+\w+|\bstruct\s+\w+", text):
        return "C/C++"
    if project.lower() in {"chrome", "linux", "imagemagick", "radare2"}:
        return "C/C++"
    return "unknown"


def wilson_ci(successes: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 0.0)
    phat = successes / n
    denom = 1 + z * z / n
    centre = (phat + z * z / (2 * n)) / denom
    margin = z * math.sqrt((phat * (1 - phat) + z * z / (4 * n)) / n) / denom
    return max(0.0, centre - margin), min(1.0, centre + margin)


def summarize(joined: list[dict], group_key: str) -> list[dict]:
    groups = defaultdict(list)
    for row in joined:
        groups[row[group_key]].append(row)
    out = []
    for key, rows in sorted(groups.items()):
        for model in sorted({r["model"] for r in rows}):
            subset = [r for r in rows if r["model"] == model]
            fp = sum(int(r["pred"]) for r in subset)
            tn = len(subset) - fp
            lo, hi = wilson_ci(tn, len(subset))
            out.append(
                {
                    "group_type": group_key,
                    "group": key,
                    "model": model,
                    "rows": len(subset),
                    "specificity": tn / len(subset) if subset else 0.0,
                    "specificity_ci_low": lo,
                    "specificity_ci_high": hi,
                    "false_positive_rate": fp / len(subset) if subset else 0.0,
                    "fp": fp,
                    "tn": tn,
                }
            )
    return out


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--clean-input", required=True, type=Path)
    parser.add_argument("--predictions", required=True, type=Path)
    parser.add_argument("--source-name", required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()

    clean = {row["idx"]: row for row in read_jsonl(args.clean_input)}
    preds = read_jsonl(args.predictions)
    joined = []
    for pred in preds:
        base = clean.get(pred["idx"], {})
        code = base.get("func", "")
        project = str(base.get("project", "unknown"))
        joined.append(
            {
                **pred,
                "source_dataset": str(base.get("source_dataset", "unknown")),
                "project": project,
                "language": str(base.get("language") or infer_language(code, project)),
            }
        )

    rows = []
    for key in ["source_dataset", "language", "project"]:
        grouped = summarize(joined, key)
        if key == "project":
            grouped = [r for r in grouped if r["rows"] >= 20]
        rows.extend(grouped)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_csv(args.output_dir / "clean_specificity_by_source.csv", rows)
    with (args.output_dir / "clean_specificity_by_source_meta.json").open("w", encoding="utf-8") as handle:
        json.dump(
            {
                "source_name": args.source_name,
                "clean_input": str(args.clean_input),
                "predictions": str(args.predictions),
                "joined_rows": len(joined),
            },
            handle,
            indent=2,
        )
    print(json.dumps({"output": str(args.output_dir), "rows": len(rows)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
