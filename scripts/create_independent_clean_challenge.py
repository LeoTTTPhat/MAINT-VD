#!/usr/bin/env python3
"""Create an independent clean-only challenge set.

The rows produced here are not assigned synthetic temporal years. They are meant
for external specificity/false-positive testing of temporal detectors trained on
CVEfixes or DiverseVul, not for temporal aging curves.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import random
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import conduct_detector_aging as aging  # noqa: E402


def first_present(row: dict, names: list[str], default=None):
    for name in names:
        if name in row and row[name] not in (None, ""):
            return row[name]
    return default


def source_name(path: Path) -> str:
    name = path.stem.lower()
    return re.sub(r"[^a-z0-9]+", "_", name).strip("_") or "clean_source"


def load_clean_rows(path: Path, source: str, max_func_chars: int) -> list[dict]:
    rows = []
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            row = json.loads(line)
            try:
                target = aging.normalize_target(first_present(row, ["target", "label", "vulnerable", "is_vulnerable"], 0))
            except ValueError:
                continue
            if target != 0:
                continue
            func = first_present(row, ["func", "code", "function", "source"])
            if not func:
                continue
            func = str(func)
            if max_func_chars and len(func) > max_func_chars:
                func = func[:max_func_chars]
            idx = first_present(row, ["idx", "id", "sample_id"], line_no)
            project = first_present(row, ["project", "repo", "repository"], source)
            cwe = first_present(row, ["cwe", "cwe_id"], "independent_clean")
            rows.append(
                {
                    "idx": f"{source}-clean-{idx}",
                    "func": func,
                    "target": 0,
                    "project": str(project),
                    "cwe": str(cwe),
                    "source_dataset": source,
                    "external_clean": True,
                }
            )
    return rows


def canonical_digest(code: str) -> str:
    return hashlib.sha1(aging.canonical_code(code).encode("utf-8")).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", action="append", required=True, type=Path)
    parser.add_argument("--exclude-temporal", action="append", default=[], type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--summary", required=True, type=Path)
    parser.add_argument("--max-func-chars", type=int, default=8000)
    parser.add_argument("--max-per-source", type=int, default=1000)
    parser.add_argument("--seed", type=int, default=17)
    args = parser.parse_args()

    excluded = set()
    for path in args.exclude_temporal:
        raw_rows = aging.read_jsonl(path)
        rows, _ = aging.normalize_rows(raw_rows, path.stem)
        excluded.update(canonical_digest(row["func"][: args.max_func_chars]) for row in rows)

    rng = random.Random(args.seed)
    output_rows = []
    source_summaries = []
    seen = set(excluded)
    for path in args.source:
        source = source_name(path)
        rows = load_clean_rows(path, source, args.max_func_chars)
        rng.shuffle(rows)
        kept = []
        duplicates = 0
        for row in rows:
            digest = canonical_digest(row["func"])
            if digest in seen:
                duplicates += 1
                continue
            seen.add(digest)
            kept.append(row)
            if args.max_per_source and len(kept) >= args.max_per_source:
                break
        kept.sort(key=lambda r: str(r["idx"]))
        output_rows.extend(kept)
        source_summaries.append(
            {
                "source": str(path),
                "candidate_clean_rows": len(rows),
                "kept_rows": len(kept),
                "duplicates_or_temporal_overlaps_skipped": duplicates,
            }
        )

    aging.write_jsonl(args.output, output_rows)
    aging.write_json(
        args.summary,
        {
            "output": str(args.output),
            "rows": len(output_rows),
            "max_per_source": args.max_per_source,
            "excluded_temporal_digests": len(excluded),
            "sources": source_summaries,
            "note": "Clean-only external specificity challenge; no synthetic temporal years assigned.",
        },
    )
    print(json.dumps({"output": str(args.output), "rows": len(output_rows)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
