#!/usr/bin/env python3
"""Create a clean-only benchmark from local non-vulnerability repositories.

This benchmark is stricter than the earlier Big-Vul/CodeXGLUE stress test
because its rows are harvested from repositories that are not used to construct
the vulnerability datasets. It is still an external clean benchmark rather than
a formal proof of defect absence.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
import random
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import conduct_detector_aging as aging  # noqa: E402


C_LIKE_EXTENSIONS = {".c", ".cc", ".cpp", ".h", ".hpp", ".java"}
PY_EXTENSIONS = {".py"}


def canonical_digest(code: str) -> str:
    return hashlib.sha1(aging.canonical_code(code).encode("utf-8")).hexdigest()


def project_name(root: Path, path: Path) -> str:
    try:
        rel = path.relative_to(root)
        return rel.parts[0] if len(rel.parts) > 1 else root.name
    except ValueError:
        return root.name


def read_text(path: Path, max_bytes: int) -> str | None:
    try:
        if path.stat().st_size > max_bytes:
            return None
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None


def python_functions(root: Path, path: Path, text: str, min_chars: int, max_chars: int) -> list[dict]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    lines = text.splitlines()
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not hasattr(node, "end_lineno"):
            continue
        snippet = "\n".join(lines[node.lineno - 1 : node.end_lineno])
        if min_chars <= len(snippet) <= max_chars:
            out.append(
                {
                    "func": snippet,
                    "language": "Python",
                    "symbol": node.name,
                    "path": str(path),
                    "project": project_name(root, path),
                }
            )
    return out


def c_like_functions(root: Path, path: Path, text: str, min_chars: int, max_chars: int) -> list[dict]:
    # Conservative source-level extractor: find likely function headers and
    # balance braces. It intentionally ignores macros and declarations.
    pattern = re.compile(
        r"(?m)^[A-Za-z_][A-Za-z0-9_\\s\\*:&<>~,]*\\s+([A-Za-z_][A-Za-z0-9_]*)\\s*\\([^;{}]*\\)\\s*\\{"
    )
    out = []
    for match in pattern.finditer(text):
        start = match.start()
        pos = match.end() - 1
        depth = 0
        end = None
        for idx in range(pos, min(len(text), pos + max_chars + 1)):
            ch = text[idx]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = idx + 1
                    break
        if end is None:
            continue
        snippet = text[start:end]
        if min_chars <= len(snippet) <= max_chars:
            out.append(
                {
                    "func": snippet,
                    "language": path.suffix.lower().lstrip(".") or "c_like",
                    "symbol": match.group(1),
                    "path": str(path),
                    "project": project_name(root, path),
                }
            )
    return out


def collect_from_root(root: Path, min_chars: int, max_chars: int, max_file_bytes: int) -> list[dict]:
    rows = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part.startswith(".") or part in {"node_modules", "__pycache__", ".venv", "venv"} for part in path.parts):
            continue
        text = read_text(path, max_file_bytes)
        if text is None:
            continue
        if path.suffix in PY_EXTENSIONS:
            rows.extend(python_functions(root, path, text, min_chars, max_chars))
        elif path.suffix in C_LIKE_EXTENSIONS:
            rows.extend(c_like_functions(root, path, text, min_chars, max_chars))
    return rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", action="append", required=True, type=Path)
    parser.add_argument("--exclude-temporal", action="append", default=[], type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--summary", required=True, type=Path)
    parser.add_argument("--max-per-project", type=int, default=500)
    parser.add_argument("--max-total", type=int, default=6000)
    parser.add_argument("--min-chars", type=int, default=80)
    parser.add_argument("--max-chars", type=int, default=8000)
    parser.add_argument("--max-file-bytes", type=int, default=500_000)
    parser.add_argument("--seed", type=int, default=17)
    args = parser.parse_args()

    excluded = set()
    for path in args.exclude_temporal:
        raw_rows = aging.read_jsonl(path)
        rows, _ = aging.normalize_rows(raw_rows, path.stem)
        excluded.update(canonical_digest(row["func"][: args.max_chars]) for row in rows)

    rng = random.Random(args.seed)
    candidates = []
    for root in args.root:
        if root.exists():
            candidates.extend(collect_from_root(root, args.min_chars, args.max_chars, args.max_file_bytes))
    rng.shuffle(candidates)

    seen = set(excluded)
    per_project: dict[str, int] = {}
    kept = []
    skipped_overlap = 0
    for row in candidates:
        digest = canonical_digest(row["func"])
        if digest in seen:
            skipped_overlap += 1
            continue
        project = row["project"]
        if per_project.get(project, 0) >= args.max_per_project:
            continue
        seen.add(digest)
        per_project[project] = per_project.get(project, 0) + 1
        kept.append(
            {
                "idx": f"repo-clean-{len(kept)}",
                "func": row["func"],
                "target": 0,
                "project": project,
                "cwe": "repo_clean",
                "source_dataset": "repo_clean_benchmark",
                "clean_source_path": row["path"],
                "language": row["language"],
                "symbol": row["symbol"],
                "external_clean": True,
            }
        )
        if args.max_total and len(kept) >= args.max_total:
            break

    kept.sort(key=lambda r: (r["project"], r["clean_source_path"], r["symbol"], r["idx"]))
    aging.write_jsonl(args.output, kept)
    aging.write_json(
        args.summary,
        {
            "output": str(args.output),
            "rows": len(kept),
            "candidate_functions": len(candidates),
            "projects": len(per_project),
            "per_project": per_project,
            "excluded_temporal_digests": len(excluded),
            "duplicates_or_temporal_overlaps_skipped": skipped_overlap,
            "roots": [str(root) for root in args.root],
            "note": "Clean-only benchmark from repositories outside the vulnerability dataset construction pipeline.",
        },
    )
    print(json.dumps({"output": str(args.output), "rows": len(kept), "projects": len(per_project)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
