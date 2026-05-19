#!/usr/bin/env python3
"""Recover commit dates for PrimeVul paired records and normalize them.

The paired PrimeVul Hugging Face mirror includes commit identifiers and commit
URLs but not an explicit timestamp column. This script fetches commit pages,
extracts real commit timestamps where possible, and writes a temporal JSONL
dataset whose date field is the recovered commit date rather than a CVE-year
proxy.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
from datetime import datetime
import json
from pathlib import Path
import re
import time
import urllib.error
import urllib.parse
import urllib.request

import pyarrow.parquet as pq


DATE_PATTERNS = [
    re.compile(r'"committedDate":"([^"]+)"'),
    re.compile(r'"authoredDate":"([^"]+)"'),
    re.compile(r'<relative-time[^>]+datetime="([^"]+)"'),
    re.compile(r'<local-time[^>]+datetime="([^"]+)"'),
    re.compile(r'datetime="([^"]+)"'),
    re.compile(r'(20\d{2}-\d{2}-\d{2}[T ][0-2]\d:[0-5]\d:[0-5]\d(?:Z|[+-][0-2]\d:?[0-5]\d)?)'),
    re.compile(r'\b((?:19|20)\d{2}-\d{2}-\d{2})\b'),
]


def read_parquet_rows(cache_dir: Path) -> list[dict]:
    rows = []
    for path in sorted(cache_dir.glob("*.parquet")):
        split_match = re.search(r"paired_data_(train|validation|test)_", path.name)
        split = split_match.group(1) if split_match else "unknown"
        table = pq.read_table(path)
        for row in table.to_pylist():
            row["_primevul_split"] = split
            rows.append(row)
    if not rows:
        raise RuntimeError(f"no PrimeVul parquet files found in {cache_dir}")
    return rows


def cwe_text(value) -> str:
    if value in (None, "", [], "None", "NOT_APPLICABLE"):
        return "unknown"
    if isinstance(value, list):
        return str(value[0]) if value else "unknown"
    return str(value)


def parse_date(text: str) -> str | None:
    for pattern in DATE_PATTERNS:
        match = pattern.search(text)
        if not match:
            continue
        value = match.group(1).replace("\\u0026", "&")
        if "T" not in value and len(value) == 10:
            return value
        normalized = value.replace("Z", "+00:00")
        if re.search(r"[+-]\d{4}$", normalized):
            normalized = normalized[:-2] + ":" + normalized[-2:]
        try:
            return datetime.fromisoformat(normalized).date().isoformat()
        except ValueError:
            if re.match(r"(?:19|20)\d{2}-\d{2}-\d{2}", value):
                return value[:10]
    return None


def fetch_commit_date(url: str, timeout: int, retries: int, sleep: float) -> tuple[str | None, str | None]:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "text/html,application/xhtml+xml",
            "User-Agent": "Mozilla/5.0 detector-aging-primevul-date-recovery",
        },
    )
    last_error = None
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                body = response.read().decode("utf-8", "ignore")
            date = parse_date(body)
            if date:
                return date, None
            return None, "no date pattern matched"
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            if attempt < retries:
                time.sleep(sleep * (attempt + 1))
    return None, last_error


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def load_existing(path: Path) -> dict[str, dict]:
    if not path.exists():
        return {}
    with path.open(encoding="utf-8") as handle:
        return {row["commit_url"]: row for row in csv.DictReader(handle)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cache-dir", type=Path, default=Path("data/external/primevul_paired_parquet"))
    parser.add_argument("--output", type=Path, default=Path("data/raw/primevul_paired_commit_dates.jsonl"))
    parser.add_argument("--summary", type=Path, default=Path("data/processed/primevul_paired_commit_dates_summary.json"))
    parser.add_argument("--date-map", type=Path, default=Path("results/primevul_commit_date_recovery/primevul_commit_dates.csv"))
    parser.add_argument("--failures", type=Path, default=Path("results/primevul_commit_date_recovery/primevul_commit_date_failures.csv"))
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--retries", type=int, default=1)
    parser.add_argument("--sleep", type=float, default=0.5)
    parser.add_argument("--max-commits", type=int, default=0)
    parser.add_argument("--github-only", action="store_true", help="Recover only github.com commit pages.")
    args = parser.parse_args()

    raw_rows = read_parquet_rows(args.cache_dir)
    by_url: dict[str, dict] = {}
    for row in raw_rows:
        url = str(row.get("commit_url") or "")
        commit = str(row.get("commit_id") or "")
        if not url or not commit:
            continue
        if url not in by_url:
            by_url[url] = {
                "commit_url": url,
                "commit_id": commit,
                "project": str(row.get("project") or ""),
                "project_url": str(row.get("project_url") or ""),
                "row_count": 0,
            }
        by_url[url]["row_count"] += 1

    existing = load_existing(args.date_map)
    pending = [item for url, item in by_url.items() if url not in existing or not existing[url].get("commit_date")]
    if args.github_only:
        pending = [item for item in pending if urllib.parse.urlparse(item["commit_url"]).netloc.lower() == "github.com"]
    pending.sort(key=lambda item: (-int(item.get("row_count", 0)), item["project"], item["commit_id"]))
    if args.max_commits:
        pending = pending[: args.max_commits]

    recovered_rows = [row for row in existing.values() if row.get("commit_date")]
    failure_rows = []
    print(
        json.dumps(
            {
                "raw_rows": len(raw_rows),
                "unique_commit_urls": len(by_url),
                "existing_recovered": len(recovered_rows),
                "pending": len(pending),
            },
            indent=2,
        ),
        flush=True,
    )

    def recover_one(item: dict) -> dict:
        date, error = fetch_commit_date(item["commit_url"], args.timeout, args.retries, args.sleep)
        out = {**item, "commit_date": date or "", "error": error or ""}
        return out

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(recover_one, item) for item in pending]
        for i, future in enumerate(concurrent.futures.as_completed(futures), start=1):
            row = future.result()
            if row["commit_date"]:
                recovered_rows.append(row)
            else:
                failure_rows.append(row)
            if i % 50 == 0 or i == len(futures):
                print(f"recovered {len(recovered_rows)} dates; failures {len(failure_rows)}; processed {i}/{len(futures)} pending", flush=True)

    merged = {row["commit_url"]: row for row in recovered_rows}
    write_csv(args.date_map, sorted(merged.values(), key=lambda r: (r.get("project", ""), r.get("commit_id", ""))))
    write_csv(args.failures, sorted(failure_rows, key=lambda r: (r.get("project", ""), r.get("commit_id", ""))))

    normalized = []
    skipped_no_date = 0
    for row_no, row in enumerate(raw_rows, start=1):
        commit_url = str(row.get("commit_url") or "")
        recovered = merged.get(commit_url)
        if not recovered:
            skipped_no_date += 1
            continue
        func = row.get("func")
        if not func:
            continue
        date = recovered["commit_date"]
        split = row.get("_primevul_split", "unknown")
        commit = str(row.get("commit_id") or f"row{row_no}")
        idx = str(row.get("idx") or row_no)
        normalized.append(
            {
                "idx": f"primevul-commit-dated-{split}-{commit}-{idx}",
                "func": str(func),
                "target": int(row.get("target", 0)),
                "date": date,
                "year": int(date[:4]),
                "project": str(row.get("project") or row.get("project_url") or "unknown"),
                "cwe": cwe_text(row.get("cwe")),
                "source_dataset": "PrimeVul_paired_commit_dates",
                "primevul_split": split,
                "primevul_commit_id": commit,
                "primevul_commit_url": commit_url,
                "primevul_cve": str(row.get("cve") or ""),
                "primevul_date_source": "recovered_commit_page",
            }
        )

    normalized.sort(key=lambda r: (r["year"], r["project"], r["idx"]))
    write_jsonl(args.output, normalized)
    by_year: dict[str, dict[str, int]] = {}
    projects = set()
    commits = set()
    for row in normalized:
        bucket = by_year.setdefault(str(row["year"]), {"rows": 0, "pos": 0, "neg": 0})
        bucket["rows"] += 1
        bucket["pos"] += int(row["target"] == 1)
        bucket["neg"] += int(row["target"] == 0)
        projects.add(row["project"])
        commits.add(row["primevul_commit_id"])
    summary = {
        "raw_rows": len(raw_rows),
        "unique_commit_urls": len(by_url),
        "recovered_commit_urls": len(merged),
        "normalized_rows": len(normalized),
        "skipped_rows_without_recovered_commit_date": skipped_no_date,
        "projects": len(projects),
        "commits": len(commits),
        "date_source": "commit pages from PrimeVul commit_url metadata",
        "by_year": by_year,
    }
    args.summary.parent.mkdir(parents=True, exist_ok=True)
    args.summary.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
