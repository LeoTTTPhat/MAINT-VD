#!/usr/bin/env python3
"""Fetch and normalize the PrimeVul paired split for temporal sensitivity.

The Hugging Face mirror used here exposes paired vulnerable/fixed functions
with CVE identifiers but not commit timestamps. We therefore use the CVE year as
a proxy date and label the resulting dataset accordingly. This makes PrimeVul a
third external sensitivity dataset, not a replacement for recovered commit-date
evidence.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import time
from urllib.parse import urlencode
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import pyarrow.parquet as pq


CVE_YEAR_RE = re.compile(r"CVE-((?:19|20)\d{2})-\d+", re.IGNORECASE)


def fetch_rows(repo: str, config: str, split: str, page_size: int):
    offset = 0
    total = None
    while True:
        params = urlencode(
            {
                "dataset": repo,
                "config": config,
                "split": split,
                "offset": offset,
                "length": page_size,
            }
        )
        url = f"https://datasets-server.huggingface.co/rows?{params}"
        payload = None
        for attempt in range(6):
            try:
                with urlopen(Request(url, headers={"User-Agent": "Mozilla/5.0"}), timeout=120) as response:
                    payload = json.load(response)
                break
            except HTTPError as exc:
                if exc.code != 429 or attempt == 5:
                    raise
                sleep_s = 5 * (attempt + 1)
                print(f"rate limited; sleeping {sleep_s}s", flush=True)
                time.sleep(sleep_s)
            except URLError:
                if attempt == 5:
                    raise
                time.sleep(3 * (attempt + 1))
        assert payload is not None
        rows = payload.get("rows", [])
        total = int(payload.get("num_rows_total", total or 0))
        if not rows:
            break
        for item in rows:
            yield item["row"]
        offset += len(rows)
        print(f"{repo}:{config}:{split} fetched {offset}/{total}", flush=True)
        if offset >= total:
            break
        time.sleep(0.05)


def fetch_parquet_rows(repo: str, config: str, splits: list[str], cache_dir: Path):
    params = urlencode({"dataset": repo})
    url = f"https://datasets-server.huggingface.co/parquet?{params}"
    with urlopen(Request(url, headers={"User-Agent": "Mozilla/5.0"}), timeout=120) as response:
        payload = json.load(response)
    files = [
        item
        for item in payload.get("parquet_files", [])
        if item.get("config") == config and item.get("split") in set(splits)
    ]
    if not files:
        raise RuntimeError(f"no parquet files found for {repo} config={config} splits={splits}")
    cache_dir.mkdir(parents=True, exist_ok=True)
    for item in files:
        split = item["split"]
        out = cache_dir / f"{config}_{split}_{item['filename']}"
        if not out.exists() or out.stat().st_size == 0:
            print(f"downloading {item['url']}", flush=True)
            with urlopen(Request(item["url"], headers={"User-Agent": "Mozilla/5.0"}), timeout=300) as response:
                out.write_bytes(response.read())
        print(f"reading {out}", flush=True)
        table = pq.read_table(out)
        for row in table.to_pylist():
            yield split, row


def cve_year(row: dict) -> str | None:
    for key in ("cve", "CVE ID", "commit_message", "cve_desc"):
        value = row.get(key)
        if value in (None, "", "None", "NOT_APPLICABLE"):
            continue
        match = CVE_YEAR_RE.search(str(value))
        if match:
            return match.group(1)
    return None


def cwe_text(value) -> str:
    if value in (None, "", [], "None", "NOT_APPLICABLE"):
        return "unknown"
    if isinstance(value, list):
        return str(value[0]) if value else "unknown"
    return str(value)


def normalize(row: dict, split: str, row_no: int) -> dict | None:
    func = row.get("func")
    year = cve_year(row)
    if not func or not year:
        return None
    idx = row.get("idx", row_no)
    commit = row.get("commit_id") or f"row{row_no}"
    project = row.get("project") or row.get("project_url") or "unknown"
    return {
        "idx": f"primevul-paired-{split}-{commit}-{idx}",
        "func": str(func),
        "target": int(row.get("target", 0)),
        "date": f"{year}-01-01",
        "year": int(year),
        "project": str(project),
        "cwe": cwe_text(row.get("cwe") or row.get("CWE ID")),
        "source_dataset": "PrimeVul_paired_CVE_year_proxy",
        "primevul_split": split,
        "primevul_commit_id": str(commit),
        "primevul_cve": str(row.get("cve") or row.get("CVE ID") or ""),
    }


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default="Andrefty/PrimeVul-v0.1-hf")
    parser.add_argument("--config", default="paired_data")
    parser.add_argument("--splits", default="train,validation,test")
    parser.add_argument("--page-size", type=int, default=100)
    parser.add_argument("--api", action="store_true", help="Use row API instead of parquet export.")
    parser.add_argument("--cache-dir", type=Path, default=Path("data/external/primevul_paired_parquet"))
    parser.add_argument("--output", type=Path, default=Path("data/raw/primevul_paired_cve_year_proxy.jsonl"))
    parser.add_argument("--summary", type=Path, default=Path("data/processed/primevul_paired_cve_year_proxy_summary.json"))
    args = parser.parse_args()

    rows = []
    raw_count = 0
    skipped_no_year = 0
    splits = [s.strip() for s in args.splits.split(",") if s.strip()]
    if args.api:
        iterator = ((split, raw) for split in splits for raw in fetch_rows(args.repo, args.config, split, args.page_size))
    else:
        iterator = fetch_parquet_rows(args.repo, args.config, splits, args.cache_dir)
    for split, raw in iterator:
            raw_count += 1
            normalized = normalize(raw, split, raw_count)
            if normalized is None:
                skipped_no_year += 1
                continue
            rows.append(normalized)

    rows.sort(key=lambda row: (row["year"], row["project"], row["idx"]))
    write_jsonl(args.output, rows)
    by_year: dict[str, dict[str, int]] = {}
    projects = set()
    for row in rows:
        year = str(row["year"])
        bucket = by_year.setdefault(year, {"rows": 0, "pos": 0, "neg": 0})
        bucket["rows"] += 1
        bucket["pos"] += int(row["target"] == 1)
        bucket["neg"] += int(row["target"] == 0)
        projects.add(row["project"])
    summary = {
        "repo": args.repo,
        "config": args.config,
        "raw_rows": raw_count,
        "normalized_rows": len(rows),
        "skipped_no_cve_year": skipped_no_year,
        "projects": len(projects),
        "date_source": "CVE-year proxy from PrimeVul cve/commit_message metadata",
        "by_year": by_year,
    }
    args.summary.parent.mkdir(parents=True, exist_ok=True)
    args.summary.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
