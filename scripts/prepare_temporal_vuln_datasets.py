#!/usr/bin/env python3
"""Download and normalize temporal vulnerability datasets.

Supported Hugging Face mirrors:

- Shrutz72/cvefixes
- bstee615/diversevul

The output schema is the one expected by scripts/conduct_detector_aging.py:
  idx, func, target, date, project, cwe, source_dataset

Notes:
- CVEfixes has explicit CVE/commit dates in the mirror and is suitable for
  temporal evaluation.
- The DiverseVul mirror exposes project, commit_id, cwe, target, func, and
  message, but not an explicit commit date in the dataset preview. This script
  uses the year in a CVE identifier found in the message as a proxy date when
  available and skips records without a recoverable year. Treat DiverseVul
  temporal results as a sensitivity analysis unless commit dates are enriched.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import time
from urllib.parse import urlencode
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import pyarrow.parquet as pq


DATASETS = {
    "cvefixes": {
        "repo": "Shrutz72/cvefixes",
        "splits": ["train"],
        "files": [
            "data/train-00000-of-00003.parquet",
            "data/train-00001-of-00003.parquet",
            "data/train-00002-of-00003.parquet",
        ],
    },
    "diversevul": {
        "repo": "bstee615/diversevul",
        "splits": ["train", "validation", "test"],
        "files": [
            "data/train-00000-of-00002-06b0cca04c9bb0f2.parquet",
            "data/train-00001-of-00002-0fb7d9c1c879fb27.parquet",
            "data/validation-00000-of-00001-4e4cf40ca95c048a.parquet",
            "data/test-00000-of-00001-467ddf31930d18ee.parquet",
        ],
    },
}

CVE_YEAR_RE = re.compile(r"CVE-(19|20)\d{2}-\d+", re.IGNORECASE)
YEAR_RE = re.compile(r"(19|20)\d{2}")


def download_file(repo: str, remote_file: str, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists() and output.stat().st_size > 0:
        try:
            pq.ParquetFile(output)
            print(f"exists {output} ({output.stat().st_size} bytes)", flush=True)
            return
        except Exception:
            print(f"removing incomplete parquet {output}", flush=True)
            output.unlink()
    url = f"https://huggingface.co/datasets/{repo}/resolve/main/{remote_file}"
    print(f"downloading {url}", flush=True)
    subprocess.run(
        [
            "curl",
            "-L",
            "--retry",
            "5",
            "--retry-delay",
            "3",
            "--fail",
            "--output",
            str(output),
            url,
        ],
        check=True,
    )
    pq.ParquetFile(output)
    print(f"wrote {output} ({output.stat().st_size} bytes)", flush=True)


def write_jsonl(path: Path, rows) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def first_present(row: dict, names: list[str], default=None):
    for name in names:
        if name in row and row[name] not in (None, "", [], {}):
            return row[name]
    return default


def cwe_text(value) -> str:
    if value is None:
        return "unknown"
    if isinstance(value, list):
        if not value:
            return "unknown"
        return str(value[0])
    return str(value)


def recover_year_from_text(*values) -> str | None:
    text = " ".join(str(v) for v in values if v not in (None, ""))
    cve_match = CVE_YEAR_RE.search(text)
    if cve_match:
        return cve_match.group(0)[4:8]
    year_match = YEAR_RE.search(text)
    if year_match:
        return year_match.group(0)
    return None


def recover_cve_year_from_text(*values) -> str | None:
    text = " ".join(str(v) for v in values if v not in (None, ""))
    cve_match = CVE_YEAR_RE.search(text)
    if cve_match:
        return cve_match.group(0)[4:8]
    return None


def normalize_cvefixes_row(row: dict, row_no: int) -> list[dict]:
    rows = []
    date = first_present(row, ["commit_date", "published_date", "cve_published_date", "published"])
    cve = first_present(row, ["cve_id", "cve"], "")
    if not date:
        year = recover_year_from_text(cve, row.get("message"), row.get("diff"))
        if not year:
            return rows
        date = f"{year}-01-01"
    project = first_present(row, ["repo_url", "repository", "project"], "unknown")
    cwe = cwe_text(first_present(row, ["cwe_id", "cwe", "cwe_ids"], "unknown"))
    commit = first_present(row, ["commit_hash", "commit", "hash"], f"row{row_no}")
    vulnerable_code = first_present(row, ["vulnerable_code", "before", "old_code", "removed_code"])
    fixed_code = first_present(row, ["fixed_code", "after", "new_code", "added_code"])
    if vulnerable_code:
        rows.append(
            {
                "idx": f"cvefixes-{commit}-vuln-{row_no}",
                "func": str(vulnerable_code),
                "target": 1,
                "date": str(date),
                "project": str(project),
                "cwe": cwe,
                "source_dataset": "CVEfixes",
            }
        )
    if fixed_code:
        rows.append(
            {
                "idx": f"cvefixes-{commit}-fix-{row_no}",
                "func": str(fixed_code),
                "target": 0,
                "date": str(date),
                "project": str(project),
                "cwe": cwe,
                "source_dataset": "CVEfixes",
            }
        )
    return rows


def normalize_diversevul_row(row: dict, row_no: int) -> list[dict]:
    func = first_present(row, ["func", "code", "function"])
    if not func:
        return []
    year = recover_cve_year_from_text(row.get("message"))
    if not year:
        return []
    commit = first_present(row, ["commit_id", "commit", "hash"], f"row{row_no}")
    project = first_present(row, ["project", "repo", "repository"], "unknown")
    return [
        {
            "idx": f"diversevul-{commit}-{row_no}",
            "func": str(func),
            "target": int(first_present(row, ["target", "label"], 0)),
            "date": f"{year}-01-01",
            "project": str(project),
            "cwe": cwe_text(first_present(row, ["cwe", "cwe_id"], "unknown")),
            "source_dataset": "DiverseVul_CVE_year_proxy",
        }
    ]


def load_parquet_rows(paths: list[Path]):
    for path in paths:
        print(f"reading {path}", flush=True)
        parquet = pq.ParquetFile(path)
        for batch in parquet.iter_batches(batch_size=128):
            for row in batch.to_pylist():
                yield row


def load_api_rows(repo: str, splits: list[str], page_size: int, max_raw_rows: int | None):
    read = 0
    for split in splits:
        offset = 0
        while True:
            params = urlencode(
                {
                    "dataset": repo,
                    "config": "default",
                    "split": split,
                    "offset": offset,
                    "length": page_size,
                }
            )
            url = f"https://datasets-server.huggingface.co/rows?{params}"
            request = Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urlopen(request, timeout=120) as response:
                payload = json.load(response)
            rows = payload.get("rows", [])
            total = int(payload.get("num_rows_total", 0))
            if not rows:
                break
            for item in rows:
                row = item["row"]
                row["_hf_split"] = split
                row["_hf_row_idx"] = item.get("row_idx")
                yield row
                read += 1
                if max_raw_rows and read >= max_raw_rows:
                    return
            offset += len(rows)
            print(f"{repo}:{split} fetched {offset}/{total}", flush=True)
            if offset >= total:
                break
            time.sleep(0.05)


def fetch_api_page(repo: str, split: str, offset: int, length: int) -> dict:
    params = urlencode(
        {
            "dataset": repo,
            "config": "default",
            "split": split,
            "offset": offset,
            "length": length,
        }
    )
    url = f"https://datasets-server.huggingface.co/rows?{params}"
    request = Request(url, headers={"User-Agent": "Mozilla/5.0"})
    last_error = None
    for attempt in range(4):
        try:
            with urlopen(request, timeout=120) as response:
                return json.load(response)
        except (HTTPError, URLError, TimeoutError) as exc:
            last_error = exc
            wait = 2 * (attempt + 1)
            print(f"warning: API fetch failed for {repo}:{split} offset={offset}: {exc}; retrying in {wait}s", flush=True)
            time.sleep(wait)
    raise RuntimeError(f"failed API fetch for {repo}:{split} offset={offset}") from last_error


def load_api_sampled_rows(repo: str, splits: list[str], sample_step: int, sample_length: int, max_raw_rows: int | None):
    emitted = 0
    for split in splits:
        first = fetch_api_page(repo, split, 0, min(sample_length, 10))
        total = int(first.get("num_rows_total", 0))
        offsets = list(range(0, total, sample_step))
        if offsets and offsets[-1] != max(0, total - sample_length):
            offsets.append(max(0, total - sample_length))
        for offset in offsets:
            try:
                payload = first if offset == 0 and sample_length <= 10 else fetch_api_page(repo, split, offset, sample_length)
            except RuntimeError as exc:
                print(f"warning: skipping sampled offset {offset}: {exc}", flush=True)
                continue
            rows = payload.get("rows", [])
            print(f"{repo}:{split} sampled offset {offset}/{total} rows={len(rows)}", flush=True)
            for item in rows:
                row = item["row"]
                row["_hf_split"] = split
                row["_hf_row_idx"] = item.get("row_idx")
                yield row
                emitted += 1
                if max_raw_rows and emitted >= max_raw_rows:
                    return
            time.sleep(0.05)


def prepare_dataset(
    name: str,
    source_dir: Path,
    output: Path,
    summary_path: Path,
    max_rows: int | None,
    via_api: bool,
    page_size: int,
    max_raw_rows: int | None,
    api_sample_step: int | None,
    api_sample_length: int,
) -> dict:
    spec = DATASETS[name]
    local_files = []
    if not via_api:
        for remote in spec["files"]:
            local = source_dir / name / Path(remote).name
            download_file(spec["repo"], remote, local)
            local_files.append(local)

    normalizer = normalize_cvefixes_row if name == "cvefixes" else normalize_diversevul_row
    out_rows = []
    raw_rows = 0
    skipped = 0
    vulnerable = 0
    non_vulnerable = 0
    years = {}
    projects = set()
    cwes = set()

    if via_api and api_sample_step:
        row_iter = load_api_sampled_rows(spec["repo"], spec["splits"], api_sample_step, api_sample_length, max_raw_rows)
    elif via_api:
        row_iter = load_api_rows(spec["repo"], spec["splits"], page_size, max_raw_rows)
    else:
        row_iter = load_parquet_rows(local_files)

    for raw_row in row_iter:
        raw_rows += 1
        rows = normalizer(raw_row, raw_rows)
        if not rows:
            skipped += 1
            continue
        for row in rows:
            out_rows.append(row)
            target = int(row["target"])
            vulnerable += target
            non_vulnerable += 1 - target
            year = str(row["date"])[:4]
            years[year] = years.get(year, 0) + 1
            projects.add(row["project"])
            cwes.add(row["cwe"])
            if max_rows and len(out_rows) >= max_rows:
                break
        if max_rows and len(out_rows) >= max_rows:
            break

    write_jsonl(output, out_rows)
    summary = {
        "dataset": name,
        "raw_rows_read": raw_rows,
        "normalized_rows": len(out_rows),
        "skipped_raw_rows": skipped,
        "vulnerable": vulnerable,
        "non_vulnerable": non_vulnerable,
        "vulnerable_ratio": vulnerable / len(out_rows) if out_rows else 0,
        "years": dict(sorted(years.items())),
        "project_count": len(projects),
        "cwe_count": len(cwes),
        "output": str(output),
        "source_files": [str(p) for p in local_files],
        "source_access": "huggingface_dataset_rows_api" if via_api else "huggingface_parquet_download",
        "api_sample_step": api_sample_step,
        "api_sample_length": api_sample_length if api_sample_step else None,
        "date_note": "DiverseVul uses CVE-year proxy dates when explicit dates are unavailable."
        if name == "diversevul"
        else "CVEfixes uses explicit date fields when available.",
    }
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(summary, indent=2), flush=True)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", choices=["cvefixes", "diversevul", "all"], default="all")
    parser.add_argument("--source-dir", type=Path, default=Path("data/sources"))
    parser.add_argument("--raw-dir", type=Path, default=Path("data/raw"))
    parser.add_argument("--summary-dir", type=Path, default=Path("data/processed"))
    parser.add_argument("--max-rows", type=int, help="Optional normalized-row cap for quick tests.")
    parser.add_argument("--max-raw-rows", type=int, help="Optional raw-row cap for API downloads.")
    parser.add_argument("--via-api", action="store_true", help="Use Hugging Face dataset rows API instead of parquet downloads.")
    parser.add_argument("--page-size", type=int, default=100)
    parser.add_argument("--api-sample-step", type=int, help="Sample API rows every N raw rows instead of exhaustive paging.")
    parser.add_argument("--api-sample-length", type=int, default=10)
    args = parser.parse_args()

    names = ["cvefixes", "diversevul"] if args.dataset == "all" else [args.dataset]
    for name in names:
        prepare_dataset(
            name,
            args.source_dir,
            args.raw_dir / f"{name}_temporal.jsonl",
            args.summary_dir / f"{name}_temporal_summary.json",
            args.max_rows,
            args.via_api,
            args.page_size,
            args.max_raw_rows,
            args.api_sample_step,
            args.api_sample_length,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
