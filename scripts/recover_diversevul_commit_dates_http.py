#!/usr/bin/env python3
"""Recover DiverseVul commit dates from web commit pages.

This broader recovery pass complements recover_diversevul_commit_dates.py. It is
designed for the official DiverseVul metadata file, whose commit URLs often
point to GitHub or to repositories with GitHub mirrors. GitHub commit pages embed
authoredDate and committedDate in page JSON, which avoids GitHub API rate limits
and large repository fetches.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import http.client
import json
from pathlib import Path
import re
import time
import urllib.error
import urllib.parse
import urllib.request


COMMIT_RE = re.compile(r"^diversevul-(?P<sha>[0-9a-fA-F]{40})-")
DATE_PATTERNS = [
    re.compile(r'"committedDate":"([^"]+)"'),
    re.compile(r'"authoredDate":"([^"]+)"'),
    re.compile(r'<relative-time[^>]+datetime="([^"]+)"'),
    re.compile(r'datetime="([^"]+)"'),
]


PROJECT_GITHUB = {
    "curl": "curl/curl",
    "envoy": "envoyproxy/envoy",
    "FFmpeg": "FFmpeg/FFmpeg",
    "FreeRDP": "FreeRDP/FreeRDP",
    "gpac": "gpac/gpac",
    "ImageMagick": "ImageMagick/ImageMagick",
    "ImageMagick6": "ImageMagick/ImageMagick6",
    "krb5": "krb5/krb5",
    "libass": "libass/libass",
    "linux": "torvalds/linux",
    "linux-2.6": "torvalds/linux",
    "node": "nodejs/node",
    "openssl": "openssl/openssl",
    "php-src": "php/php-src",
    "postgres": "postgres/postgres",
    "qemu": "qemu/qemu",
    "redis": "redis/redis",
    "samba": "samba-team/samba",
    "tcpdump": "the-tcpdump-group/tcpdump",
    "tensorflow": "tensorflow/tensorflow",
    "vim": "vim/vim",
}


def read_jsonl(path: Path) -> list[dict]:
    rows = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def load_metadata(path: Path) -> dict[tuple[str, str], dict]:
    by_key = {}
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            row = json.loads(line)
            by_key[(str(row.get("project")), str(row.get("commit_id")).lower())] = row
    return by_key


def github_slug_from_url(url: str) -> str | None:
    parsed = urllib.parse.urlparse(url or "")
    if parsed.netloc.lower() != "github.com":
        return None
    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if len(parts) >= 2:
        return "/".join(parts[:2])
    return None


def github_commit_url(project: str, sha: str, meta: dict) -> str | None:
    slug = github_slug_from_url(str(meta.get("commit_url", "")))
    if not slug:
        slug = github_slug_from_url(str(meta.get("repo_url", "")))
    if not slug:
        slug = PROJECT_GITHUB.get(project)
    if slug:
        return f"https://github.com/{slug}/commit/{sha}"
    return None


def parse_date(html: str) -> str | None:
    for pattern in DATE_PATTERNS:
        match = pattern.search(html)
        if match:
            return match.group(1)
    return None


def fetch_date(url: str, timeout: int, retries: int, sleep: float) -> tuple[str | None, str | None]:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "text/html,application/xhtml+xml",
            "User-Agent": "Mozilla/5.0 detector-aging-diversevul-date-recovery",
        },
    )
    last_error = None
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                html = response.read().decode("utf-8", "ignore")
            return parse_date(html), None
        except http.client.IncompleteRead as exc:
            html = exc.partial.decode("utf-8", "ignore")
            date = parse_date(html)
            if date:
                return date, None
            last_error = f"{type(exc).__name__}: incomplete response"
            if attempt < retries:
                time.sleep(sleep * (attempt + 1))
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            if attempt < retries:
                time.sleep(sleep * (attempt + 1))
    return None, last_error


def recover(args: argparse.Namespace) -> dict:
    rows = read_jsonl(args.input)
    metadata = load_metadata(args.metadata)

    row_counts: dict[tuple[str, str], int] = {}
    for row in rows:
        match = COMMIT_RE.match(str(row.get("idx", "")))
        if not match:
            continue
        key = (str(row.get("project")), match.group("sha").lower())
        if key in metadata:
            row_counts[key] = row_counts.get(key, 0) + 1

    candidates = []
    for (project, sha), row_count in sorted(row_counts.items(), key=lambda item: item[1], reverse=True):
        url = github_commit_url(project, sha, metadata[(project, sha)])
        if url:
            candidates.append((project, sha, row_count, url))

    if args.max_commits:
        candidates = candidates[: args.max_commits]

    recovered: dict[tuple[str, str], str] = {}
    failures = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        future_to_candidate = {
            pool.submit(fetch_date, url, args.timeout, args.retries, args.sleep): (project, sha, row_count, url)
            for project, sha, row_count, url in candidates
        }
        for future in concurrent.futures.as_completed(future_to_candidate):
            project, sha, row_count, url = future_to_candidate[future]
            date, error = future.result()
            if date:
                recovered[(project, sha)] = date
            else:
                failures.append(
                    {
                        "project": project,
                        "commit_id": sha,
                        "row_count": row_count,
                        "url": url,
                        "reason": error or "date_not_found",
                    }
                )

    enriched = []
    row_metadata = 0
    row_recovered = 0
    for row in rows:
        out = dict(row)
        match = COMMIT_RE.match(str(row.get("idx", "")))
        if match:
            sha = match.group("sha").lower()
            key = (str(row.get("project")), sha)
            meta = metadata.get(key)
            if meta:
                row_metadata += 1
                out["diversevul_commit_id"] = sha
                out["diversevul_commit_url"] = meta.get("commit_url")
                out["diversevul_repo_url"] = meta.get("repo_url")
                out["diversevul_cve"] = meta.get("CVE")
            if key in recovered:
                date = recovered[key]
                out["date"] = date[:10]
                out["year"] = int(date[:4])
                out["source_dataset"] = "diversevul_full_temporal_commit_date"
                out["diversevul_commit_date"] = date
                row_recovered += 1
        enriched.append(out)

    recovered_rows = [
        {
            "project": project,
            "commit_id": sha,
            "commit_date": date,
            "commit_year": date[:4],
            "row_count": row_counts[(project, sha)],
            "commit_url": metadata[(project, sha)].get("commit_url"),
            "repo_url": metadata[(project, sha)].get("repo_url"),
        }
        for (project, sha), date in sorted(recovered.items())
    ]

    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_jsonl(args.output, enriched)
    write_csv(args.output_dir / "diversevul_http_recovered_commit_dates.csv", recovered_rows)
    write_csv(args.output_dir / "diversevul_http_commit_date_failures.csv", failures)

    summary = {
        "input_rows": len(rows),
        "matched_rows_with_metadata": row_metadata,
        "matched_project_commit_pairs": len(row_counts),
        "candidate_project_commit_pairs": len(candidates),
        "recovered_project_commit_pairs": len(recovered),
        "rows_with_recovered_dates": row_recovered,
        "rows_without_recovered_dates": len(rows) - row_recovered,
        "failure_count": len(failures),
        "output": str(args.output),
    }
    (args.output_dir / "diversevul_http_commit_date_recovery_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8"
    )
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--retries", type=int, default=1)
    parser.add_argument("--sleep", type=float, default=0.5)
    parser.add_argument("--max-commits", type=int, default=0)
    args = parser.parse_args()
    print(json.dumps(recover(args), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
