#!/usr/bin/env python3
"""Recover DiverseVul commit dates from the official metadata commit URLs.

The Hugging Face mirror used for the temporal experiments exposes project names
and commit IDs but not explicit dates. The official DiverseVul metadata file
contains repository and commit URLs. This script joins the metadata to the
normalized DiverseVul JSONL, fetches commit objects with Git, optionally falls
back to the GitHub commit API, and writes an enriched JSONL with recovered
commit dates where possible.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
from pathlib import Path
import re
import subprocess
import urllib.parse
import urllib.error
import urllib.request


COMMIT_RE = re.compile(r"^diversevul-(?P<sha>[0-9a-fA-F]{40})-")


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
            by_key[(str(row.get("project")), str(row.get("commit_id")))] = row
    return by_key


def normalize_clone_url(repo_url: str, project: str) -> str | None:
    repo_url = (repo_url or "").strip()
    if not repo_url:
        return None
    parsed = urllib.parse.urlparse(repo_url)
    host = parsed.netloc.lower()
    path = parsed.path

    if "github.com" in host:
        clean = repo_url.split("/commit/")[0].split("/tree/")[0].rstrip("/")
        return clean if clean.endswith(".git") else clean + ".git"
    if "gitlab.com" in host:
        clean = repo_url.rstrip("/")
        return clean if clean.endswith(".git") else clean + ".git"
    if "git.kernel.org" in host and path.endswith(".git"):
        return repo_url
    if "git.samba.org" in host and "samba.git" in repo_url:
        return "https://git.samba.org/samba.git"
    if "git.qemu.org" in host:
        return "https://gitlab.com/qemu-project/qemu.git"
    if "git.openssl.org" in host:
        return "https://github.com/openssl/openssl.git"
    if "git.php.net" in host and "php-src" in repo_url:
        return "https://github.com/php/php-src.git"
    if "git.gnome.org" in host and "libxml2" in repo_url:
        return "https://gitlab.gnome.org/GNOME/libxml2.git"

    known = {
        "linux": "https://github.com/torvalds/linux.git",
        "linux-2.6": "https://github.com/torvalds/linux.git",
        "openssl": "https://github.com/openssl/openssl.git",
        "qemu": "https://gitlab.com/qemu-project/qemu.git",
        "samba": "https://github.com/samba-team/samba.git",
        "curl": "https://github.com/curl/curl.git",
        "node": "https://github.com/nodejs/node.git",
        "postgres": "https://github.com/postgres/postgres.git",
        "tcpdump": "https://github.com/the-tcpdump-group/tcpdump.git",
        "krb5": "https://github.com/krb5/krb5.git",
        "redis": "https://github.com/redis/redis.git",
        "envoy": "https://github.com/envoyproxy/envoy.git",
        "FreeRDP": "https://github.com/FreeRDP/FreeRDP.git",
        "libxml2": "https://gitlab.gnome.org/GNOME/libxml2.git",
    }
    return known.get(project)


def github_repo_slug(repo_url: str, commit_url: str) -> str | None:
    """Return owner/repo for GitHub URLs, or None for other hosts."""
    for raw_url in (commit_url or "", repo_url or ""):
        parsed = urllib.parse.urlparse(raw_url)
        if parsed.netloc.lower() != "github.com":
            continue
        parts = [part for part in parsed.path.strip("/").split("/") if part]
        if len(parts) >= 2:
            return "/".join(parts[:2])
    return None


def repo_cache_dir(cache_dir: Path, clone_url: str) -> Path:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", clone_url)
    return cache_dir / safe


def run_git(args: list[str], cwd: Path, timeout: int) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            ["git", *args],
            cwd=cwd,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return subprocess.CompletedProcess(
            ["git", *args],
            returncode=124,
            stdout=exc.stdout or "",
            stderr=f"timeout after {timeout}s",
        )


def ensure_repo(cache_dir: Path, clone_url: str, timeout: int) -> Path | None:
    repo_dir = repo_cache_dir(cache_dir, clone_url)
    repo_dir.mkdir(parents=True, exist_ok=True)
    if not (repo_dir / ".git").exists():
        result = run_git(["init", "-q"], repo_dir, timeout)
        if result.returncode != 0:
            return None
        result = run_git(["remote", "add", "origin", clone_url], repo_dir, timeout)
        if result.returncode != 0:
            return None
    return repo_dir


def has_commit(repo_dir: Path, sha: str, timeout: int) -> bool:
    result = run_git(["cat-file", "-e", f"{sha}^{{commit}}"], repo_dir, timeout)
    return result.returncode == 0


def fetch_commit(repo_dir: Path, sha: str, timeout: int) -> bool:
    if has_commit(repo_dir, sha, timeout):
        return True
    result = run_git(
        ["fetch", "-q", "--filter=blob:none", "--no-tags", "--depth=1", "origin", sha],
        repo_dir,
        timeout,
    )
    return result.returncode == 0 and has_commit(repo_dir, sha, timeout)


def commit_date(repo_dir: Path, sha: str, timeout: int) -> str | None:
    result = run_git(["show", "-s", "--format=%cI", sha], repo_dir, timeout)
    if result.returncode == 0:
        return result.stdout.strip()
    return None


def github_api_commit_date(slug: str, sha: str, token: str | None, timeout: int) -> str | None:
    url = f"https://api.github.com/repos/{slug}/commits/{sha}"
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "detector-aging-diversevul-date-recovery",
        },
    )
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return None
    commit = payload.get("commit") or {}
    committer = commit.get("committer") or {}
    author = commit.get("author") or {}
    return committer.get("date") or author.get("date")


def recover(args: argparse.Namespace) -> dict:
    metadata = load_metadata(args.metadata)
    rows = read_jsonl(args.input)

    wanted = {}
    for row in rows:
        match = COMMIT_RE.match(str(row.get("idx", "")))
        if not match:
            continue
        sha = match.group("sha").lower()
        key = (str(row.get("project")), sha)
        meta = metadata.get(key)
        if not meta:
            continue
        clone = normalize_clone_url(str(meta.get("repo_url", "")), str(row.get("project")))
        if clone:
            wanted[(str(row.get("project")), sha)] = {**meta, "clone_url": clone}

    date_by_key = {}
    failures = []
    api_queries = 0
    github_token = os.environ.get(args.github_token_env) if args.github_token_env else None
    by_repo: dict[str, list[tuple[str, str]]] = {}
    for key, meta in wanted.items():
        by_repo.setdefault(meta["clone_url"], []).append(key)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    for repo_i, (clone, keys) in enumerate(sorted(by_repo.items()), start=1):
        if args.max_repos and repo_i > args.max_repos:
            break
        repo_dir = ensure_repo(args.cache_dir, clone, args.git_timeout)
        if repo_dir is None:
            for project, sha in keys:
                failures.append({"project": project, "commit_id": sha, "clone_url": clone, "reason": "repo_init_failed"})
            continue
        repo_failures = 0
        for project, sha in keys:
            if args.max_commits and len(date_by_key) >= args.max_commits:
                break
            ok = has_commit(repo_dir, sha, args.git_timeout) if args.offline else fetch_commit(repo_dir, sha, args.git_timeout)
            if not ok:
                failures.append({"project": project, "commit_id": sha, "clone_url": clone, "reason": "fetch_failed"})
                repo_failures += 1
                if args.max_failures_per_repo and repo_failures >= args.max_failures_per_repo:
                    break
                continue
            date = commit_date(repo_dir, sha, args.git_timeout)
            if date:
                date_by_key[(project, sha)] = date
            else:
                failures.append({"project": project, "commit_id": sha, "clone_url": clone, "reason": "date_failed"})

    if args.github_api:
        for project, sha in sorted(wanted):
            if (project, sha) in date_by_key:
                continue
            if args.github_api_limit and api_queries >= args.github_api_limit:
                break
            meta = wanted[(project, sha)]
            slug = github_repo_slug(str(meta.get("repo_url", "")), str(meta.get("commit_url", "")))
            if not slug:
                continue
            api_queries += 1
            date = github_api_commit_date(slug, sha, github_token, args.git_timeout)
            if date:
                date_by_key[(project, sha)] = date

    enriched = []
    row_recovered = 0
    row_metadata = 0
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
            if key in date_by_key:
                date = date_by_key[key]
                out["date"] = date[:10]
                out["year"] = int(date[:4])
                out["source_dataset"] = "diversevul_full_temporal_commit_date"
                out["diversevul_commit_date"] = date
                row_recovered += 1
        enriched.append(out)

    write_jsonl(args.output, enriched)
    write_csv(args.output_dir / "diversevul_commit_date_failures.csv", failures)
    recovered_pairs = [
        {
            "project": project,
            "commit_id": sha,
            "commit_date": date,
            "commit_year": date[:4],
            "repo_url": wanted[(project, sha)].get("repo_url"),
            "commit_url": wanted[(project, sha)].get("commit_url"),
            "clone_url": wanted[(project, sha)].get("clone_url"),
        }
        for (project, sha), date in sorted(date_by_key.items())
    ]
    write_csv(args.output_dir / "diversevul_recovered_commit_dates.csv", recovered_pairs)

    summary = {
        "input_rows": len(rows),
        "metadata_project_commit_pairs": len(metadata),
        "matched_rows_with_metadata": row_metadata,
        "candidate_project_commit_pairs": len(wanted),
        "recovered_project_commit_pairs": len(date_by_key),
        "rows_with_recovered_dates": row_recovered,
        "rows_without_recovered_dates": len(rows) - row_recovered,
        "failure_count": len(failures),
        "api_queries_attempted": api_queries,
        "output": str(args.output),
    }
    (args.output_dir / "diversevul_commit_date_recovery_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8"
    )
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--cache-dir", type=Path, default=Path(".cache/diversevul_commit_repos"))
    parser.add_argument("--git-timeout", type=int, default=45)
    parser.add_argument("--max-commits", type=int, default=0)
    parser.add_argument("--max-repos", type=int, default=0)
    parser.add_argument("--max-failures-per-repo", type=int, default=5)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--github-api", action="store_true")
    parser.add_argument("--github-api-limit", type=int, default=0)
    parser.add_argument("--github-token-env", default="GITHUB_TOKEN")
    args = parser.parse_args()
    print(json.dumps(recover(args), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
