#!/usr/bin/env python3
"""Run the detector-aging study pipeline.

The script conducts Phases 1-9 for the model-drift study direction:

1. Dataset feasibility
2. Temporal split design
3. Model selection and baseline execution
4. Aging analysis
5. Drift source analysis
6. Maintenance policy evaluation
7. Monitoring trigger analysis
8. Statistical/sensitivity summaries
9. Paper/report assembly

It accepts a temporal JSONL dataset with at least these fields:
  func/code, target, date, project, cwe

If no input is provided, it generates a deterministic temporal smoke dataset so
the complete pipeline can be verified locally without downloading a large
external vulnerability dataset.
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
import math
from pathlib import Path
import random
import re
import statistics
from typing import Callable, Iterable

import numpy as np


TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|0x[0-9A-Fa-f]+|\d+|==|!=|<=|>=|&&|\|\||[{}()[\];,.*+\-/<>=%]")
SECURITY_TOKENS = [
    "strcpy",
    "strncpy",
    "memcpy",
    "memmove",
    "malloc",
    "free",
    "sprintf",
    "snprintf",
    "gets",
    "scanf",
    "recv",
    "send",
    "read",
    "write",
    "open",
    "close",
    "len",
    "size",
    "buf",
    "buffer",
    "ptr",
    "null",
    "if",
    "for",
    "while",
    "return",
]


def read_jsonl(path: Path) -> list[dict]:
    rows = []
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_no}: invalid JSON: {exc}") from exc
    return rows


def write_jsonl(path: Path, rows: Iterable[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")


def write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    columns = list(rows[0].keys())
    with path.open("w", encoding="utf-8") as handle:
        handle.write(",".join(columns) + "\n")
        for row in rows:
            values = []
            for col in columns:
                text = str(row.get(col, ""))
                if any(ch in text for ch in [",", '"', "\n"]):
                    text = '"' + text.replace('"', '""') + '"'
                values.append(text)
            handle.write(",".join(values) + "\n")


def safe_div(num: float, den: float) -> float:
    return num / den if den else 0.0


def parse_year(value: object) -> int:
    text = str(value).strip()
    if not text:
        raise ValueError("empty date")
    match = re.search(r"(19|20)\d{2}", text)
    if not match:
        raise ValueError(f"cannot extract year from date {value!r}")
    year = int(match.group(0))
    if year < 1990 or year > datetime.now().year + 1:
        raise ValueError(f"implausible year {year}")
    return year


def normalize_target(value: object) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return int(value)
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "vulnerable", "vuln", "unsafe"}:
        return 1
    if text in {"0", "false", "no", "clean", "safe", "secure"}:
        return 0
    raise ValueError(f"cannot normalize target {value!r}")


def first_present(row: dict, names: list[str], default: object = None) -> object:
    for name in names:
        if name in row and row[name] not in (None, ""):
            return row[name]
    return default


def normalize_rows(raw_rows: list[dict], source: str) -> tuple[list[dict], list[str]]:
    rows = []
    warnings = []
    for i, row in enumerate(raw_rows):
        func = first_present(row, ["func", "code", "function", "source", "vulnerable_code", "before"])
        date = first_present(row, ["date", "commit_date", "published_date", "cve_published_date", "year"])
        target = first_present(row, ["target", "label", "vulnerable", "is_vulnerable"])
        if func is None or date is None or target is None:
            warnings.append(f"row {i}: missing required func/date/target field")
            continue
        try:
            year = parse_year(date)
            label = normalize_target(target)
        except ValueError as exc:
            warnings.append(f"row {i}: {exc}")
            continue
        project = str(first_present(row, ["project", "repo", "repository", "repository_url"], "unknown"))
        cwe = first_present(row, ["cwe", "cwe_id", "cwe_ids"], "unknown")
        if isinstance(cwe, list):
            cwe = cwe[0] if cwe else "unknown"
        idx = first_present(row, ["idx", "id", "sample_id"], None)
        if idx is None:
            idx = hashlib.sha1(f"{source}:{i}:{func[:100]}".encode("utf-8")).hexdigest()[:16]
        rows.append(
            {
                "idx": str(idx),
                "func": str(func),
                "target": label,
                "date": str(date),
                "year": year,
                "project": project,
                "cwe": str(cwe),
                "source_dataset": source,
            }
        )
    return rows, warnings


def canonical_code(code: str) -> str:
    return re.sub(r"\s+", " ", code.strip())


def deduplicate_rows(rows: list[dict]) -> tuple[list[dict], dict]:
    """Remove exact duplicate function texts before temporal splitting."""
    seen = {}
    kept = []
    duplicate_count = 0
    conflicting_label_count = 0
    cross_year_count = 0
    for row in sorted(rows, key=lambda r: (int(r["year"]), str(r["idx"]))):
        digest = hashlib.sha1(canonical_code(row["func"]).encode("utf-8")).hexdigest()
        prior = seen.get(digest)
        if prior is None:
            seen[digest] = row
            kept.append(row)
            continue
        duplicate_count += 1
        if int(prior["target"]) != int(row["target"]):
            conflicting_label_count += 1
        if int(prior["year"]) != int(row["year"]):
            cross_year_count += 1
    return kept, {
        "dedupe_mode": "exact_canonical_function",
        "duplicate_rows_removed": duplicate_count,
        "conflicting_label_duplicates": conflicting_label_count,
        "cross_year_duplicates_removed": cross_year_count,
    }


def tokenize(code: str) -> list[str]:
    return TOKEN_RE.findall(code.lower())


def stable_hash(text: str, buckets: int) -> int:
    digest = hashlib.blake2b(text.encode("utf-8"), digest_size=8).digest()
    return int.from_bytes(digest, "big") % buckets


def make_smoke_dataset(path: Path, seed: int = 7) -> list[dict]:
    rng = random.Random(seed)
    projects_by_period = {
        2012: ["openssl", "ffmpeg", "qemu"],
        2013: ["openssl", "ffmpeg", "qemu"],
        2014: ["openssl", "ffmpeg", "qemu", "imagemagick"],
        2015: ["openssl", "ffmpeg", "imagemagick"],
        2016: ["linux", "imagemagick", "php-src"],
        2017: ["linux", "php-src", "libxml2"],
        2018: ["linux", "libxml2", "curl"],
        2019: ["linux", "curl", "nginx"],
        2020: ["nginx", "curl", "systemd"],
        2021: ["systemd", "nginx", "sqlite"],
    }
    cwes_by_period = {
        2012: ["CWE-119", "CWE-120", "CWE-20"],
        2013: ["CWE-119", "CWE-120", "CWE-20"],
        2014: ["CWE-119", "CWE-125", "CWE-20"],
        2015: ["CWE-125", "CWE-787", "CWE-20"],
        2016: ["CWE-787", "CWE-416", "CWE-200"],
        2017: ["CWE-416", "CWE-200", "CWE-476"],
        2018: ["CWE-476", "CWE-401", "CWE-190"],
        2019: ["CWE-190", "CWE-79", "CWE-22"],
        2020: ["CWE-79", "CWE-22", "CWE-502"],
        2021: ["CWE-502", "CWE-918", "CWE-787"],
    }
    risky_by_period = {
        2012: ["strcpy", "sprintf", "gets"],
        2013: ["strcpy", "sprintf", "gets"],
        2014: ["memcpy", "strncpy", "sprintf"],
        2015: ["memcpy", "malloc", "free"],
        2016: ["free", "ptr", "memmove"],
        2017: ["ptr", "null", "recv"],
        2018: ["len", "size", "read"],
        2019: ["path", "open", "snprintf"],
        2020: ["deserialize", "xml", "escape"],
        2021: ["request", "proxy", "deserialize"],
    }
    rows = []
    for year in range(2012, 2022):
        for i in range(80):
            project = rng.choice(projects_by_period[year])
            cwe = rng.choice(cwes_by_period[year])
            vulnerable = int(rng.random() < (0.38 + 0.04 * ((year - 2012) % 3)))
            early_risk = rng.choice(["strcpy", "sprintf", "gets", "memcpy"])
            safe_sink = rng.choice(["snprintf", "memmove", "strncpy", "validate"])
            new_risk = rng.choice(["deserialize_blob", "proxy_route", "copy_from_user", "xml_expand", "path_join"])
            if year <= 2015:
                guard = "if (len < sizeof(buf))" if vulnerable == 0 else "if (len <= size)"
                sink = early_risk if vulnerable else safe_sink
            elif year <= 2017:
                guard = "if (ptr != NULL && len < sizeof(buf))" if vulnerable == 0 else "if (ptr != NULL)"
                sink = rng.choice(risky_by_period[year]) if vulnerable else rng.choice([safe_sink, early_risk])
            else:
                guard = "if (validate(src, len) && len < sizeof(buf))" if vulnerable == 0 else "if (feature_flag || len > 0)"
                sink = new_risk if vulnerable else rng.choice([early_risk, "memcpy", "strcpy", safe_sink])
            noise = " ".join(rng.choice(["int", "char", "size_t", "return", "status", "ctx"]) for _ in range(rng.randint(4, 18)))
            if year >= 2018:
                noise += " api_v2 feature_flag async checked_bounds validated_wrapper"
            if year >= 2020:
                noise += " cloud proxy json stream handler"
            func = (
                f"int f_{project.replace('-', '_')}_{year}_{i}(char *src, size_t len) {{ "
                f"char buf[128]; int status = 0; {guard} {{ {sink}(buf, src, len); }} "
                f"{noise}; return status; }}"
            )
            rows.append(
                {
                    "idx": f"smoke-{year}-{i}",
                    "func": func,
                    "target": vulnerable,
                    "date": f"{year}-06-01",
                    "year": year,
                    "project": project,
                    "cwe": cwe,
                    "source_dataset": "temporal_smoke",
                }
            )
    write_jsonl(path, rows)
    return rows


def classification_metrics(targets: list[int], preds: list[int], scores: list[float] | None = None) -> dict:
    tp = sum(1 for y, p in zip(targets, preds) if y == 1 and p == 1)
    fp = sum(1 for y, p in zip(targets, preds) if y == 0 and p == 1)
    tn = sum(1 for y, p in zip(targets, preds) if y == 0 and p == 0)
    fn = sum(1 for y, p in zip(targets, preds) if y == 1 and p == 0)
    precision = safe_div(tp, tp + fp)
    recall = safe_div(tp, tp + fn)
    specificity = safe_div(tn, tn + fp)
    f1 = safe_div(2 * precision * recall, precision + recall)
    mcc_den = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    return {
        "n": len(targets),
        "accuracy": safe_div(tp + tn, len(targets)),
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "mcc": safe_div(tp * tn - fp * fn, mcc_den),
        "false_negative_rate": safe_div(fn, tp + fn),
        "false_positive_rate": safe_div(fp, fp + tn),
        "specificity": specificity,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
    }


def validate_window(name: str, rows: list[dict], min_samples: int, min_pos: int, min_neg: int) -> list[str]:
    warnings = []
    positives = sum(int(r["target"]) for r in rows)
    negatives = len(rows) - positives
    if len(rows) < min_samples:
        warnings.append(f"{name}: only {len(rows)} samples < required {min_samples}")
    if positives < min_pos:
        warnings.append(f"{name}: only {positives} positives < required {min_pos}")
    if negatives < min_neg:
        warnings.append(f"{name}: only {negatives} negatives < required {min_neg}")
    return warnings


def build_windows(
    rows: list[dict],
    min_windows: int = 5,
    train_start: int | None = None,
    train_end: int | None = None,
    validation_year: int | None = None,
    test_start: int | None = None,
    test_end: int | None = None,
    min_train_samples: int = 1,
    min_eval_samples: int = 1,
    min_pos: int = 1,
    min_neg: int = 1,
) -> dict:
    by_year = defaultdict(list)
    for row in rows:
        by_year[int(row["year"])].append(row)
    years = sorted(by_year)
    if len(years) < min_windows:
        raise ValueError(f"need at least {min_windows} temporal windows; found {len(years)}")
    if train_start is not None or train_end is not None or validation_year is not None or test_start is not None:
        if train_start is None or train_end is None or validation_year is None:
            raise ValueError("--train-start, --train-end, and --validation-year must be supplied together")
        train_years = [year for year in years if train_start <= year <= train_end]
        if validation_year not in by_year:
            raise ValueError(f"validation year {validation_year} is not present in dataset")
        if test_start is None:
            test_start = validation_year + 1
        test_years = [year for year in years if year >= test_start and (test_end is None or year <= test_end)]
    else:
        if len(years) < 6:
            train_years = years[:2]
            validation_year = years[2]
            test_years = years[3:]
        else:
            train_years = years[:3]
            validation_year = years[3]
            test_years = years[4:]
    if not train_years:
        raise ValueError("no train years selected")
    if not test_years:
        raise ValueError("no test years selected")
    split_warnings = []
    split_warnings.extend(validate_window("train", rows_for_years({"by_year": by_year}, train_years), min_train_samples, min_pos, min_neg))
    split_warnings.extend(validate_window(f"validation_{validation_year}", by_year[validation_year], min_eval_samples, min_pos, min_neg))
    for year in test_years:
        split_warnings.extend(validate_window(f"test_{year}", by_year[year], min_eval_samples, min_pos, min_neg))
    return {
        "years": years,
        "train_years": train_years,
        "validation_year": validation_year,
        "test_years": test_years,
        "by_year": dict(by_year),
        "split_warnings": split_warnings,
    }


def summarize_window(rows: list[dict]) -> dict:
    lengths = [len(r["func"]) for r in rows]
    targets = [r["target"] for r in rows]
    projects = Counter(r["project"] for r in rows)
    cwes = Counter(r["cwe"] for r in rows)
    return {
        "samples": len(rows),
        "vulnerable": sum(targets),
        "non_vulnerable": len(targets) - sum(targets),
        "vulnerable_ratio": safe_div(sum(targets), len(targets)),
        "projects": len(projects),
        "top_projects": projects.most_common(5),
        "cwes": len(cwes),
        "top_cwes": cwes.most_common(5),
        "median_chars": statistics.median(lengths) if lengths else 0,
        "max_chars": max(lengths) if lengths else 0,
    }


class FeatureSpace:
    def __init__(self, name: str, extractor: Callable[[list[dict]], np.ndarray], vocab: list[str] | None = None):
        self.name = name
        self.extractor = extractor
        self.vocab = vocab or []

    def transform(self, rows: list[dict]) -> np.ndarray:
        return self.extractor(rows)


def fit_token_space(rows: list[dict], max_features: int = 800) -> FeatureSpace:
    counts = Counter()
    for row in rows:
        counts.update(tokenize(row["func"]))
    vocab = [token for token, count in counts.most_common(max_features) if count >= 2]
    index = {token: i for i, token in enumerate(vocab)}

    def extract(batch: list[dict]) -> np.ndarray:
        x = np.zeros((len(batch), len(vocab)), dtype=np.float64)
        for r, row in enumerate(batch):
            toks = tokenize(row["func"])
            if not toks:
                continue
            local = Counter(toks)
            for token, count in local.items():
                if token in index:
                    x[r, index[token]] = 1.0 + math.log(count)
            x[r, :] /= math.sqrt(len(toks))
        return x

    return FeatureSpace("token_tfidf_logreg", extract, vocab)


def fit_char_space(rows: list[dict], buckets: int = 512) -> FeatureSpace:
    def extract(batch: list[dict]) -> np.ndarray:
        x = np.zeros((len(batch), buckets), dtype=np.float64)
        for r, row in enumerate(batch):
            text = re.sub(r"\s+", " ", row["func"].lower())
            grams = [text[i : i + 4] for i in range(max(0, len(text) - 3))]
            if not grams:
                continue
            for gram, count in Counter(grams).items():
                x[r, stable_hash(gram, buckets)] += 1.0 + math.log(count)
            x[r, :] /= math.sqrt(len(grams))
        return x

    return FeatureSpace("char4_hash_logreg", extract)


def fit_metric_space(rows: list[dict]) -> FeatureSpace:
    def extract(batch: list[dict]) -> np.ndarray:
        x = np.zeros((len(batch), 10 + len(SECURITY_TOKENS)), dtype=np.float64)
        for r, row in enumerate(batch):
            code = row["func"].lower()
            toks = tokenize(code)
            length = max(1, len(code))
            x[r, 0] = math.log1p(len(code))
            x[r, 1] = math.log1p(len(toks))
            x[r, 2] = code.count("if")
            x[r, 3] = code.count("for") + code.count("while")
            x[r, 4] = code.count("*")
            x[r, 5] = code.count("[")
            x[r, 6] = code.count("malloc")
            x[r, 7] = code.count("free")
            x[r, 8] = code.count("return")
            x[r, 9] = safe_div(code.count(";"), length)
            for i, token in enumerate(SECURITY_TOKENS, start=10):
                x[r, i] = code.count(token)
        return x

    return FeatureSpace("code_metrics_logreg", extract)


def fit_frozen_embedding_space(rows: list[dict], dims: int = 192) -> FeatureSpace:
    """Frozen random-indexing code embedding.

    This is a dependency-light stand-in for frozen neural code embeddings: token
    and character n-gram features are projected through a deterministic signed
    hash into a fixed embedding space, and only the logistic head is trained.
    """

    def add_feature(vec: np.ndarray, feature: str, value: float) -> None:
        digest = hashlib.blake2b(feature.encode("utf-8"), digest_size=16).digest()
        idx = int.from_bytes(digest[:8], "big") % dims
        sign = 1.0 if digest[8] & 1 else -1.0
        vec[idx] += sign * value

    def extract(batch: list[dict]) -> np.ndarray:
        x = np.zeros((len(batch), dims), dtype=np.float64)
        for r, row in enumerate(batch):
            code = re.sub(r"\s+", " ", row["func"].lower())
            toks = tokenize(code)
            for token, count in Counter(toks).items():
                add_feature(x[r], f"tok:{token}", 1.0 + math.log(count))
            grams = [code[i : i + 5] for i in range(max(0, len(code) - 4))]
            for gram, count in Counter(grams).items():
                add_feature(x[r], f"c5:{gram}", 0.35 * (1.0 + math.log(count)))
            norm = np.linalg.norm(x[r])
            if norm > 0:
                x[r] /= norm
        return x

    return FeatureSpace("frozen_hash_embedding_logreg", extract)


def fit_space_like(name: str, rows: list[dict]) -> FeatureSpace:
    if name == "token_tfidf_logreg":
        return fit_token_space(rows)
    if name == "char4_hash_logreg":
        return fit_char_space(rows)
    if name == "code_metrics_logreg":
        return fit_metric_space(rows)
    if name == "frozen_hash_embedding_logreg":
        return fit_frozen_embedding_space(rows)
    raise ValueError(f"unknown feature space {name!r}")


@dataclass
class LinearModel:
    weights: np.ndarray
    mean: np.ndarray
    std: np.ndarray
    threshold: float


def sigmoid(z: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-np.clip(z, -40, 40)))


def standardize_fit(x: np.ndarray) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    mean = x.mean(axis=0)
    std = x.std(axis=0)
    std[std < 1e-8] = 1.0
    return (x - mean) / std, mean, std


def standardize_apply(x: np.ndarray, mean: np.ndarray, std: np.ndarray) -> np.ndarray:
    return (x - mean) / std


def train_logreg(x: np.ndarray, y: np.ndarray, epochs: int = 240, lr: float = 0.18, l2: float = 1e-3) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    x, mean, std = standardize_fit(x)
    xb = np.concatenate([np.ones((x.shape[0], 1)), x], axis=1)
    w = np.zeros(xb.shape[1], dtype=np.float64)
    pos_weight = safe_div(len(y), 2 * max(1, int(y.sum())))
    neg_weight = safe_div(len(y), 2 * max(1, int((1 - y).sum())))
    weights = np.where(y == 1, pos_weight, neg_weight)
    for _ in range(epochs):
        p = sigmoid(xb @ w)
        grad = (xb.T @ ((p - y) * weights)) / len(y)
        grad[1:] += l2 * w[1:]
        w -= lr * grad
    return w, mean, std


def predict_scores(model: LinearModel, x: np.ndarray) -> np.ndarray:
    xs = standardize_apply(x, model.mean, model.std)
    xb = np.concatenate([np.ones((xs.shape[0], 1)), xs], axis=1)
    return sigmoid(xb @ model.weights)


def choose_threshold(scores: np.ndarray, y: np.ndarray) -> float:
    best_threshold = 0.5
    best_f1 = -1.0
    for threshold in np.linspace(0.1, 0.9, 81):
        preds = (scores >= threshold).astype(int)
        f1 = classification_metrics(y.tolist(), preds.tolist())["f1"]
        if f1 > best_f1:
            best_f1 = f1
            best_threshold = float(threshold)
    return best_threshold


def fit_model(space: FeatureSpace, train_rows: list[dict], validation_rows: list[dict]) -> LinearModel:
    x_train = space.transform(train_rows)
    y_train = np.array([r["target"] for r in train_rows], dtype=np.float64)
    w, mean, std = train_logreg(x_train, y_train)
    provisional = LinearModel(w, mean, std, 0.5)
    val_scores = predict_scores(provisional, space.transform(validation_rows))
    y_val = np.array([r["target"] for r in validation_rows], dtype=np.float64)
    threshold = choose_threshold(val_scores, y_val)
    return LinearModel(w, mean, std, threshold)


def evaluate_model(space: FeatureSpace, model: LinearModel, rows: list[dict]) -> tuple[dict, list[dict]]:
    scores = predict_scores(model, space.transform(rows))
    preds = (scores >= model.threshold).astype(int)
    targets = [r["target"] for r in rows]
    metrics = classification_metrics(targets, preds.tolist(), scores.tolist())
    pred_rows = []
    for row, score, pred in zip(rows, scores, preds):
        pred_rows.append(
            {
                "idx": row["idx"],
                "year": row["year"],
                "target": row["target"],
                "score": float(score),
                "pred": int(pred),
            }
        )
    return metrics, pred_rows


def js_divergence(a: Counter, b: Counter) -> float:
    keys = set(a) | set(b)
    total_a = sum(a.values())
    total_b = sum(b.values())
    if not total_a or not total_b:
        return 0.0
    pa = np.array([a[k] / total_a for k in keys], dtype=np.float64)
    pb = np.array([b[k] / total_b for k in keys], dtype=np.float64)
    m = 0.5 * (pa + pb)

    def kl(p: np.ndarray, q: np.ndarray) -> float:
        mask = p > 0
        return float(np.sum(p[mask] * np.log2(p[mask] / q[mask])))

    return 0.5 * kl(pa, m) + 0.5 * kl(pb, m)


def token_counter(rows: list[dict]) -> Counter:
    counts = Counter()
    for row in rows:
        counts.update(tokenize(row["func"]))
    return counts


def compute_drift(train_rows: list[dict], test_rows: list[dict], year: int) -> dict:
    train_projects = Counter(r["project"] for r in train_rows)
    test_projects = Counter(r["project"] for r in test_rows)
    train_cwes = Counter(r["cwe"] for r in train_rows)
    test_cwes = Counter(r["cwe"] for r in test_rows)
    train_tokens = token_counter(train_rows)
    test_tokens = token_counter(test_rows)
    train_vocab = set(train_tokens)
    test_vocab = set(test_tokens)
    train_len = [len(r["func"]) for r in train_rows]
    test_len = [len(r["func"]) for r in test_rows]
    return {
        "year": year,
        "project_jsd": js_divergence(train_projects, test_projects),
        "cwe_jsd": js_divergence(train_cwes, test_cwes),
        "token_jsd": js_divergence(train_tokens, test_tokens),
        "project_turnover": 1.0 - safe_div(len(set(train_projects) & set(test_projects)), len(set(test_projects))),
        "cwe_turnover": 1.0 - safe_div(len(set(train_cwes) & set(test_cwes)), len(set(test_cwes))),
        "unseen_token_rate": safe_div(len(test_vocab - train_vocab), len(test_vocab)),
        "vocab_churn": safe_div(len(train_vocab ^ test_vocab), len(train_vocab | test_vocab)),
        "median_length_shift": safe_div(statistics.median(test_len) - statistics.median(train_len), statistics.median(train_len)),
        "vulnerable_ratio_shift": safe_div(sum(r["target"] for r in test_rows), len(test_rows))
        - safe_div(sum(r["target"] for r in train_rows), len(train_rows)),
    }


def pearson(xs: list[float], ys: list[float]) -> float:
    if len(xs) < 2 or len(ys) < 2:
        return 0.0
    mean_x = statistics.mean(xs)
    mean_y = statistics.mean(ys)
    num = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys))
    den_x = math.sqrt(sum((x - mean_x) ** 2 for x in xs))
    den_y = math.sqrt(sum((y - mean_y) ** 2 for y in ys))
    return safe_div(num, den_x * den_y)


def bootstrap_ci(values: list[float], rng: random.Random, iterations: int = 500) -> tuple[float, float]:
    if not values:
        return (0.0, 0.0)
    samples = []
    for _ in range(iterations):
        draw = [rng.choice(values) for _ in values]
        samples.append(statistics.mean(draw))
    samples.sort()
    lo = samples[int(0.025 * len(samples))]
    hi = samples[int(0.975 * len(samples))]
    return (lo, hi)


def rows_for_years(windows: dict, years: Iterable[int]) -> list[dict]:
    out = []
    for year in years:
        out.extend(windows["by_year"][year])
    return out


def run_fixed_origin(windows: dict, output_dir: Path) -> tuple[list[dict], dict, dict]:
    train_rows = rows_for_years(windows, windows["train_years"])
    val_rows = windows["by_year"][windows["validation_year"]]
    spaces = [
        fit_token_space(train_rows),
        fit_char_space(train_rows),
        fit_metric_space(train_rows),
        fit_frozen_embedding_space(train_rows),
    ]
    all_metrics = []
    all_predictions = {}
    fitted = {}
    for space in spaces:
        model = fit_model(space, train_rows, val_rows)
        fitted[space.name] = (space, model)
        val_metrics, _ = evaluate_model(space, model, val_rows)
        all_metrics.append({"phase": "validation", "model": space.name, "year": windows["validation_year"], **val_metrics})
        for year in windows["test_years"]:
            metrics, pred_rows = evaluate_model(space, model, windows["by_year"][year])
            all_metrics.append({"phase": "fixed_origin_test", "model": space.name, "year": year, **metrics})
            all_predictions[(space.name, year)] = pred_rows
        write_jsonl(
            output_dir / "predictions" / f"fixed_origin_{space.name}.jsonl",
            [
                {"model": space.name, **row}
                for year in windows["test_years"]
                for row in all_predictions[(space.name, year)]
            ],
        )
    return all_metrics, all_predictions, fitted


def run_maintenance_policies(windows: dict, fixed_space: FeatureSpace, fixed_model: LinearModel) -> list[dict]:
    years = windows["years"]
    test_years = windows["test_years"]
    results = []
    for year in test_years:
        year_index = years.index(year)
        if year_index < 2:
            continue
        test_rows = windows["by_year"][year]
        validation_rows = windows["by_year"][years[year_index - 1]]

        policy_specs = []
        policy_specs.append(("P0_no_refresh", None, None, 0, fixed_space, fixed_model))

        cumulative_train_years = years[: year_index - 1]
        if cumulative_train_years:
            train_rows = rows_for_years(windows, cumulative_train_years)
            space = fit_space_like(fixed_space.name, train_rows)
            model = fit_model(space, train_rows, validation_rows)
            policy_specs.append(("P1_cumulative_retrain", cumulative_train_years, years[year_index - 1], len(validation_rows), space, model))

        sliding_train_years = years[max(0, year_index - 4) : year_index - 1]
        if sliding_train_years:
            train_rows = rows_for_years(windows, sliding_train_years)
            space = fit_space_like(fixed_space.name, train_rows)
            model = fit_model(space, train_rows, validation_rows)
            policy_specs.append(("P2_sliding_3yr_retrain", sliding_train_years, years[year_index - 1], len(validation_rows), space, model))

        val_scores = predict_scores(fixed_model, fixed_space.transform(validation_rows))
        threshold = choose_threshold(val_scores, np.array([r["target"] for r in validation_rows], dtype=np.float64))
        calibrated = LinearModel(fixed_model.weights, fixed_model.mean, fixed_model.std, threshold)
        policy_specs.append(("P3_calibration_only", None, years[year_index - 1], len(validation_rows), fixed_space, calibrated))

        recent = validation_rows[:]
        pos = [r for r in recent if r["target"] == 1][:20]
        neg = [r for r in recent if r["target"] == 0][:20]
        train_rows = rows_for_years(windows, windows["train_years"]) + pos + neg
        space = fit_space_like(fixed_space.name, train_rows)
        model = fit_model(space, train_rows, validation_rows)
        policy_specs.append(
            (
                "P4_small_recent_update",
                windows["train_years"] + [years[year_index - 1]],
                years[year_index - 1],
                len(pos) + len(neg),
                space,
                model,
            )
        )

        for policy, train_years, validation_year, labeled_samples_used, space, model in policy_specs:
            metrics, _ = evaluate_model(space, model, test_rows)
            results.append(
                {
                    "policy": policy,
                    "test_year": year,
                    "train_years": "fixed" if train_years is None else "|".join(map(str, train_years)),
                    "validation_year": "fixed" if validation_year is None else validation_year,
                    "labeled_samples_used": labeled_samples_used,
                    **metrics,
                }
            )
    return results


def evaluate_triggers(
    drift_rows: list[dict],
    aging_rows: list[dict],
    model_name: str,
    recall_floor: float = 0.70,
    recall_drop: float = 0.10,
) -> list[dict]:
    model_rows = [r for r in aging_rows if r["model"] == model_name and r["phase"] == "fixed_origin_test"]
    by_year = {r["year"]: r for r in model_rows}
    if not model_rows:
        return []
    baseline_recall = model_rows[0]["recall"]
    event_by_year = {
        r["year"]: int(r["recall"] < recall_floor or (baseline_recall - r["recall"]) >= recall_drop)
        for r in model_rows
    }
    trigger_rows = []
    signals = [k for k in drift_rows[0] if k != "year"] if drift_rows else []
    for signal in signals:
        values = [r[signal] for r in drift_rows if r["year"] in by_year]
        if not values:
            continue
        threshold = statistics.median(values)
        tp = fp = tn = fn = 0
        for row in drift_rows:
            if row["year"] not in by_year:
                continue
            trigger = int(row[signal] >= threshold)
            event = event_by_year[row["year"]]
            if trigger and event:
                tp += 1
            elif trigger and not event:
                fp += 1
            elif not trigger and event:
                fn += 1
            else:
                tn += 1
        trigger_rows.append(
            {
                "signal": signal,
                "threshold": threshold,
                "event_definition": f"recall<{recall_floor:.3f} or drop>={recall_drop:.3f}",
                "precision": safe_div(tp, tp + fp),
                "recall": safe_div(tp, tp + fn),
                "false_alarm_rate": safe_div(fp, fp + tn),
                "tp": tp,
                "fp": fp,
                "tn": tn,
                "fn": fn,
            }
        )
    return sorted(trigger_rows, key=lambda r: (r["recall"], r["precision"]), reverse=True)


def conduct(args: argparse.Namespace) -> dict:
    rng = random.Random(args.seed)
    output_dir = args.output_dir
    artifact_dir = output_dir / "artifacts"
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.input:
        raw_rows = read_jsonl(args.input)
        rows, warnings = normalize_rows(raw_rows, args.source_name)
        input_mode = "external"
    else:
        smoke_path = Path("data/raw/temporal_smoke.jsonl")
        rows = make_smoke_dataset(smoke_path, args.seed)
        warnings = []
        input_mode = "temporal_smoke"

    if not rows:
        raise ValueError("no valid temporal rows available")
    if args.max_func_chars:
        truncated = 0
        for row in rows:
            if len(row["func"]) > args.max_func_chars:
                row["func"] = row["func"][: args.max_func_chars]
                truncated += 1
    else:
        truncated = 0
    dedupe_summary = {
        "dedupe_mode": "none",
        "duplicate_rows_removed": 0,
        "conflicting_label_duplicates": 0,
        "cross_year_duplicates_removed": 0,
    }
    if args.dedupe:
        rows, dedupe_summary = deduplicate_rows(rows)
    windows = build_windows(
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
    normalized_path = artifact_dir / "normalized_temporal_dataset.jsonl"
    write_jsonl(normalized_path, rows)

    summary_by_year = {str(year): summarize_window(windows["by_year"][year]) for year in windows["years"]}
    feasibility = {
        "input_mode": input_mode,
        "valid_rows": len(rows),
        "max_func_chars": args.max_func_chars,
        "truncated_functions": truncated,
        "invalid_or_skipped_rows": len(warnings),
        "warnings_preview": warnings[:20],
        **dedupe_summary,
        "years": windows["years"],
        "train_years": windows["train_years"],
        "validation_year": windows["validation_year"],
        "test_years": windows["test_years"],
        "split_warnings": windows["split_warnings"],
        "go": not windows["split_warnings"]
        and len(windows["years"]) >= 5
        and all(sum(r["target"] for r in windows["by_year"][y]) > 0 for y in windows["test_years"]),
        "year_summary": summary_by_year,
    }
    write_json(output_dir / "phase_1_feasibility.json", feasibility)

    split_dir = artifact_dir / "splits"
    write_jsonl(split_dir / "fixed_origin_train.jsonl", rows_for_years(windows, windows["train_years"]))
    write_jsonl(split_dir / "fixed_origin_validation.jsonl", windows["by_year"][windows["validation_year"]])
    for year in windows["test_years"]:
        write_jsonl(split_dir / f"fixed_origin_test_{year}.jsonl", windows["by_year"][year])
    split_manifest = {
        "fixed_origin": {
            "train_years": windows["train_years"],
            "validation_year": windows["validation_year"],
            "test_years": windows["test_years"],
        },
        "rolling_origin": [
            {
                "test_year": year,
                "train_years": windows["years"][: max(1, windows["years"].index(year) - 1)],
                "validation_year": windows["years"][windows["years"].index(year) - 1],
            }
            for year in windows["test_years"]
        ],
    }
    write_json(output_dir / "phase_2_temporal_splits.json", split_manifest)

    aging_rows, predictions, fitted = run_fixed_origin(windows, artifact_dir)
    write_csv(output_dir / "phase_3_4_fixed_origin_aging_metrics.csv", aging_rows)
    write_json(output_dir / "phase_3_model_config.json", {"models": sorted({r["model"] for r in aging_rows})})

    train_rows = rows_for_years(windows, windows["train_years"])
    drift_rows = [compute_drift(train_rows, windows["by_year"][year], year) for year in windows["test_years"]]
    write_csv(output_dir / "phase_5_drift_metrics.csv", drift_rows)

    available_models = sorted({r["model"] for r in aging_rows})
    primary_model = args.primary_model if args.primary_model in available_models else choose_primary_aging_model(aging_rows)
    primary_rows = [r for r in aging_rows if r["model"] == primary_model and r["phase"] == "fixed_origin_test"]
    first_recall = primary_rows[0]["recall"] if primary_rows else 0.0
    drift_explanations = []
    for key in drift_rows[0].keys():
        if key == "year":
            continue
        xs = [r[key] for r in drift_rows]
        drop_by_year = {r["year"]: first_recall - r["recall"] for r in primary_rows}
        ys = [drop_by_year.get(r["year"], 0.0) for r in drift_rows]
        drift_explanations.append({"signal": key, "pearson_with_recall_drop": pearson(xs, ys)})
    drift_explanations.sort(key=lambda r: abs(r["pearson_with_recall_drop"]), reverse=True)
    write_csv(output_dir / "phase_5_drift_source_ranking.csv", drift_explanations)

    fixed_space, fixed_model = fitted[primary_model]
    maintenance_rows = run_maintenance_policies(windows, fixed_space, fixed_model)
    write_csv(output_dir / "phase_6_maintenance_policy_metrics.csv", maintenance_rows)

    policy_summary = []
    for policy in sorted({r["policy"] for r in maintenance_rows}):
        rows_for_policy = [r for r in maintenance_rows if r["policy"] == policy]
        recalls = [r["recall"] for r in rows_for_policy]
        f1s = [r["f1"] for r in rows_for_policy]
        lo, hi = bootstrap_ci(recalls, rng)
        policy_summary.append(
            {
                "policy": policy,
                "mean_recall": statistics.mean(recalls),
                "mean_f1": statistics.mean(f1s),
                "recall_ci_low": lo,
                "recall_ci_high": hi,
                "mean_labeled_samples_used": statistics.mean([r["labeled_samples_used"] for r in rows_for_policy]),
            }
        )
    write_csv(output_dir / "phase_6_maintenance_policy_summary.csv", policy_summary)

    trigger_rows = evaluate_triggers(
        drift_rows,
        aging_rows,
        primary_model,
        recall_floor=args.trigger_recall_floor,
        recall_drop=args.trigger_recall_drop,
    )
    write_csv(output_dir / "phase_7_monitoring_triggers.csv", trigger_rows)

    sensitivity = []
    for model in sorted({r["model"] for r in aging_rows}):
        model_rows = [r for r in aging_rows if r["model"] == model and r["phase"] == "fixed_origin_test"]
        if not model_rows:
            continue
        recalls = [r["recall"] for r in model_rows]
        f1s = [r["f1"] for r in model_rows]
        sensitivity.append(
            {
                "model": model,
                "first_test_recall": recalls[0],
                "last_test_recall": recalls[-1],
                "absolute_recall_decay": recalls[0] - recalls[-1],
                "worst_recall": min(recalls),
                "mean_recall": statistics.mean(recalls),
                "first_test_f1": f1s[0],
                "last_test_f1": f1s[-1],
                "absolute_f1_decay": f1s[0] - f1s[-1],
                "worst_f1": min(f1s),
                "mean_f1": statistics.mean(f1s),
            }
        )
    write_csv(output_dir / "phase_8_statistical_summary.csv", sensitivity)

    report_path = Path("docs") / f"{output_dir.name}_phase_1_9_report.md"
    write_phase_report(report_path, feasibility, aging_rows, drift_explanations, policy_summary, trigger_rows, sensitivity, output_dir, primary_model)
    return {
        "report": str(report_path),
        "output_dir": str(output_dir),
        "feasibility": feasibility,
        "models": sorted({r["model"] for r in aging_rows}),
    }


def markdown_table(rows: list[dict], columns: list[str], limit: int | None = None) -> str:
    if limit is not None:
        rows = rows[:limit]
    if not rows:
        return "_No rows._"
    out = []
    out.append("| " + " | ".join(columns) + " |")
    out.append("|" + "|".join(["---"] * len(columns)) + "|")
    for row in rows:
        cells = []
        for col in columns:
            val = row.get(col, "")
            if isinstance(val, float):
                val = f"{val:.3f}"
            cells.append(str(val))
        out.append("| " + " | ".join(cells) + " |")
    return "\n".join(out)


def choose_primary_aging_model(aging_rows: list[dict]) -> str:
    candidates = []
    for model in sorted({r["model"] for r in aging_rows}):
        model_rows = [r for r in aging_rows if r["model"] == model and r["phase"] == "fixed_origin_test"]
        if not model_rows:
            continue
        decay = model_rows[0]["recall"] - model_rows[-1]["recall"]
        worst_decay = model_rows[0]["recall"] - min(r["recall"] for r in model_rows)
        candidates.append((max(decay, worst_decay), model))
    candidates.sort(reverse=True)
    return candidates[0][1] if candidates else "token_tfidf_logreg"


def write_phase_report(
    path: Path,
    feasibility: dict,
    aging_rows: list[dict],
    drift_explanations: list[dict],
    policy_summary: list[dict],
    trigger_rows: list[dict],
    sensitivity: list[dict],
    output_dir: Path,
    primary_model: str,
) -> None:
    phase4_rows = [
        {
            "model": r["model"],
            "year": r["year"],
            "precision": r["precision"],
            "recall": r["recall"],
            "f1": r["f1"],
            "mcc": r["mcc"],
            "fnr": r["false_negative_rate"],
        }
        for r in aging_rows
        if r["phase"] == "fixed_origin_test"
    ]
    text = f"""# Detector Aging Phase 1-9 Report

## Scope

This report conducts the nine-phase detector-aging workflow for the currently
available local input.

Input mode: `{feasibility['input_mode']}`.

If the input mode is `temporal_smoke`, the results verify the pipeline and
analysis design only. They must not be reported as empirical evidence about
real vulnerability detectors.

## Phase 1: Dataset Feasibility

- Valid rows: {feasibility['valid_rows']}
- Skipped rows: {feasibility['invalid_or_skipped_rows']}
- Deduplication: {feasibility['dedupe_mode']}; removed {feasibility['duplicate_rows_removed']} duplicates
- Years: {', '.join(map(str, feasibility['years']))}
- Go decision: `{feasibility['go']}`
- Split warnings: {len(feasibility['split_warnings'])}

## Phase 2: Temporal Splits

- Fixed-origin train years: {', '.join(map(str, feasibility['train_years']))}
- Validation year: {feasibility['validation_year']}
- Future test years: {', '.join(map(str, feasibility['test_years']))}

Split manifests and JSONL files are written under `{output_dir}`.

## Phase 3: Baseline Models

The local low-compute run uses three dependency-light baselines:

- `token_tfidf_logreg`
- `char4_hash_logreg`
- `code_metrics_logreg`

These are placeholders for the paper's detector families. Real experiments
should add frozen code-model embeddings and a CodeBERT/LineVul-style detector.

## Phase 4: Aging Curves

{markdown_table(phase4_rows, ['model', 'year', 'precision', 'recall', 'f1', 'mcc', 'fnr'], limit=24)}

## Phase 5: Drift Source Analysis

Signals ranked by absolute correlation with recall drop for the primary aging
baseline, `{primary_model}`:

{markdown_table(drift_explanations, ['signal', 'pearson_with_recall_drop'], limit=10)}

## Phase 6: Maintenance Policy Evaluation

{markdown_table(policy_summary, ['policy', 'mean_recall', 'mean_f1', 'recall_ci_low', 'recall_ci_high', 'mean_labeled_samples_used'])}

## Phase 7: Monitoring Triggers

{markdown_table(trigger_rows, ['signal', 'threshold', 'event_definition', 'precision', 'recall', 'false_alarm_rate'], limit=10)}

## Phase 8: Statistical Summary

{markdown_table(sensitivity, ['model', 'first_test_recall', 'last_test_recall', 'absolute_recall_decay', 'worst_recall', 'mean_recall', 'absolute_f1_decay'])}

## Phase 9: Paper Assembly Notes

The current artifacts are enough to assemble empirical tables and figures for
the selected temporal input. For an IST submission, treat CVEfixes as the
primary date-bearing evidence, and treat DiverseVul as sensitivity evidence
unless commit dates are enriched from repository history.

Required before claiming empirical findings:

- use pre-registered temporal cutoffs with enough samples per window,
- add a frozen code embedding detector,
- add a transformer vulnerability detector,
- repeat near-duplicate and leakage checks,
- turn CSV tables into final manuscript tables/figures.

## Artifact Index

- `{output_dir / 'phase_1_feasibility.json'}`
- `{output_dir / 'phase_2_temporal_splits.json'}`
- `{output_dir / 'phase_3_4_fixed_origin_aging_metrics.csv'}`
- `{output_dir / 'phase_5_drift_metrics.csv'}`
- `{output_dir / 'phase_5_drift_source_ranking.csv'}`
- `{output_dir / 'phase_6_maintenance_policy_summary.csv'}`
- `{output_dir / 'phase_7_monitoring_triggers.csv'}`
- `{output_dir / 'phase_8_statistical_summary.csv'}`
"""
    path.write_text(text, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, help="Temporal JSONL dataset. If omitted, a smoke dataset is generated.")
    parser.add_argument("--source-name", default="external_temporal_dataset")
    parser.add_argument("--output-dir", type=Path, default=Path("results/detector_aging"))
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--max-func-chars", type=int, help="Truncate function text for detector input and artifacts.")
    parser.add_argument("--dedupe", action="store_true", help="Remove exact duplicate canonical function texts before splitting.")
    parser.add_argument("--train-start", type=int, help="First fixed-origin train year.")
    parser.add_argument("--train-end", type=int, help="Last fixed-origin train year.")
    parser.add_argument("--validation-year", type=int, help="Fixed-origin validation year.")
    parser.add_argument("--test-start", type=int, help="First future test year.")
    parser.add_argument("--test-end", type=int, help="Last future test year.")
    parser.add_argument("--min-train-samples", type=int, default=1)
    parser.add_argument("--min-eval-samples", type=int, default=1)
    parser.add_argument("--min-pos", type=int, default=1)
    parser.add_argument("--min-neg", type=int, default=1)
    parser.add_argument("--primary-model", default="char4_hash_logreg")
    parser.add_argument("--trigger-recall-floor", type=float, default=0.70)
    parser.add_argument("--trigger-recall-drop", type=float, default=0.10)
    args = parser.parse_args()
    result = conduct(args)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
