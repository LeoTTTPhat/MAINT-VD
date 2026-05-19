#!/usr/bin/env python3
"""Run neural temporal baselines for the detector-aging study.

Baselines:
- frozen CodeBERT embeddings + logistic head trained on temporal train split
- pretrained LineVul sequence classifier calibrated on validation year

The script samples each temporal window to keep local CPU/MPS runs tractable.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
import random
import sys

import numpy as np
import torch
from transformers import AutoModel, AutoModelForSequenceClassification, AutoTokenizer

sys.path.insert(0, str(Path(__file__).resolve().parent))
import conduct_detector_aging as aging  # noqa: E402


def write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    columns = list(rows[0].keys())
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)


def sample_rows(rows: list[dict], limit: int, seed: int) -> list[dict]:
    if not limit or len(rows) <= limit:
        return rows
    rng = random.Random(seed)
    pos = [r for r in rows if int(r["target"]) == 1]
    neg = [r for r in rows if int(r["target"]) == 0]
    half = limit // 2
    selected = []
    if pos:
        selected.extend(rng.sample(pos, min(len(pos), half)))
    remaining = limit - len(selected)
    if neg and remaining > 0:
        selected.extend(rng.sample(neg, min(len(neg), remaining)))
    if len(selected) < limit:
        already = {r["idx"] for r in selected}
        rest = [r for r in rows if r["idx"] not in already]
        selected.extend(rng.sample(rest, min(len(rest), limit - len(selected))))
    selected.sort(key=lambda r: (int(r["year"]), str(r["idx"])))
    return selected


def choose_threshold(scores: np.ndarray, y: np.ndarray) -> float:
    best_threshold = 0.5
    best_f1 = -1.0
    for threshold in np.linspace(0.05, 0.95, 91):
        preds = (scores >= threshold).astype(int)
        f1 = aging.classification_metrics(y.astype(int).tolist(), preds.tolist())["f1"]
        if f1 > best_f1:
            best_f1 = f1
            best_threshold = float(threshold)
    return best_threshold


def train_logreg(x: np.ndarray, y: np.ndarray, epochs: int = 320, lr: float = 0.15, l2: float = 1e-3):
    x, mean, std = aging.standardize_fit(x)
    xb = np.concatenate([np.ones((x.shape[0], 1)), x], axis=1)
    w = np.zeros(xb.shape[1], dtype=np.float64)
    pos_weight = aging.safe_div(len(y), 2 * max(1, int(y.sum())))
    neg_weight = aging.safe_div(len(y), 2 * max(1, int((1 - y).sum())))
    weights = np.where(y == 1, pos_weight, neg_weight)
    for _ in range(epochs):
        p = 1.0 / (1.0 + np.exp(-np.clip(xb @ w, -40, 40)))
        grad = (xb.T @ ((p - y) * weights)) / len(y)
        grad[1:] += l2 * w[1:]
        w -= lr * grad
    return w, mean, std


def logreg_scores(x: np.ndarray, w: np.ndarray, mean: np.ndarray, std: np.ndarray) -> np.ndarray:
    xs = aging.standardize_apply(x, mean, std)
    xb = np.concatenate([np.ones((xs.shape[0], 1)), xs], axis=1)
    return 1.0 / (1.0 + np.exp(-np.clip(xb @ w, -40, 40)))


def encode_texts(tokenizer, texts: list[str], max_length: int, device: str):
    encoded = tokenizer(
        texts,
        padding=True,
        truncation=True,
        max_length=max_length,
        return_tensors="pt",
    )
    return {key: value.to(device) for key, value in encoded.items()}


def codebert_embeddings(rows: list[dict], model_id: str, batch_size: int, max_length: int, device: str) -> np.ndarray:
    tokenizer = AutoTokenizer.from_pretrained(model_id)
    model = AutoModel.from_pretrained(model_id).to(device)
    model.eval()
    vectors = []
    with torch.no_grad():
        for start in range(0, len(rows), batch_size):
            batch = rows[start : start + batch_size]
            encoded = encode_texts(tokenizer, [r["func"] for r in batch], max_length, device)
            out = model(**encoded)
            hidden = out.last_hidden_state
            mask = encoded["attention_mask"].unsqueeze(-1)
            pooled = (hidden * mask).sum(dim=1) / mask.sum(dim=1).clamp(min=1)
            vectors.append(pooled.detach().cpu().numpy())
            print(f"{model_id}: embedded {min(start + len(batch), len(rows))}/{len(rows)}", flush=True)
    return np.concatenate(vectors, axis=0)


def linevul_scores(rows: list[dict], model_id: str, batch_size: int, max_length: int, device: str) -> np.ndarray:
    tokenizer = AutoTokenizer.from_pretrained(model_id, trust_remote_code=True)
    model = AutoModelForSequenceClassification.from_pretrained(model_id, trust_remote_code=True).to(device)
    model.eval()
    scores = []
    with torch.no_grad():
        for start in range(0, len(rows), batch_size):
            batch = rows[start : start + batch_size]
            encoded = encode_texts(tokenizer, [r["func"] for r in batch], max_length, device)
            logits = model(**encoded).logits
            if logits.shape[-1] == 1:
                probs = torch.sigmoid(logits[:, 0])
            else:
                probs = torch.softmax(logits, dim=-1)[:, min(1, logits.shape[-1] - 1)]
            scores.extend(probs.detach().cpu().numpy().tolist())
            print(f"{model_id}: scored {min(start + len(batch), len(rows))}/{len(rows)}", flush=True)
    return np.array(scores, dtype=np.float64)


def metrics_by_year(rows: list[dict], scores: np.ndarray, threshold: float, model_name: str, sample_note: str) -> list[dict]:
    out = []
    years = sorted({int(r["year"]) for r in rows})
    for year in years:
        idxs = [i for i, r in enumerate(rows) if int(r["year"]) == year]
        targets = [int(rows[i]["target"]) for i in idxs]
        year_scores = scores[idxs]
        preds = (year_scores >= threshold).astype(int).tolist()
        out.append(
            {
                "model": model_name,
                "phase": "neural_test",
                "year": year,
                "threshold": threshold,
                "sample_note": sample_note,
                **aging.classification_metrics(targets, preds, year_scores.tolist()),
            }
        )
    return out


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--source-name", default="temporal_dataset")
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--train-start", type=int, required=True)
    parser.add_argument("--train-end", type=int, required=True)
    parser.add_argument("--validation-year", type=int, required=True)
    parser.add_argument("--test-start", type=int, required=True)
    parser.add_argument("--test-end", type=int, required=True)
    parser.add_argument("--max-func-chars", type=int, default=8000)
    parser.add_argument("--sample-per-train-year", type=int, default=400)
    parser.add_argument("--sample-per-eval-year", type=int, default=300)
    parser.add_argument("--seed", type=int, default=17)
    parser.add_argument("--batch-size", type=int, default=8)
    parser.add_argument("--max-length", type=int, default=512)
    parser.add_argument("--device", choices=["auto", "cpu", "mps"], default="auto")
    parser.add_argument("--codebert-model", default="microsoft/codebert-base")
    parser.add_argument("--linevul-model", default="models_public/linevul_mickymike_converted")
    args = parser.parse_args()

    if args.device == "auto":
        device = "mps" if torch.backends.mps.is_available() else "cpu"
    else:
        device = args.device

    raw_rows = aging.read_jsonl(args.input)
    rows, warnings = aging.normalize_rows(raw_rows, args.source_name)
    for row in rows:
        if args.max_func_chars and len(row["func"]) > args.max_func_chars:
            row["func"] = row["func"][: args.max_func_chars]
    windows = aging.build_windows(
        rows,
        train_start=args.train_start,
        train_end=args.train_end,
        validation_year=args.validation_year,
        test_start=args.test_start,
        test_end=args.test_end,
    )
    by_year = windows["by_year"]
    train_rows = []
    for year in windows["train_years"]:
        train_rows.extend(sample_rows(by_year[year], args.sample_per_train_year, args.seed + year))
    val_rows = sample_rows(by_year[windows["validation_year"]], args.sample_per_eval_year, args.seed + windows["validation_year"])
    test_rows = []
    for year in windows["test_years"]:
        test_rows.extend(sample_rows(by_year[year], args.sample_per_eval_year, args.seed + year))
    sample_note = f"train_per_year={args.sample_per_train_year};eval_per_year={args.sample_per_eval_year}"

    args.output_dir.mkdir(parents=True, exist_ok=True)
    aging.write_jsonl(args.output_dir / "sampled_train.jsonl", train_rows)
    aging.write_jsonl(args.output_dir / "sampled_validation.jsonl", val_rows)
    aging.write_jsonl(args.output_dir / "sampled_test.jsonl", test_rows)

    all_rows = []
    # CodeBERT frozen embeddings + logistic head.
    codebert_all = train_rows + val_rows + test_rows
    emb = codebert_embeddings(codebert_all, args.codebert_model, args.batch_size, args.max_length, device)
    n_train = len(train_rows)
    n_val = len(val_rows)
    x_train = emb[:n_train]
    x_val = emb[n_train : n_train + n_val]
    x_test = emb[n_train + n_val :]
    y_train = np.array([int(r["target"]) for r in train_rows], dtype=np.float64)
    y_val = np.array([int(r["target"]) for r in val_rows], dtype=np.float64)
    w, mean, std = train_logreg(x_train, y_train)
    val_scores = logreg_scores(x_val, w, mean, std)
    codebert_threshold = choose_threshold(val_scores, y_val)
    test_scores = logreg_scores(x_test, w, mean, std)
    all_rows.extend(metrics_by_year(test_rows, test_scores, codebert_threshold, "codebert_frozen_embedding_logreg", sample_note))

    # LineVul pretrained classifier calibrated on validation.
    linevul_eval_rows = val_rows + test_rows
    lv_scores = linevul_scores(linevul_eval_rows, args.linevul_model, args.batch_size, args.max_length, device)
    lv_val_scores = lv_scores[: len(val_rows)]
    lv_test_scores = lv_scores[len(val_rows) :]
    lv_threshold = choose_threshold(lv_val_scores, y_val)
    all_rows.extend(metrics_by_year(test_rows, lv_test_scores, lv_threshold, "linevul_pretrained_calibrated", sample_note))

    write_csv(args.output_dir / "neural_temporal_metrics.csv", all_rows)
    meta = {
        "input": str(args.input),
        "source_name": args.source_name,
        "device": device,
        "codebert_model": args.codebert_model,
        "linevul_model": args.linevul_model,
        "normalization_warnings": len(warnings),
        "train_rows": len(train_rows),
        "validation_rows": len(val_rows),
        "test_rows": len(test_rows),
        "codebert_threshold": codebert_threshold,
        "linevul_threshold": lv_threshold,
        "sample_note": sample_note,
    }
    aging.write_json(args.output_dir / "neural_temporal_meta.json", meta)
    print(json.dumps({"output": str(args.output_dir), "metrics": len(all_rows), **meta}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
