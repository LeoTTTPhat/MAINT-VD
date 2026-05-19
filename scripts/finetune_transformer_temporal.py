#!/usr/bin/env python3
"""Fine-tune transformer vulnerability detectors under temporal splits.

This differs from run_neural_temporal_baselines.py: all transformer parameters
are updated. The script is intentionally trainer-free so it works with the local
Torch/Transformers environment and MPS.
"""

from __future__ import annotations

import argparse
import copy
import csv
import json
from pathlib import Path
import random
import sys
import time

import numpy as np
import torch
from torch.utils.data import DataLoader, Dataset
from transformers import AutoModelForSequenceClassification, AutoTokenizer

sys.path.insert(0, str(Path(__file__).resolve().parent))
import conduct_detector_aging as aging  # noqa: E402


class CodeDataset(Dataset):
    def __init__(self, rows: list[dict]):
        self.rows = rows

    def __len__(self) -> int:
        return len(self.rows)

    def __getitem__(self, idx: int) -> dict:
        row = self.rows[idx]
        return {
            "idx": row["idx"],
            "year": int(row.get("year", 0)),
            "func": row["func"],
            "target": int(row["target"]),
        }


def write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
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
    selected.extend(rng.sample(pos, min(len(pos), half)))
    remaining = limit - len(selected)
    selected.extend(rng.sample(neg, min(len(neg), remaining)))
    if len(selected) < limit:
        selected_ids = {r["idx"] for r in selected}
        rest = [r for r in rows if r["idx"] not in selected_ids]
        selected.extend(rng.sample(rest, min(len(rest), limit - len(selected))))
    selected.sort(key=lambda r: (int(r["year"]), str(r["idx"])))
    return selected


def collate_fn(tokenizer, max_length: int):
    def collate(batch: list[dict]) -> dict:
        encoded = tokenizer(
            [row["func"] for row in batch],
            padding=True,
            truncation=True,
            max_length=max_length,
            return_tensors="pt",
        )
        encoded["labels"] = torch.tensor([row["target"] for row in batch], dtype=torch.long)
        encoded["idx"] = [row["idx"] for row in batch]
        encoded["year"] = torch.tensor([row["year"] for row in batch], dtype=torch.long)
        return encoded

    return collate


def to_device(batch: dict, device: str) -> dict:
    return {k: v.to(device) if torch.is_tensor(v) else v for k, v in batch.items()}


def positive_scores(logits: torch.Tensor) -> torch.Tensor:
    if logits.shape[-1] == 1:
        return torch.sigmoid(logits[:, 0])
    return torch.softmax(logits, dim=-1)[:, min(1, logits.shape[-1] - 1)]


def average_precision(y: np.ndarray, scores: np.ndarray) -> float:
    positives = int(y.sum())
    if positives == 0:
        return 0.0
    order = np.argsort(-scores)
    ranked_y = y[order]
    tp = np.cumsum(ranked_y)
    ranks = np.arange(1, len(ranked_y) + 1)
    precision_at_k = tp / ranks
    return float((precision_at_k * ranked_y).sum() / positives)


def roc_auc(y: np.ndarray, scores: np.ndarray) -> float:
    positives = int(y.sum())
    negatives = int(len(y) - positives)
    if positives == 0 or negatives == 0:
        return 0.5
    order = np.argsort(scores)
    ranks = np.empty(len(scores), dtype=np.float64)
    start = 0
    while start < len(scores):
        end = start + 1
        while end < len(scores) and scores[order[end]] == scores[order[start]]:
            end += 1
        ranks[order[start:end]] = (start + 1 + end) / 2.0
        start = end
    sum_pos_ranks = float(ranks[y == 1].sum())
    return float((sum_pos_ranks - positives * (positives + 1) / 2.0) / (positives * negatives))


def transformer_loss(logits: torch.Tensor, labels_tensor: torch.Tensor, class_weights: torch.Tensor, args) -> torch.Tensor:
    if logits.shape[-1] == 1:
        if args.loss == "unweighted":
            bce = torch.nn.functional.binary_cross_entropy_with_logits(
                logits[:, 0], labels_tensor.float(), reduction="none"
            )
        else:
            bce = torch.nn.functional.binary_cross_entropy_with_logits(
                logits[:, 0],
                labels_tensor.float(),
                pos_weight=class_weights[1] / class_weights[0],
                reduction="none",
            )
        if args.loss == "focal":
            pt = torch.exp(-bce)
            bce = ((1.0 - pt) ** args.focal_gamma) * bce
        return bce.mean()

    weight = None if args.loss == "unweighted" else class_weights
    ce = torch.nn.functional.cross_entropy(logits, labels_tensor, weight=weight, reduction="none")
    if args.loss == "focal":
        pt = torch.exp(-ce)
        ce = ((1.0 - pt) ** args.focal_gamma) * ce
    return ce.mean()


def choose_threshold(scores: np.ndarray, y: np.ndarray, max_fpr: float | None = None) -> tuple[float, dict]:
    best_threshold = 0.5
    best_key = None
    best_metrics = {}
    candidates = []
    for threshold in np.linspace(0.05, 0.95, 91):
        preds = (scores >= threshold).astype(int)
        metrics = aging.classification_metrics(y.astype(int).tolist(), preds.tolist(), scores.tolist())
        if max_fpr is not None and metrics["false_positive_rate"] > max_fpr:
            continue
        if max_fpr is None:
            key = (metrics["f1"], metrics["recall"], -metrics["false_positive_rate"])
        else:
            # Under an FPR service level, preserve security recall first and use
            # F1 as the tie-breaker.
            key = (metrics["recall"], metrics["f1"], -metrics["false_positive_rate"])
        candidates.append((key, float(threshold), metrics))
        if best_key is None or key > best_key:
            best_key = key
            best_threshold = float(threshold)
            best_metrics = metrics
    if not candidates and max_fpr is not None:
        # If every threshold violates the requested FPR, choose the lowest-FPR
        # threshold and report that the service target was infeasible.
        for threshold in np.linspace(0.05, 0.95, 91):
            preds = (scores >= threshold).astype(int)
            metrics = aging.classification_metrics(y.astype(int).tolist(), preds.tolist(), scores.tolist())
            key = (-metrics["false_positive_rate"], metrics["recall"], metrics["f1"])
            if best_key is None or key > best_key:
                best_key = key
                best_threshold = float(threshold)
                best_metrics = metrics
        best_metrics = {**best_metrics, "fpr_target_feasible": False}
    else:
        best_metrics = {**best_metrics, "fpr_target_feasible": True}
    return best_threshold, best_metrics


def threshold_curve(scores: np.ndarray, y: np.ndarray, model_key: str, split: str) -> list[dict]:
    rows = []
    for threshold in np.linspace(0.0, 1.0, 101):
        preds = (scores >= threshold).astype(int)
        rows.append(
            {
                "model_key": model_key,
                "split": split,
                "threshold": float(threshold),
                **aging.classification_metrics(y.astype(int).tolist(), preds.tolist(), scores.tolist()),
            }
        )
    return rows


def evaluate(model, tokenizer, rows: list[dict], batch_size: int, max_length: int, device: str) -> list[dict]:
    loader = DataLoader(CodeDataset(rows), batch_size=batch_size, shuffle=False, collate_fn=collate_fn(tokenizer, max_length))
    out = []
    model.eval()
    with torch.no_grad():
        for batch in loader:
            ids = batch.pop("idx")
            years = batch.pop("year").cpu().numpy().tolist()
            batch = to_device(batch, device)
            logits = model(**batch).logits
            scores = positive_scores(logits).detach().cpu().numpy().tolist()
            labels = batch["labels"].detach().cpu().numpy().tolist()
            for idx, year, label, score in zip(ids, years, labels, scores):
                out.append({"idx": idx, "year": int(year), "target": int(label), "score": float(score)})
    return out


def evaluate_loss(model, tokenizer, rows: list[dict], batch_size: int, max_length: int, device: str, class_weights: torch.Tensor, args) -> float:
    loader = DataLoader(CodeDataset(rows), batch_size=batch_size, shuffle=False, collate_fn=collate_fn(tokenizer, max_length))
    losses = []
    model.eval()
    with torch.no_grad():
        for batch in loader:
            batch.pop("idx")
            batch.pop("year")
            batch = to_device(batch, device)
            labels_tensor = batch.pop("labels")
            logits = model(**batch).logits
            loss = transformer_loss(logits, labels_tensor, class_weights, args)
            losses.append(float(loss.detach().cpu()))
    return float(np.mean(losses)) if losses else 0.0


def metrics_by_year(pred_rows: list[dict], threshold: float, model_name: str, note: str) -> list[dict]:
    rows = []
    years = sorted({int(r["year"]) for r in pred_rows})
    for year in years:
        subset = [r for r in pred_rows if int(r["year"]) == year]
        targets = [int(r["target"]) for r in subset]
        scores = [float(r["score"]) for r in subset]
        preds = [int(score >= threshold) for score in scores]
        rows.append(
            {
                "model": model_name,
                "phase": "finetuned_test",
                "year": year,
                "threshold": threshold,
                "sample_note": note,
                **aging.classification_metrics(targets, preds, scores),
            }
        )
    return rows


def train_one_model(args, model_key: str, model_id: str, train_rows: list[dict], val_rows: list[dict], test_rows: list[dict]) -> tuple[list[dict], dict]:
    tokenizer = AutoTokenizer.from_pretrained(model_id, trust_remote_code=True)
    model = AutoModelForSequenceClassification.from_pretrained(
        model_id,
        num_labels=2,
        ignore_mismatched_sizes=True,
        trust_remote_code=True,
    )
    model.to(args.device)

    loader = DataLoader(
        CodeDataset(train_rows),
        batch_size=args.train_batch_size,
        shuffle=True,
        collate_fn=collate_fn(tokenizer, args.max_length),
    )
    labels = np.array([int(r["target"]) for r in train_rows], dtype=np.int64)
    class_counts = np.bincount(labels, minlength=2)
    class_weights = torch.tensor(
        [len(labels) / max(1, 2 * class_counts[0]), len(labels) / max(1, 2 * class_counts[1])],
        dtype=torch.float32,
        device=args.device,
    )
    optimizer = torch.optim.AdamW(model.parameters(), lr=args.learning_rate, weight_decay=args.weight_decay)
    total_steps = args.epochs * len(loader)
    print(f"{model_key}: train_rows={len(train_rows)} val_rows={len(val_rows)} test_rows={len(test_rows)} steps={total_steps}", flush=True)

    start_time = time.time()
    global_step = 0
    best_val_auprc = -1.0
    best_epoch = 0
    best_state = None
    stale_epochs = 0
    curve_rows = []
    for epoch in range(args.epochs):
        model.train()
        losses = []
        for batch in loader:
            batch.pop("idx")
            batch.pop("year")
            batch = to_device(batch, args.device)
            labels_tensor = batch.pop("labels")
            logits = model(**batch).logits
            loss = transformer_loss(logits, labels_tensor, class_weights, args)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), args.max_grad_norm)
            optimizer.step()
            optimizer.zero_grad(set_to_none=True)
            losses.append(float(loss.detach().cpu()))
            global_step += 1
            if args.log_every and global_step % args.log_every == 0:
                print(f"{model_key}: step {global_step}/{total_steps} loss={np.mean(losses[-args.log_every:]):.4f}", flush=True)
        val_pred_epoch = evaluate(model, tokenizer, val_rows, args.eval_batch_size, args.max_length, args.device)
        val_loss = evaluate_loss(model, tokenizer, val_rows, args.eval_batch_size, args.max_length, args.device, class_weights, args)
        val_scores_epoch = np.array([r["score"] for r in val_pred_epoch], dtype=np.float64)
        val_targets_epoch = np.array([r["target"] for r in val_pred_epoch], dtype=np.int64)
        val_auprc = average_precision(val_targets_epoch, val_scores_epoch)
        val_auroc = roc_auc(val_targets_epoch, val_scores_epoch)
        f1_threshold, f1_metrics = choose_threshold(val_scores_epoch, val_targets_epoch, max_fpr=None)
        fpr_threshold, fpr_metrics = choose_threshold(
            val_scores_epoch,
            val_targets_epoch,
            max_fpr=args.max_validation_fpr if args.threshold_policy == "fpr_control" else None,
        )
        curve_row = {
            "model_key": model_key,
            "epoch": epoch + 1,
            "train_loss": float(np.mean(losses)),
            "validation_loss": val_loss,
            "validation_auprc": val_auprc,
            "validation_auroc": val_auroc,
            "best_f1_threshold": f1_threshold,
            "best_f1_recall": f1_metrics["recall"],
            "best_f1_fpr": f1_metrics["false_positive_rate"],
            "selected_threshold": fpr_threshold,
            "selected_recall": fpr_metrics["recall"],
            "selected_fpr": fpr_metrics["false_positive_rate"],
            "selected_f1": fpr_metrics["f1"],
            "fpr_target_feasible": fpr_metrics.get("fpr_target_feasible", True),
            "learning_rate": args.learning_rate,
            "loss": args.loss,
            "max_length": args.max_length,
        }
        curve_rows.append(curve_row)
        write_csv(args.output_dir / f"{model_key}_training_curve.csv", curve_rows)
        print(
            f"{model_key}: epoch {epoch + 1}/{args.epochs} loss={np.mean(losses):.4f} "
            f"val_loss={val_loss:.4f} val_auprc={val_auprc:.4f} val_auroc={val_auroc:.4f} "
            f"selected_recall={fpr_metrics['recall']:.4f} selected_fpr={fpr_metrics['false_positive_rate']:.4f}",
            flush=True,
        )
        if val_auprc > best_val_auprc + args.early_stopping_min_delta:
            best_val_auprc = val_auprc
            best_epoch = epoch + 1
            best_state = copy.deepcopy({k: v.detach().cpu() for k, v in model.state_dict().items()})
            stale_epochs = 0
        else:
            stale_epochs += 1
            if args.early_stopping_patience and stale_epochs >= args.early_stopping_patience:
                print(f"{model_key}: early stopping after epoch {epoch + 1}; best_epoch={best_epoch}", flush=True)
                break

    if best_state is not None:
        model.load_state_dict(best_state)
        model.to(args.device)

    val_pred = evaluate(model, tokenizer, val_rows, args.eval_batch_size, args.max_length, args.device)
    val_scores = np.array([r["score"] for r in val_pred], dtype=np.float64)
    val_targets = np.array([r["target"] for r in val_pred], dtype=np.int64)
    write_csv(args.output_dir / f"{model_key}_validation_threshold_curve.csv", threshold_curve(val_scores, val_targets, model_key, "validation"))
    max_fpr = args.max_validation_fpr if args.threshold_policy == "fpr_control" else None
    threshold, threshold_metrics = choose_threshold(val_scores, val_targets, max_fpr=max_fpr)
    test_pred = evaluate(model, tokenizer, test_rows, args.eval_batch_size, args.max_length, args.device)
    note = (
        f"train_rows={len(train_rows)};val_rows={len(val_rows)};test_rows={len(test_rows)};"
        f"epochs={args.epochs};max_length={args.max_length};all_transformer_layers_finetuned=true;"
        f"threshold_policy={args.threshold_policy};max_validation_fpr={args.max_validation_fpr};"
        f"project_holdout={args.project_holdout}"
    )
    metric_rows = metrics_by_year(test_pred, threshold, f"{model_key}_full_finetuned", note)
    meta = {
        "model_key": model_key,
        "model_id": model_id,
        "train_rows": len(train_rows),
        "validation_rows": len(val_rows),
        "test_rows": len(test_rows),
        "epochs": args.epochs,
        "learning_rate": args.learning_rate,
        "weight_decay": args.weight_decay,
        "max_length": args.max_length,
        "threshold": threshold,
        "threshold_policy": args.threshold_policy,
        "max_validation_fpr": args.max_validation_fpr,
        "loss": args.loss,
        "focal_gamma": args.focal_gamma,
        "early_stopping_patience": args.early_stopping_patience,
        "early_stopping_metric": "validation_auprc",
        "best_epoch": best_epoch,
        "best_validation_auprc": best_val_auprc,
        "validation_threshold_metrics": threshold_metrics,
        "class_counts": class_counts.tolist(),
        "seconds": time.time() - start_time,
        "all_transformer_layers_finetuned": True,
    }
    pred_path = args.output_dir / f"{model_key}_full_finetuned_predictions.jsonl"
    aging.write_jsonl(pred_path, [{**row, "pred": int(row["score"] >= threshold), "model": f"{model_key}_full_finetuned"} for row in test_pred])
    if args.save_models:
        save_dir = args.output_dir / f"{model_key}_full_finetuned_model"
        save_dir.mkdir(parents=True, exist_ok=True)
        model.save_pretrained(save_dir)
        tokenizer.save_pretrained(save_dir)
        meta["saved_model"] = str(save_dir)
    del model
    if args.device == "mps":
        torch.mps.empty_cache()
    return metric_rows, meta


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--source-name", required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--train-start", type=int, required=True)
    parser.add_argument("--train-end", type=int, required=True)
    parser.add_argument("--validation-year", type=int, required=True)
    parser.add_argument("--test-start", type=int, required=True)
    parser.add_argument("--test-end", type=int, required=True)
    parser.add_argument("--models", default="codebert,linevul")
    parser.add_argument("--codebert-model", default="microsoft/codebert-base")
    parser.add_argument("--linevul-model", default="models_public/linevul_mickymike_converted")
    parser.add_argument("--max-func-chars", type=int, default=8000)
    parser.add_argument("--max-length", type=int, default=256)
    parser.add_argument("--epochs", type=int, default=1)
    parser.add_argument("--learning-rate", type=float, default=2e-5)
    parser.add_argument("--weight-decay", type=float, default=0.01)
    parser.add_argument("--max-grad-norm", type=float, default=1.0)
    parser.add_argument("--loss", choices=["class_balanced", "focal", "unweighted"], default="class_balanced")
    parser.add_argument("--focal-gamma", type=float, default=2.0)
    parser.add_argument("--early-stopping-patience", type=int, default=0)
    parser.add_argument("--early-stopping-min-delta", type=float, default=1e-4)
    parser.add_argument("--train-batch-size", type=int, default=4)
    parser.add_argument("--eval-batch-size", type=int, default=8)
    parser.add_argument("--device", choices=["auto", "cpu", "mps"], default="auto")
    parser.add_argument("--seed", type=int, default=17)
    parser.add_argument("--max-train-rows", type=int, default=0)
    parser.add_argument("--max-validation-rows", type=int, default=0)
    parser.add_argument("--max-eval-rows-per-year", type=int, default=0)
    parser.add_argument("--project-holdout", choices=["none", "future_unseen"], default="none")
    parser.add_argument("--threshold-policy", choices=["f1", "fpr_control"], default="f1")
    parser.add_argument("--max-validation-fpr", type=float, default=0.20)
    parser.add_argument("--log-every", type=int, default=100)
    parser.add_argument("--save-models", action="store_true")
    args = parser.parse_args()

    random.seed(args.seed)
    np.random.seed(args.seed)
    torch.manual_seed(args.seed)
    if args.device == "auto":
        args.device = "mps" if torch.backends.mps.is_available() else "cpu"

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
    train_rows = aging.rows_for_years(windows, windows["train_years"])
    val_rows = windows["by_year"][windows["validation_year"]]
    train_projects = {row["project"] for row in train_rows}
    if args.project_holdout == "future_unseen":
        val_rows = [row for row in val_rows if row["project"] not in train_projects]
    if args.max_validation_rows:
        val_rows = sample_rows(val_rows, args.max_validation_rows, args.seed + windows["validation_year"])
    test_rows = []
    for year in windows["test_years"]:
        year_rows = windows["by_year"][year]
        if args.project_holdout == "future_unseen":
            year_rows = [row for row in year_rows if row["project"] not in train_projects]
        if args.max_eval_rows_per_year:
            year_rows = sample_rows(year_rows, args.max_eval_rows_per_year, args.seed + year)
        test_rows.extend(year_rows)
    if args.max_train_rows:
        train_rows = sample_rows(train_rows, args.max_train_rows, args.seed)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    aging.write_jsonl(args.output_dir / "finetune_train_rows.jsonl", train_rows)
    aging.write_jsonl(args.output_dir / "finetune_validation_rows.jsonl", val_rows)
    aging.write_jsonl(args.output_dir / "finetune_test_rows.jsonl", test_rows)

    model_map = {
        "codebert": args.codebert_model,
        "linevul": args.linevul_model,
    }
    all_metrics = []
    all_meta = {
        "input": str(args.input),
        "source_name": args.source_name,
        "device": args.device,
        "normalization_warnings": len(warnings),
        "train_years": windows["train_years"],
        "validation_year": windows["validation_year"],
        "test_years": windows["test_years"],
        "requested_models": args.models,
        "max_train_rows": args.max_train_rows,
        "max_validation_rows": args.max_validation_rows,
        "max_eval_rows_per_year": args.max_eval_rows_per_year,
        "project_holdout": args.project_holdout,
        "threshold_policy": args.threshold_policy,
        "max_validation_fpr": args.max_validation_fpr,
        "train_project_count": len(train_projects),
        "model_runs": [],
    }
    for model_key in [m.strip() for m in args.models.split(",") if m.strip()]:
        if model_key not in model_map:
            raise ValueError(f"unknown model key {model_key!r}")
        metric_rows, meta = train_one_model(args, model_key, model_map[model_key], train_rows, val_rows, test_rows)
        all_metrics.extend(metric_rows)
        all_meta["model_runs"].append(meta)
        write_csv(args.output_dir / "finetuned_temporal_metrics.csv", all_metrics)
        aging.write_json(args.output_dir / "finetuned_temporal_meta.json", all_meta)

    print(json.dumps({"output": str(args.output_dir), "metrics": len(all_metrics), **all_meta}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
