#!/usr/bin/env bash
set -euo pipefail

# Stronger recovered-date DiverseVul neural protocol for the IST submission.
# Requires a Python environment with torch and transformers installed.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INPUT="${ROOT_DIR}/data/raw/diversevul_recovered_commit_dates_only.jsonl"
OUT_ROOT="${ROOT_DIR}/results/finetuned_project_holdout_diversevul_recovered_dates_sweep"
LINEVUL_MODEL="${LINEVUL_MODEL:-${ROOT_DIR}/models_public/linevul_mickymike_converted}"
CODEBERT_MODEL="${CODEBERT_MODEL:-microsoft/codebert-base}"

mkdir -p "${OUT_ROOT}"

for model in codebert linevul; do
  for lr in 1e-5 2e-5 5e-5; do
    for loss in class_balanced focal; do
      run_dir="${OUT_ROOT}/${model}_lr${lr}_${loss}_seq512"
      python3 "${ROOT_DIR}/scripts/finetune_transformer_temporal.py" \
        --input "${INPUT}" \
        --source-name diversevul \
        --output-dir "${run_dir}" \
        --train-start 2009 \
        --train-end 2015 \
        --validation-year 2016 \
        --test-start 2017 \
        --test-end 2022 \
        --models "${model}" \
        --codebert-model "${CODEBERT_MODEL}" \
        --linevul-model "${LINEVUL_MODEL}" \
        --project-holdout future_unseen \
        --threshold-policy fpr_control \
        --max-validation-fpr 0.20 \
        --epochs 10 \
        --early-stopping-patience 3 \
        --max-length 512 \
        --learning-rate "${lr}" \
        --loss "${loss}" \
        --train-batch-size 4 \
        --eval-batch-size 8 \
        --log-every 100
    done
  done
done
