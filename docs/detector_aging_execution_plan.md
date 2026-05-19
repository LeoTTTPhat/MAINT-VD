# Execution Plan: Detector Aging and Model Drift

## Phase 0: Feasibility Check

Goal: confirm that the selected dataset supports reliable temporal evaluation.

Tasks:

- download CVEfixes metadata or reuse an existing local copy,
- inspect available date fields,
- identify whether dates refer to fix commit, CVE publication, or collection,
- count C/C++ functions by year or quarter,
- check label balance by temporal window,
- estimate duplicate and near-duplicate rates across windows.

Exit criteria:

- at least five usable chronological windows,
- no future leakage in sample identifiers or preprocessing,
- enough vulnerable samples per test window for stable recall estimates.

## Phase 1: Temporal Dataset Builder

Goal: produce normalized JSONL files and split manifests.

Generated artifacts:

- `data/raw/cvefixes_functions.jsonl`
- `data/processed/temporal_windows.json`
- `data/processed/splits/fixed_origin/*.jsonl`
- `data/processed/splits/rolling_origin/*.jsonl`
- `data/processed/temporal_dataset_summary.json`

Required summary tables:

- samples by window,
- vulnerable ratio by window,
- projects by window,
- CWE distribution by window,
- median and maximum function length by window,
- duplicate overlap across train/validation/test windows.

## Phase 2: Baselines

Goal: run enough detectors to support model-family comparison.

Baseline A: TF-IDF + logistic regression.

- fast,
- transparent,
- useful as a maintenance-friendly reference.

Baseline B: frozen code embeddings + logistic regression.

- stronger representation,
- still low compute,
- retraining cost remains small.

Baseline C: transformer detector.

- CodeBERT/LineVul-style model,
- represents common modern vulnerability detector practice,
- can be fine-tuned only on training windows if compute allows.

Optional Baseline D: graph-based detector.

- include only if setup cost does not threaten the core temporal study.

## Phase 3: Aging Curves

Goal: answer RQ1.

For each detector:

1. Train on early window block.
2. Tune threshold only on validation window.
3. Evaluate each later test window independently.
4. Plot F1, recall, MCC, and false-negative rate over time.
5. Report absolute decay, relative decay, and threshold crossing time.

Important rule:

> No preprocessing vocabulary, scaler, duplicate detector, threshold, or
> hyperparameter may be fitted using future test windows.

## Phase 4: Drift Source Analysis

Goal: answer RQ2.

Compute per-window drift signals:

- project turnover,
- CWE distribution divergence,
- token vocabulary churn,
- unseen API/token rate,
- function length shift,
- complexity shift if metrics are available,
- embedding centroid distance.

Analysis:

- correlate each drift signal with performance drop,
- fit a simple regression model,
- inspect whether drift signals explain recall decay better than elapsed time
  alone.

Deliverable:

- ranked list of drift indicators with confidence intervals.

## Phase 5: Maintenance Policies

Goal: answer RQ3.

Compare policies:

- `P0_no_refresh`: train once and reuse forever,
- `P1_periodic_full`: retrain every N windows with all past data,
- `P2_sliding_window`: retrain using only recent N windows,
- `P3_calibration_only`: keep model fixed, update threshold/calibration,
- `P4_small_recent_update`: retrain with a small labeled sample from the most
  recent window.

Metrics:

- average future recall,
- average future F1,
- false-positive burden,
- training time,
- labeled samples required,
- maintenance events required.

Deliverable:

- cost-effectiveness table showing performance recovered per maintenance cost.

## Phase 6: Monitoring Triggers

Goal: answer RQ4.

Create trigger rules:

- refresh when input drift exceeds a threshold,
- refresh when vulnerable prediction rate changes sharply,
- refresh when uncertainty increases,
- refresh when unseen token/API rate exceeds a threshold,
- refresh when combined drift score exceeds a threshold.

Evaluate triggers:

- did the trigger fire before a real performance drop,
- how many false alarms occurred,
- how much performance was recovered if refresh followed the trigger.

Deliverable:

- practical monitoring recommendation for CI/CD or security triage deployment.

## Phase 7: Paper Assembly

Goal: convert the empirical package into an IST-ready manuscript.

Core figures:

- study pipeline,
- temporal dataset timeline,
- aging curves by detector,
- drift signal vs performance drop,
- maintenance policy comparison,
- trigger precision/lead-time plot.

Core tables:

- dataset windows,
- detector configurations,
- aging metrics,
- drift source ranking,
- maintenance cost-effectiveness,
- threats and mitigation summary.

## Go/No-Go Criteria

Go if:

- temporal splits are large enough,
- at least one detector shows measurable aging or at least clear stability
  under a rigorous design,
- maintenance policies produce interpretable tradeoffs,
- temporal leakage controls can be documented.

No-go or reposition if:

- date metadata is too ambiguous,
- temporal windows are too sparse,
- labels are too noisy for meaningful recall analysis,
- all models are statistically flat across time and drift metrics explain
  nothing.

If performance does not decay, the paper can still work, but the thesis changes
to:

> Under careful temporal validation, some vulnerability detectors are more
> temporally stable than expected; maintenance should be triggered by measured
> drift rather than by fixed retraining schedules.

