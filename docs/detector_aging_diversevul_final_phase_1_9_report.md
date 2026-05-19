# Detector Aging Phase 1-9 Report

## Scope

This report conducts the nine-phase detector-aging workflow for the currently
available local input.

Input mode: `external`.

If the input mode is `temporal_smoke`, the results verify the pipeline and
analysis design only. They must not be reported as empirical evidence about
real vulnerability detectors.

## Phase 1: Dataset Feasibility

- Valid rows: 48046
- Skipped rows: 0
- Deduplication: exact_canonical_function; removed 199 duplicates
- Years: 2002, 2003, 2005, 2006, 2007, 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017, 2018, 2019, 2020, 2021, 2022
- Go decision: `True`
- Split warnings: 0

## Phase 2: Temporal Splits

- Fixed-origin train years: 2010, 2011, 2012, 2013, 2014, 2015
- Validation year: 2016
- Future test years: 2017, 2018, 2019, 2020, 2021, 2022

Split manifests and JSONL files are written under `results/detector_aging_diversevul_final`.

## Phase 3: Baseline Models

The local low-compute run uses three dependency-light baselines:

- `token_tfidf_logreg`
- `char4_hash_logreg`
- `code_metrics_logreg`

These are placeholders for the paper's detector families. Real experiments
should add frozen code-model embeddings and a CodeBERT/LineVul-style detector.

## Phase 4: Aging Curves

| model | year | precision | recall | f1 | mcc | fnr |
|---|---|---|---|---|---|---|
| token_tfidf_logreg | 2017 | 0.183 | 0.343 | 0.239 | 0.122 | 0.657 |
| token_tfidf_logreg | 2018 | 0.143 | 0.374 | 0.207 | 0.130 | 0.626 |
| token_tfidf_logreg | 2019 | 0.114 | 0.314 | 0.168 | 0.119 | 0.686 |
| token_tfidf_logreg | 2020 | 0.088 | 0.231 | 0.128 | 0.059 | 0.769 |
| token_tfidf_logreg | 2021 | 0.076 | 0.225 | 0.113 | 0.057 | 0.775 |
| token_tfidf_logreg | 2022 | 0.117 | 0.274 | 0.164 | 0.087 | 0.726 |
| char4_hash_logreg | 2017 | 0.158 | 0.669 | 0.255 | 0.147 | 0.331 |
| char4_hash_logreg | 2018 | 0.108 | 0.622 | 0.185 | 0.115 | 0.378 |
| char4_hash_logreg | 2019 | 0.071 | 0.540 | 0.125 | 0.077 | 0.460 |
| char4_hash_logreg | 2020 | 0.077 | 0.550 | 0.135 | 0.076 | 0.450 |
| char4_hash_logreg | 2021 | 0.068 | 0.499 | 0.120 | 0.075 | 0.501 |
| char4_hash_logreg | 2022 | 0.093 | 0.473 | 0.155 | 0.076 | 0.527 |
| code_metrics_logreg | 2017 | 0.273 | 0.457 | 0.342 | 0.250 | 0.543 |
| code_metrics_logreg | 2018 | 0.214 | 0.444 | 0.289 | 0.229 | 0.556 |
| code_metrics_logreg | 2019 | 0.165 | 0.345 | 0.223 | 0.181 | 0.655 |
| code_metrics_logreg | 2020 | 0.142 | 0.354 | 0.203 | 0.152 | 0.646 |
| code_metrics_logreg | 2021 | 0.156 | 0.361 | 0.218 | 0.182 | 0.639 |
| code_metrics_logreg | 2022 | 0.160 | 0.325 | 0.215 | 0.149 | 0.675 |
| frozen_hash_embedding_logreg | 2017 | 0.163 | 0.510 | 0.247 | 0.126 | 0.490 |
| frozen_hash_embedding_logreg | 2018 | 0.131 | 0.545 | 0.211 | 0.147 | 0.455 |
| frozen_hash_embedding_logreg | 2019 | 0.112 | 0.571 | 0.188 | 0.168 | 0.429 |
| frozen_hash_embedding_logreg | 2020 | 0.097 | 0.498 | 0.162 | 0.114 | 0.502 |
| frozen_hash_embedding_logreg | 2021 | 0.075 | 0.440 | 0.128 | 0.084 | 0.560 |
| frozen_hash_embedding_logreg | 2022 | 0.108 | 0.451 | 0.175 | 0.104 | 0.549 |

## Phase 5: Drift Source Analysis

Signals ranked by absolute correlation with recall drop for the primary aging
baseline, `char4_hash_logreg`:

| signal | pearson_with_recall_drop |
|---|---|
| vulnerable_ratio_shift | -0.786 |
| cwe_turnover | 0.747 |
| project_turnover | 0.666 |
| unseen_token_rate | 0.580 |
| cwe_jsd | 0.473 |
| vocab_churn | 0.247 |
| project_jsd | -0.239 |
| token_jsd | 0.184 |
| median_length_shift | 0.023 |

## Phase 6: Maintenance Policy Evaluation

| policy | mean_recall | mean_f1 | recall_ci_low | recall_ci_high | mean_labeled_samples_used |
|---|---|---|---|---|---|
| P0_no_refresh | 0.559 | 0.163 | 0.513 | 0.620 | 0 |
| P1_cumulative_retrain | 0.411 | 0.156 | 0.294 | 0.513 | 4578.500 |
| P2_sliding_3yr_retrain | 0.392 | 0.172 | 0.311 | 0.507 | 4578.500 |
| P3_calibration_only | 0.424 | 0.159 | 0.279 | 0.566 | 4578.500 |
| P4_small_recent_update | 0.366 | 0.163 | 0.263 | 0.467 | 40 |

## Phase 7: Monitoring Triggers

| signal | threshold | event_definition | precision | recall | false_alarm_rate |
|---|---|---|---|---|---|
| cwe_jsd | 0.507 | recall<0.200 or drop>=0.100 | 1.000 | 0.750 | 0.000 |
| project_turnover | 0.666 | recall<0.200 or drop>=0.100 | 1.000 | 0.750 | 0.000 |
| unseen_token_rate | 0.697 | recall<0.200 or drop>=0.100 | 1.000 | 0.750 | 0.000 |
| project_jsd | 0.639 | recall<0.200 or drop>=0.100 | 0.667 | 0.500 | 0.500 |
| token_jsd | 0.160 | recall<0.200 or drop>=0.100 | 0.667 | 0.500 | 0.500 |
| cwe_turnover | 0.458 | recall<0.200 or drop>=0.100 | 0.667 | 0.500 | 0.500 |
| vocab_churn | 0.903 | recall<0.200 or drop>=0.100 | 0.667 | 0.500 | 0.500 |
| median_length_shift | 0.209 | recall<0.200 or drop>=0.100 | 0.333 | 0.250 | 1.000 |
| vulnerable_ratio_shift | -0.005 | recall<0.200 or drop>=0.100 | 0.333 | 0.250 | 1.000 |

## Phase 8: Statistical Summary

| model | first_test_recall | last_test_recall | absolute_recall_decay | worst_recall | mean_recall | absolute_f1_decay |
|---|---|---|---|---|---|---|
| char4_hash_logreg | 0.669 | 0.473 | 0.196 | 0.473 | 0.559 | 0.100 |
| code_metrics_logreg | 0.457 | 0.325 | 0.133 | 0.325 | 0.381 | 0.127 |
| frozen_hash_embedding_logreg | 0.510 | 0.451 | 0.059 | 0.440 | 0.503 | 0.072 |
| token_tfidf_logreg | 0.343 | 0.274 | 0.069 | 0.225 | 0.294 | 0.075 |

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

- `results/detector_aging_diversevul_final/phase_1_feasibility.json`
- `results/detector_aging_diversevul_final/phase_2_temporal_splits.json`
- `results/detector_aging_diversevul_final/phase_3_4_fixed_origin_aging_metrics.csv`
- `results/detector_aging_diversevul_final/phase_5_drift_metrics.csv`
- `results/detector_aging_diversevul_final/phase_5_drift_source_ranking.csv`
- `results/detector_aging_diversevul_final/phase_6_maintenance_policy_summary.csv`
- `results/detector_aging_diversevul_final/phase_7_monitoring_triggers.csv`
- `results/detector_aging_diversevul_final/phase_8_statistical_summary.csv`
