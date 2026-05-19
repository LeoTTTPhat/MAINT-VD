# Detector Aging Phase 1-9 Report

## Scope

This report conducts the nine-phase detector-aging workflow for the currently
available local input.

Input mode: `external`.

If the input mode is `temporal_smoke`, the results verify the pipeline and
analysis design only. They must not be reported as empirical evidence about
real vulnerability detectors.

## Phase 1: Dataset Feasibility

- Valid rows: 1267
- Skipped rows: 0
- Deduplication: exact_canonical_function; removed 126 duplicates
- Years: 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017, 2018, 2019, 2020, 2021, 2022
- Go decision: `True`
- Split warnings: 0

## Phase 2: Temporal Splits

- Fixed-origin train years: 2011, 2012, 2013, 2014, 2015, 2016
- Validation year: 2017
- Future test years: 2018, 2019, 2020, 2021, 2022

Split manifests and JSONL files are written under `results/detector_aging_primevul_paired_commit_dates`.

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
| token_tfidf_logreg | 2018 | 0.494 | 0.779 | 0.605 | 0.068 | 0.221 |
| token_tfidf_logreg | 2019 | 0.524 | 0.864 | 0.652 | 0.063 | 0.136 |
| token_tfidf_logreg | 2020 | 0.538 | 0.764 | 0.632 | -0.003 | 0.236 |
| token_tfidf_logreg | 2021 | 0.639 | 0.742 | 0.687 | 0.159 | 0.258 |
| token_tfidf_logreg | 2022 | 0.474 | 0.900 | 0.621 | -0.229 | 0.100 |
| char4_hash_logreg | 2018 | 0.485 | 0.726 | 0.582 | 0.033 | 0.274 |
| char4_hash_logreg | 2019 | 0.518 | 0.845 | 0.642 | 0.035 | 0.155 |
| char4_hash_logreg | 2020 | 0.524 | 0.600 | 0.559 | -0.039 | 0.400 |
| char4_hash_logreg | 2021 | 0.600 | 0.774 | 0.676 | 0.054 | 0.226 |
| char4_hash_logreg | 2022 | 0.500 | 1.000 | 0.667 | 0.000 | 0.000 |
| code_metrics_logreg | 2018 | 0.477 | 1.000 | 0.646 | 0.062 | 0.000 |
| code_metrics_logreg | 2019 | 0.510 | 1.000 | 0.675 | 0.000 | 0.000 |
| code_metrics_logreg | 2020 | 0.539 | 1.000 | 0.701 | 0.000 | 0.000 |
| code_metrics_logreg | 2021 | 0.585 | 1.000 | 0.738 | 0.000 | 0.000 |
| code_metrics_logreg | 2022 | 0.500 | 1.000 | 0.667 | 0.000 | 0.000 |
| frozen_hash_embedding_logreg | 2018 | 0.484 | 0.938 | 0.639 | 0.063 | 0.062 |
| frozen_hash_embedding_logreg | 2019 | 0.513 | 0.961 | 0.669 | 0.028 | 0.039 |
| frozen_hash_embedding_logreg | 2020 | 0.551 | 0.891 | 0.681 | 0.060 | 0.109 |
| frozen_hash_embedding_logreg | 2021 | 0.571 | 0.903 | 0.700 | -0.096 | 0.097 |
| frozen_hash_embedding_logreg | 2022 | 0.500 | 1.000 | 0.667 | 0.000 | 0.000 |

## Phase 5: Drift Source Analysis

Signals ranked by absolute correlation with recall drop for the primary aging
baseline, `char4_hash_logreg`:

| signal | pearson_with_recall_drop |
|---|---|
| unseen_token_rate | 0.659 |
| vocab_churn | -0.560 |
| token_jsd | -0.534 |
| median_length_shift | -0.429 |
| vulnerable_ratio_shift | 0.261 |
| project_turnover | 0.243 |
| cwe_jsd | -0.193 |
| project_jsd | 0.098 |
| cwe_turnover | 0.032 |

## Phase 6: Maintenance Policy Evaluation

| policy | mean_recall | mean_f1 | recall_ci_low | recall_ci_high | mean_labeled_samples_used |
|---|---|---|---|---|---|
| P0_no_refresh | 0.789 | 0.625 | 0.684 | 0.900 | 0 |
| P1_cumulative_retrain | 0.892 | 0.661 | 0.795 | 0.965 | 154 |
| P2_sliding_3yr_retrain | 0.827 | 0.637 | 0.726 | 0.924 | 154 |
| P3_calibration_only | 0.776 | 0.618 | 0.649 | 0.912 | 154 |
| P4_small_recent_update | 0.780 | 0.625 | 0.694 | 0.851 | 40 |

## Phase 7: Monitoring Triggers

| signal | threshold | event_definition | precision | recall | false_alarm_rate |
|---|---|---|---|---|---|
| project_jsd | 0.688 | recall<0.700 or drop>=0.100 | 0.333 | 1.000 | 0.500 |
| cwe_jsd | 0.661 | recall<0.700 or drop>=0.100 | 0.333 | 1.000 | 0.500 |
| token_jsd | 0.267 | recall<0.700 or drop>=0.100 | 0.333 | 1.000 | 0.500 |
| project_turnover | 0.762 | recall<0.700 or drop>=0.100 | 0.333 | 1.000 | 0.500 |
| unseen_token_rate | 0.685 | recall<0.700 or drop>=0.100 | 0.333 | 1.000 | 0.500 |
| vocab_churn | 0.928 | recall<0.700 or drop>=0.100 | 0.333 | 1.000 | 0.500 |
| median_length_shift | 0.123 | recall<0.700 or drop>=0.100 | 0.333 | 1.000 | 0.500 |
| vulnerable_ratio_shift | 0.021 | recall<0.700 or drop>=0.100 | 0.333 | 1.000 | 0.500 |
| cwe_turnover | 0.214 | recall<0.700 or drop>=0.100 | 0.000 | 0.000 | 0.750 |

## Phase 8: Statistical Summary

| model | first_test_recall | last_test_recall | absolute_recall_decay | worst_recall | mean_recall | absolute_f1_decay |
|---|---|---|---|---|---|---|
| char4_hash_logreg | 0.726 | 1.000 | -0.274 | 0.600 | 0.789 | -0.085 |
| code_metrics_logreg | 1.000 | 1.000 | 0.000 | 1.000 | 1.000 | -0.021 |
| frozen_hash_embedding_logreg | 0.938 | 1.000 | -0.062 | 0.891 | 0.939 | -0.028 |
| token_tfidf_logreg | 0.779 | 0.900 | -0.121 | 0.742 | 0.810 | -0.016 |

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

- `results/detector_aging_primevul_paired_commit_dates/phase_1_feasibility.json`
- `results/detector_aging_primevul_paired_commit_dates/phase_2_temporal_splits.json`
- `results/detector_aging_primevul_paired_commit_dates/phase_3_4_fixed_origin_aging_metrics.csv`
- `results/detector_aging_primevul_paired_commit_dates/phase_5_drift_metrics.csv`
- `results/detector_aging_primevul_paired_commit_dates/phase_5_drift_source_ranking.csv`
- `results/detector_aging_primevul_paired_commit_dates/phase_6_maintenance_policy_summary.csv`
- `results/detector_aging_primevul_paired_commit_dates/phase_7_monitoring_triggers.csv`
- `results/detector_aging_primevul_paired_commit_dates/phase_8_statistical_summary.csv`
