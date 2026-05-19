# Detector Aging Phase 1-9 Report

## Scope

This report conducts the nine-phase detector-aging workflow for the currently
available local input.

Input mode: `external`.

If the input mode is `temporal_smoke`, the results verify the pipeline and
analysis design only. They must not be reported as empirical evidence about
real vulnerability detectors.

## Phase 1: Dataset Feasibility

- Valid rows: 19791
- Skipped rows: 0
- Deduplication: exact_canonical_function; removed 2269 duplicates
- Years: 1999, 2001, 2005, 2006, 2007, 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017, 2018, 2019, 2020, 2021, 2022, 2023, 2024
- Go decision: `True`
- Split warnings: 0

## Phase 2: Temporal Splits

- Fixed-origin train years: 2010, 2011, 2012, 2013, 2014, 2015, 2016
- Validation year: 2017
- Future test years: 2018, 2019, 2020, 2021, 2022, 2023, 2024

Split manifests and JSONL files are written under `results/detector_aging_cvefixes_final`.

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
| token_tfidf_logreg | 2018 | 0.494 | 0.928 | 0.645 | 0.218 | 0.072 |
| token_tfidf_logreg | 2019 | 0.490 | 0.913 | 0.638 | 0.183 | 0.087 |
| token_tfidf_logreg | 2020 | 0.502 | 0.898 | 0.644 | 0.201 | 0.102 |
| token_tfidf_logreg | 2021 | 0.476 | 0.889 | 0.620 | 0.180 | 0.111 |
| token_tfidf_logreg | 2022 | 0.511 | 0.903 | 0.652 | 0.209 | 0.097 |
| token_tfidf_logreg | 2023 | 0.537 | 0.899 | 0.673 | 0.275 | 0.101 |
| token_tfidf_logreg | 2024 | 0.542 | 0.855 | 0.663 | 0.250 | 0.145 |
| char4_hash_logreg | 2018 | 0.462 | 0.866 | 0.602 | 0.067 | 0.134 |
| char4_hash_logreg | 2019 | 0.469 | 0.871 | 0.610 | 0.084 | 0.129 |
| char4_hash_logreg | 2020 | 0.470 | 0.881 | 0.613 | 0.078 | 0.119 |
| char4_hash_logreg | 2021 | 0.454 | 0.868 | 0.596 | 0.095 | 0.132 |
| char4_hash_logreg | 2022 | 0.482 | 0.895 | 0.626 | 0.100 | 0.105 |
| char4_hash_logreg | 2023 | 0.479 | 0.906 | 0.626 | 0.081 | 0.094 |
| char4_hash_logreg | 2024 | 0.478 | 0.902 | 0.624 | 0.055 | 0.098 |
| code_metrics_logreg | 2018 | 0.452 | 0.983 | 0.619 | 0.058 | 0.017 |
| code_metrics_logreg | 2019 | 0.453 | 0.973 | 0.618 | 0.026 | 0.027 |
| code_metrics_logreg | 2020 | 0.462 | 0.959 | 0.624 | 0.072 | 0.041 |
| code_metrics_logreg | 2021 | 0.437 | 0.962 | 0.601 | 0.042 | 0.038 |
| code_metrics_logreg | 2022 | 0.469 | 0.967 | 0.632 | 0.070 | 0.033 |
| code_metrics_logreg | 2023 | 0.475 | 0.961 | 0.636 | 0.089 | 0.039 |
| code_metrics_logreg | 2024 | 0.477 | 0.959 | 0.637 | 0.078 | 0.041 |
| frozen_hash_embedding_logreg | 2018 | 0.486 | 0.875 | 0.625 | 0.159 | 0.125 |
| frozen_hash_embedding_logreg | 2019 | 0.485 | 0.879 | 0.625 | 0.147 | 0.121 |
| frozen_hash_embedding_logreg | 2020 | 0.501 | 0.856 | 0.632 | 0.179 | 0.144 |

## Phase 5: Drift Source Analysis

Signals ranked by absolute correlation with recall drop for the primary aging
baseline, `char4_hash_logreg`:

| signal | pearson_with_recall_drop |
|---|---|
| vulnerable_ratio_shift | -0.880 |
| project_turnover | -0.763 |
| median_length_shift | -0.762 |
| cwe_turnover | -0.753 |
| project_jsd | -0.741 |
| unseen_token_rate | -0.686 |
| cwe_jsd | -0.518 |
| token_jsd | -0.412 |
| vocab_churn | 0.218 |

## Phase 6: Maintenance Policy Evaluation

| policy | mean_recall | mean_f1 | recall_ci_low | recall_ci_high | mean_labeled_samples_used |
|---|---|---|---|---|---|
| P0_no_refresh | 0.884 | 0.614 | 0.873 | 0.895 | 0 |
| P1_cumulative_retrain | 0.955 | 0.624 | 0.935 | 0.970 | 2046.571 |
| P2_sliding_3yr_retrain | 0.949 | 0.623 | 0.936 | 0.959 | 2046.571 |
| P3_calibration_only | 0.953 | 0.622 | 0.924 | 0.971 | 2046.571 |
| P4_small_recent_update | 0.956 | 0.624 | 0.934 | 0.974 | 40 |

## Phase 7: Monitoring Triggers

| signal | threshold | event_definition | precision | recall | false_alarm_rate |
|---|---|---|---|---|---|
| project_jsd | 0.873 | recall<0.700 or drop>=0.100 | 0.000 | 0.000 | 0.571 |
| cwe_jsd | 0.324 | recall<0.700 or drop>=0.100 | 0.000 | 0.000 | 0.571 |
| token_jsd | 0.158 | recall<0.700 or drop>=0.100 | 0.000 | 0.000 | 0.571 |
| project_turnover | 0.933 | recall<0.700 or drop>=0.100 | 0.000 | 0.000 | 0.571 |
| cwe_turnover | 0.391 | recall<0.700 or drop>=0.100 | 0.000 | 0.000 | 0.571 |
| unseen_token_rate | 0.728 | recall<0.700 or drop>=0.100 | 0.000 | 0.000 | 0.571 |
| vocab_churn | 0.880 | recall<0.700 or drop>=0.100 | 0.000 | 0.000 | 0.571 |
| median_length_shift | 0.520 | recall<0.700 or drop>=0.100 | 0.000 | 0.000 | 0.571 |
| vulnerable_ratio_shift | -0.001 | recall<0.700 or drop>=0.100 | 0.000 | 0.000 | 0.571 |

## Phase 8: Statistical Summary

| model | first_test_recall | last_test_recall | absolute_recall_decay | worst_recall | mean_recall | absolute_f1_decay |
|---|---|---|---|---|---|---|
| char4_hash_logreg | 0.866 | 0.902 | -0.035 | 0.866 | 0.884 | -0.022 |
| code_metrics_logreg | 0.983 | 0.959 | 0.024 | 0.959 | 0.966 | -0.018 |
| frozen_hash_embedding_logreg | 0.875 | 0.844 | 0.031 | 0.844 | 0.873 | -0.007 |
| token_tfidf_logreg | 0.928 | 0.855 | 0.073 | 0.855 | 0.898 | -0.018 |

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

- `results/detector_aging_cvefixes_final/phase_1_feasibility.json`
- `results/detector_aging_cvefixes_final/phase_2_temporal_splits.json`
- `results/detector_aging_cvefixes_final/phase_3_4_fixed_origin_aging_metrics.csv`
- `results/detector_aging_cvefixes_final/phase_5_drift_metrics.csv`
- `results/detector_aging_cvefixes_final/phase_5_drift_source_ranking.csv`
- `results/detector_aging_cvefixes_final/phase_6_maintenance_policy_summary.csv`
- `results/detector_aging_cvefixes_final/phase_7_monitoring_triggers.csv`
- `results/detector_aging_cvefixes_final/phase_8_statistical_summary.csv`
