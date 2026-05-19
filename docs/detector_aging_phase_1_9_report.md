# Detector Aging Phase 1-9 Report

## Scope

This report conducts the nine-phase detector-aging workflow for the currently
available local input.

Input mode: `external`.

If the input mode is `temporal_smoke`, the results verify the pipeline and
analysis design only. They must not be reported as empirical evidence about
real vulnerability detectors.

## Phase 1: Dataset Feasibility

- Valid rows: 106
- Skipped rows: 0
- Years: 2014, 2015, 2016, 2017, 2018, 2019, 2020, 2021, 2022, 2023, 2024
- Go decision: `True`

## Phase 2: Temporal Splits

- Fixed-origin train years: 2014, 2015, 2016
- Validation year: 2017
- Future test years: 2018, 2019, 2020, 2021, 2022, 2023, 2024

Split manifests and JSONL files are written under `results/detector_aging_cvefixes`.

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
| token_tfidf_logreg | 2018 | 0.500 | 1.000 | 0.667 | 0.000 | 0.000 |
| token_tfidf_logreg | 2019 | 0.500 | 0.500 | 0.500 | 0.000 | 0.500 |
| token_tfidf_logreg | 2020 | 0.500 | 1.000 | 0.667 | 0.408 | 0.000 |
| token_tfidf_logreg | 2021 | 0.444 | 0.800 | 0.571 | -0.043 | 0.200 |
| token_tfidf_logreg | 2022 | 0.455 | 1.000 | 0.625 | 0.255 | 0.000 |
| token_tfidf_logreg | 2023 | 0.467 | 0.875 | 0.609 | 0.100 | 0.125 |
| token_tfidf_logreg | 2024 | 0.444 | 0.800 | 0.571 | -0.333 | 0.200 |
| char4_hash_logreg | 2018 | 0.500 | 1.000 | 0.667 | 0.000 | 0.000 |
| char4_hash_logreg | 2019 | 0.000 | 0.000 | 0.000 | 0.000 | 1.000 |
| char4_hash_logreg | 2020 | 0.500 | 0.500 | 0.500 | 0.167 | 0.500 |
| char4_hash_logreg | 2021 | 0.333 | 0.600 | 0.429 | -0.516 | 0.400 |
| char4_hash_logreg | 2022 | 0.375 | 0.600 | 0.462 | -0.120 | 0.400 |
| char4_hash_logreg | 2023 | 0.417 | 0.625 | 0.500 | -0.079 | 0.375 |
| char4_hash_logreg | 2024 | 0.571 | 0.800 | 0.667 | 0.218 | 0.200 |
| code_metrics_logreg | 2018 | 0.500 | 1.000 | 0.667 | 0.000 | 0.000 |
| code_metrics_logreg | 2019 | 0.333 | 0.500 | 0.400 | -0.577 | 0.500 |
| code_metrics_logreg | 2020 | 0.400 | 1.000 | 0.571 | 0.000 | 0.000 |
| code_metrics_logreg | 2021 | 0.600 | 0.600 | 0.600 | 0.267 | 0.400 |
| code_metrics_logreg | 2022 | 0.429 | 0.600 | 0.500 | 0.029 | 0.400 |
| code_metrics_logreg | 2023 | 0.625 | 0.625 | 0.625 | 0.325 | 0.375 |
| code_metrics_logreg | 2024 | 0.600 | 0.600 | 0.600 | 0.200 | 0.400 |

## Phase 5: Drift Source Analysis

Signals ranked by absolute correlation with recall drop for the primary aging
baseline, `char4_hash_logreg`:

| signal | pearson_with_recall_drop |
|---|---|
| unseen_token_rate | 0.429 |
| token_jsd | -0.288 |
| vocab_churn | 0.227 |
| project_jsd | -0.128 |
| project_turnover | -0.128 |
| median_length_shift | -0.094 |
| vulnerable_ratio_shift | -0.072 |
| cwe_jsd | 0.053 |
| cwe_turnover | 0.047 |

## Phase 6: Maintenance Policy Evaluation

| policy | mean_recall | mean_f1 | recall_ci_low | recall_ci_high | mean_labeled_samples_used |
|---|---|---|---|---|---|
| P0_no_refresh | 0.589 | 0.460 | 0.361 | 0.771 | 0 |
| P1_cumulative_retrain | 0.554 | 0.428 | 0.325 | 0.782 | 7.714 |
| P2_sliding_3yr_retrain | 0.643 | 0.524 | 0.371 | 0.886 | 7.714 |
| P3_calibration_only | 0.561 | 0.447 | 0.329 | 0.746 | 7.714 |
| P4_small_recent_update | 0.646 | 0.498 | 0.432 | 0.857 | 7.714 |

## Phase 7: Monitoring Triggers

| signal | threshold | precision | recall | false_alarm_rate |
|---|---|---|---|---|
| project_jsd | 1.000 | 0.833 | 0.833 | 1.000 |
| project_turnover | 1.000 | 0.833 | 0.833 | 1.000 |
| unseen_token_rate | 0.585 | 1.000 | 0.667 | 0.000 |
| median_length_shift | -0.603 | 1.000 | 0.667 | 0.000 |
| cwe_jsd | 1.000 | 0.750 | 0.500 | 1.000 |
| token_jsd | 0.418 | 0.750 | 0.500 | 1.000 |
| cwe_turnover | 1.000 | 0.750 | 0.500 | 1.000 |
| vocab_churn | 0.918 | 0.750 | 0.500 | 1.000 |
| vulnerable_ratio_shift | -0.022 | 0.750 | 0.500 | 1.000 |

## Phase 8: Statistical Summary

| model | first_test_recall | last_test_recall | absolute_recall_decay | worst_recall | mean_recall | absolute_f1_decay |
|---|---|---|---|---|---|---|
| char4_hash_logreg | 1.000 | 0.800 | 0.200 | 0.000 | 0.589 | 0.000 |
| code_metrics_logreg | 1.000 | 0.600 | 0.400 | 0.500 | 0.704 | 0.067 |
| token_tfidf_logreg | 1.000 | 0.800 | 0.200 | 0.500 | 0.854 | 0.095 |

## Phase 9: Paper Assembly Notes

The current artifacts are enough to assemble the empirical tables and figures
once a real temporal vulnerability dataset is provided. For an IST submission,
replace the smoke dataset with CVEfixes, DiverseVul with reliable commit dates,
or Big-Vul with verified temporal metadata.

Required before claiming empirical findings:

- use real date-bearing vulnerability records,
- add a frozen code embedding detector,
- add a transformer vulnerability detector,
- repeat duplicate and leakage checks on the real dataset,
- turn CSV tables into final manuscript tables/figures.

## Artifact Index

- `results/detector_aging_cvefixes/phase_1_feasibility.json`
- `results/detector_aging_cvefixes/phase_2_temporal_splits.json`
- `results/detector_aging_cvefixes/phase_3_4_fixed_origin_aging_metrics.csv`
- `results/detector_aging_cvefixes/phase_5_drift_metrics.csv`
- `results/detector_aging_cvefixes/phase_5_drift_source_ranking.csv`
- `results/detector_aging_cvefixes/phase_6_maintenance_policy_summary.csv`
- `results/detector_aging_cvefixes/phase_7_monitoring_triggers.csv`
- `results/detector_aging_cvefixes/phase_8_statistical_summary.csv`
