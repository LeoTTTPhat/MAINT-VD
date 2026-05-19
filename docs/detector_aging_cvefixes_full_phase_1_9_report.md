# Detector Aging Phase 1-9 Report

## Scope

This report conducts the nine-phase detector-aging workflow for the currently
available local input.

Input mode: `external`.

If the input mode is `temporal_smoke`, the results verify the pipeline and
analysis design only. They must not be reported as empirical evidence about
real vulnerability detectors.

## Phase 1: Dataset Feasibility

- Valid rows: 22060
- Skipped rows: 0
- Years: 1999, 2001, 2005, 2006, 2007, 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017, 2018, 2019, 2020, 2021, 2022, 2023, 2024
- Go decision: `True`

## Phase 2: Temporal Splits

- Fixed-origin train years: 1999, 2001, 2005
- Validation year: 2006
- Future test years: 2007, 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017, 2018, 2019, 2020, 2021, 2022, 2023, 2024

Split manifests and JSONL files are written under `results/detector_aging_cvefixes_full`.

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
| token_tfidf_logreg | 2007 | 0.667 | 0.286 | 0.400 | 0.200 | 0.714 |
| token_tfidf_logreg | 2008 | 0.647 | 0.688 | 0.667 | 0.335 | 0.312 |
| token_tfidf_logreg | 2009 | 0.333 | 0.273 | 0.300 | -0.161 | 0.727 |
| token_tfidf_logreg | 2010 | 0.438 | 0.378 | 0.406 | -0.022 | 0.622 |
| token_tfidf_logreg | 2011 | 0.473 | 0.413 | 0.441 | 0.033 | 0.587 |
| token_tfidf_logreg | 2012 | 0.485 | 0.362 | 0.414 | 0.053 | 0.638 |
| token_tfidf_logreg | 2013 | 0.440 | 0.421 | 0.430 | -0.010 | 0.579 |
| token_tfidf_logreg | 2014 | 0.534 | 0.454 | 0.491 | 0.123 | 0.546 |
| token_tfidf_logreg | 2015 | 0.510 | 0.458 | 0.483 | 0.070 | 0.542 |
| token_tfidf_logreg | 2016 | 0.492 | 0.382 | 0.430 | 0.042 | 0.618 |
| token_tfidf_logreg | 2017 | 0.485 | 0.412 | 0.445 | 0.052 | 0.588 |
| token_tfidf_logreg | 2018 | 0.473 | 0.380 | 0.422 | 0.031 | 0.620 |
| token_tfidf_logreg | 2019 | 0.505 | 0.393 | 0.442 | 0.067 | 0.607 |
| token_tfidf_logreg | 2020 | 0.503 | 0.463 | 0.482 | 0.082 | 0.537 |
| token_tfidf_logreg | 2021 | 0.485 | 0.478 | 0.481 | 0.083 | 0.522 |
| token_tfidf_logreg | 2022 | 0.483 | 0.496 | 0.490 | 0.034 | 0.504 |
| token_tfidf_logreg | 2023 | 0.503 | 0.537 | 0.519 | 0.076 | 0.463 |
| token_tfidf_logreg | 2024 | 0.502 | 0.524 | 0.513 | 0.064 | 0.476 |
| char4_hash_logreg | 2007 | 0.800 | 0.571 | 0.667 | 0.472 | 0.429 |
| char4_hash_logreg | 2008 | 0.481 | 0.812 | 0.605 | -0.014 | 0.188 |
| char4_hash_logreg | 2009 | 0.526 | 0.909 | 0.667 | 0.309 | 0.091 |
| char4_hash_logreg | 2010 | 0.431 | 0.595 | 0.500 | -0.051 | 0.405 |
| char4_hash_logreg | 2011 | 0.449 | 0.510 | 0.477 | -0.006 | 0.490 |
| char4_hash_logreg | 2012 | 0.450 | 0.546 | 0.494 | 0.006 | 0.454 |

## Phase 5: Drift Source Analysis

Signals ranked by absolute correlation with recall drop for the primary aging
baseline, `char4_hash_logreg`:

| signal | pearson_with_recall_drop |
|---|---|
| token_jsd | -0.868 |
| unseen_token_rate | 0.699 |
| cwe_turnover | 0.632 |
| vocab_churn | 0.572 |
| median_length_shift | -0.560 |
| cwe_jsd | -0.360 |
| project_jsd | -0.158 |
| project_turnover | -0.157 |
| vulnerable_ratio_shift | -0.041 |

## Phase 6: Maintenance Policy Evaluation

| policy | mean_recall | mean_f1 | recall_ci_low | recall_ci_high | mean_labeled_samples_used |
|---|---|---|---|---|---|
| P0_no_refresh | 0.562 | 0.510 | 0.519 | 0.626 | 0 |
| P1_cumulative_retrain | 0.857 | 0.614 | 0.790 | 0.916 | 1140.278 |
| P2_sliding_3yr_retrain | 0.791 | 0.593 | 0.691 | 0.872 | 1140.278 |
| P3_calibration_only | 0.633 | 0.540 | 0.589 | 0.685 | 1140.278 |
| P4_small_recent_update | 0.819 | 0.618 | 0.773 | 0.861 | 1140.278 |

## Phase 7: Monitoring Triggers

| signal | threshold | precision | recall | false_alarm_rate |
|---|---|---|---|---|
| project_jsd | 1.000 | 0.000 | 0.000 | 0.722 |
| cwe_jsd | 0.730 | 0.000 | 0.000 | 0.500 |
| token_jsd | 0.402 | 0.000 | 0.000 | 0.500 |
| project_turnover | 1.000 | 0.000 | 0.000 | 0.889 |
| cwe_turnover | 0.952 | 0.000 | 0.000 | 0.500 |
| unseen_token_rate | 0.961 | 0.000 | 0.000 | 0.500 |
| vocab_churn | 0.962 | 0.000 | 0.000 | 0.500 |
| median_length_shift | 3.354 | 0.000 | 0.000 | 0.500 |
| vulnerable_ratio_shift | 0.012 | 0.000 | 0.000 | 0.500 |

## Phase 8: Statistical Summary

| model | first_test_recall | last_test_recall | absolute_recall_decay | worst_recall | mean_recall | absolute_f1_decay |
|---|---|---|---|---|---|---|
| char4_hash_logreg | 0.571 | 0.506 | 0.066 | 0.478 | 0.562 | 0.183 |
| code_metrics_logreg | 0.714 | 0.816 | -0.101 | 0.703 | 0.762 | 0.006 |
| token_tfidf_logreg | 0.286 | 0.524 | -0.238 | 0.273 | 0.433 | -0.113 |

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

- `results/detector_aging_cvefixes_full/phase_1_feasibility.json`
- `results/detector_aging_cvefixes_full/phase_2_temporal_splits.json`
- `results/detector_aging_cvefixes_full/phase_3_4_fixed_origin_aging_metrics.csv`
- `results/detector_aging_cvefixes_full/phase_5_drift_metrics.csv`
- `results/detector_aging_cvefixes_full/phase_5_drift_source_ranking.csv`
- `results/detector_aging_cvefixes_full/phase_6_maintenance_policy_summary.csv`
- `results/detector_aging_cvefixes_full/phase_7_monitoring_triggers.csv`
- `results/detector_aging_cvefixes_full/phase_8_statistical_summary.csv`
