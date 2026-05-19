# Detector Aging Phase 1-9 Report

## Scope

This report conducts the nine-phase detector-aging workflow for the currently
available local input.

Input mode: `external`.

If the input mode is `temporal_smoke`, the results verify the pipeline and
analysis design only. They must not be reported as empirical evidence about
real vulnerability detectors.

## Phase 1: Dataset Feasibility

- Valid rows: 19018
- Skipped rows: 0
- Deduplication: exact_canonical_function; removed 0 duplicates
- Years: 1999, 2001, 2005, 2006, 2007, 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017, 2018, 2019, 2020, 2021, 2022, 2023, 2024
- Go decision: `True`
- Split warnings: 0

## Phase 2: Temporal Splits

- Fixed-origin train years: 2010, 2011, 2012, 2013, 2014, 2015, 2016
- Validation year: 2017
- Future test years: 2018, 2019, 2020, 2021, 2022, 2023, 2024

Split manifests and JSONL files are written under `results/detector_aging_cvefixes_ndcontrol`.

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
| token_tfidf_logreg | 2018 | 0.518 | 0.885 | 0.654 | 0.251 | 0.115 |
| token_tfidf_logreg | 2019 | 0.513 | 0.872 | 0.646 | 0.215 | 0.128 |
| token_tfidf_logreg | 2020 | 0.518 | 0.853 | 0.645 | 0.221 | 0.147 |
| token_tfidf_logreg | 2021 | 0.501 | 0.841 | 0.628 | 0.213 | 0.159 |
| token_tfidf_logreg | 2022 | 0.538 | 0.852 | 0.659 | 0.241 | 0.148 |
| token_tfidf_logreg | 2023 | 0.559 | 0.845 | 0.673 | 0.284 | 0.155 |
| token_tfidf_logreg | 2024 | 0.570 | 0.808 | 0.668 | 0.267 | 0.192 |
| char4_hash_logreg | 2018 | 0.466 | 0.868 | 0.607 | 0.075 | 0.132 |
| char4_hash_logreg | 2019 | 0.475 | 0.868 | 0.614 | 0.087 | 0.132 |
| char4_hash_logreg | 2020 | 0.472 | 0.881 | 0.615 | 0.085 | 0.119 |
| char4_hash_logreg | 2021 | 0.459 | 0.864 | 0.599 | 0.093 | 0.136 |
| char4_hash_logreg | 2022 | 0.488 | 0.892 | 0.631 | 0.105 | 0.108 |
| char4_hash_logreg | 2023 | 0.484 | 0.904 | 0.631 | 0.086 | 0.096 |
| char4_hash_logreg | 2024 | 0.490 | 0.899 | 0.634 | 0.062 | 0.101 |
| code_metrics_logreg | 2018 | 0.465 | 0.933 | 0.621 | 0.095 | 0.067 |
| code_metrics_logreg | 2019 | 0.470 | 0.928 | 0.624 | 0.088 | 0.072 |
| code_metrics_logreg | 2020 | 0.486 | 0.895 | 0.630 | 0.144 | 0.105 |
| code_metrics_logreg | 2021 | 0.463 | 0.897 | 0.611 | 0.122 | 0.103 |
| code_metrics_logreg | 2022 | 0.495 | 0.900 | 0.639 | 0.136 | 0.100 |
| code_metrics_logreg | 2023 | 0.508 | 0.891 | 0.647 | 0.172 | 0.109 |
| code_metrics_logreg | 2024 | 0.529 | 0.883 | 0.662 | 0.204 | 0.117 |
| frozen_hash_embedding_logreg | 2018 | 0.501 | 0.838 | 0.627 | 0.180 | 0.162 |
| frozen_hash_embedding_logreg | 2019 | 0.492 | 0.803 | 0.610 | 0.125 | 0.197 |
| frozen_hash_embedding_logreg | 2020 | 0.512 | 0.798 | 0.624 | 0.182 | 0.202 |

## Phase 5: Drift Source Analysis

Signals ranked by absolute correlation with recall drop for the primary aging
baseline, `char4_hash_logreg`:

| signal | pearson_with_recall_drop |
|---|---|
| vulnerable_ratio_shift | -0.899 |
| median_length_shift | -0.759 |
| cwe_turnover | -0.714 |
| project_jsd | -0.702 |
| project_turnover | -0.694 |
| unseen_token_rate | -0.616 |
| cwe_jsd | -0.479 |
| token_jsd | -0.399 |
| vocab_churn | 0.341 |

## Phase 6: Maintenance Policy Evaluation

| policy | mean_recall | mean_f1 | recall_ci_low | recall_ci_high | mean_labeled_samples_used |
|---|---|---|---|---|---|
| P0_no_refresh | 0.882 | 0.619 | 0.871 | 0.893 | 0 |
| P1_cumulative_retrain | 0.954 | 0.630 | 0.935 | 0.971 | 1948.429 |
| P2_sliding_3yr_retrain | 0.951 | 0.629 | 0.933 | 0.967 | 1948.429 |
| P3_calibration_only | 0.952 | 0.627 | 0.924 | 0.969 | 1948.429 |
| P4_small_recent_update | 0.961 | 0.629 | 0.938 | 0.978 | 40 |

## Phase 7: Monitoring Triggers

| signal | threshold | event_definition | precision | recall | false_alarm_rate |
|---|---|---|---|---|---|
| project_jsd | 0.870 | recall<0.700 or drop>=0.100 | 0.000 | 0.000 | 0.571 |
| cwe_jsd | 0.326 | recall<0.700 or drop>=0.100 | 0.000 | 0.000 | 0.571 |
| token_jsd | 0.159 | recall<0.700 or drop>=0.100 | 0.000 | 0.000 | 0.571 |
| project_turnover | 0.933 | recall<0.700 or drop>=0.100 | 0.000 | 0.000 | 0.571 |
| cwe_turnover | 0.397 | recall<0.700 or drop>=0.100 | 0.000 | 0.000 | 0.571 |
| unseen_token_rate | 0.706 | recall<0.700 or drop>=0.100 | 0.000 | 0.000 | 0.571 |
| vocab_churn | 0.880 | recall<0.700 or drop>=0.100 | 0.000 | 0.000 | 0.571 |
| median_length_shift | 0.387 | recall<0.700 or drop>=0.100 | 0.000 | 0.000 | 0.571 |
| vulnerable_ratio_shift | 0.001 | recall<0.700 or drop>=0.100 | 0.000 | 0.000 | 0.571 |

## Phase 8: Statistical Summary

| model | first_test_recall | last_test_recall | absolute_recall_decay | worst_recall | mean_recall | absolute_f1_decay |
|---|---|---|---|---|---|---|
| char4_hash_logreg | 0.868 | 0.899 | -0.031 | 0.864 | 0.882 | -0.027 |
| code_metrics_logreg | 0.933 | 0.883 | 0.050 | 0.883 | 0.904 | -0.041 |
| frozen_hash_embedding_logreg | 0.838 | 0.806 | 0.032 | 0.798 | 0.820 | -0.008 |
| token_tfidf_logreg | 0.885 | 0.808 | 0.078 | 0.808 | 0.851 | -0.015 |

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

- `results/detector_aging_cvefixes_ndcontrol/phase_1_feasibility.json`
- `results/detector_aging_cvefixes_ndcontrol/phase_2_temporal_splits.json`
- `results/detector_aging_cvefixes_ndcontrol/phase_3_4_fixed_origin_aging_metrics.csv`
- `results/detector_aging_cvefixes_ndcontrol/phase_5_drift_metrics.csv`
- `results/detector_aging_cvefixes_ndcontrol/phase_5_drift_source_ranking.csv`
- `results/detector_aging_cvefixes_ndcontrol/phase_6_maintenance_policy_summary.csv`
- `results/detector_aging_cvefixes_ndcontrol/phase_7_monitoring_triggers.csv`
- `results/detector_aging_cvefixes_ndcontrol/phase_8_statistical_summary.csv`
