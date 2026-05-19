# Detector Aging Phase 1-9 Report

## Scope

This report conducts the nine-phase detector-aging workflow for the currently
available local input.

Input mode: `external`.

If the input mode is `temporal_smoke`, the results verify the pipeline and
analysis design only. They must not be reported as empirical evidence about
real vulnerability detectors.

## Phase 1: Dataset Feasibility

- Valid rows: 34
- Skipped rows: 0
- Years: 2009, 2010, 2011, 2012, 2014, 2015, 2016, 2017, 2018, 2019, 2020, 2021, 2022
- Go decision: `False`

## Phase 2: Temporal Splits

- Fixed-origin train years: 2009, 2010, 2011
- Validation year: 2012
- Future test years: 2014, 2015, 2016, 2017, 2018, 2019, 2020, 2021, 2022

Split manifests and JSONL files are written under `results/detector_aging_diversevul`.

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
| token_tfidf_logreg | 2014 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 |
| token_tfidf_logreg | 2015 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 |
| token_tfidf_logreg | 2016 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 |
| token_tfidf_logreg | 2017 | 0.333 | 1.000 | 0.500 | 0.000 | 0.000 |
| token_tfidf_logreg | 2018 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 |
| token_tfidf_logreg | 2019 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 |
| token_tfidf_logreg | 2020 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 |
| token_tfidf_logreg | 2021 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 |
| token_tfidf_logreg | 2022 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 |
| char4_hash_logreg | 2014 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 |
| char4_hash_logreg | 2015 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 |
| char4_hash_logreg | 2016 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 |
| char4_hash_logreg | 2017 | 0.333 | 1.000 | 0.500 | 0.000 | 0.000 |
| char4_hash_logreg | 2018 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 |
| char4_hash_logreg | 2019 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 |
| char4_hash_logreg | 2020 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 |
| char4_hash_logreg | 2021 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 |
| char4_hash_logreg | 2022 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 |
| code_metrics_logreg | 2014 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 |
| code_metrics_logreg | 2015 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 |
| code_metrics_logreg | 2016 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 |
| code_metrics_logreg | 2017 | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 |
| code_metrics_logreg | 2018 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 |
| code_metrics_logreg | 2019 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 |

## Phase 5: Drift Source Analysis

Signals ranked by absolute correlation with recall drop for the primary aging
baseline, `token_tfidf_logreg`:

| signal | pearson_with_recall_drop |
|---|---|
| vulnerable_ratio_shift | -1.000 |
| vocab_churn | -0.375 |
| unseen_token_rate | -0.330 |
| cwe_jsd | 0.284 |
| token_jsd | 0.201 |
| median_length_shift | 0.147 |
| cwe_turnover | 0.117 |
| project_jsd | 0.000 |
| project_turnover | 0.000 |

## Phase 6: Maintenance Policy Evaluation

| policy | mean_recall | mean_f1 | recall_ci_low | recall_ci_high | mean_labeled_samples_used |
|---|---|---|---|---|---|
| P0_no_refresh | 0.111 | 0.056 | 0.000 | 0.333 | 0 |
| P1_cumulative_retrain | 0.111 | 0.056 | 0.000 | 0.333 | 2.778 |
| P2_sliding_3yr_retrain | 0.000 | 0.000 | 0.000 | 0.000 | 2.778 |
| P3_calibration_only | 0.111 | 0.056 | 0.000 | 0.333 | 2.778 |
| P4_small_recent_update | 0.111 | 0.074 | 0.000 | 0.333 | 2.778 |

## Phase 7: Monitoring Triggers

| signal | threshold | precision | recall | false_alarm_rate |
|---|---|---|---|---|
| project_jsd | 1.000 | 0.000 | 0.000 | 1.000 |
| cwe_jsd | 1.000 | 0.000 | 0.000 | 0.556 |
| token_jsd | 0.401 | 0.000 | 0.000 | 0.556 |
| project_turnover | 1.000 | 0.000 | 0.000 | 1.000 |
| cwe_turnover | 1.000 | 0.000 | 0.000 | 0.556 |
| unseen_token_rate | 0.855 | 0.000 | 0.000 | 0.556 |
| vocab_churn | 0.901 | 0.000 | 0.000 | 0.556 |
| median_length_shift | -0.455 | 0.000 | 0.000 | 0.556 |
| vulnerable_ratio_shift | -0.333 | 0.000 | 0.000 | 1.000 |

## Phase 8: Statistical Summary

| model | first_test_recall | last_test_recall | absolute_recall_decay | worst_recall | mean_recall | absolute_f1_decay |
|---|---|---|---|---|---|---|
| char4_hash_logreg | 0.000 | 0.000 | 0.000 | 0.000 | 0.111 | 0.000 |
| code_metrics_logreg | 0.000 | 0.000 | 0.000 | 0.000 | 0.111 | 0.000 |
| token_tfidf_logreg | 0.000 | 0.000 | 0.000 | 0.000 | 0.111 | 0.000 |

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

- `results/detector_aging_diversevul/phase_1_feasibility.json`
- `results/detector_aging_diversevul/phase_2_temporal_splits.json`
- `results/detector_aging_diversevul/phase_3_4_fixed_origin_aging_metrics.csv`
- `results/detector_aging_diversevul/phase_5_drift_metrics.csv`
- `results/detector_aging_diversevul/phase_5_drift_source_ranking.csv`
- `results/detector_aging_diversevul/phase_6_maintenance_policy_summary.csv`
- `results/detector_aging_diversevul/phase_7_monitoring_triggers.csv`
- `results/detector_aging_diversevul/phase_8_statistical_summary.csv`
