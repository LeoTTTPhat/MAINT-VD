# Detector Aging Phase 1-9 Report

## Scope

This report conducts the nine-phase detector-aging workflow for the currently
available local input.

Input mode: `external`.

If the input mode is `temporal_smoke`, the results verify the pipeline and
analysis design only. They must not be reported as empirical evidence about
real vulnerability detectors.

## Phase 1: Dataset Feasibility

- Valid rows: 4910
- Skipped rows: 0
- Years: 2003, 2005, 2006, 2007, 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017, 2018, 2019, 2020, 2021, 2022
- Go decision: `False`

## Phase 2: Temporal Splits

- Fixed-origin train years: 2003, 2005, 2006
- Validation year: 2007
- Future test years: 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017, 2018, 2019, 2020, 2021, 2022

Split manifests and JSONL files are written under `results/detector_aging_diversevul_test`.

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
| token_tfidf_logreg | 2008 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 |
| token_tfidf_logreg | 2009 | 0.000 | 0.000 | 0.000 | -0.066 | 1.000 |
| token_tfidf_logreg | 2010 | 0.059 | 0.500 | 0.105 | 0.111 | 0.500 |
| token_tfidf_logreg | 2011 | 0.080 | 0.200 | 0.114 | -0.024 | 0.800 |
| token_tfidf_logreg | 2012 | 0.000 | 0.000 | 0.000 | -0.067 | 1.000 |
| token_tfidf_logreg | 2013 | 0.000 | 0.000 | 0.000 | -0.117 | 1.000 |
| token_tfidf_logreg | 2014 | 0.032 | 0.061 | 0.042 | -0.067 | 0.939 |
| token_tfidf_logreg | 2015 | 0.037 | 0.053 | 0.043 | -0.071 | 0.947 |
| token_tfidf_logreg | 2016 | 0.073 | 0.103 | 0.086 | -0.047 | 0.897 |
| token_tfidf_logreg | 2017 | 0.034 | 0.054 | 0.042 | -0.107 | 0.946 |
| token_tfidf_logreg | 2018 | 0.033 | 0.071 | 0.045 | -0.057 | 0.929 |
| token_tfidf_logreg | 2019 | 0.000 | 0.000 | 0.000 | -0.124 | 1.000 |
| token_tfidf_logreg | 2020 | 0.042 | 0.071 | 0.053 | -0.043 | 0.929 |
| token_tfidf_logreg | 2021 | 0.037 | 0.150 | 0.059 | -0.030 | 0.850 |
| token_tfidf_logreg | 2022 | 0.116 | 0.167 | 0.137 | 0.060 | 0.833 |
| char4_hash_logreg | 2008 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 |
| char4_hash_logreg | 2009 | 0.000 | 0.000 | 0.000 | -0.154 | 1.000 |
| char4_hash_logreg | 2010 | 0.025 | 0.500 | 0.048 | -0.004 | 0.500 |
| char4_hash_logreg | 2011 | 0.106 | 0.500 | 0.175 | 0.042 | 0.500 |
| char4_hash_logreg | 2012 | 0.000 | 0.000 | 0.000 | -0.158 | 1.000 |
| char4_hash_logreg | 2013 | 0.015 | 0.133 | 0.027 | -0.196 | 0.867 |
| char4_hash_logreg | 2014 | 0.027 | 0.163 | 0.047 | -0.162 | 0.837 |
| char4_hash_logreg | 2015 | 0.051 | 0.289 | 0.087 | -0.137 | 0.711 |
| char4_hash_logreg | 2016 | 0.070 | 0.241 | 0.109 | -0.093 | 0.759 |

## Phase 5: Drift Source Analysis

Signals ranked by absolute correlation with recall drop for the primary aging
baseline, `token_tfidf_logreg`:

| signal | pearson_with_recall_drop |
|---|---|
| median_length_shift | 0.198 |
| cwe_turnover | 0.186 |
| project_turnover | -0.168 |
| token_jsd | 0.145 |
| unseen_token_rate | -0.107 |
| project_jsd | 0.099 |
| vocab_churn | 0.069 |
| cwe_jsd | -0.036 |
| vulnerable_ratio_shift | 0.011 |

## Phase 6: Maintenance Policy Evaluation

| policy | mean_recall | mean_f1 | recall_ci_low | recall_ci_high | mean_labeled_samples_used |
|---|---|---|---|---|---|
| P0_no_refresh | 0.095 | 0.048 | 0.043 | 0.165 | 0 |
| P1_cumulative_retrain | 0.396 | 0.120 | 0.249 | 0.576 | 297.867 |
| P2_sliding_3yr_retrain | 0.452 | 0.142 | 0.324 | 0.582 | 297.867 |
| P3_calibration_only | 0.203 | 0.057 | 0.129 | 0.278 | 297.867 |
| P4_small_recent_update | 0.104 | 0.093 | 0.055 | 0.164 | 297.867 |

## Phase 7: Monitoring Triggers

| signal | threshold | precision | recall | false_alarm_rate |
|---|---|---|---|---|
| project_jsd | 1.000 | 0.000 | 0.000 | 0.533 |
| cwe_jsd | 0.687 | 0.000 | 0.000 | 0.533 |
| token_jsd | 0.300 | 0.000 | 0.000 | 0.533 |
| project_turnover | 1.000 | 0.000 | 0.000 | 0.667 |
| cwe_turnover | 0.917 | 0.000 | 0.000 | 0.600 |
| unseen_token_rate | 0.964 | 0.000 | 0.000 | 0.533 |
| vocab_churn | 0.965 | 0.000 | 0.000 | 0.533 |
| median_length_shift | -0.247 | 0.000 | 0.000 | 0.533 |
| vulnerable_ratio_shift | 0.012 | 0.000 | 0.000 | 0.533 |

## Phase 8: Statistical Summary

| model | first_test_recall | last_test_recall | absolute_recall_decay | worst_recall | mean_recall | absolute_f1_decay |
|---|---|---|---|---|---|---|
| char4_hash_logreg | 0.000 | 0.167 | -0.167 | 0.000 | 0.220 | -0.057 |
| code_metrics_logreg | 0.000 | 0.133 | -0.133 | 0.000 | 0.363 | -0.047 |
| token_tfidf_logreg | 0.000 | 0.167 | -0.167 | 0.000 | 0.095 | -0.137 |

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

- `results/detector_aging_diversevul_test/phase_1_feasibility.json`
- `results/detector_aging_diversevul_test/phase_2_temporal_splits.json`
- `results/detector_aging_diversevul_test/phase_3_4_fixed_origin_aging_metrics.csv`
- `results/detector_aging_diversevul_test/phase_5_drift_metrics.csv`
- `results/detector_aging_diversevul_test/phase_5_drift_source_ranking.csv`
- `results/detector_aging_diversevul_test/phase_6_maintenance_policy_summary.csv`
- `results/detector_aging_diversevul_test/phase_7_monitoring_triggers.csv`
- `results/detector_aging_diversevul_test/phase_8_statistical_summary.csv`
