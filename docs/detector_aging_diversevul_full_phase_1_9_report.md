# Detector Aging Phase 1-9 Report

## Scope

This report conducts the nine-phase detector-aging workflow for the currently
available local input.

Input mode: `external`.

If the input mode is `temporal_smoke`, the results verify the pipeline and
analysis design only. They must not be reported as empirical evidence about
real vulnerability detectors.

## Phase 1: Dataset Feasibility

- Valid rows: 48245
- Skipped rows: 0
- Years: 2002, 2003, 2005, 2006, 2007, 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017, 2018, 2019, 2020, 2021, 2022
- Go decision: `True`

## Phase 2: Temporal Splits

- Fixed-origin train years: 2002, 2003, 2005
- Validation year: 2006
- Future test years: 2007, 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017, 2018, 2019, 2020, 2021, 2022

Split manifests and JSONL files are written under `results/detector_aging_diversevul_full`.

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
| token_tfidf_logreg | 2007 | 0.037 | 0.048 | 0.042 | -0.143 | 0.952 |
| token_tfidf_logreg | 2008 | 0.286 | 0.182 | 0.222 | 0.166 | 0.818 |
| token_tfidf_logreg | 2009 | 0.156 | 0.417 | 0.227 | 0.214 | 0.583 |
| token_tfidf_logreg | 2010 | 0.050 | 0.172 | 0.078 | 0.028 | 0.828 |
| token_tfidf_logreg | 2011 | 0.112 | 0.165 | 0.133 | 0.039 | 0.835 |
| token_tfidf_logreg | 2012 | 0.167 | 0.205 | 0.184 | 0.143 | 0.795 |
| token_tfidf_logreg | 2013 | 0.109 | 0.182 | 0.136 | 0.069 | 0.818 |
| token_tfidf_logreg | 2014 | 0.217 | 0.246 | 0.230 | 0.175 | 0.754 |
| token_tfidf_logreg | 2015 | 0.135 | 0.130 | 0.132 | 0.058 | 0.870 |
| token_tfidf_logreg | 2016 | 0.169 | 0.151 | 0.159 | 0.078 | 0.849 |
| token_tfidf_logreg | 2017 | 0.200 | 0.188 | 0.194 | 0.097 | 0.812 |
| token_tfidf_logreg | 2018 | 0.148 | 0.194 | 0.168 | 0.092 | 0.806 |
| token_tfidf_logreg | 2019 | 0.109 | 0.150 | 0.127 | 0.074 | 0.850 |
| token_tfidf_logreg | 2020 | 0.103 | 0.157 | 0.125 | 0.062 | 0.843 |
| token_tfidf_logreg | 2021 | 0.099 | 0.131 | 0.113 | 0.065 | 0.869 |
| token_tfidf_logreg | 2022 | 0.116 | 0.088 | 0.100 | 0.045 | 0.912 |
| char4_hash_logreg | 2007 | 0.222 | 0.286 | 0.250 | 0.108 | 0.714 |
| char4_hash_logreg | 2008 | 0.000 | 0.000 | 0.000 | -0.081 | 1.000 |
| char4_hash_logreg | 2009 | 0.077 | 0.333 | 0.125 | 0.100 | 0.667 |
| char4_hash_logreg | 2010 | 0.060 | 0.172 | 0.089 | 0.044 | 0.828 |
| char4_hash_logreg | 2011 | 0.139 | 0.184 | 0.158 | 0.071 | 0.816 |
| char4_hash_logreg | 2012 | 0.051 | 0.091 | 0.065 | 0.010 | 0.909 |
| char4_hash_logreg | 2013 | 0.083 | 0.135 | 0.103 | 0.032 | 0.865 |
| char4_hash_logreg | 2014 | 0.091 | 0.217 | 0.128 | 0.048 | 0.783 |

## Phase 5: Drift Source Analysis

Signals ranked by absolute correlation with recall drop for the primary aging
baseline, `char4_hash_logreg`:

| signal | pearson_with_recall_drop |
|---|---|
| cwe_jsd | 0.458 |
| vulnerable_ratio_shift | -0.294 |
| cwe_turnover | -0.151 |
| project_turnover | -0.120 |
| unseen_token_rate | -0.075 |
| median_length_shift | -0.070 |
| project_jsd | 0.063 |
| vocab_churn | -0.037 |
| token_jsd | -0.011 |

## Phase 6: Maintenance Policy Evaluation

| policy | mean_recall | mean_f1 | recall_ci_low | recall_ci_high | mean_labeled_samples_used |
|---|---|---|---|---|---|
| P0_no_refresh | 0.186 | 0.123 | 0.145 | 0.232 | 0 |
| P1_cumulative_retrain | 0.344 | 0.152 | 0.264 | 0.431 | 2746.125 |
| P2_sliding_3yr_retrain | 0.353 | 0.156 | 0.277 | 0.429 | 2746.125 |
| P3_calibration_only | 0.253 | 0.129 | 0.198 | 0.311 | 2746.125 |
| P4_small_recent_update | 0.227 | 0.146 | 0.169 | 0.279 | 2746.125 |

## Phase 7: Monitoring Triggers

| signal | threshold | precision | recall | false_alarm_rate |
|---|---|---|---|---|
| cwe_jsd | 0.672 | 0.875 | 0.700 | 0.167 |
| project_jsd | 0.988 | 0.750 | 0.600 | 0.333 |
| project_turnover | 0.980 | 0.750 | 0.600 | 0.333 |
| token_jsd | 0.250 | 0.625 | 0.500 | 0.500 |
| cwe_turnover | 0.875 | 0.625 | 0.500 | 0.500 |
| unseen_token_rate | 0.964 | 0.625 | 0.500 | 0.500 |
| vocab_churn | 0.965 | 0.625 | 0.500 | 0.500 |
| median_length_shift | -0.402 | 0.625 | 0.500 | 0.500 |
| vulnerable_ratio_shift | 0.022 | 0.500 | 0.400 | 0.667 |

## Phase 8: Statistical Summary

| model | first_test_recall | last_test_recall | absolute_recall_decay | worst_recall | mean_recall | absolute_f1_decay |
|---|---|---|---|---|---|---|
| char4_hash_logreg | 0.286 | 0.184 | 0.102 | 0.000 | 0.186 | 0.107 |
| code_metrics_logreg | 0.190 | 0.131 | 0.060 | 0.083 | 0.165 | 0.068 |
| token_tfidf_logreg | 0.048 | 0.088 | -0.041 | 0.048 | 0.175 | -0.059 |

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

- `results/detector_aging_diversevul_full/phase_1_feasibility.json`
- `results/detector_aging_diversevul_full/phase_2_temporal_splits.json`
- `results/detector_aging_diversevul_full/phase_3_4_fixed_origin_aging_metrics.csv`
- `results/detector_aging_diversevul_full/phase_5_drift_metrics.csv`
- `results/detector_aging_diversevul_full/phase_5_drift_source_ranking.csv`
- `results/detector_aging_diversevul_full/phase_6_maintenance_policy_summary.csv`
- `results/detector_aging_diversevul_full/phase_7_monitoring_triggers.csv`
- `results/detector_aging_diversevul_full/phase_8_statistical_summary.csv`
