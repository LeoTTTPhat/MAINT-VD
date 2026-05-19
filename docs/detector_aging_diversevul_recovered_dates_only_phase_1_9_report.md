# Detector Aging Phase 1-9 Report

## Scope

This report conducts the nine-phase detector-aging workflow for the currently
available local input.

Input mode: `external`.

If the input mode is `temporal_smoke`, the results verify the pipeline and
analysis design only. They must not be reported as empirical evidence about
real vulnerability detectors.

## Phase 1: Dataset Feasibility

- Valid rows: 37425
- Skipped rows: 0
- Deduplication: exact_canonical_function; removed 342 duplicates
- Years: 2005, 2007, 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017, 2018, 2019, 2020, 2021, 2022
- Go decision: `True`
- Split warnings: 0

## Phase 2: Temporal Splits

- Fixed-origin train years: 2009, 2010, 2011, 2012, 2013, 2014, 2015
- Validation year: 2016
- Future test years: 2017, 2018, 2019, 2020, 2021, 2022

Split manifests and JSONL files are written under `results/detector_aging_diversevul_recovered_dates_only`.

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
| token_tfidf_logreg | 2017 | 0.166 | 0.671 | 0.266 | 0.143 | 0.329 |
| token_tfidf_logreg | 2018 | 0.106 | 0.644 | 0.182 | 0.117 | 0.356 |
| token_tfidf_logreg | 2019 | 0.078 | 0.628 | 0.138 | 0.105 | 0.372 |
| token_tfidf_logreg | 2020 | 0.099 | 0.591 | 0.170 | 0.115 | 0.409 |
| token_tfidf_logreg | 2021 | 0.067 | 0.569 | 0.119 | 0.088 | 0.431 |
| token_tfidf_logreg | 2022 | 0.088 | 0.692 | 0.156 | 0.134 | 0.308 |
| char4_hash_logreg | 2017 | 0.219 | 0.668 | 0.329 | 0.234 | 0.332 |
| char4_hash_logreg | 2018 | 0.119 | 0.403 | 0.184 | 0.105 | 0.597 |
| char4_hash_logreg | 2019 | 0.094 | 0.527 | 0.159 | 0.126 | 0.473 |
| char4_hash_logreg | 2020 | 0.103 | 0.413 | 0.165 | 0.094 | 0.587 |
| char4_hash_logreg | 2021 | 0.075 | 0.424 | 0.127 | 0.088 | 0.576 |
| char4_hash_logreg | 2022 | 0.070 | 0.295 | 0.113 | 0.043 | 0.705 |
| code_metrics_logreg | 2017 | 0.214 | 0.733 | 0.331 | 0.245 | 0.267 |
| code_metrics_logreg | 2018 | 0.142 | 0.678 | 0.235 | 0.198 | 0.322 |
| code_metrics_logreg | 2019 | 0.120 | 0.721 | 0.206 | 0.211 | 0.279 |
| code_metrics_logreg | 2020 | 0.124 | 0.626 | 0.206 | 0.169 | 0.374 |
| code_metrics_logreg | 2021 | 0.089 | 0.587 | 0.154 | 0.141 | 0.413 |
| code_metrics_logreg | 2022 | 0.093 | 0.582 | 0.160 | 0.127 | 0.418 |
| frozen_hash_embedding_logreg | 2017 | 0.181 | 0.322 | 0.232 | 0.101 | 0.678 |
| frozen_hash_embedding_logreg | 2018 | 0.153 | 0.376 | 0.217 | 0.146 | 0.624 |
| frozen_hash_embedding_logreg | 2019 | 0.103 | 0.381 | 0.162 | 0.115 | 0.619 |
| frozen_hash_embedding_logreg | 2020 | 0.129 | 0.370 | 0.192 | 0.127 | 0.630 |
| frozen_hash_embedding_logreg | 2021 | 0.080 | 0.312 | 0.127 | 0.081 | 0.688 |
| frozen_hash_embedding_logreg | 2022 | 0.097 | 0.312 | 0.148 | 0.091 | 0.688 |

## Phase 5: Drift Source Analysis

Signals ranked by absolute correlation with recall drop for the primary aging
baseline, `char4_hash_logreg`:

| signal | pearson_with_recall_drop |
|---|---|
| vulnerable_ratio_shift | -0.728 |
| cwe_turnover | 0.704 |
| cwe_jsd | 0.366 |
| unseen_token_rate | 0.358 |
| token_jsd | 0.345 |
| vocab_churn | 0.284 |
| project_jsd | -0.253 |
| project_turnover | -0.158 |
| median_length_shift | 0.145 |

## Phase 6: Maintenance Policy Evaluation

| policy | mean_recall | mean_f1 | recall_ci_low | recall_ci_high | mean_labeled_samples_used |
|---|---|---|---|---|---|
| P0_no_refresh | 0.455 | 0.180 | 0.373 | 0.558 | 0 |
| P1_cumulative_retrain | 0.360 | 0.192 | 0.265 | 0.477 | 3578 |
| P2_sliding_3yr_retrain | 0.407 | 0.188 | 0.321 | 0.489 | 3578 |
| P3_calibration_only | 0.385 | 0.171 | 0.229 | 0.542 | 3578 |
| P4_small_recent_update | 0.295 | 0.180 | 0.208 | 0.426 | 40 |

## Phase 7: Monitoring Triggers

| signal | threshold | event_definition | precision | recall | false_alarm_rate |
|---|---|---|---|---|---|
| project_jsd | 0.610 | recall<0.700 or drop>=0.100 | 1.000 | 0.500 | 0.000 |
| cwe_jsd | 0.611 | recall<0.700 or drop>=0.100 | 1.000 | 0.500 | 0.000 |
| token_jsd | 0.170 | recall<0.700 or drop>=0.100 | 1.000 | 0.500 | 0.000 |
| project_turnover | 0.770 | recall<0.700 or drop>=0.100 | 1.000 | 0.500 | 0.000 |
| cwe_turnover | 0.481 | recall<0.700 or drop>=0.100 | 1.000 | 0.500 | 0.000 |
| unseen_token_rate | 0.728 | recall<0.700 or drop>=0.100 | 1.000 | 0.500 | 0.000 |
| vocab_churn | 0.903 | recall<0.700 or drop>=0.100 | 1.000 | 0.500 | 0.000 |
| median_length_shift | 0.230 | recall<0.700 or drop>=0.100 | 1.000 | 0.500 | 0.000 |
| vulnerable_ratio_shift | -0.002 | recall<0.700 or drop>=0.100 | 1.000 | 0.500 | 0.000 |

## Phase 8: Statistical Summary

| model | first_test_recall | last_test_recall | absolute_recall_decay | worst_recall | mean_recall | absolute_f1_decay |
|---|---|---|---|---|---|---|
| char4_hash_logreg | 0.668 | 0.295 | 0.372 | 0.295 | 0.455 | 0.216 |
| code_metrics_logreg | 0.733 | 0.582 | 0.151 | 0.582 | 0.655 | 0.172 |
| frozen_hash_embedding_logreg | 0.322 | 0.312 | 0.010 | 0.312 | 0.345 | 0.083 |
| token_tfidf_logreg | 0.671 | 0.692 | -0.021 | 0.569 | 0.633 | 0.110 |

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

- `results/detector_aging_diversevul_recovered_dates_only/phase_1_feasibility.json`
- `results/detector_aging_diversevul_recovered_dates_only/phase_2_temporal_splits.json`
- `results/detector_aging_diversevul_recovered_dates_only/phase_3_4_fixed_origin_aging_metrics.csv`
- `results/detector_aging_diversevul_recovered_dates_only/phase_5_drift_metrics.csv`
- `results/detector_aging_diversevul_recovered_dates_only/phase_5_drift_source_ranking.csv`
- `results/detector_aging_diversevul_recovered_dates_only/phase_6_maintenance_policy_summary.csv`
- `results/detector_aging_diversevul_recovered_dates_only/phase_7_monitoring_triggers.csv`
- `results/detector_aging_diversevul_recovered_dates_only/phase_8_statistical_summary.csv`
