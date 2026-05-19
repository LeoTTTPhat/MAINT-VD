# Detector Aging Phase 1-9 Report

## Scope

This report conducts the nine-phase detector-aging workflow for the currently
available local input.

Input mode: `external`.

If the input mode is `temporal_smoke`, the results verify the pipeline and
analysis design only. They must not be reported as empirical evidence about
real vulnerability detectors.

## Phase 1: Dataset Feasibility

- Valid rows: 47841
- Skipped rows: 0
- Deduplication: exact_canonical_function; removed 404 duplicates
- Years: 2003, 2005, 2007, 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017, 2018, 2019, 2020, 2021, 2022
- Go decision: `True`
- Split warnings: 0

## Phase 2: Temporal Splits

- Fixed-origin train years: 2009, 2010, 2011, 2012, 2013, 2014, 2015
- Validation year: 2016
- Future test years: 2017, 2018, 2019, 2020, 2021, 2022

Split manifests and JSONL files are written under `results/detector_aging_diversevul_commit_dates_http`.

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
| token_tfidf_logreg | 2017 | 0.151 | 0.678 | 0.247 | 0.151 | 0.322 |
| token_tfidf_logreg | 2018 | 0.107 | 0.663 | 0.184 | 0.131 | 0.337 |
| token_tfidf_logreg | 2019 | 0.089 | 0.574 | 0.155 | 0.109 | 0.426 |
| token_tfidf_logreg | 2020 | 0.092 | 0.581 | 0.159 | 0.108 | 0.419 |
| token_tfidf_logreg | 2021 | 0.065 | 0.509 | 0.116 | 0.071 | 0.491 |
| token_tfidf_logreg | 2022 | 0.081 | 0.595 | 0.143 | 0.089 | 0.405 |
| char4_hash_logreg | 2017 | 0.168 | 0.605 | 0.263 | 0.168 | 0.395 |
| char4_hash_logreg | 2018 | 0.113 | 0.500 | 0.185 | 0.117 | 0.500 |
| char4_hash_logreg | 2019 | 0.094 | 0.483 | 0.157 | 0.104 | 0.517 |
| char4_hash_logreg | 2020 | 0.097 | 0.483 | 0.162 | 0.104 | 0.517 |
| char4_hash_logreg | 2021 | 0.076 | 0.439 | 0.129 | 0.087 | 0.561 |
| char4_hash_logreg | 2022 | 0.091 | 0.431 | 0.150 | 0.088 | 0.569 |
| code_metrics_logreg | 2017 | 0.197 | 0.678 | 0.306 | 0.233 | 0.322 |
| code_metrics_logreg | 2018 | 0.145 | 0.647 | 0.237 | 0.201 | 0.353 |
| code_metrics_logreg | 2019 | 0.124 | 0.565 | 0.203 | 0.173 | 0.435 |
| code_metrics_logreg | 2020 | 0.121 | 0.596 | 0.201 | 0.168 | 0.404 |
| code_metrics_logreg | 2021 | 0.098 | 0.541 | 0.166 | 0.147 | 0.459 |
| code_metrics_logreg | 2022 | 0.108 | 0.582 | 0.182 | 0.146 | 0.418 |
| frozen_hash_embedding_logreg | 2017 | 0.140 | 0.548 | 0.223 | 0.104 | 0.452 |
| frozen_hash_embedding_logreg | 2018 | 0.113 | 0.609 | 0.191 | 0.135 | 0.391 |
| frozen_hash_embedding_logreg | 2019 | 0.096 | 0.584 | 0.165 | 0.126 | 0.416 |
| frozen_hash_embedding_logreg | 2020 | 0.094 | 0.577 | 0.162 | 0.112 | 0.423 |
| frozen_hash_embedding_logreg | 2021 | 0.071 | 0.561 | 0.126 | 0.093 | 0.439 |
| frozen_hash_embedding_logreg | 2022 | 0.083 | 0.500 | 0.142 | 0.081 | 0.500 |

## Phase 5: Drift Source Analysis

Signals ranked by absolute correlation with recall drop for the primary aging
baseline, `char4_hash_logreg`:

| signal | pearson_with_recall_drop |
|---|---|
| vulnerable_ratio_shift | -0.952 |
| cwe_turnover | 0.927 |
| unseen_token_rate | 0.730 |
| cwe_jsd | 0.608 |
| project_turnover | 0.399 |
| vocab_churn | 0.327 |
| token_jsd | 0.303 |
| median_length_shift | -0.120 |
| project_jsd | -0.088 |

## Phase 6: Maintenance Policy Evaluation

| policy | mean_recall | mean_f1 | recall_ci_low | recall_ci_high | mean_labeled_samples_used |
|---|---|---|---|---|---|
| P0_no_refresh | 0.490 | 0.174 | 0.454 | 0.544 | 0 |
| P1_cumulative_retrain | 0.395 | 0.171 | 0.271 | 0.530 | 4423.667 |
| P2_sliding_3yr_retrain | 0.383 | 0.178 | 0.307 | 0.477 | 4423.667 |
| P3_calibration_only | 0.403 | 0.173 | 0.303 | 0.500 | 4423.667 |
| P4_small_recent_update | 0.337 | 0.174 | 0.231 | 0.466 | 40 |

## Phase 7: Monitoring Triggers

| signal | threshold | event_definition | precision | recall | false_alarm_rate |
|---|---|---|---|---|---|
| project_jsd | 0.626 | recall<0.700 or drop>=0.100 | 1.000 | 0.500 | 0.000 |
| cwe_jsd | 0.537 | recall<0.700 or drop>=0.100 | 1.000 | 0.500 | 0.000 |
| token_jsd | 0.158 | recall<0.700 or drop>=0.100 | 1.000 | 0.500 | 0.000 |
| project_turnover | 0.713 | recall<0.700 or drop>=0.100 | 1.000 | 0.500 | 0.000 |
| cwe_turnover | 0.486 | recall<0.700 or drop>=0.100 | 1.000 | 0.500 | 0.000 |
| unseen_token_rate | 0.703 | recall<0.700 or drop>=0.100 | 1.000 | 0.500 | 0.000 |
| vocab_churn | 0.903 | recall<0.700 or drop>=0.100 | 1.000 | 0.500 | 0.000 |
| median_length_shift | 0.220 | recall<0.700 or drop>=0.100 | 1.000 | 0.500 | 0.000 |
| vulnerable_ratio_shift | -0.002 | recall<0.700 or drop>=0.100 | 1.000 | 0.500 | 0.000 |

## Phase 8: Statistical Summary

| model | first_test_recall | last_test_recall | absolute_recall_decay | worst_recall | mean_recall | absolute_f1_decay |
|---|---|---|---|---|---|---|
| char4_hash_logreg | 0.605 | 0.431 | 0.174 | 0.431 | 0.490 | 0.113 |
| code_metrics_logreg | 0.678 | 0.582 | 0.096 | 0.541 | 0.601 | 0.124 |
| frozen_hash_embedding_logreg | 0.548 | 0.500 | 0.048 | 0.500 | 0.563 | 0.081 |
| token_tfidf_logreg | 0.678 | 0.595 | 0.083 | 0.509 | 0.600 | 0.104 |

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

- `results/detector_aging_diversevul_commit_dates_http/phase_1_feasibility.json`
- `results/detector_aging_diversevul_commit_dates_http/phase_2_temporal_splits.json`
- `results/detector_aging_diversevul_commit_dates_http/phase_3_4_fixed_origin_aging_metrics.csv`
- `results/detector_aging_diversevul_commit_dates_http/phase_5_drift_metrics.csv`
- `results/detector_aging_diversevul_commit_dates_http/phase_5_drift_source_ranking.csv`
- `results/detector_aging_diversevul_commit_dates_http/phase_6_maintenance_policy_summary.csv`
- `results/detector_aging_diversevul_commit_dates_http/phase_7_monitoring_triggers.csv`
- `results/detector_aging_diversevul_commit_dates_http/phase_8_statistical_summary.csv`
