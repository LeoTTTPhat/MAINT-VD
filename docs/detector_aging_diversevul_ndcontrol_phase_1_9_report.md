# Detector Aging Phase 1-9 Report

## Scope

This report conducts the nine-phase detector-aging workflow for the currently
available local input.

Input mode: `external`.

If the input mode is `temporal_smoke`, the results verify the pipeline and
analysis design only. They must not be reported as empirical evidence about
real vulnerability detectors.

## Phase 1: Dataset Feasibility

- Valid rows: 42088
- Skipped rows: 0
- Deduplication: exact_canonical_function; removed 0 duplicates
- Years: 2002, 2003, 2005, 2006, 2007, 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017, 2018, 2019, 2020, 2021, 2022
- Go decision: `True`
- Split warnings: 0

## Phase 2: Temporal Splits

- Fixed-origin train years: 2010, 2011, 2012, 2013, 2014, 2015
- Validation year: 2016
- Future test years: 2017, 2018, 2019, 2020, 2021, 2022

Split manifests and JSONL files are written under `results/detector_aging_diversevul_ndcontrol`.

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
| token_tfidf_logreg | 2017 | 0.160 | 0.289 | 0.206 | 0.099 | 0.711 |
| token_tfidf_logreg | 2018 | 0.127 | 0.320 | 0.182 | 0.113 | 0.680 |
| token_tfidf_logreg | 2019 | 0.098 | 0.275 | 0.145 | 0.101 | 0.725 |
| token_tfidf_logreg | 2020 | 0.072 | 0.203 | 0.106 | 0.050 | 0.797 |
| token_tfidf_logreg | 2021 | 0.067 | 0.201 | 0.101 | 0.051 | 0.799 |
| token_tfidf_logreg | 2022 | 0.071 | 0.174 | 0.101 | 0.030 | 0.826 |
| char4_hash_logreg | 2017 | 0.147 | 0.643 | 0.239 | 0.146 | 0.357 |
| char4_hash_logreg | 2018 | 0.099 | 0.621 | 0.170 | 0.117 | 0.379 |
| char4_hash_logreg | 2019 | 0.060 | 0.487 | 0.106 | 0.060 | 0.513 |
| char4_hash_logreg | 2020 | 0.057 | 0.462 | 0.102 | 0.045 | 0.538 |
| char4_hash_logreg | 2021 | 0.056 | 0.442 | 0.099 | 0.053 | 0.558 |
| char4_hash_logreg | 2022 | 0.067 | 0.384 | 0.114 | 0.040 | 0.616 |
| code_metrics_logreg | 2017 | 0.240 | 0.455 | 0.314 | 0.230 | 0.545 |
| code_metrics_logreg | 2018 | 0.191 | 0.485 | 0.274 | 0.229 | 0.515 |
| code_metrics_logreg | 2019 | 0.135 | 0.321 | 0.190 | 0.153 | 0.679 |
| code_metrics_logreg | 2020 | 0.099 | 0.316 | 0.151 | 0.107 | 0.684 |
| code_metrics_logreg | 2021 | 0.127 | 0.353 | 0.187 | 0.156 | 0.647 |
| code_metrics_logreg | 2022 | 0.103 | 0.273 | 0.150 | 0.091 | 0.727 |
| frozen_hash_embedding_logreg | 2017 | 0.180 | 0.434 | 0.254 | 0.156 | 0.566 |
| frozen_hash_embedding_logreg | 2018 | 0.128 | 0.403 | 0.195 | 0.132 | 0.597 |
| frozen_hash_embedding_logreg | 2019 | 0.111 | 0.456 | 0.179 | 0.156 | 0.544 |
| frozen_hash_embedding_logreg | 2020 | 0.075 | 0.335 | 0.122 | 0.072 | 0.665 |
| frozen_hash_embedding_logreg | 2021 | 0.072 | 0.338 | 0.118 | 0.077 | 0.662 |
| frozen_hash_embedding_logreg | 2022 | 0.087 | 0.302 | 0.135 | 0.072 | 0.698 |

## Phase 5: Drift Source Analysis

Signals ranked by absolute correlation with recall drop for the primary aging
baseline, `char4_hash_logreg`:

| signal | pearson_with_recall_drop |
|---|---|
| cwe_turnover | 0.811 |
| vulnerable_ratio_shift | -0.780 |
| cwe_jsd | 0.537 |
| project_turnover | 0.470 |
| unseen_token_rate | 0.361 |
| vocab_churn | -0.239 |
| project_jsd | -0.170 |
| token_jsd | -0.138 |
| median_length_shift | -0.002 |

## Phase 6: Maintenance Policy Evaluation

| policy | mean_recall | mean_f1 | recall_ci_low | recall_ci_high | mean_labeled_samples_used |
|---|---|---|---|---|---|
| P0_no_refresh | 0.507 | 0.138 | 0.441 | 0.585 | 0 |
| P1_cumulative_retrain | 0.348 | 0.127 | 0.170 | 0.516 | 3742.167 |
| P2_sliding_3yr_retrain | 0.309 | 0.152 | 0.225 | 0.424 | 3742.167 |
| P3_calibration_only | 0.333 | 0.134 | 0.222 | 0.470 | 3742.167 |
| P4_small_recent_update | 0.258 | 0.131 | 0.173 | 0.333 | 40 |

## Phase 7: Monitoring Triggers

| signal | threshold | event_definition | precision | recall | false_alarm_rate |
|---|---|---|---|---|---|
| cwe_jsd | 0.510 | recall<0.200 or drop>=0.100 | 1.000 | 0.750 | 0.000 |
| project_turnover | 0.681 | recall<0.200 or drop>=0.100 | 1.000 | 0.750 | 0.000 |
| cwe_turnover | 0.441 | recall<0.200 or drop>=0.100 | 1.000 | 0.750 | 0.000 |
| unseen_token_rate | 0.694 | recall<0.200 or drop>=0.100 | 1.000 | 0.750 | 0.000 |
| project_jsd | 0.655 | recall<0.200 or drop>=0.100 | 0.667 | 0.500 | 0.500 |
| vocab_churn | 0.917 | recall<0.200 or drop>=0.100 | 0.667 | 0.500 | 0.500 |
| token_jsd | 0.166 | recall<0.200 or drop>=0.100 | 0.333 | 0.250 | 1.000 |
| median_length_shift | -0.010 | recall<0.200 or drop>=0.100 | 0.333 | 0.250 | 1.000 |
| vulnerable_ratio_shift | -0.017 | recall<0.200 or drop>=0.100 | 0.333 | 0.250 | 1.000 |

## Phase 8: Statistical Summary

| model | first_test_recall | last_test_recall | absolute_recall_decay | worst_recall | mean_recall | absolute_f1_decay |
|---|---|---|---|---|---|---|
| char4_hash_logreg | 0.643 | 0.384 | 0.259 | 0.384 | 0.507 | 0.126 |
| code_metrics_logreg | 0.455 | 0.273 | 0.182 | 0.273 | 0.367 | 0.164 |
| frozen_hash_embedding_logreg | 0.434 | 0.302 | 0.132 | 0.302 | 0.378 | 0.119 |
| token_tfidf_logreg | 0.289 | 0.174 | 0.115 | 0.174 | 0.244 | 0.106 |

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

- `results/detector_aging_diversevul_ndcontrol/phase_1_feasibility.json`
- `results/detector_aging_diversevul_ndcontrol/phase_2_temporal_splits.json`
- `results/detector_aging_diversevul_ndcontrol/phase_3_4_fixed_origin_aging_metrics.csv`
- `results/detector_aging_diversevul_ndcontrol/phase_5_drift_metrics.csv`
- `results/detector_aging_diversevul_ndcontrol/phase_5_drift_source_ranking.csv`
- `results/detector_aging_diversevul_ndcontrol/phase_6_maintenance_policy_summary.csv`
- `results/detector_aging_diversevul_ndcontrol/phase_7_monitoring_triggers.csv`
- `results/detector_aging_diversevul_ndcontrol/phase_8_statistical_summary.csv`
