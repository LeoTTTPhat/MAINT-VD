# Temporal Maintenance of Vulnerability Detectors

This repository contains the MAINT-VD replication package for the manuscript
`Temporal Maintenance of Vulnerability Detectors: Pre/Post-Fix and
Clean-Specificity Evidence`.

MAINT-VD is a maintenance-evaluation framework for learning-based vulnerability
detectors. It treats a detector as a maintained software artifact rather than a
single static model, and evaluates four checks:

1. chronological aging,
2. project-held-out temporal testing,
3. independent-clean specificity,
4. operating-point and threshold sensitivity.

The goal is not to provide a new detector leaderboard. The repository instead
documents how maintenance policies, threshold rules, temporal metadata, label
cost, and false-positive cost affect future detector behavior.

Recent additions include rolling-origin drift/performance replicates, an
expanded C/C++-majority repository-clean benchmark, and a CWE-aware sliding
maintenance policy.

## Repository Layout

- `paper/`: IST manuscript source, references, and generated PDF.
- `scripts/`: dataset preparation, date recovery, temporal evaluation,
  policy evaluation, neural fine-tuning, and validity-check scripts.
- `docs/`: generated phase reports and protocol notes.
- `PROTOCOL.md`: frozen study protocol snapshot.
- `artifact_manifest.tsv`: local artifact manifest with checksums.
- `BADGES.md`: artifact-badge intent notes.
- `Dockerfile`: minimal reproduction environment scaffold.

Large generated artifacts are intentionally not tracked in Git:

- `data/`
- `results/`
- `.venv_neural/`
- `.cache/`

They should be archived separately as release assets or a DOI-backed artifact.

## Manuscript

The current PDF is:

```text
paper/ist_submission_detector_aging.pdf
```

To rebuild the manuscript locally:

```bash
cd paper
latexmk -pdf -interaction=nonstopmode -halt-on-error ist_submission_detector_aging.tex
```

## Reproduction Notes

The pipeline scripts are designed to be run from the repository root. Examples:

```bash
python3 scripts/conduct_detector_aging.py --help
python3 scripts/run_project_heldout_classical_policies.py --help
python3 scripts/rolling_origin_drift_performance.py --help
python3 scripts/create_repo_clean_benchmark.py --help
python3 scripts/run_cross_dataset_classical_probe.py --help
python3 scripts/finetune_transformer_temporal.py --help
```

Some experiments require local dataset exports and substantial compute.

## Data Availability

The local replication package contains normalization scripts, temporal JSONL
exports, split manifests, model outputs, metrics, and generated reports. A
release DOI is pending; `artifact_manifest.tsv` records the current local
manifest entries and checksums. The package also includes a Dockerfile, an
artifact-badge intent file, and a protocol snapshot that should be replaced by
a DOI or immutable repository tag before submission.

### Artifact Manifest Excerpt

| Artifact | Format | SHA-256 prefix | Producing script |
| --- | --- | --- | --- |
| CVEfixes temporal export | JSONL | `755e512c41cd` | `prepare_temporal_vuln_datasets.py` |
| DiverseVul recovered-date export | JSONL | `a9dd1b374436` | `recover_diversevul_commit_dates_http.py` |
| DiverseVul recovered commit-date map | CSV | `9f51d2ccb3bf` | `recover_diversevul_commit_dates_http.py` |
| CVEfixes aging metrics | CSV | `2e6bcaaf94b` | `conduct_detector_aging.py` |
| CVEfixes project-held-out policy summary | CSV | `8e66c34e6565` | `run_project_heldout_classical_policies.py` |
| Repository-clean benchmark | JSONL | `971c96199c01` | `create_repo_clean_benchmark.py` |
| Recovered-date neural threshold rerun | CSV | `e3fa50228820` | `neural_operating_point_curves.py` |
| PrimeVul recovered-date export | JSONL | `3428602a3dcd` | `prepare_primevul_commit_dated_temporal.py` |
| PrimeVul recovered commit-date map | CSV | `bfc739aac1f3` | `prepare_primevul_commit_dated_temporal.py` |
| PrimeVul recovered aging metrics | CSV | `402a9daa5b50` | `conduct_detector_aging.py` |
| PrimeVul recovered CodeBERT curve | CSV | `a733c5d91c9c` | `finetune_transformer_temporal.py` |
| PrimeVul recovered LineVul curve | CSV | `b50879b23a70` | `finetune_transformer_temporal.py` |
| Cross-dataset probe summary | CSV | `176cb3280f68` | `run_cross_dataset_classical_probe.py` |
| Small-update budget summaries | CSV | `b486fa449aae` | `run_project_heldout_classical_policies.py` |
| PaperReview AI review snapshot | JSON | `d9f6cfde79ea` | Manual API export |

## Code Availability

Repository:

```text
https://github.com/LeoTTTPhat/MAINT-VD
```

Before formal publication, create an immutable release tag or DOI archive so
the code version matches the artifact checksums reported in this README and
`artifact_manifest.tsv`.
