# MAINT-VD Protocol Snapshot

This file records the local protocol snapshot for the IST detector-maintenance study.
It is not an external OSF preregistration. Before a new experimental rerun intended
for submission, this protocol should be deposited in a tagged repository release or
OSF project and cited by DOI or immutable commit hash.

## Primary Framework

MAINT-VD evaluates learning-based vulnerability detectors as maintained software
artifacts. The detector includes training data, feature extraction, model weights,
calibration data, threshold policy, monitoring signals, and update schedule.

## Primary Endpoints

- Recall, F1, and FPR over future temporal windows.
- Independent-clean specificity and clean false-positive rate.
- Label cost per future maintenance window.
- Project-held-out temporal behavior.

## Service-Level Decision Criteria

- C1: On CVEfixes under unseen-project temporal testing, small recent updates should increase recall by at least 0.05 over no refresh while keeping future FPR at or below 0.20.
- C2: On recovered-date DiverseVul, a maintenance policy should maintain recall at least 0.50 with future FPR at or below 0.30 across future windows.

## Neural Rerun Required Before Strong Submission

- Epochs: at least 3; preferably 5-10 with early stopping.
- Max sequence length: 512.
- Learning rates: 1e-5, 2e-5, 5e-5.
- Loss: class-balanced cross entropy or focal loss.
- Selection metric: validation AUPRC.
- Required outputs: training loss, validation loss, validation AUROC/AUPRC, validation FPR/recall curves, and test operating-point table.

Local launcher:

```bash
scripts/run_diversevul_neural_sweep.sh
```

The fine-tuning script records per-epoch training curves in
`<output-dir>/<model>_training_curve.csv`, writes the validation operating
curve to `<output-dir>/<model>_validation_threshold_curve.csv`, and selects the
checkpoint with the highest validation AUPRC when early stopping is enabled.
