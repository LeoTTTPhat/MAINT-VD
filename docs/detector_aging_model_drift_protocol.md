# Study Protocol: Security Detector Aging and Model Drift

## Working Title

**Security Detector Aging: Treating Model Drift as a Software Maintenance Problem**

Alternative titles:

- **Do Vulnerability Detectors Age? A Longitudinal Study of Model Drift in Security Detection**
- **Maintaining Learning-Based Vulnerability Detectors under Temporal Drift**
- **From Benchmark Accuracy to Detector Maintenance: A Temporal Evaluation of Vulnerability Detection Models**

## 1. Core Positioning

This is a strong Information and Software Technology paper if framed as a
software maintenance and empirical software engineering problem, not as a new
machine learning model.

The central claim is:

> A learning-based security detector is a maintained software component. Its
> usefulness depends not only on initial benchmark accuracy, but also on how
> quickly it decays as software ecosystems, coding practices, libraries,
> projects, and vulnerability types evolve.

The paper should use the language of maintenance:

- model aging
- retraining interval
- maintenance trigger
- decay rate
- temporal validity
- detector refresh policy
- maintenance cost
- operational risk

Avoid making the contribution sound like a generic concept drift paper. The
IST angle is that detectors are deployed inside software engineering workflows
and need evidence-based maintenance policies.

## 2. Research Gap

Most vulnerability detector evaluations use random, stratified, or benchmark
provided splits. These are useful for comparability, but they do not represent
the deployment situation where a detector trained at time `t` is used on code
and vulnerabilities appearing after `t`.

The missing empirical question is:

> How long does a vulnerability detector remain useful before maintenance is
> needed?

This gap is easier to defend than a pure robustness study because the argument
maps directly to familiar SE concerns: software evolution, aging, maintenance,
quality assurance, and operational monitoring.

## 3. Study Object

The study object is a function-level or method-level vulnerability detector
trained on historical vulnerability data and evaluated on later vulnerability
data.

The unit of analysis should be:

- one detector family,
- one training window,
- one future test window,
- one dataset or project group,
- one vulnerability label or CWE group.

The empirical design should treat time as a first-class variable.

## 4. Main Research Questions

### RQ1: Aging Effect

**How does the performance of learning-based vulnerability detectors change as
the temporal distance between training data and target code increases?**

Purpose: establish whether detector aging exists and how large it is.

Primary metrics:

- F1 over future windows.
- Recall over future windows.
- False-negative rate over future windows.
- Matthews correlation coefficient if class imbalance is severe.
- AUC or average precision when scores are available.

Expected answer shape:

> Detector performance decreases as the evaluation window moves farther from
> the training window, but the decay rate differs across model families and
> vulnerability categories.

### RQ2: Drift Sources

**Which observable changes in the data are associated with detector decay?**

Purpose: explain aging as a maintainable engineering phenomenon rather than a
black-box score drop.

Candidate drift sources:

- project distribution shift,
- CWE distribution shift,
- API/library vocabulary shift,
- code style and token distribution shift,
- function size and complexity shift,
- vulnerable/non-vulnerable ratio shift,
- duplicated or near-duplicated code across time.

Primary metrics:

- Jensen-Shannon divergence between train and test windows.
- Population Stability Index for numeric features.
- vocabulary churn rate,
- unseen token/API rate,
- project and CWE turnover,
- embedding-space distance between windows.

Expected answer shape:

> Performance decay is most strongly associated with project/CWE turnover and
> vocabulary/API churn, while some surface-level size metrics explain less of
> the drop.

### RQ3: Maintenance Policy

**When should a detector be refreshed, and which low-cost maintenance strategy
recovers the most performance?**

Purpose: convert the study from diagnosis to actionable software maintenance.

Maintenance strategies:

- no refresh,
- periodic full retraining,
- sliding-window retraining,
- cumulative retraining,
- lightweight calibration only,
- threshold adjustment,
- small incremental update using recent labeled data.

Primary metrics:

- recovered F1/recall,
- vulnerable recall recovery,
- false-positive cost,
- training/inference time,
- number of new labeled samples required,
- area under the temporal performance curve.

Expected answer shape:

> Lightweight refresh policies can recover a meaningful fraction of lost recall
> at lower cost than full retraining, but the best policy depends on label
> latency and acceptable false-positive burden.

### RQ4: Drift Monitoring

**Can unlabeled or weakly labeled monitoring signals predict when detector
maintenance is needed?**

Purpose: make the paper useful in realistic settings where labels arrive late.

Candidate monitoring signals:

- input distribution divergence,
- prediction score distribution shift,
- uncertainty or entropy shift,
- vulnerable prediction rate shift,
- unseen token/API rate,
- project/CWE mix change if metadata is available.

Primary metrics:

- correlation between drift signal and future performance drop,
- detection lead time,
- precision/recall of maintenance triggers,
- false alarm rate for refresh recommendations.

Expected answer shape:

> Some monitoring signals provide early warning of recall decay without
> requiring immediate ground-truth labels, supporting detector maintenance
> dashboards in CI/CD and security triage workflows.

## 5. Dataset Design

### Preferred Primary Dataset

Use **CVEfixes** or **DiverseVul** as the primary dataset because they expose
vulnerability-fixing commits, project metadata, CWE metadata, and dates that
support temporal splitting.

Recommended order:

1. CVEfixes for temporal metadata and relational structure.
2. DiverseVul for scale and C/C++ vulnerability diversity.
3. Big-Vul as a comparison dataset if date and commit metadata are reliable.
4. CodeXGLUE/Devign only as a secondary reference, because it is less ideal for
   a temporal maintenance study.

### Required Fields

Each normalized record should contain:

```json
{
  "idx": "stable sample id",
  "func": "source code",
  "target": 0,
  "project": "project/repository",
  "commit": "fix or source commit hash",
  "date": "YYYY-MM-DD",
  "cwe": "CWE-XXX or unknown",
  "language": "C/C++",
  "source_dataset": "CVEfixes"
}
```

### Temporal Windows

Use chronological windows, not random splits.

Recommended designs:

- **Blocked time split:** train on years 1..k, validate on year k+1, test on
  later years.
- **Rolling-origin evaluation:** train through time `t`, validate on `t+1`,
  test on `t+2`, repeat.
- **Fixed-origin aging curve:** train once on an early period, then test on
  each later period separately.

The fixed-origin curve is the clearest for RQ1. Rolling-origin evaluation is
the clearest for maintenance policy comparison.

## 6. Models

Choose models that are feasible and defensible rather than expensive.

Minimum IST-ready set:

- classical baseline using TF-IDF or code metrics plus logistic regression,
- frozen code-model embeddings plus logistic regression,
- transformer vulnerability detector such as a CodeBERT/LineVul-style model,
- optional graph-based detector if implementation time allows.

Why this is enough:

- It compares simple maintainable baselines against deeper detectors.
- It lets the paper discuss whether higher initial accuracy comes with faster
  aging.
- It avoids making the contribution depend on one model family.

## 7. Metrics

### Clean Predictive Metrics

- precision,
- recall,
- F1,
- MCC,
- AUC or average precision,
- false-negative rate.

Recall and false-negative rate should be emphasized because security detectors
are often used to avoid missing vulnerabilities.

### Aging Metrics

Let `P(t)` be detector performance on test window `t`, and let `P(0)` be the
first future test window after validation.

**Absolute decay**

```text
Decay(t) = P(0) - P(t)
```

**Relative decay**

```text
RelativeDecay(t) = (P(0) - P(t)) / P(0)
```

**Half-life**

The first future window where performance has lost at least 50% of its initial
post-validation margin over a naive baseline.

**Maintenance threshold crossing**

The first future window where recall, F1, or MCC falls below a pre-declared
acceptable threshold.

**Area under temporal performance curve**

Average performance across future windows. This rewards detectors that remain
stable, not only detectors with high first-window performance.

### Drift Metrics

- Jensen-Shannon divergence for categorical distributions.
- Population Stability Index for numeric code metrics.
- vocabulary churn and unseen-token rate.
- project turnover and CWE turnover.
- embedding centroid distance.

## 8. Statistical Analysis

Use paired and temporal analyses:

- bootstrap confidence intervals for performance in each time window,
- regression models linking drift metrics to performance decay,
- paired tests when comparing maintenance policies over the same windows,
- sensitivity analysis using different window sizes,
- robustness checks excluding duplicated or near-duplicated functions.

Recommended regression form:

```text
performance_drop ~ time_gap + project_turnover + cwe_shift
                 + vocabulary_churn + size_shift + model_family
                 + dataset + random_effect(project)
```

Keep the statistics transparent. The strongest paper is not the one with the
most complex model; it is the one with a defensible temporal design.

## 9. Threats to Validity

### Construct Validity

The date attached to a vulnerability may be disclosure date, fix date, commit
date, or collection date. These are not equivalent. The protocol must define
which date is used and run sensitivity checks with alternatives when possible.

### Internal Validity

Temporal leakage is the main risk. The study must prevent future data from
influencing training, preprocessing, feature selection, threshold selection,
duplicate removal, and hyperparameter tuning.

### External Validity

Open-source C/C++ vulnerability datasets may not generalize to proprietary
systems, other languages, or commercial SAST/DAST tools. The discussion should
limit claims to learning-based source-code vulnerability detection unless
additional tools are evaluated.

### Conclusion Validity

Observed decay may depend on the chosen window size, model threshold, class
imbalance, and project mix. Report confidence intervals and repeat the analysis
under multiple temporal granularities.

## 10. Minimum Publishable Study

The smallest defensible IST version:

- one temporally rich dataset, preferably CVEfixes or DiverseVul,
- C/C++ function-level detection,
- three detector families,
- fixed-origin aging curve,
- rolling-origin maintenance comparison,
- at least three refresh strategies,
- drift metrics linked to performance decay,
- explicit temporal leakage controls,
- public scripts for time splitting, drift measurement, and aging metrics.

## 11. Recommended Paper Structure

1. Introduction: detectors as maintained software components.
2. Background: vulnerability detection, software aging, concept drift, temporal
   validation.
3. Study design: datasets, temporal splits, models, metrics, maintenance
   policies.
4. RQ1 results: aging curves.
5. RQ2 results: drift sources.
6. RQ3 results: maintenance policies.
7. RQ4 results: monitoring triggers.
8. Discussion: implications for CI/CD, benchmark design, tool vendors, and
   security teams.
9. Threats to validity.
10. Conclusion.

## 12. Why This Is Probably Stronger Than the Transformation Study

The transformation study asks:

> Is the detector stable under harmless edits?

The aging study asks:

> How should we maintain a detector after deployment?

Both are valid. The aging study is easier to defend for IST because it connects
directly to software evolution, maintenance cost, operational monitoring, and
longitudinal empirical design. It also gives reviewers a clearer practical
output: when to refresh the detector and what signal should trigger
maintenance.

