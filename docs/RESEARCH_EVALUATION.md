# Research & evaluation notes (for the project report)

## Research questions

1. Does a hybrid of signature rules, a supervised ensemble and an unsupervised anomaly detector outperform a single anomaly detector (the v1 prototype)?
2. How much does ensembling help over its individual members?
3. Can unknown ("zero-day") behaviour be detected, and can it be *named*?
4. What does it cost in false positives?

## Method

Controlled experiment on simulated flows (see `docs/ML_PIPELINE.md`): stratified hold-out, k-fold CV with SMOTE inside folds, a held-out novel attack family, thresholds tuned on out-of-fold data only.

## Findings

| # | Finding | Evidence |
|---|---|---|
| 1 | The v1 prototype (Isolation Forest on 4 features) could only say "anomaly"; attack names and severities were assigned by the data generator, not predicted. v2 *classifies* 11 attack types and scores risk. | v1 `data_generator.py` / `main.py`; v2 per-class table |
| 2 | Supervised models reach 93.6% macro-F1 / 96.8% accuracy at 0.80% benign FPR on simulated data; hardest classes: Insider Threat, MITM, SQL Injection. | per-class table |
| 3 | Ensembling gave a small gain (F1 93.6% vs 93.6% best member): errors are correlated because the hard cases are stealth samples that overlap benign traffic. | model table |
| 4 | Anomaly detection finds unseen behaviour reliably (AUC 1.0; 100% of the novel family flagged) but cannot by itself *name* it as novel. | zero-day table |
| 5 | A data-generation leak (constant default values) silently inflated results until a benign request was flagged as an attack. After the fix the share of novel traffic labelled "Zero-Day" dropped from ≈79 % (quick model, leaky data) to ≈40 % (full model, clean data) at threshold 0.6 — the two runs also differed in training size, so this is indicative, not a controlled comparison. Hand-made sanity probes are worth keeping in the test suite. | ML_PIPELINE §1 |
| 6 | Signature rules add precision for text-borne attacks the flow features only weakly capture (a SQL-injection string is flagged even if its flow statistics look normal), and, together with the ML vote, produce a corroboration signal used in severity. | `tests/test_pipeline.py` |

## Threats to validity

* **Synthetic data** — the dominant limitation. Distributions were designed by the author, so the models may be learning the author's assumptions. Real datasets (CICIDS2017, UNSW-NB15) have different, messier structure; expect lower scores.
* The novel "zero-day" family is also author-designed; detection of it shows the mechanism works, not that arbitrary unseen attacks are caught.
* Hold-out size per rare class is small (e.g. Ransomware n = 50), so per-class figures have wide confidence intervals. Single seed; no repeated-run variance reported.
* Flow-level features cannot capture campaign structure (slow multi-stage attacks); the 60-second window features only partly address this.
* Threshold τ was tuned for a 1 % benign FPR; real traffic volumes make even 1 % thousands of daily alerts. Alert de-duplication reduces, but does not remove, analyst load.

## Suggested future work

Evaluate on CICIDS2017 / UNSW-NB15 with a time-based split; add a sequence model (LSTM/1D-CNN) over per-source windows; calibrate probabilities (isotonic) before thresholding; adversarial robustness tests; measure analyst workload with de-duplication on real logs.

## Addendum: a second bug found by looking at the dashboard

After the model was trained, the seeded dashboard showed "Zero-Day" as the most frequent attack although the simulator injects it ~3 % of the time. Cause: the *simulator* attached a web request payload to every benign flow, including DNS lookups, SSH sessions and large backups — incoherent flows that the autoencoder rightly flagged (7.5 % of benign traffic labelled Zero-Day vs 0.6 % on the training-pipeline path). Fixed by attaching request text only to web-like benign flows. Lesson: evaluate the *deployed path*, not just the training path; end-to-end checks with the simulator and a "what does the dashboard say?" review caught what offline metrics could not.
