# ML pipeline

> **All figures below come from `models/active/metrics.json` (training run 2026-10-10T06:24:14+00:00) and were measured on _simulated_ traffic. They show that the pipeline works end to end; they are not evidence of real-world accuracy.** See `docs/datasets` for training on real captures.

## 1. Data

`backend/app/ml/synthetic.py` generates 15,000 labelled flows (12,000 train / 3,000 hold-out, stratified): Benign 9378, DDoS 1017, SQL Injection 497, XSS 453, Phishing 464, Brute Force 697, Malware 419, Ransomware 250, Botnet 499, Port Scanning 681, Insider Threat 277, MITM 368.

Realism devices, so results are not trivially perfect: benign *hard negatives* (authorised scanners, mistyped passwords, nightly backups, crawlers), 20 % *stealth* attack rows blended feature-wise with benign rows, overlapping families (botnet vs DDoS vs malware, insider vs backup), 0.5 % label noise. Text-borne attacks (SQLi, XSS, phishing) are generated as real request strings and featurised by the same code as live traffic. Zero-Day is a **held-out novel family** (covert tunnel) never used in supervised training.

**Leakage audit.** An earlier version let attack samplers inherit constant default values for features they did not set, which let models separate classes by "is this value exactly the default?". This was found when an ordinary request was flagged as an attack, fixed by drawing background features from shared realistic distributions for *every* class, and guarded by a regression check (`tests/`) that a default-valued request is benign.

## 2. Training procedure (`ml/trainer.py`)

1. Stratified 20 % hold-out split — never touched until final evaluation.
2. **Stratified 5-fold CV** on the training part. **SMOTE** (own implementation, minority classes raised to 35 % of the majority) is applied **inside each training fold only**, so synthetic points cannot leak into validation.
3. Feature scaling: `log1p` on heavy-tailed counts/bytes for all models, `StandardScaler` inside the MLP pipeline (tree models are scale-invariant).
4. Members: Random Forest, HistGradientBoosting, MLP — plus XGBoost and LightGBM automatically when installed (`not present in this run`).
5. **Ensemble**: soft voting, weights ∝ (CV macro-F1)⁴ → random_forest 34%, gradient_boosting 35%, neural_network 30%.
6. **Threshold tuning**: a sample is called an attack when 1 − P(benign) ≥ τ; τ = 0.3766 is the value at which ≈1% of *out-of-fold* benign traffic is flagged (the blueprint's "threshold tuning" for false positives). The same rule is used to evaluate every model, for a fair comparison.
7. **Autoencoder** (scikit-learn MLP, 34→24→10→24→34) trained on benign traffic only; threshold = 99.5th percentile of reconstruction error on held-out benign rows.
8. Evaluation on the hold-out set + the novel family; model, checksum and `metrics.json` saved; metrics also stored in the `model_runs` table.

## 3. Results (hold-out set, 3,000 flows)

| Model | Accuracy | Precision (macro) | Recall (macro) | F1 (macro) | ROC-AUC (OvR) | False-positive rate | Attack detection rate | CV F1 | ms / event |
|---|---|---|---|---|---|---|---|---|---|
| Random Forest | 96.4% | 94.0% | 91.8% | 92.8% | 0.989 | 0.85% | 96.1% | 0.9297 ± 0.0074 | 9.331 |
| Gradient Boosting (HistGB) | 96.7% | 94.4% | 92.9% | 93.6% | 0.989 | 0.91% | 96.2% | 0.9377 ± 0.005 | 8.302 |
| Neural Network (MLP) | 95.5% | 92.9% | 89.1% | 90.8% | 0.982 | 0.96% | 94.8% | 0.9023 ± 0.0043 | 0.145 |
| **Weighted ensemble** | 96.8% | 94.6% | 92.8% | 93.6% | 0.989 | 0.80% | 96.5% | 0.9232 | 16.154 |

**Reading this honestly**
* The ensemble is **not dramatically better** than its best member here (macro-F1 93.6% vs 93.6% for gradient boosting). Members make correlated mistakes on the stealth rows, which are close to indistinguishable from benign by construction. The ensemble's value is stability and a slightly lower false-positive rate, not a large accuracy jump.
* Accuracy 96.8% is below the blueprint's 97–99.5 % target. That target was not forced by tuning the data; reaching it on simulated data would only be a statement about the simulator.
* Accuracy is dominated by the benign majority class; macro-F1, per-class recall and the false-positive rate are the informative numbers.

### Per class (ensemble)

| Class | Precision | Recall | F1 | Support |
|---|---|---|---|---|
| Benign | 98.0% | 99.2% | 98.6% | 1876 |
| DDoS | 95.5% | 95.1% | 95.3% | 203 |
| SQL Injection | 94.6% | 88.9% | 91.7% | 99 |
| XSS | 96.5% | 92.3% | 94.4% | 91 |
| Phishing | 97.7% | 89.2% | 93.3% | 93 |
| Brute Force | 97.7% | 90.6% | 94.0% | 139 |
| Malware | 97.5% | 92.9% | 95.1% | 84 |
| Ransomware | 93.8% | 90.0% | 91.8% | 50 |
| Botnet | 94.0% | 94.0% | 94.0% | 100 |
| Port Scanning | 94.2% | 96.3% | 95.3% | 136 |
| Insider Threat | 87.7% | 90.9% | 89.3% | 55 |
| MITM | 87.5% | 94.6% | 90.9% | 74 |

## 4. Zero-day / unknown attacks

| Measure | Result |
|---|---|
| Autoencoder ROC-AUC, novel vs benign | 1.0 (Isolation Forest baseline: 0.9921) |
| Benign flagged by autoencoder alone | 0.59% |
| Known attacks flagged by autoencoder alone | 74.9% |
| **Novel traffic detected as a threat (full pipeline)** | **100%** of 1,500 |
| …of which labelled "Zero-Day" | 53.5% (rest attributed to the nearest known class, mostly Botnet) |
| Full-pipeline benign false-positive rate | 1.28% |
| Known attacks detected / correct type | 96.7% / 89.5% |

**Important limitation.** The autoencoder separates anomalous from normal traffic almost perfectly, but it **cannot distinguish a novel attack from a known one** — known attacks are anomalous too (median anomaly ratio 2.6 vs 4.4 for the novel family, both far above benign 0.1). The *label* "Zero-Day" therefore comes from the classifier being unsure (best attack probability < `unknown_conf`), which is a genuine trade-off:

| `unknown_conf` | Known attacks: correct type | Known attacks mislabelled "Zero-Day" | Novel traffic labelled "Zero-Day" |
|---|---|---|---|
| 0.5 | 91.2% | 2.5% | 24.0% |
| 0.6 | 90.6% | 3.4% | 39.6% |
| 0.7 **(default)** | 89.5% | 4.6% | 53.5% |
| 0.8 | 88.3% | 6.2% | 89.8% |
| 0.9 | 83.5% | 11.2% | 100.0% |

Detection of the novel family is 100% at every setting; only the *naming* changes. The default is configurable per bundle (`ThreatModelBundle.unknown_conf`).

## 5. Explainability

`ml/explain.py` — for a flagged event each of 20 feature *groups* (e.g. all volume features) is replaced by its benign median and the drop in the predicted-class probability is measured; the top groups are shown with their observed value. Grouping matters because derived features are strongly correlated with raw ones. For Zero-Day events the per-group autoencoder reconstruction error is shown instead. This is a model-agnostic stand-in for SHAP (not installed offline); it explains *this* model's behaviour, not causality.

## 6. Reproducing

```bash
cd cyber-threat-platform
python scripts/train_models.py            # ≈ 4–6 min on a laptop; --quick for ≈ 1 min
python scripts/train_models.py --csv my_labelled.csv
```
