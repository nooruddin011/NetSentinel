# Viva guide — questions you should be ready for

Answers are tied to what this project actually does. Be upfront about the limitations; examiners respect that more than inflated claims.

**What did you build, and what is new compared with a typical IDS project?**
A hybrid detector (signature + supervised ensemble + autoencoder) that also *classifies* the attack, scores severity, explains the decision, recommends measured detector comparisons and mitigation playbooks, and lets an analyst simulate applying one — inside a role-based dashboard with persistence and audit.

**Why an ensemble? Why not one model?**
Different models make different errors; soft voting weighted by cross-validated F1 stabilises predictions. In our results the gain over the best single model is small (see `RESEARCH_EVALUATION.md`) because the hard cases are stealth samples that overlap benign traffic — we report that rather than claiming a big jump.

**How do you keep false positives low?**
(1) threshold tuned on out-of-fold predictions to a target benign FPR, (2) class balancing with SMOTE inside folds, (3) signature rules are high-precision, (4) hard-negative benign traffic in training, (5) alert de-duplication. Measured benign FPR ≈ 0.8 % (models) / 1.3 % (full hybrid) on simulated data.

**Why do you say you will not claim 100 %?** and **why is accuracy below 97 %?**
Because on data with deliberately overlapping classes and label noise a perfect score would indicate leakage. We found and fixed one such leak (constant defaults). The target was not reached by tuning the simulator.

**What is SMOTE and where is it applied?**
Interpolates new minority-class samples between nearest neighbours. Applied only to training folds — applying it before splitting would leak synthetic neighbours of validation points into training.

**How do you detect zero-day attacks?**
An autoencoder trained only on benign traffic has high reconstruction error on unfamiliar traffic (AUC ≈ 1.0 on our held-out novel family). Limitation: attacks are anomalous too, so the autoencoder alone cannot say “novel vs known”; the “Zero-Day” label needs the classifier to be unsure, and we show the trade-off table.

**Why not LSTM/CNN?**
They need sequence data and a deep-learning framework; they are listed as future work rather than faked. The MLP and autoencoder are the neural components; the ensemble interface accepts more members.

**Why simulated data?**
Offline, reproducible, and lets us create a truly held-out attack family. The cost: results do not transfer automatically. The platform includes an uploader that evaluates against CICIDS-style labelled CSVs and a trainer for real data.

**How is the platform itself secured?**
scrypt, JWT with pinned algorithm, RBAC, lockout, input bounds, parameterised SQL, escaped output (UI/PDF/CSV), rule-injection-safe mitigation text, model checksum, production config guards. Limitations (no built-in TLS, in-memory throttle, non-revocable JWT) are in `SECURITY_DESIGN.md`.

**Is mitigation real?**
No. It is a simulation that generates and records rule text and a blocklist; nothing is executed. Real enforcement would need its own authorisation and human approval.

**How would you scale it?**
PostgreSQL, Redis (pub/sub, throttle, cache), multiple workers, a message queue (Kafka) between ingestion and detection, model server for inference.

**Explain the risk score.**
`base(class) × (0.55 + 0.45·confidence) + 8 if target is a critical asset + up to 8 for repeated activity + 5 if signature and ML agree`, clamped to 0–100 and bucketed (≥80 Critical, ≥60 High, ≥40 Medium).

**What was the hardest bug?**
A data-generation leak: attack samplers kept constant default values, so models learned “exactly the default ⇒ attack”. It showed up when a plain search request was flagged as an attack. Fixed by drawing shared background features for every class.

**Is this still a simulation?**
The flow models and the demo feed are trained/produced on simulated data, and the app says so. But Argus also monitors *real* systems: a collector streams a web server's actual access log in real time (opt-in, with client-controlled privacy). In the Docker lab you attack a real (deliberately vulnerable) website from your browser and the alert appears seconds later. The simulator switches itself off when a real source connects.

**Why a collector instead of an API or a CSV export?**
Every system logs differently and clients will not export files by hand. Products like Splunk and Wazuh solve it the same way: a small agent beside the system pushes selected events. The client controls exactly what leaves their machine, can revoke the key instantly, and a new log type needs only one new parser.

**What about privacy?**
Opt-in; exclusions, secret redaction and IP pseudonymisation are applied on the client machine before sending (and enforced again on arrival); cookies, auth headers and bodies are never collected; `--dry-run` shows what would leave.

**Do you see all attacks?**
No, and the dashboard says so: the Coverage panel lists which attack types the connected sources cover and what logs would cover the rest. A web log cannot reveal ransomware.

**How do you know the web detector is not just memorising your generator?**
We built a leak audit into training (a model on request *structure only* must score ~0.5; ours scored 0.80 until two generator artefacts were found and fixed, now 0.54), we test on payload *families held out* of training, and independently written probes (27 attacks, 28 benign requests) were all classified correctly, with a subset kept as regression tests. Numbers are from generated data, so we call them indicative.

**What is the weakest part?**
Command injection via newline and DOM-style XSS (listed in WEB_DETECTOR.md), attacks in POST bodies (invisible to logs), and NAT'd clients distorting rate rules.
