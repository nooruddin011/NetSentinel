# Web request detector

Argus's second detector. The first (the flow classifier + autoencoder) reads *network-flow numbers*; this one reads *web-server logs*. It runs on every event a collector sends.

> **Honesty note.** All metrics below come from a **generated** request corpus (payload patterns written from public cheat-sheets, mixed with realistic benign traffic). They show how the detector behaves on payload styles it has not seen; they are **not** a real-world benchmark. To retrain on real labelled requests see "Retraining" at the end.

## Three layers, one verdict

| Layer | Looks at | Catches | File |
|---|---|---|---|
| **Signature rules** | decoded path + query, User-Agent | SQL injection, XSS, path traversal, command injection, scanner tools, sensitive-file probes | `detectors/webrules.py` |
| **Behaviour tracker** | requests over time, per client (sliding window) | brute force, HTTP flood, directory scans | `services/connectors/behaviour.py` |
| **Text model** | character n-grams of the request (TF-IDF + logistic regression) | payload *variants* the rules do not list | `ml/webmodel.py` |

Evidence is combined per attack type with a noisy-OR (independent evidence strengthens, never weakens) and the best type wins; near-ties go to the more severe type (`services/detection/webfuse.py`). A request is an attack at combined confidence >= 0.75. A weak hint alone (for example a lone quote character) never alerts; it only counts when another layer agrees. A behaviour verdict (flood, brute force, scan) is attached only to the events that *contribute* to the pattern, so a scan from an address that earlier guessed passwords is not mislabelled "brute force".

Everything is URL-decoded twice before matching, SQL comments are neutralised (`UNION/**/SELECT`), and the text model sees the same decoded text, so encoding tricks do not hide an attack.

## Results (payload families held out of training)

The model is trained **without** two whole payload families per attack class, then tested on exactly those families plus fresh benign traffic (4,100 test requests in total). Held-out families: SQL Injection: error, blind, XSS: tags, dom, Path Traversal: app, nullbyte, Command Injection: newline, reverse.

| Detector | Attack detection | False positives (benign flagged) | Accuracy |
|---|---|---|---|
| Signature rules only | 65.8% | 0.00% | 85.7% |
| Text model only | 74.1% | 0.00% | 89.9% |
| **Combined (what Argus runs)** | 93.6% | 0.00% | 97.5% |

Recall per attack class on unseen payload styles:

| Class | Rules | Text model | Combined |
|---|---|---|---|
| SQL Injection | 20% | 92% | 94% |
| XSS | 54% | 87% | 87% |
| Path Traversal | 100% | 59% | 100% |
| Command Injection | 79% | 59% | 94% |

Recall per held-out family:

| Family | Rules | Text model | Combined |
|---|---|---|---|
| Command Injection / newline | 59% | 61% | 88% |
| Command Injection / reverse | 100% | 57% | 100% |
| Path Traversal / app | 100% | 44% | 100% |
| Path Traversal / nullbyte | 100% | 77% | 100% |
| SQL Injection / blind | 24% | 84% | 87% |
| SQL Injection / error | 17% | 100% | 100% |
| XSS / dom | 51% | 76% | 76% |
| XSS / tags | 58% | 99% | 99% |

**Reading this honestly**
* The learned model clearly adds value: rules alone miss most error-based and blind SQL injection styles, which the text model recognises.
* The weakest families are DOM-style XSS and newline-separated command injection. They are listed rather than hidden.
* "Combined" is the number that matters; the other two rows explain *why* both layers exist.

## The corpus leaked, twice. How it was found and fixed

Early versions of this experiment reported ~98 % on unseen families. That number was wrong, and the detector flagged normal DVWA pages as attacks, which exposed generator artefacts the model had learned instead of attacks:

1. `&Submit=Submit` appeared only on attack requests (and only attacks used a fixed list of pages and exactly one parameter).
2. Attack requests used parameter names that benign requests never used.

Both were fixed by making benign and attack requests share **identical structure** (same endpoints, parameter names, decoy parameters and extras). The training report now includes an automatic **leak audit**: it trains a model on request *structure only* (page and parameter names, no payload) and reports its ROC-AUC. A value near 0.5 means structure carries no signal. Current value: **0.541**. (It was 0.80 before the fixes.) The honest held-out figures above are lower than the early inflated ones, and they are the ones to quote.

Independent check: during development, 27 attack payloads and 28 benign requests (including normal DVWA pages) written *after* training, in styles not present in the corpus, were all classified correctly. A subset (8 attacks, 6 normal DVWA pages) is kept as a regression test (`tests/test_web_detection.py::test_shipped_model_independent_probes`), and the full attack traffic of `lab/attack_demo.py` is checked end to end (`tests/test_lab_pipeline.py`).

## What access logs cannot see

* **Request bodies.** Standard access logs record the URL, not the POST body. An injection sent in a form body or JSON payload is invisible to this connector. (DVWA's SQL-injection, XSS, brute-force and file-inclusion pages use URL parameters, so they are visible; its command-injection form posts a body and is not.) Capturing bodies needs a WAF or application-level logging.
* **Encrypted or non-web traffic.** Only what the web server logged.
* **Many users behind one address** (a corporate NAT) look like one client; the flood and brute-force thresholds assume one client per address and are configurable (`BehaviourConfig`).
* A real attacker who is slow ("low and slow") stays under the time-window thresholds; the signature and text layers still catch payload attacks regardless of speed.

## Retraining on real data

```bash
python scripts/train_web_model.py                      # regenerate the corpus and retrain (about 15 seconds)
python scripts/train_web_model.py --csv requests.csv   # your own labelled requests: columns path,query,label
```
Labels: Benign, SQL Injection, XSS, Path Traversal, Command Injection. With real data, hold out whole attack families or a later time period when you evaluate, and report those numbers.

Model files: `models/web/web_model.joblib` (+ `.sha256` checksum, verified on load) and `models/web/metrics.json`.
