# Project status & roadmap

## Delivered (v2)

- [x] Real hybrid detection: signature rules + ensemble classifier + autoencoder (v1 only flagged "anomaly" and *assigned attack names at random*)
- [x] 11 trained attack classes + Zero-Day via anomaly detection; severity from class × confidence × context
- [x] Training pipeline: stratified k-fold CV, SMOTE (inside folds), FPR-targeted threshold, ROC/AUC, confusion matrix, per-class metrics, held-out novel-family evaluation; models + metrics saved and stored in DB
- [x] Recommendation engine driven by *measured* metrics; mitigation playbooks for all 12 attacks; simulated apply with generated rules and blocklist
- [x] Explainability (local grouped-occlusion), alert de-duplication, prediction cache
- [x] SQLite persistence, audit log, retention
- [x] JWT auth, self-registration (Viewer by default), 3 roles, Admin console (create / reset password / disable / delete users, settings, system status, audit), lockout, hardened inputs/outputs, per-user upload history
- [x] Light/dark themes, new identity (Argus), account page, toasts/confirm dialogs, training progress that survives page changes
- [x] Upload analysis (CSV, CICIDS headers, optional labels → live accuracy), NSL-KDD adapter
- [x] Dashboard: live charts, heatmap, forecast, alerts workflow, model comparison, chatbot, PDF/CSV reports, email alerts
- [x] Docker, docs, unit + integration tests

- [x] **Real-time connector architecture**: collector, parser, API-keyed ingest door, privacy policy, source health, Demo/Live modes, Coverage panel
- [x] **Web detector** (signatures + behaviour + text model) with an honest held-out-family evaluation and an automatic leak audit
- [x] **Docker lab** (vulnerable target + collector + Argus) and a no-Docker verification script

## Not done / honest gaps

| Gap | Why it matters | Next step |
|---|---|---|
| Trained on **simulated** data only | Reported accuracy is a pipeline check, not a real-world claim | Train on CICIDS2017/UNSW-NB15 captures (`docs/datasets`); add a feature extractor from PCAP/NetFlow |
| No CNN / LSTM | Blueprint lists them; they need TensorFlow/PyTorch and sequence data | Add a sequence model over per-source flow windows; register it as another ensemble member |
| XGBoost/LightGBM are optional | The trainer uses them automatically when installed; the shipped model was built without them | `pip install -r backend/requirements.txt && python scripts/train_models.py` |
| No real packet capture | Deliberate (blueprint: simulate first) | Add a Zeek/Suricata log ingester |
| No world attack map | GeoIP database needed (licensing) | MaxMind GeoLite2 + map widget |
| SHAP not used | Offline substitute (occlusion) is implemented | Optional: add `shap` for tree models |
| Single node | In-memory hub/throttle, SQLite | PostgreSQL + Redis, multiple workers |
| Live feed is simulated by default | Labelled "SIMULATED DEMO FEED" in the UI; can be switched off in Admin → Settings | Replay mode for real datasets, then a real log/honeypot source |
| Only one real connector (web access logs) | Coverage panel shows what is *not* visible | Auth/SSH logs, DNS, honeypot (Cowrie), endpoint, firewall connectors reuse the same door, keys and policy |
| Request bodies are invisible to access logs | Attacks inside POST bodies are missed | WAF / application-level logging connector |
| Live feed is simulated by default | Labelled "SIMULATED DEMO FEED"; Auto mode switches it off when a real source connects | Real-data replay mode, honeypot source |
| Frontend has no automated tests | Backend is covered | Vitest + React Testing Library, Playwright smoke test |
