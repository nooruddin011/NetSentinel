# Datasets

The shipped models are trained on **simulated** flows (`backend/app/ml/synthetic.py`) so the project runs offline. For credible accuracy numbers, retrain on a real labelled dataset.

## Your own CSV (platform schema)

```bash
python scripts/train_models.py --csv my_labelled.csv      # needs a `label` column using the platform's class names
```
Labels are matched case-insensitively to: Benign, DDoS, SQL Injection, XSS, Phishing, Brute Force, Malware, Ransomware, Botnet, Port Scanning, Insider Threat, MITM. Rows with other labels are dropped and counted. Columns: `data/schemas/feature_schema.json`.

## NSL-KDD

Download `KDDTrain+.txt` (Canadian Institute for Cybersecurity / UNB) and run
```bash
python scripts/train_models.py --nslkdd KDDTrain+.txt
```
The adapter maps the 41 KDD features onto the platform schema (duration, bytes, connection count, SYN/error rates, failed logins, port-diversity) and attack names to platform classes: *neptune/smurf/back/teardrop/pod/land/… → DDoS*, *portsweep/ipsweep/nmap/satan → Port Scanning*, *guess_passwd → Brute Force*, *buffer_overflow/rootkit/loadmodule/perl → Malware*, *sqlattack → SQL Injection*, *xss → XSS*. Other R2L/U2R attacks are dropped. **Caveat:** NSL-KDD has no payloads, TLS or timing data, so most platform features stay at defaults and only a subset of classes is learnable; treat results as a sanity check, and note NSL-KDD is dated (1999 traffic).

## CICIDS2017

Download the *MachineLearningCVE* CSVs. The uploader already recognises its headers (`Destination Port`, `Flow Duration`, `Total Fwd Packets`, `Total Length of Fwd Packets`, …) and label names (`BENIGN`, `DDoS`, `PortScan`, `FTP-Patator`, `Web Attack – XSS`, …), so you can **upload a CICIDS CSV on the Upload page** and get accuracy against its labels immediately. To train on it, convert with the same aliases (`services/ingestion/loader.py: COLUMN_ALIASES / LABEL_ALIASES`) and pass `--csv`. Expect lower scores than on simulated data — real traffic is messier.

## Zero-day evaluation

With a real dataset, hold out an entire attack family from training (e.g. label it `Zero-Day` in the CSV): the trainer excludes `Zero-Day` rows from supervised training and uses them to measure anomaly detection on unseen behaviour.
