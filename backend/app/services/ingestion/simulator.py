"""Live traffic simulator: produces a realistic stream of benign flows with attack campaigns mixed in.

Events are generated from the same feature distributions the models were trained on but they carry NO
label into the detector -- the pipeline must classify them. The ground-truth label is returned
separately so the Attack Lab can show whether the platform got it right.
"""
from __future__ import annotations

import threading
import time

import numpy as np

from app.ml.synthetic import generate_event
from app.models.attacks import BENIGN

ATTACK_WEIGHTS = {"DDoS": 3, "SQL Injection": 2, "XSS": 2, "Phishing": 1.5, "Brute Force": 2.5, "Malware": 1.5,
                  "Ransomware": 0.7, "Botnet": 2, "Port Scanning": 3, "Insider Threat": 1, "MITM": 1, "Zero-Day": 0.6}


class TrafficSimulator:
    def __init__(self, attack_ratio: float = 0.12, seed: int | None = None, stealth: float = 0.1):
        self.attack_ratio = attack_ratio
        self.stealth = stealth
        self.rng = np.random.default_rng(seed)
        self._lock = threading.Lock()
        self._attackers: dict = {}  # attack type -> recurring attacker IP (campaigns)
        names = list(ATTACK_WEIGHTS)
        w = np.array([ATTACK_WEIGHTS[n] for n in names], dtype=float)
        self._names, self._p = names, w / w.sum()

    def next_event(self, scenario: str | None = None) -> tuple:
        """Return (raw_event, ground_truth_label). `scenario` forces a specific class."""
        with self._lock:
            if scenario is None:
                is_attack = self.rng.random() < self.attack_ratio
                scenario = str(self.rng.choice(self._names, p=self._p)) if is_attack else BENIGN
            ip = None
            if scenario != BENIGN:
                if scenario in self._attackers and self.rng.random() < 0.6:
                    ip = self._attackers[scenario]
            ev = generate_event(scenario, self.rng, stealth=self.stealth if scenario != BENIGN else 0.0, attacker_ip=ip)
            if scenario != BENIGN:
                self._attackers[scenario] = ev["src_ip"]
        ev["ts"] = time.time()
        return ev, scenario
