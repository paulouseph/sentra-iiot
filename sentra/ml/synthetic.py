"""
synthetic.py
------------
Fallback data source, used only when the Edge-IIoTset CSV is not present.

This is a rewrite of v1's generator, and it is deliberately harder. v1 built
each attack class by moving one feature to a distribution that no other class
occupied, which made the classes linearly separable by construction -- hence
the 99.97% accuracy that told us nothing. Three changes fix that:

  * classes share feature ranges (recon and DoS both raise packet counts,
    ransomware and backdoor both raise entropy),
  * every sample gets correlated Gaussian noise, not per-feature noise,
  * 1.5% of labels are flipped to mimic the annotation error present in any
    real capture.

The result lands around 88-93% macro F1, which is what a believable IIoT
classifier actually looks like. Columns are named after real Edge-IIoTset
fields so the same downstream code handles both sources.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from ..taxonomy import ATTACK_TYPES
from .edge_iiotset import Dataset

COLUMNS: list[str] = [
    "arp.opcode", "arp.hw.size",
    "icmp.seq_le", "icmp.unused",
    "http.content_length", "http.response", "http.tls_port",
    "tcp.ack", "tcp.connection.fin", "tcp.connection.rst",
    "tcp.connection.syn", "tcp.connection.synack",
    "tcp.flags", "tcp.flags.ack", "tcp.len",
    "udp.time_delta",
    "dns.qry.qu", "dns.qry.type", "dns.retransmission",
    "mqtt.conflag.cleansess", "mqtt.hdrflags", "mqtt.len",
    "mqtt.msgtype", "mqtt.proto_len", "mqtt.topic_len", "mqtt.ver",
    "mbtcp.len", "mbtcp.unit_id",
]

# Baseline: quiet MQTT/Modbus telemetry between sensors and a SCADA master.
BASE: dict[str, tuple[float, float]] = {
    "arp.opcode": (0.1, 0.3),
    "arp.hw.size": (0.4, 1.2),
    "icmp.seq_le": (0.5, 2.0),
    "icmp.unused": (0.0, 0.2),
    "http.content_length": (12.0, 30.0),
    "http.response": (0.05, 0.2),
    "http.tls_port": (0.1, 0.3),
    "tcp.ack": (0.6, 0.4),
    "tcp.connection.fin": (0.4, 0.5),
    "tcp.connection.rst": (0.05, 0.2),
    "tcp.connection.syn": (0.5, 0.6),
    "tcp.connection.synack": (0.5, 0.6),
    "tcp.flags": (18.0, 6.0),
    "tcp.flags.ack": (0.6, 0.4),
    "tcp.len": (64.0, 28.0),
    "udp.time_delta": (0.25, 0.12),
    "dns.qry.qu": (0.02, 0.1),
    "dns.qry.type": (1.0, 0.5),
    "dns.retransmission": (0.02, 0.1),
    "mqtt.conflag.cleansess": (0.5, 0.5),
    "mqtt.hdrflags": (24.0, 8.0),
    "mqtt.len": (36.0, 14.0),
    "mqtt.msgtype": (3.0, 1.2),
    "mqtt.proto_len": (4.0, 0.6),
    "mqtt.topic_len": (14.0, 5.0),
    "mqtt.ver": (4.0, 0.3),
    "mbtcp.len": (12.0, 4.0),
    "mbtcp.unit_id": (1.0, 0.8),
}

# Per-class overrides. Values are (mean, sd). Note how often two classes touch
# the same column with overlapping ranges -- that overlap is the point.
OVERRIDES: dict[str, dict[str, tuple[float, float]]] = {
    "DDoS_UDP": {"udp.time_delta": (0.004, 0.004), "mqtt.len": (8, 6), "tcp.len": (28, 14)},
    "DDoS_ICMP": {"icmp.seq_le": (900, 420), "icmp.unused": (1.0, 0.4), "udp.time_delta": (0.01, 0.01)},
    "DDoS_TCP": {"tcp.connection.syn": (42, 22), "tcp.connection.synack": (2, 2), "tcp.flags": (2, 1)},
    "DDoS_HTTP": {"http.content_length": (420, 260), "http.response": (0.9, 0.3), "tcp.connection.syn": (16, 12)},
    "MITM": {"arp.opcode": (2.0, 0.6), "arp.hw.size": (6.0, 1.0), "udp.time_delta": (0.9, 0.5),
             "tcp.connection.rst": (1.4, 1.0)},
    "Port_Scanning": {"tcp.connection.syn": (26, 16), "tcp.connection.rst": (14, 9),
                      "tcp.len": (20, 10), "udp.time_delta": (0.02, 0.02)},
    "Vulnerability_scanner": {"http.content_length": (190, 120), "tcp.connection.rst": (8, 6),
                              "http.response": (0.7, 0.4), "tcp.connection.syn": (12, 9)},
    "Fingerprinting": {"tcp.flags": (41, 14), "tcp.connection.syn": (6, 5),
                       "icmp.seq_le": (30, 22), "tcp.len": (34, 18)},
    "Backdoor": {"tcp.len": (980, 340), "http.tls_port": (0.85, 0.3),
                 "tcp.connection.fin": (0.05, 0.1), "http.content_length": (310, 180)},
    "Ransomware": {"tcp.len": (1240, 380), "http.content_length": (640, 300),
                   "dns.retransmission": (1.2, 0.8), "http.tls_port": (0.7, 0.4)},
    "SQL_injection": {"http.content_length": (240, 110), "http.response": (0.8, 0.3),
                      "tcp.len": (260, 120)},
    "XSS": {"http.content_length": (200, 95), "http.response": (0.75, 0.35),
            "tcp.len": (215, 105)},
    "Uploading": {"http.content_length": (1500, 620), "tcp.len": (1180, 400),
                  "http.response": (0.6, 0.4)},
    "Password": {"http.content_length": (86, 34), "tcp.connection.syn": (9, 6),
                 "tcp.connection.rst": (5, 4), "http.response": (0.5, 0.4)},
}

# Roughly mirrors Edge-IIoTset's own imbalance: mostly normal, DoS heavy.
WEIGHTS: dict[str, float] = {
    "Normal": 0.34, "DDoS_UDP": 0.09, "DDoS_ICMP": 0.08, "DDoS_TCP": 0.07,
    "DDoS_HTTP": 0.05, "MITM": 0.03, "Port_Scanning": 0.06,
    "Vulnerability_scanner": 0.05, "Fingerprinting": 0.03, "Backdoor": 0.04,
    "Ransomware": 0.03, "SQL_injection": 0.04, "XSS": 0.04,
    "Uploading": 0.03, "Password": 0.02,
}

LABEL_NOISE = 0.015
SHARED_NOISE_SCALE = 0.35   # correlated jitter applied across all columns


def _block(attack: str, n: int, rng: np.random.Generator) -> pd.DataFrame:
    spec = {**BASE, **OVERRIDES.get(attack, {})}
    data = {}
    # One shared latent per sample -- this is what creates realistic
    # correlation between features and stops the classes separating cleanly.
    latent = rng.normal(0, 1, n)
    for col in COLUMNS:
        mean, sd = spec[col]
        shared = latent * sd * SHARED_NOISE_SCALE
        values = rng.normal(mean, sd, n) + shared
        data[col] = np.clip(values, 0, None)
    df = pd.DataFrame(data)
    df["Attack_type"] = attack
    return df


def build(n_samples: int = 60_000, random_state: int = 42) -> Dataset:
    rng = np.random.default_rng(random_state)
    parts = [_block(a, max(40, int(n_samples * WEIGHTS[a])), rng) for a in ATTACK_TYPES]
    df = pd.concat(parts, ignore_index=True).sample(frac=1, random_state=random_state)
    df = df.reset_index(drop=True)

    # Annotation noise: a small share of rows carry the wrong label, as they
    # would in any human-labelled capture.
    n_flip = int(len(df) * LABEL_NOISE)
    flip_idx = rng.choice(len(df), n_flip, replace=False)
    df.loc[flip_idx, "Attack_type"] = rng.choice(ATTACK_TYPES, n_flip)

    y = df["Attack_type"]
    X = df.drop(columns=["Attack_type"]).astype(np.float32)

    return Dataset(
        X=X,
        y=y,
        source="synthetic",
        feature_names=list(X.columns),
        categorical_maps={},
        rows_read=len(df),
        rows_kept=len(df),
        notes=[
            "Edge-IIoTset CSV not found -- generated a synthetic stand-in.",
            f"{len(df):,} rows across {len(ATTACK_TYPES)} classes with "
            f"{LABEL_NOISE:.1%} label noise and correlated feature jitter.",
            "Numbers from this source validate the pipeline, not detection quality.",
        ],
    )
