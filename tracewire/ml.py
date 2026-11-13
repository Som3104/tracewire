"""
Machine-learning detectors.

* Random Forest (supervised, multiclass): learns attack classes from day-1
  labeled flows. Strong on known attack types, needs labels.
* Isolation Forest (unsupervised): trained on day-1 benign flows only and
  flags flows that look unlike normal traffic. Needs no attack labels, so it
  can surface novel behaviour, at the price of more false positives.

IP addresses and raw port numbers are deliberately NOT features: the model
would memorise "203.0.113.45 is bad" and fail on a new attacker. Ports are
reduced to coarse service classes instead.
"""
from __future__ import annotations

import ipaddress

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler

LAB_NET = ipaddress.ip_network("10.10.0.0/24")
STATES = ["SF", "S0", "REJ", "RSTO", "RSTOS0", "RSTR", "SH", "S1", "S2", "S3", "OTH"]

FEATURES_BASE = [
    "duration", "fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes", "syn", "synack",
    "rst_fwd", "rst_bwd", "fin", "psh", "data_fwd", "data_bwd",
    "dns_qlen", "dns_label_max", "dns_entropy",
    "src_conns_60s", "src_dsts_60s", "src_dports_same_dst_60s", "src_failed_ratio_60s",
    "src_dports_600s", "src_failed_600s", "dsvc_conns_10s", "dsvc_srcs_10s", "dsvc_failed_10s",
]


def featurize(df: pd.DataFrame) -> pd.DataFrame:
    X = df[FEATURES_BASE].astype(float).copy()
    X["bytes_ratio"] = (df.fwd_bytes + 1) / (df.bwd_bytes + 1)
    X["mean_fwd_size"] = df.fwd_bytes / df.fwd_pkts.clip(lower=1)
    for p in ["tcp", "udp", "icmp"]:
        X[f"proto_{p}"] = (df.proto == p).astype(float)
    for s in STATES:
        X[f"state_{s}"] = (df.conn_state == s).astype(float)
    X["handshake_done"] = df.handshake_done.astype(float)
    X["dport_wellknown"] = (df.dport < 1024).astype(float)
    X["dport_login"] = df.dport.isin([21, 22, 23, 3389, 5900]).astype(float)
    X["dst_external"] = (~df.dst.map(lambda i: ipaddress.ip_address(i) in LAB_NET)).astype(float)
    X["src_external"] = (~df.src.map(lambda i: ipaddress.ip_address(i) in LAB_NET)).astype(float)
    # heavy-tailed counts -> log scale (helps Isolation Forest; harmless for trees)
    for c in ["duration", "fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes", "bytes_ratio", "mean_fwd_size"]:
        X[c] = np.log1p(X[c])
    return X


class Detectors:
    def __init__(self, seed: int = 42):
        self.rf = RandomForestClassifier(n_estimators=300, min_samples_leaf=2,
                                         class_weight="balanced_subsample", n_jobs=-1, random_state=seed)
        self.iso = IsolationForest(n_estimators=300, contamination="auto", random_state=seed)
        self.scaler = StandardScaler()
        self.iso_threshold = None

    def fit(self, train: pd.DataFrame):
        X = featurize(train)
        self.columns = list(X.columns)
        self.rf.fit(X, train.label)
        benign = X[train.label == "benign"]
        self.iso.fit(self.scaler.fit_transform(benign))
        # threshold = 1st percentile of benign anomaly scores -> ~1% FPR on training benign
        scores = self.iso.score_samples(self.scaler.transform(benign))
        self.iso_threshold = float(np.percentile(scores, 1))
        return self

    def predict(self, df: pd.DataFrame) -> pd.DataFrame:
        X = featurize(df)[self.columns]
        proba = self.rf.predict_proba(X)
        out = df[["flow_id"]].copy()
        out["rf_pred"] = self.rf.classes_[proba.argmax(1)]
        out["rf_conf"] = proba.max(1)
        s = self.iso.score_samples(self.scaler.transform(X))
        out["iso_score"] = -s
        out["iso_pred"] = np.where(s < self.iso_threshold, "anomaly", "benign")
        return out

    def importances(self, top=12):
        imp = sorted(zip(self.columns, self.rf.feature_importances_), key=lambda x: -x[1])
        return [{"feature": f, "importance": round(float(v), 4)} for f, v in imp[:top]]
