"""
Evaluation against ground truth, at three levels:

Engines: Tracewire rules, Suricata (when an eve.json is supplied), Random Forest, Isolation Forest.

1. Flow level   - precision / recall / F1 / false-positive rate per detector
2. Class level  - detection rate for each attack type, plus confusion matrices
3. Episode level- was each attack episode caught at all, and how fast
                  (time from first malicious packet to first detection).
                  This is the number a SOC actually cares about.
4. Alert level  - how many raised alerts contained no malicious flow
                  (pure noise an analyst would have to triage).
"""
from __future__ import annotations

import numpy as np
import pandas as pd

ALL_DETECTORS = {"signature": "sig_pred", "suricata": "sur_pred", "random_forest": "rf_pred",
                 "isolation_forest": "iso_pred"}
ALERT_TS = {"signature": "sig_alert_ts", "suricata": "sur_alert_ts"}   # rule engines: time the alert fired


def detectors(df: pd.DataFrame) -> dict:
    return {k: v for k, v in ALL_DETECTORS.items() if v in df}


def _binary(y_true_mal, y_pred_mal):
    tp = int((y_true_mal & y_pred_mal).sum()); fp = int((~y_true_mal & y_pred_mal).sum())
    fn = int((y_true_mal & ~y_pred_mal).sum()); tn = int((~y_true_mal & ~y_pred_mal).sum())
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    return dict(tp=tp, fp=fp, fn=fn, tn=tn, precision=round(p, 4), recall=round(r, 4),
                f1=round(f1, 4), fpr=round(fp / (fp + tn) if fp + tn else 0.0, 5))


def evaluate(df: pd.DataFrame, episodes: list[dict], alerts, extra_events: list[dict] | None = None) -> dict:
    DETECTORS = detectors(df)
    mal = df.label != "benign"
    out = {"flow_level": {}, "per_class": {}, "confusion": {}, "episodes": [], "alert_level": {}}
    classes = sorted(df.label.unique(), key=lambda c: (c != "benign", c))

    for name, col in DETECTORS.items():
        pred_mal = df[col] != "benign"
        out["flow_level"][name] = _binary(mal, pred_mal)
        out["per_class"][name] = {c: round(float(pred_mal[df.label == c].mean()), 4)
                                  for c in classes if c != "benign"}
        pred_classes = sorted(df[col].unique(), key=lambda c: (c != "benign", c))
        ct = pd.crosstab(df.label, df[col]).reindex(index=classes, columns=pred_classes, fill_value=0)
        out["confusion"][name] = {"rows": classes, "cols": pred_classes, "matrix": ct.values.tolist()}

    # RF also predicts the class: report multiclass accuracy on malicious flows
    out["rf_class_accuracy"] = round(float((df.rf_pred[mal] == df.label[mal]).mean()), 4)

    for ep in episodes:
        f = df[df.episode_id == ep["episode_id"]]
        row = {**ep, "flows": int(len(f))}
        for name, col in DETECTORS.items():
            hit = f[f[col] != "benign"]
            if name in ALERT_TS:
                times = hit[ALERT_TS[name]].dropna()
                first = float(times.min()) if len(times) else None
            else:
                first = float(hit["last"].min()) if len(hit) else None   # ML scores a flow when it completes
            row[name] = {"detected": first is not None,
                         "coverage": round(len(hit) / max(len(f), 1), 4),
                         "latency_s": round(first - ep["start"], 2) if first is not None else None}
        out["episodes"].append(row)

    labels = df.set_index("flow_id").label
    noisy = [a for a in alerts if (labels.reindex(a.flow_ids) == "benign").all()]
    out["alert_level"] = {"alerts": len(alerts), "false_alerts": len(noisy),
                          "alert_precision": round(1 - len(noisy) / max(len(alerts), 1), 4),
                          "false_alert_ids": [a.alert_id for a in noisy]}
    if extra_events:   # Suricata: events are already grouped and verdicted against the labels
        fp = [e for e in extra_events if e["verdict"] == "false positive"]
        out["alert_level_suricata"] = {"alerts": len(extra_events), "raw_alerts": sum(e["alerts"] for e in extra_events),
                                       "false_alerts": len(fp),
                                       "alert_precision": round(1 - len(fp) / max(len(extra_events), 1), 4),
                                       "false_alert_ids": [e["id"] for e in fp]}
    return out
