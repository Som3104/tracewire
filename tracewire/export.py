"""Shape pipeline results into the single JSON document the dashboard reads."""
from __future__ import annotations

import ipaddress
from collections import Counter, defaultdict

import numpy as np
import pandas as pd

from .signatures import RULES, internal

SERVICE = {("tcp", 80): "HTTP", ("tcp", 443): "HTTPS", ("udp", 53): "DNS", ("tcp", 22): "SSH",
           ("tcp", 445): "SMB", ("tcp", 5432): "Postgres", ("tcp", 3389): "RDP", ("udp", 123): "NTP"}
ROLE = {"10.10.0.10": "web server", "10.10.0.11": "dns resolver", "10.10.0.12": "file + ssh server",
        "10.10.0.13": "database", "10.10.0.5": "monitoring", "10.10.0.1": "gateway"}
SEVERITY = {"synflood": 4, "exfil": 4, "portscan": 3, "sweep": 3, "bruteforce": 3, "dns_tunnel": 3,
            "stealth_scan": 2, "burst": 1, "anomaly": 1}
ATTACK_NAME = {"portscan": "Port scan", "sweep": "Host sweep", "synflood": "SYN flood",
               "bruteforce": "Brute force", "dns_tunnel": "DNS tunneling", "stealth_scan": "Slow scan",
               "exfil": "Exfiltration", "burst": "Connection burst", "benign": "Benign"}


def _alert_target(g: dict) -> str:
    if "dst" in g:
        return g["dst"] + (f":{g['dport']}" if "dport" in g else "")
    if g.get("proto") == "icmp":
        return "many hosts, ICMP echo"
    if "dport" in g:
        return f"many hosts, {g.get('proto', 'tcp').upper()}/{g['dport']}"
    return "many"


def service(proto, dport):
    if proto == "icmp":
        return "ICMP"
    return SERVICE.get((proto, int(dport)), f"{proto.upper()} other")


def _nodes(df: pd.DataFrame):
    """Collapse the long tail of hosts so the topology stays readable."""
    stats = defaultdict(lambda: {"flows": 0, "labels": Counter(), "sent": 0, "mal_sent": 0, "recv": 0})
    for r in df[["src", "dst", "label"]].itertuples(index=False):
        stats[r.src]["flows"] += 1; stats[r.src]["labels"][r.label] += 1; stats[r.src]["sent"] += 1
        stats[r.src]["mal_sent"] += r.label != "benign"
        stats[r.dst]["flows"] += 1; stats[r.dst]["labels"][r.label] += 1; stats[r.dst]["recv"] += 1
    answered = set(df.loc[df.bwd_pkts > 0, "dst"])
    node = {}
    for ip, s in stats.items():
        mal = sum(v for k, v in s["labels"].items() if k != "benign")
        if ip in ROLE:
            node[ip] = ip
        elif internal(ip):
            if ip not in answered and s["sent"] == 0:
                node[ip] = "unused addresses"
            elif s["mal_sent"] == 0:
                node[ip] = "workstations"
            else:
                node[ip] = ip
        else:
            top = s["labels"].most_common(1)[0][0]
            if s["flows"] < 30 and top == "synflood":
                node[ip] = "spoofed sources"
            elif top == "benign" and s["recv"] == 0:
                node[ip] = "internet visitors"
            else:
                node[ip] = ip
    return node


def build(df: pd.DataFrame, alerts, metrics: dict, importances, meta: dict, bin_s: int = 10) -> dict:
    t0 = float(df.ts.min())
    df = df.copy()
    df["svc"] = [service(p, d) for p, d in zip(df.proto, df.dport)]
    df["pkts"] = df.fwd_pkts + df.bwd_pkts
    df["bytes"] = df.fwd_bytes + df.bwd_bytes
    df["bin"] = ((df.ts - t0) // bin_s).astype(int)
    nbins = int(meta["duration"] // bin_s) + 1

    # ------------------------------------------------ timeline
    bins = []
    g = df.groupby("bin")
    for b in range(nbins):
        if b in g.groups:
            x = df.loc[g.groups[b]]
            truth = {k: int(v) for k, v in x.label.value_counts().items() if k != "benign"}
            det = {c: [int(n), int((x.sig_pred[x.label == c] != "benign").sum()),
                       int((x.rf_pred[x.label == c] != "benign").sum())] for c, n in truth.items()}
            ben = x.label == "benign"
            fp = [int((x.sig_pred[ben] != "benign").sum()), int((x.rf_pred[ben] != "benign").sum())]
            bins.append({"t": b * bin_s, "flows": int(len(x)), "pkts": int(x.pkts.sum()),
                         "bytes": int(x.bytes.sum()),
                         "proto": {k: int(v) for k, v in x.proto.value_counts().items()},
                         "truth": truth, "det": det, "fp": fp,
                         "sig": int((x.sig_pred != "benign").sum()),
                         "rf": int((x.rf_pred != "benign").sum()),
                         "iso": int((x.iso_pred != "benign").sum())})
        else:
            bins.append({"t": b * bin_s, "flows": 0, "pkts": 0, "bytes": 0, "proto": {}, "truth": {}, "det": {}, "fp": [0, 0],
                         "sig": 0, "rf": 0, "iso": 0})

    # ------------------------------------------------ unified event ledger
    labels = df.set_index("flow_id").label
    events = []
    for a in alerts:
        lab = labels.reindex(a.flow_ids)
        mal = lab[lab != "benign"]
        events.append({"id": a.alert_id, "engine": "signature", "rule": a.rule_id, "name": a.name,
                       "attack": a.attack, "severity": a.severity, "t": round(a.ts - t0, 2),
                       "t_end": round(a.last_ts - t0, 2), "src": a.group.get("src", "many"),
                       "dst": _alert_target(a.group),
                       "flows": len(a.flow_ids),
                       "truth": mal.value_counts().index[0] if len(mal) else "benign",
                       "verdict": "true positive" if len(mal) else "false positive"})
    rf = df[df.rf_pred != "benign"].sort_values("ts")
    open_ev: dict = {}
    for r in rf.itertuples(index=False):
        key = (r.rf_pred, r.dst if r.rf_pred == "synflood" else r.src)
        e = open_ev.get(key)
        if e and r.ts - e["_last"] <= 60:
            e["_last"] = r.ts; e["flows"] += 1; e["_labels"][r.label] += 1; e["_dsts"].add(r.dst)
            e["_conf"].append(r.rf_conf)
        else:
            e = {"id": f"ML-{len(open_ev) + 1:04d}", "engine": "ml", "rule": "RF", "attack": r.rf_pred,
                 "name": ATTACK_NAME.get(r.rf_pred, r.rf_pred), "severity": SEVERITY.get(r.rf_pred, 2),
                 "_first": r.ts, "_last": r.ts, "src": "many" if r.rf_pred == "synflood" else r.src,
                 "flows": 1, "_labels": Counter([r.label]), "_dsts": {r.dst}, "_conf": [r.rf_conf]}
            open_ev[key + (r.ts,)] = e
            open_ev[key] = e
    seen = set()
    for e in open_ev.values():
        if id(e) in seen:
            continue
        seen.add(id(e))
        mal = {k: v for k, v in e["_labels"].items() if k != "benign"}
        events.append({"id": e["id"], "engine": "ml", "rule": "RF", "name": e["name"], "attack": e["attack"],
                       "severity": e["severity"], "t": round(e["_first"] - t0, 2), "t_end": round(e["_last"] - t0, 2),
                       "src": e["src"], "dst": next(iter(e["_dsts"])) if len(e["_dsts"]) == 1 else f"{len(e['_dsts'])} hosts",
                       "flows": e["flows"], "confidence": round(float(np.mean(e["_conf"])), 3),
                       "truth": max(mal, key=mal.get) if mal else "benign",
                       "verdict": "true positive" if mal else "false positive"})
    events.sort(key=lambda e: e["t"])
    for i, e in enumerate(sorted([e for e in events if e["engine"] == "ml"], key=lambda e: e["t"])):
        e["id"] = f"ML-{i + 1:04d}"

    # ------------------------------------------------ topology
    node = _nodes(df)
    df["sn"] = df.src.map(node); df["dn"] = df.dst.map(node)
    nodes = []
    for n, x in pd.concat([df.assign(_n=df.sn), df.assign(_n=df.dn)]).groupby("_n"):
        members = sorted(set(x.src[x.sn == n]) | set(x.dst[x.dn == n]))
        mal = x[x.label != "benign"]
        kind = ("server" if n in ROLE and n not in ("10.10.0.5", "10.10.0.1") else
                "internal" if (n in ("workstations", "unused addresses", "10.10.0.5") or (n[0].isdigit() and internal(n)))
                else "external")
        nodes.append({"id": n, "kind": kind, "role": ROLE.get(n, ""), "members": len(members),
                      "flows": int(len(x) // 1), "bytes": int(x.bytes.sum()),
                      "malicious_flows": int(len(mal)),
                      "attacks": sorted(set(mal.label)),
                      "as_attacker": int((mal.sn == n).sum()), "as_victim": int((mal.dn == n).sum())})
    edges = []
    for (s, d), x in df.groupby(["sn", "dn"]):
        mal = x[x.label != "benign"]
        edges.append({"src": s, "dst": d, "flows": int(len(x)), "bytes": int(x.bytes.sum()),
                      "services": {k: int(v) for k, v in x.svc.value_counts().head(4).items()},
                      "truth": mal.label.value_counts().index[0] if len(mal) else "benign",
                      "malicious": int(len(mal)),
                      "sig": int((x.sig_pred != "benign").sum()), "rf": int((x.rf_pred != "benign").sum())})

    # ------------------------------------------------ services
    services = []
    for s, x in df.groupby("svc"):
        services.append({"service": s, "flows": int(len(x)), "pkts": int(x.pkts.sum()), "bytes": int(x.bytes.sum()),
                         "malicious": int((x.label != "benign").sum()),
                         "attacks": {k: int(v) for k, v in x.label[x.label != "benign"].value_counts().items()}})
    services.sort(key=lambda s: -s["flows"])

    eps = []
    for e in metrics["episodes"]:
        e = dict(e); e["start"] = round(e["start"] - t0, 2); e["end"] = round(e["end"] - t0, 2); eps.append(e)

    return {"meta": meta, "bin_s": bin_s, "bins": bins, "episodes": eps, "events": events,
            "nodes": nodes, "edges": edges, "services": services,
            "metrics": {k: v for k, v in metrics.items() if k != "episodes"},
            "rules": [{"id": r.rule_id, "name": r.name, "attack": r.attack, "severity": r.severity,
                       "logic": r.logic, "window_s": r.window} for r in RULES],
            "importances": importances, "importances_total": meta.get("n_features"),
            "attack_names": ATTACK_NAME}
