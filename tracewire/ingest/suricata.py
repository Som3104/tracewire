"""
Suricata adapter: turn EVE JSON alerts into a third detection engine.

    suricata -r data/day2.pcap -S rules/suricata/tracewire.rules -l out/suricata -k none \
             --set vars.address-groups.HOME_NET="[10.10.0.0/24]"
    python run_pipeline.py --suricata-eve out/suricata/eve.json

Suricata alerts on packets, not flows. Each alert is mapped back to the flow
it belongs to by 5-tuple and time, so Suricata can be scored with the same
flow-level metrics as the other engines. Threshold rules (`threshold: type
both`) deliberately alert once per interval, so flow-level recall understates
them; the episode-level view (was the attack noticed, how fast) is the fairer
comparison and is reported too.
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import datetime

import pandas as pd

SID = {  # sid -> (attack class, severity 1..4)
    9100001: ("portscan", 3), 9100002: ("sweep", 3), 9100003: ("synflood", 4),
    9100004: ("bruteforce", 3), 9100005: ("dns_tunnel", 3), 9100006: ("exfil", 4),
    9100007: ("dns_tunnel", 2),
}
TRACK_DST = {9100003}            # rules that track by destination instead of source


def _ts(s: str) -> float:
    return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()


def read_eve_alerts(path: str) -> list[dict]:
    out = []
    with open(path) as f:
        for line in f:
            if '"event_type":"alert"' not in line and '"event_type": "alert"' not in line:
                continue
            e = json.loads(line)
            a = e["alert"]
            sid = a.get("signature_id")
            attack, sev = SID.get(sid, ("other", {1: 4, 2: 3, 3: 2}.get(a.get("severity", 3), 1)))
            out.append({"ts": _ts(e["timestamp"]), "sid": sid, "name": a.get("signature", "").replace("TRACEWIRE ", ""),
                        "attack": attack, "severity": sev, "proto": e.get("proto", "").lower(),
                        "src": e.get("src_ip"), "sport": int(e.get("src_port", 0) or 0),
                        "dst": e.get("dest_ip"), "dport": int(e.get("dest_port", 0) or 0)})
    out.sort(key=lambda a: a["ts"])
    return out


def map_alerts_to_flows(df: pd.DataFrame, alerts: list[dict]) -> list[dict]:
    """Attach the matching flow_id to each alert (5-tuple in either direction, alert inside the flow's lifetime)."""
    idx = defaultdict(list)
    for r in df[["flow_id", "proto", "src", "sport", "dst", "dport", "ts", "last"]].itertuples(index=False):
        idx[(r.proto, r.src, int(r.sport), r.dst, int(r.dport))].append((r.ts, r.last, r.flow_id))
        if r.proto == "icmp":
            idx[("icmp", r.src, r.dst)].append((r.ts, r.last, r.flow_id))
    for a in alerts:
        if a["proto"] == "icmp":
            cands = idx.get(("icmp", a["src"], a["dst"]), []) + idx.get(("icmp", a["dst"], a["src"]), [])
        else:
            cands = idx.get((a["proto"], a["src"], a["sport"], a["dst"], a["dport"]), []) + \
                    idx.get((a["proto"], a["dst"], a["dport"], a["src"], a["sport"]), [])
        best = None
        for t0, t1, fid in cands:
            if t0 - 1 <= a["ts"] <= t1 + 1:
                gap = abs(a["ts"] - t0)
                if best is None or gap < best[0]:
                    best = (gap, fid)
        a["flow_id"] = best[1] if best else None
    return alerts


def flow_predictions(df: pd.DataFrame, alerts: list[dict]) -> pd.DataFrame:
    best: dict = {}
    for a in alerts:
        fid = a.get("flow_id")
        if fid is None:
            continue
        if fid not in best or a["severity"] > best[fid][1] or (a["severity"] == best[fid][1] and a["ts"] < best[fid][2]):
            best[fid] = (a["attack"], a["severity"], a["ts"])
    out = df[["flow_id"]].copy()
    out["sur_pred"] = out.flow_id.map(lambda f: best.get(f, ("benign",))[0])
    out["sur_alert_ts"] = out.flow_id.map(lambda f: best.get(f, (None, None, None))[2])
    return out


def events(alerts: list[dict], labels: pd.Series, t0: float, gap: float = 60.0) -> list[dict]:
    """Collapse raw alerts into ledger events: same rule + same tracked host, no gap longer than `gap` seconds."""
    open_ev, evs = {}, []
    for a in alerts:
        key = (a["sid"], a["dst"] if a["sid"] in TRACK_DST else a["src"])
        e = open_ev.get(key)
        if e and a["ts"] - e["_last"] <= gap:
            e["_last"] = a["ts"]; e["alerts"] += 1; e["_dsts"].add(a["dst"]); e["_srcs"].add(a["src"])
            if a.get("flow_id") is not None:
                e["_flows"].add(a["flow_id"])
        else:
            e = {"_first": a["ts"], "_last": a["ts"], "sid": a["sid"], "name": a["name"], "attack": a["attack"],
                 "severity": a["severity"], "alerts": 1, "_dsts": {a["dst"]}, "_srcs": {a["src"]},
                 "_flows": {a["flow_id"]} if a.get("flow_id") is not None else set()}
            open_ev[key] = e
            evs.append(e)
    out = []
    for i, e in enumerate(evs):
        lab = labels.reindex(list(e["_flows"])).fillna("benign")
        mal = Counter(l for l in lab if l != "benign")
        out.append({"id": f"SUR-{i + 1:04d}", "engine": "suricata", "rule": str(e["sid"]), "name": e["name"],
                    "attack": e["attack"], "severity": e["severity"],
                    "t": round(e["_first"] - t0, 2), "t_end": round(e["_last"] - t0, 2),
                    "src": next(iter(e["_srcs"])) if len(e["_srcs"]) == 1 else f"{len(e['_srcs'])} hosts",
                    "dst": next(iter(e["_dsts"])) if len(e["_dsts"]) == 1 else f"{len(e['_dsts'])} hosts",
                    "flows": len(e["_flows"]), "alerts": e["alerts"],
                    "truth": mal.most_common(1)[0][0] if mal else "benign",
                    "verdict": "true positive" if mal else "false positive"})
    return out


if __name__ == "__main__":
    import sys
    for a in read_eve_alerts(sys.argv[1])[:20]:
        print(a)
