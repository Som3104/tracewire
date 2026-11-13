"""
Load pipeline results into PostgreSQL so Grafana can query them with its
built-in PostgreSQL data source (no plugins needed).

    python -m tracewire.store --dsn postgresql://tracewire:tracewire@localhost:5432/tracewire

In Docker Compose the `loader` service runs this automatically.
"""
from __future__ import annotations

import argparse
import io
import json
import time

import pandas as pd
import psycopg

ENGINE_NAME = {"signature": "Tracewire rules", "suricata": "Suricata", "random_forest": "Random forest",
               "isolation_forest": "Isolation forest", "ml": "Random forest"}
SERVICE = {("tcp", 80): "HTTP", ("tcp", 443): "HTTPS", ("udp", 53): "DNS", ("tcp", 22): "SSH",
           ("tcp", 445): "SMB", ("tcp", 5432): "Postgres", ("tcp", 3389): "RDP"}

SCHEMA = """
DROP TABLE IF EXISTS flows, events, scores, episodes, capture;
CREATE TABLE flows (
  ts timestamptz, last_ts timestamptz, proto text, src text, sport int, dst text, dport int,
  service text, conn_state text, history text, pkts int, bytes bigint,
  label text, sig_pred text, sur_pred text, rf_pred text, iso_pred text);
CREATE TABLE events (
  t timestamptz, t_end timestamptz, engine text, rule text, name text, attack text, severity int,
  src text, dst text, flows int, truth text, verdict text);
CREATE TABLE scores (engine text, precision float8, recall float8, f1 float8, fpr float8,
                     tp int, fp int, fn int, tn int);
CREATE TABLE episodes (episode text, attack text, attacker text, target text, start_ts timestamptz,
                       engine text, detected boolean, latency_s float8, coverage float8);
CREATE TABLE capture (name text, trained_on text, start_ts timestamptz, end_ts timestamptz,
                      flows int, packets int, hosts int, flow_source text);
CREATE INDEX ON flows (ts);
CREATE INDEX ON events (t);
"""


def _copy(cur, table: str, df: pd.DataFrame):
    buf = io.StringIO()
    df.to_csv(buf, index=False, header=False, na_rep="\\N")
    buf.seek(0)
    with cur.copy(f"COPY {table} ({', '.join(df.columns)}) FROM STDIN WITH (FORMAT csv, NULL '\\N')") as cp:
        cp.write(buf.read())


def _utc(x):
    return pd.to_datetime(x, unit="s", utc=True)


def load(dsn: str, flows_csv: str, dashboard_json: str):
    doc = json.load(open(dashboard_json))
    m, t0 = doc["meta"], doc["meta"]["start"]
    f = pd.read_csv(flows_csv, low_memory=False)
    if "sur_pred" not in f:
        f["sur_pred"] = None
    flows = pd.DataFrame({
        "ts": _utc(f.ts), "last_ts": _utc(f["last"]), "proto": f.proto, "src": f.src, "sport": f.sport,
        "dst": f.dst, "dport": f.dport,
        "service": [("ICMP" if p == "icmp" else SERVICE.get((p, int(d)), f"{p.upper()} other")) for p, d in zip(f.proto, f.dport)],
        "conn_state": f.conn_state, "history": f.history.fillna(""), "pkts": f.fwd_pkts + f.bwd_pkts,
        "bytes": f.fwd_bytes + f.bwd_bytes, "label": f.label, "sig_pred": f.sig_pred, "sur_pred": f.sur_pred,
        "rf_pred": f.rf_pred, "iso_pred": f.iso_pred})
    ev = pd.DataFrame(doc["events"])
    events = pd.DataFrame({
        "t": _utc(t0 + ev.t), "t_end": _utc(t0 + ev.t_end), "engine": ev.engine.map(ENGINE_NAME).fillna(ev.engine),
        "rule": ev.rule, "name": ev.name, "attack": ev.attack.map(doc["attack_names"]).fillna(ev.attack),
        "severity": ev.severity, "src": ev.src, "dst": ev.dst, "flows": ev.flows,
        "truth": ev.truth.map(doc["attack_names"]).fillna(ev.truth), "verdict": ev.verdict})
    scores = pd.DataFrame([{"engine": ENGINE_NAME[k], **{c: v[c] for c in ["precision", "recall", "f1", "fpr", "tp", "fp", "fn", "tn"]}}
                           for k, v in doc["metrics"]["flow_level"].items()])
    eps = []
    for e in doc["episodes"]:
        for k in doc["engines"]:
            d = e[k]
            eps.append({"episode": e["episode_id"], "attack": doc["attack_names"][e["attack"]], "attacker": e["attacker"],
                        "target": e["target"], "start_ts": _utc(t0 + e["start"]), "engine": ENGINE_NAME[k],
                        "detected": d["detected"], "latency_s": d["latency_s"], "coverage": d["coverage"]})
    capture = pd.DataFrame([{"name": m["capture"], "trained_on": m["trained_on"], "start_ts": _utc(t0),
                             "end_ts": _utc(t0 + m["duration"]), "flows": m["flows"], "packets": m["packets"],
                             "hosts": m["hosts"], "flow_source": m.get("flow_source", "native")}])
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(SCHEMA)
        for name, df in [("flows", flows), ("events", events), ("scores", scores),
                         ("episodes", pd.DataFrame(eps)), ("capture", capture)]:
            _copy(cur, name, df)
        conn.commit()
    print(f"loaded {len(flows):,} flows, {len(events)} events, {len(scores)} engines, {len(eps)} episode rows")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dsn", default="postgresql://tracewire:tracewire@localhost:5432/tracewire")
    ap.add_argument("--flows", default="data/day2.flows.csv")
    ap.add_argument("--dashboard", default="dashboard/public/data.json")
    ap.add_argument("--wait", type=int, default=0, help="seconds to keep retrying while the database starts")
    a = ap.parse_args()
    deadline = time.time() + a.wait
    while True:
        try:
            return load(a.dsn, a.flows, a.dashboard)
        except psycopg.OperationalError:
            if time.time() > deadline:
                raise
            time.sleep(2)


if __name__ == "__main__":
    main()
