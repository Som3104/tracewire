"""
Zeek adapter: read conn.log (+ optional dns.log) into the same flow schema the
rule engine and ML model use, so Tracewire can run on a real Zeek sensor
instead of its own pcap parser.

    zeek -C -r capture.pcap            # produces conn.log, dns.log, ...
    python -m tracewire.ingest.zeek conn.log --dns dns.log

Both Zeek's default TSV format and JSON logs (LogAscii::use_json=T) are accepted.
"""
from __future__ import annotations

import json

import pandas as pd

from ..flows import shannon, derive_handshake

COLS = {"id.orig_h": "src", "id.orig_p": "sport", "id.resp_h": "dst", "id.resp_p": "dport",
        "orig_pkts": "fwd_pkts", "resp_pkts": "bwd_pkts", "orig_bytes": "fwd_bytes", "resp_bytes": "bwd_bytes"}


def read_zeek_log(path: str) -> pd.DataFrame:
    with open(path) as f:
        first = f.readline()
        f.seek(0)
        if first.startswith("{"):
            return pd.DataFrame(json.loads(l) for l in f if l.strip())
        fields, rows = None, []
        for line in f:
            if line.startswith("#fields"):
                fields = line.rstrip("\n").split("\t")[1:]
            elif line.startswith("#"):
                continue
            else:
                rows.append(line.rstrip("\n").split("\t"))
    df = pd.DataFrame(rows, columns=fields)
    return df.replace({"-": None, "(empty)": None})


def _history_counts(h: str) -> dict:
    """Zeek history: uppercase = originator, lowercase = responder.
    S syn, H syn-ack, A ack, D data, F fin, R rst."""
    h = h or ""
    return {"syn": h.count("S"), "synack": h.count("h") + h.count("H"), "rst_fwd": h.count("R"),
            "rst_bwd": h.count("r"), "fin": h.count("F") + h.count("f"), "psh": 0,
            "data_fwd": int("D" in h), "data_bwd": int("d" in h)}


def conn_to_flows(conn: pd.DataFrame, dns: pd.DataFrame | None = None) -> pd.DataFrame:
    df = conn.rename(columns=COLS).copy()
    df["ts"] = df.ts.astype(float)
    df["duration"] = pd.to_numeric(df.duration, errors="coerce").fillna(0.0)
    df["last"] = df.ts + df.duration
    for c in ["sport", "dport", "fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes"]:
        df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0).astype(int)
    if "history" not in df:
        df["history"] = ""
    df["history"] = df["history"].fillna("")
    hist = pd.DataFrame([_history_counts(h) for h in df["history"]])
    df = pd.concat([df.reset_index(drop=True), hist], axis=1)
    df["flow_id"] = range(1, len(df) + 1)
    df["icmp_type"] = df.apply(lambda r: r.sport if r.proto == "icmp" else -1, axis=1)
    df["dns_qname"] = ""
    df["dns_qtype"] = ""
    if dns is not None and len(dns):
        q = dns.dropna(subset=["query"]).drop_duplicates("uid").set_index("uid")["query"]
        df["dns_qname"] = df.uid.map(q).fillna("")
    df["dns_qlen"] = df.dns_qname.str.len()
    df["dns_label_max"] = df.dns_qname.map(lambda q: max((len(x) for x in q.split(".")), default=0) if q else 0)
    df["dns_entropy"] = df.dns_qname.map(lambda q: shannon(q.split(".")[0]) if q else 0.0)
    # conn_state comes straight from Zeek; the handshake flags are derived from history
    # exactly as the native parser derives them, so rules and features behave the same
    df = derive_handshake(df)
    return df.sort_values("ts").reset_index(drop=True)


def flows_to_conn_log(flows: pd.DataFrame, path: str):
    """Write flows in Zeek conn.log TSV format (used to test this adapter round-trip)."""
    fields = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "duration",
              "orig_bytes", "resp_bytes", "conn_state", "history", "orig_pkts", "resp_pkts"]
    with open(path, "w") as f:
        f.write("#separator \\x09\n#path\tconn\n#fields\t" + "\t".join(fields) + "\n")
        for r in flows.itertuples(index=False):
            f.write("\t".join(map(str, [f"{r.ts:.6f}", f"C{r.flow_id}", r.src, r.sport, r.dst,
                    r.icmp_type if r.proto == "icmp" else r.dport, r.proto, f"{r.duration:.6f}",
                    r.fwd_bytes, r.bwd_bytes, r.conn_state, r.history or "-", r.fwd_pkts, r.bwd_pkts])) + "\n")


if __name__ == "__main__":
    import argparse
    from ..flows import add_context
    from ..signatures import run_rules
    ap = argparse.ArgumentParser()
    ap.add_argument("conn"); ap.add_argument("--dns")
    a = ap.parse_args()
    flows = add_context(conn_to_flows(read_zeek_log(a.conn), read_zeek_log(a.dns) if a.dns else None))
    for al in run_rules(flows):
        print(f"{al.alert_id}  {al.name:<34} {al.group}  flows={len(al.flow_ids)}")
