"""
Packet capture -> bidirectional flow records (Zeek conn.log style).

Headers are decoded with struct instead of full Scapy dissection, which is
roughly 20x faster on large captures; Scapy is only used to decode DNS
payloads. Each flow gets per-flow features plus behavioural context features
(what the same source / destination did in the preceding seconds), which is
what both the correlation rules and the ML model consume.
"""
from __future__ import annotations

import math
import socket
import struct
from collections import defaultdict, deque, Counter

import pandas as pd
from scapy.all import DNS
from scapy.utils import RawPcapReader

IDLE_TIMEOUT = 120.0
PROTO = {6: "tcp", 17: "udp", 1: "icmp"}
F_FIN, F_SYN, F_RST, F_PSH, F_ACK = 0x01, 0x02, 0x04, 0x08, 0x10


def shannon(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def _new_flow(fid, ts, proto, src, sp, dst, dp):
    return dict(flow_id=fid, ts=ts, last=ts, proto=proto, src=src, sport=sp, dst=dst, dport=dp,
                fwd_pkts=0, bwd_pkts=0, fwd_bytes=0, bwd_bytes=0,
                syn=0, synack=0, rst_fwd=0, rst_bwd=0, fin=0, psh=0, data_fwd=0, data_bwd=0,
                closed=False, dns_qname="", dns_qtype="", icmp_type=-1, history="")


def read_flows(path: str) -> pd.DataFrame:
    flows: dict = {}
    done: list = []
    fid = 0
    reader = RawPcapReader(path)
    linktype = getattr(reader, "linktype", 1)
    for raw, meta in reader:
        ts = meta.sec + meta.usec / 1e6 if hasattr(meta, "usec") else float(meta.tshigh)
        off = 14 if linktype == 1 else 0
        if linktype == 1:
            etype = struct.unpack("!H", raw[12:14])[0]
            if etype == 0x8100:  # VLAN tag
                etype = struct.unpack("!H", raw[16:18])[0]; off = 18
            if etype != 0x0800:
                continue
        ihl = (raw[off] & 0x0F) * 4
        proto_n = raw[off + 9]
        if proto_n not in PROTO:
            continue
        src = socket.inet_ntoa(raw[off + 12:off + 16])
        dst = socket.inet_ntoa(raw[off + 16:off + 20])
        tot = struct.unpack("!H", raw[off + 2:off + 4])[0]
        l4 = off + ihl
        flags = 0
        icmp_type = -1
        if proto_n == 6:
            sp, dp = struct.unpack("!HH", raw[l4:l4 + 4])
            doff = (raw[l4 + 12] >> 4) * 4
            flags = raw[l4 + 13]
            payload = tot - ihl - doff
        elif proto_n == 17:
            sp, dp = struct.unpack("!HH", raw[l4:l4 + 4])
            payload = tot - ihl - 8
        else:
            icmp_type = raw[l4]
            ident = struct.unpack("!H", raw[l4 + 4:l4 + 6])[0]
            sp, dp = (ident, 0) if icmp_type == 8 else (0, ident) if icmp_type == 0 else (0, 0)
            payload = tot - ihl - 8
        proto = PROTO[proto_n]
        key = (proto, src, sp, dst, dp)
        rkey = (proto, dst, dp, src, sp)

        f, fwd = flows.get(key), True
        if f is None and rkey in flows:
            f, fwd = flows[rkey], False
        # start a new flow on idle timeout or a fresh SYN after close
        if f is not None and (ts - f["last"] > IDLE_TIMEOUT or
                              (f["closed"] and flags & F_SYN and not flags & F_ACK)):
            done.append(flows.pop(key if fwd else rkey))
            f = None
        if f is None:
            fid += 1
            f, fwd = _new_flow(fid, ts, proto, src, sp, dst, dp), True
            flows[key] = f
        f["last"] = ts
        if fwd:
            f["fwd_pkts"] += 1; f["fwd_bytes"] += max(payload, 0)
            if payload > 0: f["data_fwd"] += 1
        else:
            f["bwd_pkts"] += 1; f["bwd_bytes"] += max(payload, 0)
            if payload > 0: f["data_bwd"] += 1
        if proto == "tcp":
            if flags & F_SYN and not flags & F_ACK and fwd: f["syn"] += 1
            if flags & F_SYN and flags & F_ACK and not fwd: f["synack"] += 1
            if flags & F_RST: f["rst_fwd" if fwd else "rst_bwd"] += 1; f["closed"] = True
            if flags & F_FIN: f["fin"] += 1; f["closed"] = f["fin"] >= 2 or f["closed"]
            if flags & F_PSH: f["psh"] += 1
            # Zeek-style history: uppercase = originator, lowercase = responder
            ev = []
            if flags & F_SYN:
                ev.append("H" if flags & F_ACK else "S")
            elif flags & F_RST:
                ev.append("R")
            else:
                if payload > 0: ev.append("D")
                elif flags & F_ACK and not flags & F_FIN: ev.append("A")
                if flags & F_FIN: ev.append("F")
            for c in ev:
                c = c if fwd else c.lower()
                if c not in f["history"]:
                    f["history"] += c
        else:
            if proto == "icmp" and f["icmp_type"] < 0:
                f["icmp_type"] = icmp_type
            c = "D" if fwd else "d"
            if payload > 0 and c not in f["history"]:
                f["history"] += c
        if proto == "udp" and 53 in (sp, dp) and fwd and not f["dns_qname"]:
            try:
                d = DNS(raw[l4 + 8:])
                if d.qd is not None:
                    q = d.qd[0] if hasattr(d.qd, "__getitem__") else d.qd
                    f["dns_qname"] = q.qname.decode(errors="replace").rstrip(".")
                    f["dns_qtype"] = {1: "A", 16: "TXT", 28: "AAAA", 5: "CNAME"}.get(q.qtype, str(q.qtype))
            except Exception:
                pass
    reader.close()
    done.extend(flows.values())
    df = pd.DataFrame(done).sort_values("ts").reset_index(drop=True)
    df["duration"] = df["last"] - df["ts"]
    df["conn_state"] = df.apply(_conn_state, axis=1)
    df = derive_handshake(df)
    df["dns_qlen"] = df["dns_qname"].str.len()
    df["dns_label_max"] = df["dns_qname"].map(lambda q: max((len(x) for x in q.split(".")), default=0) if q else 0)
    df["dns_entropy"] = df["dns_qname"].map(lambda q: shannon(q.split(".")[0]) if q else 0.0)
    return df.drop(columns=["closed"])


def _conn_state(f) -> str:
    """Connection state using Zeek's definitions (base/protocols/conn/main.zeek)."""
    h = f["history"]
    if f["proto"] != "tcp":
        return "SF" if f["bwd_pkts"] else "S0"
    if "S" not in h:
        return "OTH"                            # midstream, no SYN seen
    if "h" not in h:                            # responder never sent SYN-ACK
        if "r" in h: return "REJ"               # attempt rejected
        if "R" in h: return "RSTOS0"            # SYN then originator RST
        if "F" in h: return "SH"                # SYN then FIN, half open
        return "S0"                             # attempt seen, no reply
    # SYN + SYN-ACK seen: Zeek treats the connection as established
    if "R" in h: return "RSTO"                  # originator aborted (incl. SYN-scan "ShR")
    if "r" in h: return "RSTR"                  # responder sent RST
    if "F" in h and "f" in h: return "SF"       # normal establishment and termination
    if "F" in h: return "S2"
    if "f" in h: return "S3"
    return "S1"                                 # established, not terminated


def derive_handshake(df: pd.DataFrame) -> pd.DataFrame:
    """Flags shared by the native parser and the Zeek adapter, both computed from history.
    A TCP connection only counts as completed if the originator ACKed the SYN-ACK."""
    h = df["history"].fillna("")
    tcp = df["proto"] == "tcp"
    df["handshake_done"] = tcp & h.str.contains("S") & h.str.contains("h") & h.str.contains("A", regex=False)
    df["failed"] = (tcp & ~df["handshake_done"]) | (~tcp & (df["bwd_pkts"] == 0))
    return df


def add_context(df: pd.DataFrame) -> pd.DataFrame:
    """Behavioural features computed over a trailing window of earlier flows."""
    ts = df["ts"].to_numpy()
    src, dst = df["src"].to_numpy(), df["dst"].to_numpy()
    dport, failed_col = df["dport"].to_numpy(), df["failed"].to_numpy()
    by_src = defaultdict(deque)        # src -> deque[(ts, dst, dport, failed)]
    by_dsvc = defaultdict(deque)       # (dst,dport) -> deque[(ts, src, failed)]
    out = defaultdict(list)
    for i in range(len(df)):
        t = ts[i]
        q = by_src[src[i]]
        while q and t - q[0][0] > 600:
            q.popleft()
        w60 = [x for x in q if t - x[0] <= 60]
        out["src_conns_60s"].append(len(w60))
        out["src_dsts_60s"].append(len({x[1] for x in w60}))
        out["src_dports_same_dst_60s"].append(len({x[2] for x in w60 if x[1] == dst[i]}))
        out["src_failed_ratio_60s"].append(sum(x[3] for x in w60) / len(w60) if w60 else 0.0)
        out["src_dports_600s"].append(len({x[2] for x in q}))
        out["src_failed_600s"].append(sum(x[3] for x in q))
        d = by_dsvc[(dst[i], dport[i])]
        while d and t - d[0][0] > 10:
            d.popleft()
        out["dsvc_conns_10s"].append(len(d))
        out["dsvc_srcs_10s"].append(len({x[1] for x in d}))
        out["dsvc_failed_10s"].append(sum(x[2] for x in d))
        failed = bool(failed_col[i])
        q.append((t, dst[i], dport[i], failed))
        d.append((t, src[i], failed))
    for k, v in out.items():
        df[k] = v
    return df


def attach_labels(df: pd.DataFrame, labels_csv: str) -> pd.DataFrame:
    lab = pd.read_csv(labels_csv)
    lab["episode_id"] = lab["episode_id"].fillna("")
    exact = {(r.proto, r.src, int(r.sport), r.dst, int(r.dport)): (r.label, r.episode_id) for r in lab.itertuples()}
    # Zeek puts ICMP type/code in the port fields, so ICMP also matches on (src, dst) alone
    icmp = {}
    for r in lab[lab.proto == "icmp"].itertuples():
        k = (r.src, r.dst)
        if k not in icmp or r.label != "benign":
            icmp[k] = (r.label, r.episode_id)
    out = []
    for p, s, sp, d, dp in zip(df.proto, df.src, df.sport.astype(int), df.dst, df.dport.astype(int)):
        v = exact.get((p, s, sp, d, dp))
        if v is None and p == "icmp":
            v = icmp.get((s, d)) or icmp.get((d, s))
        out.append(v or ("benign", ""))
    df["label"] = [v[0] for v in out]
    df["episode_id"] = [v[1] for v in out]
    return df
