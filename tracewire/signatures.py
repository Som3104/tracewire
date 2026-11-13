"""
Signature / correlation rule engine.

Rules are declarative: a flow filter, a grouping key, a sliding window, a
measure (count, distinct values, or sum) and a threshold. This mirrors how
Suricata `threshold`/`detection_filter` keywords and Zeek's SumStats
framework express scan and flood logic, so every rule here has a direct
counterpart in rules/suricata and rules/zeek.
"""
from __future__ import annotations

import ipaddress
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Callable

import pandas as pd

LAB_NET = ipaddress.ip_network("10.10.0.0/24")
STD_PORTS = {20, 21, 22, 25, 53, 80, 110, 123, 143, 443, 445, 465, 587, 993, 995, 3389, 5432}


def internal(ip: str) -> bool:
    return ipaddress.ip_address(ip) in LAB_NET


@dataclass
class Rule:
    rule_id: str
    name: str
    attack: str                      # class this rule predicts
    severity: int                    # 1 low .. 4 critical
    logic: str                       # human-readable condition, shown in the dashboard
    match: Callable[[pd.DataFrame], pd.Series]
    group: tuple
    window: float
    measure: str                     # "count" | "nunique:<col>" | "sum:<col>"
    threshold: float
    cooldown: float = 60.0


RULES = [
    Rule("TW-1001", "Vertical port scan", "portscan", 3,
         "≥ 20 distinct ports on one host, handshake never completed, within 10 s",
         lambda d: (d.proto == "tcp") & d.failed,
         ("src", "dst"), 10, "nunique:dport", 20),
    Rule("TW-1002", "Horizontal host sweep", "sweep", 3,
         "≥ 15 distinct hosts on one port (or ICMP echo), within 30 s",
         lambda d: ((d.proto == "tcp") & d.failed) | ((d.proto == "icmp") & (d.icmp_type == 8)),
         ("src", "proto", "dport"), 30, "nunique:dst", 15),
    Rule("TW-1003", "SYN flood", "synflood", 4,
         "≥ 100 half-open connections to one service within 5 s",
         lambda d: (d.proto == "tcp") & d.failed & d.conn_state.isin(["S0", "S1"]),   # no reply, or SYN-ACK never ACKed
         ("dst", "dport"), 5, "count", 100),
    Rule("TW-1004", "Login brute force", "bruteforce", 3,
         "≥ 15 short sessions to a login port (21/22/23/3389/5900) within 60 s",
         lambda d: (d.proto == "tcp") & d.dport.isin([21, 22, 23, 3389, 5900]) & (d.duration < 10),
         ("src", "dst", "dport"), 60, "count", 15),
    Rule("TW-1005", "DNS tunneling", "dns_tunnel", 3,
         "≥ 10 queries with a label ≥ 30 chars or name ≥ 60 chars within 60 s",
         lambda d: (d.dport == 53) & ((d.dns_label_max >= 30) | (d.dns_qlen >= 60)),
         ("src",), 60, "count", 10),
    Rule("TW-1006", "Bulk upload to non-standard port", "exfil", 4,
         "≥ 1 MB sent to an external host on a non-standard port within 5 min",
         lambda d: (d.proto == "tcp") & ~d.dport.isin(STD_PORTS) & ~d.dst.map(internal) & (d.fwd_bytes > d.bwd_bytes * 5),
         ("src", "dst", "dport"), 300, "sum:fwd_bytes", 1_000_000),
    Rule("TW-1007", "Connection burst", "burst", 1,
         "≥ 40 new connections from one source within 5 s",
         lambda d: d.proto.isin(["tcp", "udp"]),
         ("src",), 5, "count", 40),
]


@dataclass
class Alert:
    alert_id: str
    rule_id: str
    name: str
    attack: str
    severity: int
    ts: float
    last_ts: float
    group: dict
    value: float
    flow_ids: list = field(default_factory=list)


def _measure(q, measure):
    if measure == "count":
        return len(q)
    kind, _ = measure.split(":")
    if kind == "nunique":
        return len({x[1] for x in q})
    return sum(x[1] for x in q)


def run_rules(df: pd.DataFrame, rules=RULES) -> list[Alert]:
    alerts: list[Alert] = []
    for rule in rules:
        sub = df[rule.match(df)]
        col = rule.measure.split(":")[1] if ":" in rule.measure else None
        windows: dict = defaultdict(deque)
        open_alert: dict = {}
        for row in sub.itertuples(index=False):
            g = tuple(getattr(row, k) for k in rule.group)
            q = windows[g]
            q.append((row.ts, getattr(row, col) if col else 1, row.flow_id))
            seen = row.last              # evidence exists once the flow has completed
            while q and row.ts - q[0][0] > rule.window:
                q.popleft()
            v = _measure(q, rule.measure)
            if v < rule.threshold:
                continue
            a = open_alert.get(g)
            if a and seen - a.last_ts <= rule.cooldown:
                a.flow_ids.append(row.flow_id)
                a.last_ts = max(a.last_ts, seen)
                a.value = max(a.value, v)
            else:
                a = Alert(f"{rule.rule_id}-{len(alerts) + 1:04d}", rule.rule_id, rule.name, rule.attack,
                          rule.severity, seen, seen, dict(zip(rule.group, map(str, g))), v,
                          [x[2] for x in q])
                open_alert[g] = a
                alerts.append(a)
    alerts.sort(key=lambda a: a.ts)
    return alerts


def flow_predictions(df: pd.DataFrame, alerts: list[Alert]) -> pd.DataFrame:
    """Per-flow verdict: the highest-severity rule that covered the flow."""
    best: dict = {}
    for a in alerts:
        for fid in a.flow_ids:
            if fid not in best or a.severity > best[fid][1]:
                best[fid] = (a.attack, a.severity, a.ts)
    out = df[["flow_id"]].copy()
    out["sig_pred"] = out.flow_id.map(lambda f: best.get(f, ("benign",))[0])
    out["sig_alert_ts"] = out.flow_id.map(lambda f: best.get(f, (None, None, None))[2])
    return out
