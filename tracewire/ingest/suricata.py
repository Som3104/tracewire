"""
Suricata adapter: turn EVE JSON alerts into dashboard ledger events, so
Suricata's packet-level signatures can be shown next to Tracewire's
flow-level rules and the ML model.

    suricata -r capture.pcap -S rules/suricata/tracewire.rules -l out/
    python -m tracewire.ingest.suricata out/eve.json
"""
from __future__ import annotations

import json
from datetime import datetime

SID_TO_ATTACK = {9100001: "portscan", 9100002: "sweep", 9100003: "synflood", 9100004: "bruteforce",
                 9100005: "dns_tunnel", 9100006: "exfil", 9100007: "dns_tunnel"}


def read_eve_alerts(path: str, t0: float | None = None) -> list[dict]:
    events = []
    with open(path) as f:
        for line in f:
            if not line.strip():
                continue
            e = json.loads(line)
            if e.get("event_type") != "alert":
                continue
            ts = datetime.fromisoformat(e["timestamp"].replace("Z", "+00:00")).timestamp()
            al = e["alert"]
            events.append({
                "id": f"SUR-{len(events) + 1:04d}", "engine": "suricata", "rule": str(al.get("signature_id")),
                "name": al.get("signature", ""), "attack": SID_TO_ATTACK.get(al.get("signature_id"), "other"),
                "severity": {1: 4, 2: 3, 3: 2}.get(al.get("severity", 3), 1),
                "t": round(ts - (t0 or 0), 3), "src": e.get("src_ip"), "dst": f"{e.get('dest_ip')}:{e.get('dest_port', '')}",
                "proto": e.get("proto", "").lower()})
    return events


if __name__ == "__main__":
    import sys
    for ev in read_eve_alerts(sys.argv[1]):
        print(ev)
