"""
End-to-end pipeline:

    day1.pcap ──► flows ──► train ML (RF + Isolation Forest)
    day2.pcap ──► flows ──► signature rules ─┐
                         └► ML inference ────┴─► evaluate vs labels ──► dashboard JSON

Usage:
    python -m tracewire.labgen --out data      # build the labeled lab captures (once)
    python run_pipeline.py                     # detect, evaluate, export
    python run_pipeline.py --test-pcap my.pcap --test-labels my.labels.csv
"""
import argparse
import json
import pathlib
import time

from tracewire.flows import read_flows, add_context, attach_labels
from tracewire.signatures import run_rules, flow_predictions
from tracewire.ingest import suricata as sur
from tracewire.ingest.zeek import read_zeek_log, conn_to_flows
from tracewire.ml import Detectors
from tracewire.evaluate import evaluate
from tracewire import export


def load(pcap, labels, zeek_dir=None):
    """Flows from our own pcap parser, or from Zeek logs in zeek_dir (conn.log + dns.log)."""
    if zeek_dir:
        d = pathlib.Path(zeek_dir)
        dns = read_zeek_log(str(d / "dns.log")) if (d / "dns.log").exists() else None
        df = conn_to_flows(read_zeek_log(str(d / "conn.log")), dns)
        df = df[df.proto.isin(["tcp", "udp", "icmp"])].reset_index(drop=True)
    else:
        df = read_flows(pcap)
    df = add_context(df)
    return attach_labels(df, labels) if labels else df.assign(label="benign", episode_id="")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--train-pcap", default="data/day1.pcap")
    ap.add_argument("--train-labels", default="data/day1.labels.csv")
    ap.add_argument("--test-pcap", default="data/day2.pcap")
    ap.add_argument("--test-labels", default="data/day2.labels.csv")
    ap.add_argument("--episodes", default="data/day2.episodes.json")
    ap.add_argument("--out", default="dashboard/public/data.json")
    ap.add_argument("--suricata-eve", default="out/suricata/eve.json",
                    help="Suricata EVE log for the test capture; used as a third engine when the file exists")
    ap.add_argument("--flow-source", choices=["native", "zeek"], default="native",
                    help="native = Tracewire's pcap parser; zeek = conn.log/dns.log from out/zeek/day1 and day2")
    ap.add_argument("--zeek-dir", default="out/zeek")
    a = ap.parse_args()

    t = time.time()
    zk = a.flow_source == "zeek"
    train = load(a.train_pcap, a.train_labels, f"{a.zeek_dir}/day1" if zk else None)
    test = load(a.test_pcap, a.test_labels, f"{a.zeek_dir}/day2" if zk else None)
    print(f"flows ({a.flow_source}): train {len(train):,}  test {len(test):,}  ({time.time() - t:.1f}s)")

    alerts = run_rules(test)
    test = test.merge(flow_predictions(test, alerts), on="flow_id")

    sur_events = None
    if pathlib.Path(a.suricata_eve).exists():
        raw = sur.map_alerts_to_flows(test, sur.read_eve_alerts(a.suricata_eve))
        test = test.merge(sur.flow_predictions(test, raw), on="flow_id")
        sur_events = sur.events(raw, test.set_index("flow_id").label, float(test.ts.min()))
        unmapped = sum(r["flow_id"] is None for r in raw)
        print(f"suricata: {len(raw):,} alerts -> {len(sur_events)} events ({unmapped} not matched to a flow)")
    det = Detectors().fit(train)
    test = test.merge(det.predict(test), on="flow_id")

    episodes = json.load(open(a.episodes)) if pathlib.Path(a.episodes).exists() else []
    metrics = evaluate(test, episodes, alerts, sur_events)

    print("\nflow-level            precision  recall    F1     FPR")
    for k, m in metrics["flow_level"].items():
        print(f"  {k:<18} {m['precision']:>9.3f} {m['recall']:>7.3f} {m['f1']:>7.3f} {m['fpr']:>8.4f}")
    print(f"\nRF class accuracy on malicious flows: {metrics['rf_class_accuracy']:.3f}")
    print(f"signature alerts: {metrics['alert_level']['alerts']}  "
          f"false alerts: {metrics['alert_level']['false_alerts']}")
    if "alert_level_suricata" in metrics:
        s_ = metrics["alert_level_suricata"]
        print(f"suricata events: {s_['alerts']} ({s_['raw_alerts']} raw alerts)  false events: {s_['false_alerts']}")
    engines = list(metrics["flow_level"])
    print("\nepisode             " + "".join(f"{k:<18}" for k in engines))
    for e in metrics["episodes"]:
        cells = []
        for k in engines:
            d = e[k]
            cells.append(f"{'hit ' + str(d['latency_s']) + 's' if d['detected'] else 'MISSED':<18}")
        print(f"  {e['attack']:<18}" + "".join(cells))

    meta = {"capture": pathlib.Path(a.test_pcap).name, "trained_on": pathlib.Path(a.train_pcap).name,
            "start": float(test.ts.min()), "duration": float(test["last"].max() - test.ts.min()),
            "flows": int(len(test)), "packets": int((test.fwd_pkts + test.bwd_pkts).sum()),
            "bytes": int((test.fwd_bytes + test.bwd_bytes).sum()),
            "hosts": int(len(set(test.src) | set(test.dst))), "train_flows": int(len(train)),
            "n_features": len(det.columns)}
    meta["flow_source"] = a.flow_source
    doc = export.build(test, alerts, metrics, det.importances(), meta, sur_events=sur_events)
    out = pathlib.Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, separators=(",", ":")))
    test.drop(columns=[c for c in ["dns_qname", "uid"] if c in test]).to_csv("data/day2.flows.csv", index=False)
    json.dump(metrics, open("data/metrics.json", "w"), indent=2)
    print(f"\nwrote {out} ({out.stat().st_size / 1024:.0f} kB), data/metrics.json, data/day2.flows.csv")


if __name__ == "__main__":
    main()
