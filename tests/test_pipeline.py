"""Run with:  python -m pytest -q   (expects `python -m tracewire.labgen --out data` to have run)"""
import pathlib
import pandas as pd
import pytest

from tracewire.flows import read_flows, add_context, attach_labels
from tracewire.signatures import run_rules, flow_predictions
from tracewire.ingest.zeek import flows_to_conn_log, read_zeek_log, conn_to_flows

DATA = pathlib.Path(__file__).parent.parent / "data"
pytestmark = pytest.mark.skipif(not (DATA / "day2.pcap").exists(), reason="generate captures first")


@pytest.fixture(scope="module")
def day2():
    return attach_labels(add_context(read_flows(str(DATA / "day2.pcap"))), str(DATA / "day2.labels.csv"))


def test_every_labeled_flow_is_reconstructed(day2):
    labels = pd.read_csv(DATA / "day2.labels.csv")
    assert len(day2) == len(labels)
    assert (day2.label != "benign").sum() == (labels.label != "benign").sum()


def test_scan_flows_never_complete_a_handshake(day2):
    scan = day2[day2.label == "portscan"]
    assert scan.failed.all()
    # closed ports answer RST (REJ, history "Sr"); open ports get SYN-ACK then the scanner's RST ("ShR")
    assert set(scan.conn_state) <= {"REJ", "RSTO"}
    assert set(scan.history) <= {"Sr", "ShR"}


def test_benign_sessions_complete_handshake(day2):
    web = day2[(day2.label == "benign") & (day2.dport == 443) & (day2.conn_state == "SF")]
    assert len(web) > 1000 and web.handshake_done.all()


def test_each_rule_fires_on_its_attack(day2):
    alerts = run_rules(day2)
    fired = {a.attack for a in alerts}
    for attack in ["portscan", "sweep", "synflood", "bruteforce", "dns_tunnel", "exfil"]:
        assert attack in fired


def test_slow_scan_evades_threshold_rules(day2):
    preds = day2.merge(flow_predictions(day2, run_rules(day2)), on="flow_id")
    assert (preds[preds.label == "stealth_scan"].sig_pred == "benign").all()


def test_zeek_conn_log_round_trip(day2, tmp_path):
    p = tmp_path / "conn.log"
    flows_to_conn_log(day2, str(p))
    z = add_context(conn_to_flows(read_zeek_log(str(p))))
    assert len(z) == len(day2)
    native = {a.rule_id for a in run_rules(day2) if a.rule_id != "TW-1005"}   # dns needs dns.log
    via_zeek = {a.rule_id for a in run_rules(z)}
    assert native <= via_zeek


EVE = DATA.parent / "out" / "suricata" / "eve.json"


@pytest.mark.skipif(not EVE.exists(), reason="run Suricata first (docker compose --profile sensors run --rm suricata)")
def test_suricata_alerts_map_to_flows(day2):
    from tracewire.ingest import suricata as sur
    raw = sur.map_alerts_to_flows(day2, sur.read_eve_alerts(str(EVE)))
    assert raw, "no alerts in eve.json"
    assert sum(a["flow_id"] is None for a in raw) / len(raw) < 0.01     # every alert lands on a flow
    preds = day2.merge(sur.flow_predictions(day2, raw), on="flow_id")
    hit = preds[preds.sur_pred != "benign"]
    assert (hit.label != "benign").mean() > 0.95                        # Suricata alerts are on attack traffic


ZEEK2 = DATA.parent / "out" / "zeek" / "day2" / "conn.log"


@pytest.mark.skipif(not ZEEK2.exists(), reason="run Zeek first (docker compose --profile sensors run --rm zeek)")
def test_zeek_conn_log_matches_native_parser(day2):
    """Real Zeek output: same connections, same states, and the rules fire identically."""
    dns = read_zeek_log(str(ZEEK2.parent / "dns.log"))
    z = attach_labels(add_context(conn_to_flows(read_zeek_log(str(ZEEK2)), dns)), str(DATA / "day2.labels.csv"))
    assert len(z) == len(day2)
    assert (z.label != "benign").sum() == (day2.label != "benign").sum()
    tcp = lambda d: d[d.proto == "tcp"].conn_state.value_counts().sort_index()
    assert tcp(z).equals(tcp(day2))
    assert {a.rule_id for a in run_rules(z)} == {a.rule_id for a in run_rules(day2)}
