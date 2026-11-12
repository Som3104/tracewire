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


def test_scan_flows_are_rejected_or_half_open(day2):
    assert day2[day2.label == "portscan"].conn_state.isin({"REJ", "RSTOS0"}).all()


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
