# Tracewire

Network intrusion detection lab that scores **signature rules against machine learning** on labeled traffic, and shows the result on a dashboard built like a logic analyzer.

```
day1.pcap ──► flows ──► train ML (Random Forest + Isolation Forest)
day2.pcap ──► flows ──► 7 signature rules ──┐
                     └► ML inference ───────┴─► evaluate vs labels ──► dashboard
```

## Quick start

```bash
pip install -r requirements.txt

python -m tracewire.labgen --out data     # craft two labeled lab captures with Scapy (~2 min)
python run_pipeline.py                    # detect, evaluate, write dashboard/public/data.json
python -m pytest -q                       # 5 tests: flow reconstruction, rules, Zeek round-trip

cd dashboard && npm install && npm run dev        # dashboard at http://localhost:5173
npm run build:single                              # one portable HTML file in dist-single/

uvicorn api.server:app --port 8000                # JSON API (also a Grafana data source)
```

## What is in the lab capture

A 40-workstation office (web, DNS, file/SSH and database servers), public visitors, a remote admin, a monitoring host, OS updates, a cloud backup and benign failed connections, plus seven injected attacks. Day 1 trains; day 2 tests, with **different attackers, targets, ports and pacing**.

| Attack | Day 2 variant |
|---|---|
| Port scan | 700 random ports on the web server at 45/s |
| Host sweep | ICMP + TCP/3389 across the /24 |
| SYN flood | 2,000 spoofed SYNs to :443 in 10 s |
| Brute force | 90 SSH sessions in 110 s |
| DNS tunneling | 280 TXT queries with base32 labels |
| Slow scan | one probe every ~9 s for 27 min |
| Exfiltration | 10 uploads (~5 MB) to an external host on :4444 |

## Results (held-out day 2, 8,675 flows)

| Engine | Precision | Recall | F1 | FPR |
|---|---|---|---|---|
| Signature rules | 0.963 | 0.953 | 0.958 | 2.79% |
| Random forest | 1.000 | 0.986 | 0.993 | 0.02% |
| Isolation forest | 0.984 | 0.885 | 0.932 | 1.12% |

Rules miss the slow scan entirely; the forest catches it. The burst rule raises 3 false alerts on heavy web pages; the forest mistakes a benign cloud backup for exfiltration. Synthetic traffic is cleaner than real traffic: treat these as upper bounds.

## Layout

| Path | Purpose |
|---|---|
| `tracewire/labgen.py` | Scapy traffic generator with per-flow ground truth |
| `tracewire/flows.py` | pcap → bidirectional flows, Zeek-style conn states, context features |
| `tracewire/signatures.py` | Declarative sliding-window rule engine (TW-1001 … TW-1007) |
| `tracewire/ml.py` | Random Forest + Isolation Forest, no IP/port identity features |
| `tracewire/evaluate.py` | Flow, class, episode (time-to-detect) and alert-level metrics |
| `tracewire/ingest/` | Zeek conn.log/dns.log and Suricata eve.json adapters |
| `rules/suricata/`, `rules/zeek/` | Equivalent sensor rules (written, not yet run on a live sensor) |
| `api/server.py` | FastAPI read-only API |
| `dashboard/` | React + Vite dashboard |

## Running on real sensors (phase 2)

```bash
zeek -C -r data/day2.pcap rules/zeek/tracewire.zeek
python -m tracewire.ingest.zeek conn.log --dns dns.log

suricata -r data/day2.pcap -S rules/suricata/tracewire.rules -l out/
python -m tracewire.ingest.suricata out/eve.json
```
