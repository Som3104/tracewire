# Tracewire

Network intrusion detection lab that scores **signature rules, Suricata and machine learning** on the same labeled traffic, and shows the result on a dashboard built like a logic analyzer, plus a Grafana operations view.

```
day1.pcap ──► flows (Tracewire parser or Zeek) ──► train ML (Random Forest + Isolation Forest)
day2.pcap ──► flows ──► Tracewire rules ────────┐
          │          └► ML inference ───────────┤
          └► Suricata ──► eve.json alerts ───────┴─► evaluate vs labels ──► React dashboard
                                                                        └─► PostgreSQL ──► Grafana
```

## Quick start

```bash
pip install -r requirements.txt

python -m tracewire.labgen --out data     # craft two labeled lab captures with Scapy (~2 min)
python run_pipeline.py                    # detect, evaluate, write dashboard/public/data.json
python -m pytest -q                       # flow reconstruction, rules, handshake states, Zeek round-trip, Suricata mapping

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

| Engine | Precision | Recall | F1 | FPR | Episodes caught |
|---|---|---|---|---|---|
| Tracewire rules | 0.963 | 0.953 | 0.958 | 2.79% | 6 of 7 |
| Suricata 7.0.3 | 1.000 | 0.320 | 0.485 | 0.00% | 5 of 7 |
| Random forest | 1.000 | 0.987 | 0.993 | 0.02% | 7 of 7 |
| Isolation forest | 0.982 | 0.869 | 0.922 | 1.22% | 4 of 7 |

- Every rule engine misses the slow scan; the forest catches it.
- Suricata never raises a false alert, but its threshold rules alert once per interval, so flow-level recall is low. It misses the exfiltration because `stream_size` counts bytes per connection and the attacker split 5 MB into ten uploads.
- Suricata labels the RDP host sweep as "brute force": a packet-rate rule cannot tell many hosts from many attempts.
- Tracewire's burst rule raises 3 false alerts on heavy web pages; the forest mistakes a benign cloud backup for exfiltration.

Synthetic traffic is cleaner than real traffic: treat these as upper bounds.

## Layout

| Path | Purpose |
|---|---|
| `tracewire/labgen.py` | Scapy traffic generator with per-flow ground truth |
| `tracewire/flows.py` | pcap → bidirectional flows, Zeek-style conn states, context features |
| `tracewire/signatures.py` | Declarative sliding-window rule engine (TW-1001 … TW-1007) |
| `tracewire/ml.py` | Random Forest + Isolation Forest, no IP/port identity features |
| `tracewire/evaluate.py` | Flow, class, episode (time-to-detect) and alert-level metrics |
| `tracewire/ingest/` | Zeek conn.log/dns.log and Suricata eve.json adapters |
| `tracewire/store.py` | Loads results into PostgreSQL for Grafana |
| `rules/suricata/`, `rules/zeek/` | Sensor rules, run on the lab captures |
| `api/server.py` | FastAPI read-only API |
| `dashboard/` | React + Vite dashboard |
| `grafana/` | Dashboard-as-code generator, provisioned data source and dashboard |
| `docker-compose.yml` | Sensors, PostgreSQL, loader, API, Grafana |

## Phase 2: real sensors and Grafana (Docker)

Needs Docker Desktop. Run from the project folder after `python -m tracewire.labgen --out data`.

```bash
docker compose --profile sensors run --rm suricata    # Suricata on day2.pcap   -> out/suricata/eve.json
docker compose --profile sensors run --rm zeek        # Zeek on both captures   -> out/zeek/day1, out/zeek/day2

python run_pipeline.py                                # Suricata is picked up automatically as a third engine
python run_pipeline.py --flow-source zeek             # optional: use Zeek's conn.log instead of Tracewire's parser

docker compose up -d                                  # PostgreSQL + loader + API + Grafana
```

- Grafana: http://localhost:3000 (dashboard **Tracewire operations**; sign in as admin / admin to edit)
- API: http://localhost:8000/docs

After re-running the pipeline, reload Grafana's data with `docker compose run --rm loader`.

The Grafana dashboard is generated from code (`python grafana/make_dashboard.py`) and reads PostgreSQL through Grafana's built-in data source, so no plugins are downloaded.
