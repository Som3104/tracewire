"""
Small read-only API over the pipeline output, for the React dashboard in dev
mode and as a JSON datasource for Grafana (Infinity plugin).

    uvicorn api.server:app --reload --port 8000
"""
import json
import pathlib

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

ROOT = pathlib.Path(__file__).resolve().parent.parent
DATA = ROOT / "dashboard" / "public" / "data.json"

app = FastAPI(title="Tracewire API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["GET"])


def doc():
    if not DATA.exists():
        raise HTTPException(503, "Run `python run_pipeline.py` first to produce detection results.")
    return json.loads(DATA.read_text())


@app.get("/api/summary")
def summary():
    d = doc()
    return {"meta": d["meta"], "metrics": d["metrics"]["flow_level"], "alerts": d["metrics"]["alert_level"]}


@app.get("/api/events")
def events(engine: str | None = Query(None, pattern="^(signature|ml)$"), min_severity: int = 1):
    return [e for e in doc()["events"] if (engine is None or e["engine"] == engine) and e["severity"] >= min_severity]


@app.get("/api/timeline")
def timeline():
    d = doc()
    t0 = d["meta"]["start"]
    # Grafana wants absolute epoch-ms timestamps
    return [{"time": int((t0 + b["t"]) * 1000), "flows": b["flows"], "packets": b["pkts"],
             "signature_hits": b["sig"], "ml_hits": b["rf"], "malicious_truth": sum(b["truth"].values())}
            for b in d["bins"]]


@app.get("/api/episodes")
def episodes():
    return doc()["episodes"]


@app.get("/api/dashboard")
def everything():
    return doc()
