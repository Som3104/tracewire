"""
Dashboards as code: generates grafana/dashboards/tracewire.json.

    python grafana/make_dashboard.py

Every panel is plain SQL against the tables written by tracewire.store, using
Grafana's built-in PostgreSQL data source (uid "tracewire-db").
"""
import json
import pathlib

DS = {"uid": "tracewire-db"}   # resolved by uid, so it works whatever plugin id the Grafana version uses
# hue = engine family (amber rules, blue ML), as on the React dashboard; Suricata is told apart by a dashed line
COLORS = {"Ground truth": "#8f9a98", "Tracewire rules": "#c98500", "Suricata": "#e3b04b",
          "Random forest": "#2c93c0", "Isolation forest": "#5fb0d6"}
_id = iter(range(1, 100))


def target(sql, fmt="table"):
    return [{"refId": "A", "datasource": DS, "format": fmt, "rawQuery": True, "editorMode": "code", "rawSql": sql}]


def panel(kind, title, sql, x, y, w, h, fmt="table", description="", **extra):
    p = {"id": next(_id), "type": kind, "title": title, "description": description, "datasource": DS,
         "gridPos": {"x": x, "y": y, "w": w, "h": h}, "targets": target(sql, fmt)}
    p.update(extra)
    return p


def series_colors(names):
    out = [{"matcher": {"id": "byName", "options": n},
            "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": COLORS[n]}}]} for n in names]
    for o in out:
        if o["matcher"]["options"] == "Suricata":
            o["properties"].append({"id": "custom.lineStyle", "value": {"fill": "dash", "dash": [8, 4]}})
    return out


def stat(title, sql, x, w, description="", color="text"):
    return panel("stat", title, sql, x, 0, w, 4, description=description,
                 options={"reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
                          "colorMode": "value", "graphMode": "none", "textMode": "value", "justifyMode": "center"},
                 fieldConfig={"defaults": {"color": {"mode": "fixed", "fixedColor": color}, "decimals": 0}, "overrides": []})


ENGINES_SQL = """count(*) FILTER (WHERE label <> 'benign') AS "Ground truth",
  count(*) FILTER (WHERE sig_pred <> 'benign') AS "Tracewire rules",
  count(*) FILTER (WHERE sur_pred IS NOT NULL AND sur_pred <> 'benign') AS "Suricata",
  count(*) FILTER (WHERE rf_pred <> 'benign') AS "Random forest\""""

LATENCY_COL = """max(CASE WHEN engine = '{e}' THEN CASE WHEN detected THEN to_char(latency_s, 'FM990.0') || ' s' ELSE 'missed' END END) AS "{e}\""""

panels = [
    stat("Flows analysed", "SELECT count(*) FROM flows WHERE $__timeFilter(ts)", 0, 6),
    stat("Attack flows (ground truth)", "SELECT count(*) FROM flows WHERE label <> 'benign' AND $__timeFilter(ts)", 6, 6),
    stat("Alerts raised, all engines", "SELECT count(*) FROM events WHERE $__timeFilter(t)", 12, 6,
         "Grouped detections from Tracewire rules, Suricata and the random forest."),
    stat("False alerts", "SELECT count(*) FROM events WHERE verdict = 'false positive' AND $__timeFilter(t)", 18, 6,
         "Alerts whose flows were all benign: noise an analyst would have to triage.", color="#b8326a"),

    panel("timeseries", "Flows per 10 seconds",
          "SELECT $__timeGroupAlias(ts, '10s'), count(*) AS \"Flows\"\nFROM flows WHERE $__timeFilter(ts)\nGROUP BY 1 ORDER BY 1",
          0, 4, 12, 8, fmt="time_series",
          fieldConfig={"defaults": {"color": {"mode": "fixed", "fixedColor": "#8f9a98"},
                                    "custom": {"lineWidth": 1, "fillOpacity": 12, "showPoints": "never"}}, "overrides": []},
          options={"legend": {"showLegend": False}, "tooltip": {"mode": "single"}}),
    panel("timeseries", "Attack flows flagged per 10 seconds, by engine",
          f"SELECT $__timeGroupAlias(ts, '10s'),\n  {ENGINES_SQL}\nFROM flows WHERE $__timeFilter(ts)\nGROUP BY 1 ORDER BY 1",
          12, 4, 12, 8, fmt="time_series",
          description="Ground truth is the number of attack flows that started in each 10-second bin; each engine line counts the flows it flagged.",
          fieldConfig={"defaults": {"custom": {"lineWidth": 1.5, "fillOpacity": 0, "showPoints": "never", "drawStyle": "line"}},
                       "overrides": series_colors(["Ground truth", "Tracewire rules", "Suricata", "Random forest"])},
          options={"legend": {"showLegend": True, "displayMode": "list", "placement": "bottom"}, "tooltip": {"mode": "multi"}}),

    panel("table", "Detector scores (flow level)",
          "SELECT engine AS \"Engine\", precision AS \"Precision\", recall AS \"Recall\", f1 AS \"F1\", fpr AS \"False-positive rate\",\n  tp AS \"TP\", fp AS \"FP\", fn AS \"FN\"\nFROM scores ORDER BY f1 DESC",
          0, 12, 12, 7,
          fieldConfig={"defaults": {"decimals": 3}, "overrides": [
              {"matcher": {"id": "byName", "options": "False-positive rate"}, "properties": [{"id": "unit", "value": "percentunit"}, {"id": "decimals", "value": 2}]},
              {"matcher": {"id": "byRegexp", "options": "TP|FP|FN"}, "properties": [{"id": "decimals", "value": 0}]},
              {"matcher": {"id": "byName", "options": "F1"}, "properties": [
                  {"id": "custom.cellOptions", "value": {"type": "gauge", "mode": "basic"}}, {"id": "min", "value": 0}, {"id": "max", "value": 1},
                  {"id": "color", "value": {"mode": "fixed", "fixedColor": "#2c93c0"}}]}]}),
    panel("table", "Time to detect, per attack episode",
          "SELECT attack AS \"Attack\",\n  "
          + ",\n  ".join(LATENCY_COL.format(e=e) for e in ["Tracewire rules", "Suricata", "Random forest", "Isolation forest"])
          + "\nFROM episodes GROUP BY attack ORDER BY min(start_ts)",
          12, 12, 12, 7,
          description="Seconds from the attack's first packet to the engine's first detection.",
          fieldConfig={"defaults": {"mappings": [{"type": "value", "options": {"missed": {"color": "#b8326a", "index": 0}}}],
                                    "custom": {"cellOptions": {"type": "color-text"}}}, "overrides": []}),

    panel("table", "Event ledger",
          "SELECT t AS \"Time\", engine AS \"Engine\", rule AS \"Rule\", name AS \"Detection\", severity AS \"Severity\",\n"
          "  src AS \"Source\", dst AS \"Target\", flows AS \"Flows\", truth AS \"Ground truth\", verdict AS \"Verdict\"\n"
          "FROM events WHERE $__timeFilter(t) ORDER BY t",
          0, 19, 24, 10,
          fieldConfig={"defaults": {}, "overrides": [
              {"matcher": {"id": "byName", "options": "Verdict"}, "properties": [
                  {"id": "custom.cellOptions", "value": {"type": "color-text"}},
                  {"id": "mappings", "value": [{"type": "value", "options": {
                      "false positive": {"color": "#b8326a", "index": 0}, "true positive": {"color": "text", "index": 1}}}]}]},
              {"matcher": {"id": "byName", "options": "Engine"}, "properties": [
                  {"id": "custom.cellOptions", "value": {"type": "color-text"}},
                  {"id": "mappings", "value": [{"type": "value", "options": {k: {"color": v, "index": i} for i, (k, v) in enumerate(COLORS.items()) if k != "Ground truth"}}]}]},
              {"matcher": {"id": "byName", "options": "Time"}, "properties": [{"id": "unit", "value": "dateTimeAsIso"}, {"id": "custom.width", "value": 190}]}]},
          options={"showHeader": True, "cellHeight": "sm"}),

    panel("bargauge", "Flows by service",
          "SELECT service AS metric, count(*) AS value FROM flows WHERE $__timeFilter(ts)\nGROUP BY 1 ORDER BY 2 DESC",
          0, 29, 12, 8,
          options={"orientation": "horizontal", "displayMode": "basic", "showUnfilled": True,
                   "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": True}},
          fieldConfig={"defaults": {"color": {"mode": "fixed", "fixedColor": "#8f9a98"}, "min": 0}, "overrides": []}),
    panel("table", "Top talkers",
          "SELECT src AS \"Source\", count(*) AS \"Flows\", count(DISTINCT dst) AS \"Hosts contacted\",\n"
          "  count(DISTINCT dport) AS \"Ports contacted\", count(*) FILTER (WHERE label <> 'benign') AS \"Attack flows\"\n"
          "FROM flows WHERE $__timeFilter(ts)\nGROUP BY src ORDER BY count(DISTINCT dport) DESC, count(*) DESC LIMIT 12",
          12, 29, 12, 8,
          description="Sorted by distinct ports: scanners float to the top even when they send few flows."),
]

dashboard = {
    "uid": "tracewire-ops", "title": "Tracewire operations", "tags": ["tracewire", "ids", "soc"],
    "timezone": "utc", "schemaVersion": 39, "version": 1, "editable": True, "graphTooltip": 1,
    "time": {"from": "2025-11-13T08:00:00.000Z", "to": "2025-11-13T08:30:00.000Z"},
    "refresh": "", "panels": panels, "templating": {"list": []}, "annotations": {"list": [
        {"name": "Attack episodes", "enable": True, "iconColor": "#b8326a", "datasource": DS,
         "target": {"refId": "Anno", "format": "table", "rawQuery": True, "editorMode": "code",
                    "rawSql": "SELECT DISTINCT ON (episode) start_ts AS time, attack || ' by ' || attacker AS text, 'episode' AS tags\nFROM episodes WHERE $__timeFilter(start_ts) ORDER BY episode"}}]},
}

out = pathlib.Path(__file__).parent / "dashboards" / "tracewire.json"
out.parent.mkdir(exist_ok=True)
out.write_text(json.dumps(dashboard, indent=2))
print(f"wrote {out} ({len(panels)} panels)")
