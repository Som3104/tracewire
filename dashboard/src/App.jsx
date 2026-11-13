import { useState } from 'react'
import data from '../public/data.json'
import Analyzer from './Analyzer.jsx'
import Bench, { Episodes } from './Bench.jsx'
import PatchPanel from './PatchPanel.jsx'
import { Matrix, Services, Rules, Importances, Ledger } from './Panels.jsx'
import { C, int, mmss, bytes } from './util.jsx'

export default function App() {
  const [probe, setProbe] = useState(null)
  const [pinned, setPinned] = useState(null)
  const [node, setNode] = useState(null)
  const m = data.meta
  const al = data.metrics.alert_level
  const hasSur = data.engines.includes('suricata')
  const sal = data.metrics.alert_level_suricata
  const started = new Date(m.start * 1000).toISOString().replace('T', ' ').slice(0, 16)

  return (
    <div className="plate">
      <header className="head">
        <div className="brand">
          <h1>
            Tracewire
            <svg className="wire" viewBox="0 0 64 18" aria-hidden>
              <path d="M0 14H10V4H18V14H30V4H34V14H44V4H56V14H64" fill="none" stroke={C.ink} strokeWidth="2" />
            </svg>
          </h1>
          <p>Network intrusion detection lab: signature rules and machine learning, scored against a labeled capture.</p>
        </div>
        <dl className="readouts">
          <div className="readout"><dt>Capture under test</dt><dd>{m.capture}</dd></div>
          <div className="readout"><dt>Started (UTC)</dt><dd>{started}</dd></div>
          <div className="readout"><dt>Length</dt><dd>{mmss(m.duration)}</dd></div>
          <div className="readout"><dt>Packets</dt><dd>{int(m.packets)}</dd></div>
          <div className="readout"><dt>Flows</dt><dd>{int(m.flows)}</dd></div>
          <div className="readout"><dt>Hosts</dt><dd>{int(m.hosts)}</dd></div>
          <div className="readout"><dt>Flows from</dt><dd>{m.flow_source === 'zeek' ? 'Zeek' : 'Tracewire'}</dd></div>
        </dl>
        <div className="key-legend">
          <span><svg width="26" height="12"><path d="M1 10H8V2H18V10H25" fill="none" stroke={C.ink} strokeWidth="1.6" /></svg>Ground truth (attack traffic present)</span>
          <span><svg width="10" height="10"><rect width="10" height="10" fill={C.sigInk} /></svg>Tracewire rules</span>
          {hasSur && <span><svg width="10" height="10"><rect x="1" y="1" width="8" height="8" fill="none" stroke={C.sigInk} strokeWidth="1.8" /></svg>Suricata</span>}
          <span><svg width="10" height="10"><circle cx="5" cy="5" r="5" fill={C.mlInk} /></svg>Random forest</span>
          <span><svg width="10" height="10"><polygon points="5,0.5 9.5,9.5 0.5,9.5" fill="none" stroke={C.mlInk} strokeWidth="1.5" /></svg>Isolation forest</span>
          <span><svg width="10" height="10"><rect width="10" height="10" fill={C.missInk} /></svg>Missed by both</span>
        </div>
      </header>

      <section className="section">
        <h2>What happened, and who noticed <small>Each row is one attack type in the held-out capture. Amber ticks sit above the trace, cyan ticks below it.</small></h2>
        <Analyzer data={data} probe={probe} setProbe={setProbe} pinned={pinned} setPinned={setPinned} />
      </section>

      <section className="section">
        <h2>Detector bench <small>Flow-level scores on {int(m.flows)} test flows; models trained on {m.trained_on}</small></h2>
        <Bench data={data} />
        <p className="note">
          Tracewire's rules raised {al.alerts} alerts, {al.false_alerts} of them on benign traffic only
          ({al.false_alert_ids.join(', ')}): heavy web pages opening dozens of connections at once trip the burst rule.
          {sal && <> Suricata raised {int(sal.raw_alerts)} raw alerts, grouped into {sal.alerts} events, {sal.false_alerts === 0 ? 'none' : sal.false_alerts} of them false. Its threshold rules alert once per interval by design, which is why its flow-level recall is low while it still notices most episodes.</>}
        </p>
      </section>

      <div className="grid-2 section">
        <section>
          <h2>Time to detect <small>Per attack episode</small></h2>
          <Episodes data={data} />
        </section>
        <section>
          <h2>Services <small>Flows per service; hatched share is attack traffic</small></h2>
          <Services data={data} />
          <p className="note">{bytes(m.bytes)} of payload across {data.services.length} services. Port scans land in "TCP other" because they probe ports nothing listens on.</p>
        </section>
      </div>

      <section className="section">
        <h2>Conversations <small>Every link carrying attack traffic, plus the busiest benign ones. Select a host to filter the ledger.</small></h2>
        <PatchPanel data={data} node={node} setNode={setNode} />
      </section>

      <section className="section">
        <h2>Event ledger <small>{data.events.length} detections from all engines, checked against ground truth</small></h2>
        <Ledger data={data} pinnedT={pinned != null ? data.bins[pinned].t : null} node={node}
          clearPin={() => setPinned(null)} clearNode={() => setNode(null)} />
      </section>

      <section className="section">
        <h2>Where each engine puts each attack</h2>
        <div className={hasSur ? 'grid-3' : 'grid-2b'}>
          <Matrix data={data} engine="signature" title="Tracewire rules" mark="sig" />
          {hasSur && <Matrix data={data} engine="suricata" title="Suricata" mark="sur" />}
          <Matrix data={data} engine="random_forest" title="Random forest" mark="ml" />
        </div>
      </section>

      <div className="grid-2b section">
        <section>
          <h2>Rule set</h2>
          <Rules data={data} />
        </section>
        <section>
          <h2>What the forest looks at</h2>
          <Importances data={data} />
        </section>
      </div>

      <footer className="foot">
        Lab data: synthetic traffic crafted with Scapy, labeled per flow. {hasSur && 'Suricata 7.0.3 run on the same capture with rules/suricata/tracewire.rules. '} Model trained on {m.trained_on} ({int(m.train_flows)} flows), evaluated on {m.capture}.
      </footer>
    </div>
  )
}
