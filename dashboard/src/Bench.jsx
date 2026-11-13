import { C, ENGINE, EngineMark, int, pct } from './util.jsx'

const INFO = {
  signature: { color: C.sig, sub: '7 flow-level threshold rules; no training, every alert explainable' },
  suricata: { color: C.sig, sub: 'Suricata 7 packet rules; alerts mapped back to flows' },
  random_forest: { color: C.ml, sub: 'Supervised, 300 trees, trained on the day-1 capture' },
  isolation_forest: { color: C.ml, sub: 'Unsupervised, fitted on day-1 benign traffic only' },
}
const enginesOf = (data) => data.engines.map((k) => ({ key: k, ...ENGINE[k], ...INFO[k] }))

function Meter({ label, value, display, color, invert }) {
  // FPR: a short bar is good, so scale it against 5% instead of 100%
  const w = invert ? Math.min(1, value / 0.05) : value
  return (
    <div className="meter">
      <div className="row"><span className="lbl">{label}</span><span className="num">{display}</span></div>
      <div className="track"><div className="fill" style={{ width: `${w * 100}%`, background: invert ? C.miss : color }} /></div>
    </div>
  )
}

export default function Bench({ data }) {
  const m = data.metrics
  const engines = enginesOf(data)
  return (
    <div className="well">
      <div className="bench" style={{ '--n': engines.length }}>
        {engines.map((e) => {
          const f = m.flow_level[e.key]
          return (
            <div className="engine" key={e.key}>
              <h3><EngineMark engine={e.mark} size={11} />{e.name}</h3>
              <div className="sub">{e.sub}</div>
              <Meter label="Precision" value={f.precision} display={pct(f.precision)} color={e.color} />
              <Meter label="Recall" value={f.recall} display={pct(f.recall)} color={e.color} />
              <Meter label="F1 score" value={f.f1} display={f.f1.toFixed(3)} color={e.color} />
              <Meter label="False-positive rate" value={f.fpr} display={pct(f.fpr, 2)} invert />
              <div className="note num" style={{ fontSize: 12, marginTop: 4 }}>
                TP {int(f.tp)}  FP {int(f.fp)}  FN {int(f.fn)}
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

export function Episodes({ data }) {
  const names = data.attack_names
  const engines = enginesOf(data)
  const cell = (d) => d.detected
    ? <><span>{d.latency_s < 0.05 ? '< 0.1' : d.latency_s.toFixed(1)} s</span><div className="cov">{pct(d.coverage, 0)} of flows</div></>
    : <span className="missed">✕ missed</span>
  return (
    <div className="well">
      <div className="well-scroll">
      <table className="episodes">
        <thead>
          <tr>
            <th>Attack episode</th>
            {engines.map((e) => <th key={e.key}><span className="eng"><EngineMark engine={e.mark} />{e.name}</span></th>)}
          </tr>
        </thead>
        <tbody>
          {data.episodes.map((e) => (
            <tr key={e.episode_id}>
              <td>
                {names[e.attack]}
                <div className="who">{e.attacker} to {e.target}</div>
              </td>
              {engines.map((g) => <td key={g.key} className="num">{cell(e[g.key])}</td>)}
            </tr>
          ))}
        </tbody>
      </table>
      </div>
      <p className="note">Time from the attack's first packet to its first detection. ML scores a flow when it completes, rules fire when a threshold is crossed.</p>
    </div>
  )
}
