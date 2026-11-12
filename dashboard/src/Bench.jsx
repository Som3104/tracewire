import { C, EngineMark, int, pct } from './util.jsx'

const ENGINES = [
  { key: 'signature', mark: 'sig', name: 'Signature rules', color: C.sig,
    sub: '7 threshold rules over flows; no training, every alert explainable' },
  { key: 'random_forest', mark: 'ml', name: 'Random forest', color: C.ml,
    sub: 'Supervised, 300 trees, trained on the day-1 capture' },
  { key: 'isolation_forest', mark: 'iso', name: 'Isolation forest', color: C.ml,
    sub: 'Unsupervised, fitted on day-1 benign traffic only' },
]

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
  return (
    <div className="well">
      <div className="bench">
        {ENGINES.map((e) => {
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
            <th><span className="eng"><EngineMark engine="sig" /> Signature</span></th>
            <th><span className="eng"><EngineMark engine="ml" /> Forest</span></th>
            <th><span className="eng"><EngineMark engine="iso" /> Isolation</span></th>
          </tr>
        </thead>
        <tbody>
          {data.episodes.map((e) => (
            <tr key={e.episode_id}>
              <td>
                {names[e.attack]}
                <div className="who">{e.attacker} to {e.target}</div>
              </td>
              <td className="num">{cell(e.signature)}</td>
              <td className="num">{cell(e.random_forest)}</td>
              <td className="num">{cell(e.isolation_forest)}</td>
            </tr>
          ))}
        </tbody>
      </table>
      </div>
      <p className="note">Time from the attack's first packet to its first detection. ML scores a flow when it completes, rules fire when a threshold is crossed.</p>
    </div>
  )
}
