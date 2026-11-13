import { useState } from 'react'
import { C, ENGINE, EngineMark, int, mmss, bytes } from './util.jsx'

/** Confusion matrix on the faceplate: rows are the true class, columns what the engine said.
 *  Shade = share of the row (single-hue ramp), number = flow count. */
export function Matrix({ data, engine, title, mark }) {
  const cm = data.metrics.confusion[engine]
  const names = { ...data.attack_names, anomaly: 'Anomaly' }
  const [hover, setHover] = useState(null)
  const cell = 34
  return (
    <div style={{ minWidth: 0 }}>
      <h3 style={{ margin: '0 0 8px', font: '600 15px/1.2 var(--sans)', display: 'flex', gap: 8, alignItems: 'center' }}>
        <EngineMark engine={mark} ink />{title}
      </h3>
      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: 'auto', fontSize: 12.5 }}>
          <thead>
            <tr>
              <th style={{ textAlign: 'left', fontWeight: 400, color: 'var(--ink-3)', padding: '0 8px 4px 0', fontSize: 12 }}>truth ↓ predicted →</th>
              {cm.cols.map((c) => (
                <th key={c} style={{ width: cell, height: 74, verticalAlign: 'bottom', padding: 0 }}>
                  <div style={{ writingMode: 'vertical-rl', transform: 'rotate(180deg)', fontWeight: 500, fontSize: 12, whiteSpace: 'nowrap', margin: '0 auto' }}>{names[c] || c}</div>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {cm.rows.map((r, i) => {
              const total = cm.matrix[i].reduce((a, b) => a + b, 0)
              return (
                <tr key={r}>
                  <td style={{ padding: '0 10px 0 0', whiteSpace: 'nowrap', fontWeight: 500 }}>{names[r]}</td>
                  {cm.matrix[i].map((v, j) => {
                    const share = total ? v / total : 0
                    const diag = cm.cols[j] === r || (r !== 'benign' && cm.cols[j] !== 'benign' && engine === 'isolation_forest')
                    return (
                      <td key={j} onMouseEnter={() => setHover({ r, c: cm.cols[j], v, share })} onMouseLeave={() => setHover(null)}
                        style={{
                          width: cell, height: 26, padding: 0, textAlign: 'center', fontFamily: 'var(--mono)', fontSize: 10.5,
                          background: v ? `rgba(27,31,34,${0.08 + share * 0.82})` : 'transparent',
                          color: share > 0.45 ? '#e8ecea' : 'var(--ink)',
                          outline: !diag && v && r !== 'benign' && cm.cols[j] === 'benign' ? `2px solid ${C.missInk}` : 'none',
                          outlineOffset: -2, border: '2px solid var(--plate)',
                        }}>
                        {v ? (v >= 1000 ? `${(v / 1000).toFixed(1)}k` : v) : ''}
                      </td>
                    )
                  })}
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
      <p className="note" style={{ minHeight: '2.9em' }}>
        {hover
          ? <>{int(hover.v)} {names[hover.r]} flows labelled {names[hover.c] || hover.c} ({(hover.share * 100).toFixed(1)}% of the row).</>
          : <>Magenta outline: attack flows the engine let through as benign.</>}
      </p>
    </div>
  )
}

export function Services({ data }) {
  const max = Math.max(...data.services.map((s) => s.flows))
  return (
    <table className="svc">
      <tbody>
        {data.services.map((s) => (
          <tr key={s.service}>
            <td style={{ width: 92, fontWeight: 500 }}>{s.service}</td>
            <td>
              <svg width="100%" height="14" preserveAspectRatio="none" viewBox="0 0 100 14" aria-hidden>
                <defs>
                  <pattern id="hatch" width="3" height="3" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
                    <rect width="3" height="3" fill="#c4c8c6" /><line x1="0" y1="0" x2="0" y2="3" stroke={C.ink} strokeWidth="1.6" />
                  </pattern>
                </defs>
                <rect x="0" y="2" height="10" width={(s.flows / max) * 100} fill={C.ink} opacity=".78" />
                <rect x={((s.flows - s.malicious) / max) * 100} y="2" height="10" width={(s.malicious / max) * 100} fill="url(#hatch)" />
              </svg>
            </td>
            <td className="mono">{int(s.flows)}</td>
            <td className="mono" style={{ color: 'var(--ink-3)', width: 74 }}>{s.malicious ? `${int(s.malicious)} bad` : ''}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

export function Rules({ data }) {
  return (
    <div className="well">
      <table className="rules">
        <tbody>
          {data.rules.map((r) => (
            <tr key={r.id}>
              <td className="mono">{r.id}</td>
              <td><div style={{ fontWeight: 500 }}>{r.name}</div><div className="logic">{r.logic}</div></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export function Importances({ data }) {
  const max = data.importances[0].importance
  return (
    <div className="well">
      <table className="rules">
        <tbody>
          {data.importances.map((f) => (
            <tr key={f.feature}>
              <td className="mono" style={{ width: '46%' }}>{f.feature}</td>
              <td style={{ width: '42%' }}>
                <div style={{ height: 6, borderRadius: 3, background: C.ml, width: `${(f.importance / max) * 100}%` }} />
              </td>
              <td className="mono" style={{ textAlign: 'right' }}>{(f.importance * 100).toFixed(1)}%</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="note">Top 12 of {data.importances_total ?? 41} features by mean decrease in impurity. No single feature dominates: the forest combines flow shape (byte ratio, duration, payload size) with behavioural context (what the same source did in the previous minute).</p>
    </div>
  )
}

export function Ledger({ data, pinnedT, node, clearPin, clearNode }) {
  const [engine, setEngine] = useState('all')
  const [fpOnly, setFpOnly] = useState(false)
  const bin = data.bin_s
  const rows = data.events.filter((e) =>
    (engine === 'all' || e.engine === engine) && (!fpOnly || e.verdict === 'false positive') &&
    (!node || e.src === node || e.dst.split(':')[0] === node))
  const inPin = (e) => pinnedT == null || (e.t <= pinnedT + bin && e.t_end >= pinnedT - 0)
  const key = (v, label, led) => (
    <button className="key" aria-pressed={engine === v} style={{ '--led': led }} onClick={() => setEngine(v)}>
      <span className="led" />{label}
    </button>
  )
  return (
    <div>
      <div className="ledger-tools">
        <div className="keys" role="group" aria-label="Engine">
          {key('all', 'All engines', '#2e9b5f')}
          {key('signature', 'Tracewire rules', C.sig)}
          {data.engines.includes('suricata') && key('suricata', 'Suricata', C.sig)}
          {key('ml', 'Random forest', C.ml)}
        </div>
        <button className="key" aria-pressed={fpOnly} style={{ '--led': C.miss }} onClick={() => setFpOnly(!fpOnly)}>
          <span className="led" />False positives only
        </button>
        {pinnedT != null && <span className="chip">At {mmss(pinnedT)}<button aria-label="Clear time filter" onClick={clearPin}>×</button></span>}
        {node && <span className="chip">Host {node}<button aria-label="Clear host filter" onClick={clearNode}>×</button></span>}
      </div>
      <div className="ledger-wrap">
        <table className="ledger">
          <thead>
            <tr><th>Time</th><th>Engine</th><th>Severity</th><th>Detection</th><th>Source</th><th>Target</th><th style={{ textAlign: 'right' }}>Flows</th><th>Ground truth</th></tr>
          </thead>
          <tbody>
            {rows.map((e) => (
              <tr key={e.id} className={pinnedT == null ? '' : inPin(e) ? 'hl' : 'dim'}>
                <td className="mono">{mmss(e.t)}{e.t_end - e.t > 1 ? <span style={{ color: 'var(--ink-3)' }}> to {mmss(e.t_end)}</span> : null}</td>
                <td><span className="eng"><EngineMark engine={e.engine === 'signature' ? 'sig' : e.engine === 'suricata' ? 'sur' : 'ml'} ink />
                  {e.engine === 'ml' ? `RF ${(e.confidence * 100).toFixed(0)}%` : e.engine === 'suricata' ? `SID ${e.rule}` : e.rule}</span></td>
                <td><span className="sev" aria-label={`severity ${e.severity} of 4`}>{[1, 2, 3, 4].map((k) => <i key={k} className={k <= e.severity ? 'on' : ''} />)}</span></td>
                <td>{e.name}</td>
                <td className="mono">{e.src}</td>
                <td className="mono">{e.dst}</td>
                <td className="mono" style={{ textAlign: 'right' }}>{int(e.flows)}{e.alerts ? <div style={{ color: 'var(--ink-3)', fontSize: 11 }}>{int(e.alerts)} alerts</div> : null}</td>
                <td className={`verdict ${e.verdict === 'false positive' ? 'fp' : ''}`}>
                  {e.verdict === 'false positive' ? '✕ false positive' : `✓ ${data.attack_names[e.truth]}`}
                </td>
              </tr>
            ))}
            {!rows.length && <tr><td colSpan={8} className="empty">No events match these filters. Clear the host or time filter to see the full ledger.</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  )
}
