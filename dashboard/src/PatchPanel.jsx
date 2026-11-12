import { useMemo, useState } from 'react'
import { C, int, bytes, useWidth } from './util.jsx'

/** Who talked to whom: sources on the left jacks, destinations on the right,
 *  one cable per pair. Cable color shows how the malicious traffic on it was handled. */
const STATUS = {
  benign: { color: '#4b646b', label: 'Benign only' },
  both: { color: C.phos, label: 'Caught by both engines' },
  sig: { color: C.sig, label: 'Caught by signatures only' },
  ml: { color: C.ml, label: 'Caught by ML only' },
  missed: { color: C.miss, label: 'Missed by both' },
}

function status(e) {
  if (!e.malicious) return 'benign'
  if (e.sig && e.rf) return 'both'
  if (e.sig) return 'sig'
  if (e.rf) return 'ml'
  return 'missed'
}

export default function PatchPanel({ data, node, setNode }) {
  const [ref, width] = useWidth(700)
  const [hover, setHover] = useState(null)
  const nodes = useMemo(() => Object.fromEntries(data.nodes.map((n) => [n.id, n])), [data])

  const edges = useMemo(() => {
    const mal = data.edges.filter((e) => e.malicious)
    const ben = data.edges.filter((e) => !e.malicious).sort((a, b) => b.flows - a.flows).slice(0, 9)
    return [...mal, ...ben].map((e) => ({ ...e, status: status(e) }))
  }, [data])

  const rank = (side) => {
    const m = new Map()
    edges.forEach((e) => { const k = e[side]; m.set(k, (m.get(k) || 0) + e.malicious * 1000 + e.flows) })
    return [...m.entries()].sort((a, b) => b[1] - a[1]).map(([k]) => k)
  }
  const left = rank('src'), right = rank('dst')
  const W = Math.max(width, 560), ROWH = 27, top = 30
  const H = top + Math.max(left.length, right.length) * ROWH + 10
  const xl = Math.min(250, W * 0.36), xr = W - Math.min(250, W * 0.36)
  const yl = (id) => top + left.indexOf(id) * ROWH + ROWH / 2
  const yr = (id) => top + right.indexOf(id) * ROWH + ROWH / 2
  const label = (id) => {
    const n = nodes[id]
    if (!n) return id
    if (n.members > 1) return `${id} (${n.members})`
    return n.role ? `${id} ${n.role}` : id
  }
  const touches = (e) => !node || e.src === node || e.dst === node

  return (
    <div className="well" style={{ paddingBottom: 6 }}>
      <div ref={ref} className="well-scroll" style={{ position: 'relative' }}>
        <svg width={W} height={H} viewBox={`0 0 ${W} ${H}`} role="img" aria-label="Source to destination connections">
          <text x={xl} y={16} fill={C.phos2} fontSize="13" textAnchor="end">Source</text>
          <text x={xr} y={16} fill={C.phos2} fontSize="13">Destination</text>
          {edges.slice().sort((a, b) => (a.status === 'benign') - (b.status === 'benign')).reverse().map((e, i) => {
            const y1 = yl(e.src), y2 = yr(e.dst), mx = (xl + xr) / 2
            const on = touches(e)
            const sw = 1.2 + Math.log10(e.flows + 1) * 1.4
            return (
              <g key={i} onMouseEnter={(ev) => setHover({ e, x: mx, y: (y1 + y2) / 2 })} onMouseLeave={() => setHover(null)}>
                <path d={`M${xl + 8},${y1} C${mx},${y1} ${mx},${y2} ${xr - 8},${y2}`} fill="none" stroke="transparent" strokeWidth="12" />
                <path d={`M${xl + 8},${y1} C${mx},${y1} ${mx},${y2} ${xr - 8},${y2}`} fill="none"
                  stroke={STATUS[e.status].color} strokeWidth={sw} strokeLinecap="round"
                  opacity={on ? (hover && hover.e !== e ? 0.35 : 0.95) : 0.08} />
              </g>
            )
          })}
          {[[left, xl, yl, 'end'], [right, xr, yr, 'start']].map(([list, xx, yy, anchor]) =>
            list.map((id) => {
              const n = nodes[id] || {}
              const sel = node === id
              const bad = anchor === 'end' ? n.as_attacker > 0 : n.as_victim > 0
              return (
                <g key={anchor + id} style={{ cursor: 'pointer' }} onClick={() => setNode(sel ? null : id)}
                  role="button" tabIndex={0} aria-pressed={sel}
                  onKeyDown={(ev) => { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); setNode(sel ? null : id) } }}>
                  <rect x={anchor === 'end' ? 0 : xx} y={yy(id) - ROWH / 2 + 2} width={anchor === 'end' ? xx + 8 : W - xx} height={ROWH - 4} fill={sel ? '#21414a' : 'transparent'} rx="3" />
                  <circle cx={xx} cy={yy(id)} r="5.5" fill={C.well2} stroke={bad ? C.phos : C.phos3} strokeWidth="1.5" />
                  <circle cx={xx} cy={yy(id)} r="2" fill={bad ? C.phos : C.phos3} />
                  <text x={anchor === 'end' ? xx - 12 : xx + 12} y={yy(id) + 4.5} textAnchor={anchor} fontSize="13"
                    fill={sel || bad ? C.phos : C.phos2} fontWeight={bad ? 500 : 400}>{label(id)}</text>
                </g>
              )
            }))}
        </svg>
        {hover && (
          <div className="tip" style={{ left: Math.min(hover.x - 90, W - 290), top: hover.y + 14 }}>
            <b>{hover.e.src}</b> to <b>{hover.e.dst}</b><br />
            <span className="mono">{int(hover.e.flows)} flows, {bytes(hover.e.bytes)}</span><br />
            {Object.entries(hover.e.services).map(([k, v]) => `${k} ${v}`).join(', ')}<br />
            {hover.e.malicious
              ? <>{int(hover.e.malicious)} malicious ({data.attack_names[hover.e.truth]}); signature flagged {int(hover.e.sig)}, ML flagged {int(hover.e.rf)}</>
              : 'No attack traffic on this link'}
          </div>
        )}
      </div>
      <div className="key-legend" style={{ color: C.phos2, margin: '6px 0 4px' }}>
        {Object.entries(STATUS).map(([k, s]) => (
          <span key={k}><svg width="22" height="6"><line x1="1" x2="21" y1="3" y2="3" stroke={s.color} strokeWidth="3" strokeLinecap="round" /></svg>{s.label}</span>
        ))}
      </div>
    </div>
  )
}
