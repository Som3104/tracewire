import { useMemo, useState } from 'react'
import { ATTACKS, C, ENGINE, EngineMark, mmss, int, pct, useWidth } from './util.jsx'

/**
 * Logic-analyzer view of the capture.
 * Top channel: packets per 10-second bin (analog trace).
 * One channel per attack type: ground truth as a square wave (high = attack
 * traffic present in that bin); amber ticks above the wave = signature engine
 * flagged those flows, cyan ticks below = ML flagged them, magenta = present
 * but caught by neither. Last channel: false alarms on benign traffic.
 */
export default function Analyzer({ data, probe, setProbe, pinned, setPinned }) {
  const [ref, width] = useWidth()
  const hasSur = data.engines.includes('suricata')
  const [rules, setRules] = useState('signature')          // which rule engine fills the amber lane
  const RE = ENGINE[rules]
  const hollow = rules === 'suricata'
  const W = Math.max(width, 980)
  const L = 158, R = 104
  const plotW = W - L - R
  const bins = data.bins
  const n = bins.length
  const bw = plotW / n
  const x = (i) => L + i * bw

  const A_TOP = 6, A_H = 70
  const ROW = 40
  const chTop = A_TOP + A_H + 18
  const channels = [...ATTACKS, 'false_alarm']
  const H = chTop + channels.length * ROW + 30

  const maxPk = useMemo(() => Math.max(...bins.map((b) => b.pkts)), [bins])
  const analog = useMemo(() => {
    const y = (v) => A_TOP + A_H - (v / maxPk) * (A_H - 6)
    let d = `M${x(0)},${y(bins[0].pkts)}`
    bins.forEach((b, i) => { d += `L${x(i) + bw / 2},${y(b.pkts)}` })
    d += `L${x(n)},${y(bins[n - 1].pkts)}`
    return { line: d, area: `${d}L${x(n)},${A_TOP + A_H}L${x(0)},${A_TOP + A_H}Z` }
  }, [bins, W])

  const per = data.metrics.per_class
  const names = data.attack_names
  const fpTotals = bins.reduce((a, b) => [a[0] + (b.fp[RE.fp] || 0), a[1] + b.fp[1]], [0, 0])
  const benignFlows = data.metrics.confusion.signature.matrix[0].reduce((a, b) => a + b, 0)

  function onMove(e) {
    const r = e.currentTarget.getBoundingClientRect()
    const px = ((e.clientX - r.left) / r.width) * W
    const i = Math.floor((px - L) / bw)
    setProbe(i >= 0 && i < n ? i : null)
  }
  function onKey(e) {
    const cur = pinned ?? probe ?? 0
    if (e.key === 'ArrowRight') { setPinned(Math.min(n - 1, cur + 1)); e.preventDefault() }
    if (e.key === 'ArrowLeft') { setPinned(Math.max(0, cur - 1)); e.preventDefault() }
    if (e.key === 'Escape') setPinned(null)
  }

  const active = pinned ?? probe
  const b = active != null ? bins[active] : null

  return (
    <div className="well">
      <div className="probe" aria-live="polite">
        {b ? (
          <>
            <div className="cell"><div className="lbl">Slice</div><div className="val">{mmss(b.t)} to {mmss(b.t + data.bin_s)}</div></div>
            <div className="cell"><div className="lbl">Packets</div><div className="val">{int(b.pkts)}</div></div>
            <div className="cell"><div className="lbl">Flows</div><div className="val">{int(b.flows)}</div></div>
            <div className="cell"><div className="lbl">Attack traffic present</div><div className="val">{Object.keys(b.truth).length ? Object.entries(b.truth).map(([k, v]) => `${names[k]} ${v}`).join(', ') : 'none'}</div></div>
            <div className="cell"><div className="lbl">{RE.name} flagged</div><div className="val sig">{int(rules === 'suricata' ? b.sur : b.sig)} flows</div></div>
            <div className="cell"><div className="lbl">ML flagged</div><div className="val ml">{int(b.rf)} flows</div></div>
            {pinned != null && <button className="key pin" onClick={() => setPinned(null)}>Unpin</button>}
          </>
        ) : (
          <div className="hint">Hover the trace to read a 10-second slice. Click to pin it and filter the event ledger; arrow keys step through time.</div>
        )}
        {hasSur && (
          <div className="keys lane-pick" role="group" aria-label="Rule engine shown above the trace">
            {['signature', 'suricata'].map((k) => (
              <button key={k} className="key" aria-pressed={rules === k} style={{ '--led': C.sig }} onClick={() => setRules(k)}>
                <EngineMark engine={ENGINE[k].mark} size={9} />{ENGINE[k].name}
              </button>
            ))}
          </div>
        )}
      </div>
      <div className="well-scroll" ref={ref}>
        <svg className="analyzer" width={W} height={H} viewBox={`0 0 ${W} ${H}`} role="img" tabIndex={0}
          aria-label="Timeline of attack traffic and detections per attack type"
          onMouseMove={onMove} onMouseLeave={() => setProbe(null)} onKeyDown={onKey}
          onClick={() => setPinned(probe === pinned ? null : probe)}>
          <defs>
            <clipPath id="sweep"><rect className="sweep" x={L} y="0" width={plotW} height={H} /></clipPath>
            <linearGradient id="glow" x1="0" x2="0" y1="0" y2="1">
              <stop offset="0" stopColor={C.phos} stopOpacity=".28" /><stop offset="1" stopColor={C.phos} stopOpacity="0" />
            </linearGradient>
          </defs>

          {/* graticule: vertical line every 2 minutes */}
          {Array.from({ length: Math.floor(data.meta.duration / 120) + 1 }, (_, k) => {
            const xx = x((k * 120) / data.bin_s)
            const showLabel = plotW / (data.meta.duration / 120) > 54 || k % 2 === 0
            return (
              <g key={k}>
                <line x1={xx} x2={xx} y1={A_TOP} y2={H - 26} stroke={C.line} strokeDasharray={k % 5 ? '1 3' : '0'} />
                {showLabel && <text x={xx} y={H - 10} fill={C.phos2} fontSize="12" textAnchor="middle" className="num">{mmss(k * 120)}</text>}
              </g>
            )
          })}

          {/* channel labels */}
          <text x={8} y={A_TOP + 16} fill={C.phos} fontSize="14" fontWeight="500">Packets</text>
          <text x={8} y={A_TOP + 33} fill={C.phos2} fontSize="12.5">per 10 s, peak {int(maxPk)}</text>
          <text x={W - R + 12} y={A_TOP + 16} fill={C.phos2} fontSize="12.5">Recall</text>
          <text x={W - R + 12} y={A_TOP + 32} fill={C.phos2} fontSize="12">by engine</text>

          {channels.map((c, k) => {
            const y0 = chTop + k * ROW
            const fa = c === 'false_alarm'
            return (
              <g key={c}>
                <line x1={L} x2={W - R} y1={y0} y2={y0} stroke={C.line} />
                <text x={8} y={y0 + 17} fill={fa ? C.miss : C.phos} fontSize="14" fontWeight="500">{fa ? 'False alarms' : names[c]}</text>
                <text x={8} y={y0 + 33} fill={C.phos2} fontSize="12">
                  {fa ? `on ${int(benignFlows)} benign flows` : `${int(data.episodes.find((e) => e.attack === c)?.flows ?? 0)} flows`}
                </text>
                <g className="num" fontSize="12.5">
                  {fa ? (
                    <>
                      <text x={W - R + 12} y={y0 + 17} fill={C.sig}>{RE.short} {int(fpTotals[0])}</text>
                      <text x={W - R + 12} y={y0 + 33} fill={C.ml}>RF {int(fpTotals[1])}</text>
                    </>
                  ) : (
                    <>
                      <text x={W - R + 12} y={y0 + 17} fill={per[rules][c] === 0 ? C.miss : C.sig}>{RE.short} {pct(per[rules][c], 0)}</text>
                      <text x={W - R + 12} y={y0 + 33} fill={per.random_forest[c] === 0 ? C.miss : C.ml}>RF {pct(per.random_forest[c], 0)}</text>
                    </>
                  )}
                </g>
              </g>
            )
          })}

          <g clipPath="url(#sweep)">
            <path d={analog.area} fill="url(#glow)" />
            <path d={analog.line} fill="none" stroke={C.phos} strokeWidth="1.5" strokeLinejoin="round" />

            {channels.map((c, k) => {
              const y0 = chTop + k * ROW
              const hi = y0 + 13, lo = y0 + ROW - 13
              if (c === 'false_alarm') {
                const lg = (v) => Math.min(10, 3 + Math.log2(v + 1) * 1.6)
                return (
                  <g key={c}>
                    <line x1={L} x2={W - R} y1={(hi + lo) / 2} y2={(hi + lo) / 2} stroke={C.phos3} strokeDasharray="2 3" />
                    {bins.map((b, i) => (
                      <g key={i}>
                        {b.fp[RE.fp] > 0 && <rect x={x(i) + bw * 0.1 + (hollow ? 0.6 : 0)} y={(hi + lo) / 2 - 1 - lg(b.fp[RE.fp])} width={Math.max(bw * 0.8, 2) - (hollow ? 1.2 : 0)} height={lg(b.fp[RE.fp])} fill={hollow ? 'none' : C.sig} stroke={hollow ? C.sig : 'none'} strokeWidth="1.2" rx="1" />}
                        {b.fp[1] > 0 && <rect x={x(i) + bw * 0.1} y={(hi + lo) / 2 + 1} width={Math.max(bw * 0.8, 2)} height={lg(b.fp[1])} fill={C.ml} rx="1" />}
                      </g>
                    ))}
                  </g>
                )
              }
              let d = `M${x(0)},${lo}`, prev = lo
              bins.forEach((b, i) => {
                const yy = b.truth[c] ? hi : lo
                if (yy !== prev) d += `V${yy}`
                d += `H${x(i + 1)}`; prev = yy
              })
              return (
                <g key={c}>
                  <path d={d} fill="none" stroke={C.phos} strokeWidth="1.5" />
                  {bins.map((b, i) => {
                    const dt = b.det[c]
                    if (!dt) return null
                    const tot = dt[0], s = dt[RE.idx] || 0, m = dt[2]
                    const w = Math.max(bw * 0.8, 2)
                    return (
                      <g key={i}>
                        {s > 0 && <rect x={x(i) + bw * 0.1 + (hollow ? 0.6 : 0)} y={y0 + 2.6} width={w - (hollow ? 1.2 : 0)} height={Math.max(3, 8 * s / tot)} fill={hollow ? 'none' : C.sig} stroke={hollow ? C.sig : 'none'} strokeWidth="1.2" rx="1" />}
                        {m > 0 && <rect x={x(i) + bw * 0.1} y={y0 + ROW - 2 - Math.max(3, 8 * m / tot)} width={w} height={Math.max(3, 8 * m / tot)} fill={C.ml} rx="1" />}
                        {s === 0 && m === 0 && <rect x={x(i) + bw * 0.1} y={hi - 1} width={w} height={lo - hi + 2} fill={C.miss} opacity=".85" rx="1" />}
                      </g>
                    )
                  })}
                </g>
              )
            })}
          </g>
          <line className="beam" x1={L} x2={L} y1={A_TOP} y2={H - 26} stroke={C.phos} strokeWidth="2" style={{ '--beam-to': `${plotW}px` }} opacity="0" />

          {active != null && (
            <g pointerEvents="none">
              <rect x={x(active)} y={A_TOP} width={bw} height={H - 26 - A_TOP} fill={C.phos} opacity=".09" />
              <line x1={x(active) + bw / 2} x2={x(active) + bw / 2} y1={A_TOP} y2={H - 26} stroke={pinned != null ? C.phos : C.phos2} strokeWidth="1" />
            </g>
          )}
        </svg>
      </div>
    </div>
  )
}
