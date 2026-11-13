import { useEffect, useRef, useState } from 'react'

export const ATTACKS = ['portscan', 'sweep', 'synflood', 'bruteforce', 'dns_tunnel', 'stealth_scan', 'exfil']
export const C = {
  phos: '#cfe3dc', phos2: '#8fa9a2', phos3: '#5c7a74', line: '#24414a', well2: '#162d32',
  sig: '#c98500', ml: '#2c93c0', miss: '#d55181',
  sigInk: '#9a6200', mlInk: '#006fa8', missInk: '#b8326a', ink: '#1b1f22',
}

export const mmss = (t) => {
  const s = Math.max(0, Math.round(t))
  return `${String(Math.floor(s / 60)).padStart(2, '0')}:${String(s % 60).padStart(2, '0')}`
}
export const int = (n) => Math.round(n).toLocaleString('en-US')
export const pct = (v, d = 1) => `${(v * 100).toFixed(d)}%`
export const bytes = (b) => {
  if (b < 1024) return `${b} B`
  const u = ['kB', 'MB', 'GB']; let i = -1
  do { b /= 1000; i++ } while (b >= 1000 && i < 2)
  return `${b.toFixed(b < 10 ? 1 : 0)} ${u[i]}`
}

/** Width of an element, kept current with ResizeObserver. */
export function useWidth(initial = 900) {
  const ref = useRef(null)
  const [w, setW] = useState(initial)
  useEffect(() => {
    if (!ref.current) return
    const ro = new ResizeObserver(([e]) => setW(Math.floor(e.contentRect.width)))
    ro.observe(ref.current)
    return () => ro.disconnect()
  }, [])
  return [ref, w]
}

/** Engine markers. Hue = engine family (amber rules, cyan ML); fill/shape = which engine.
 *  Tracewire rules: filled square. Suricata: outlined square. Random forest: filled circle. Isolation forest: outlined triangle. */
export const ENGINE = {
  signature: { mark: 'sig', name: 'Tracewire rules', short: 'TW', idx: 1, fp: 0 },
  suricata: { mark: 'sur', name: 'Suricata', short: 'SU', idx: 3, fp: 2 },
  random_forest: { mark: 'ml', name: 'Random forest', short: 'RF', idx: 2, fp: 1 },
  isolation_forest: { mark: 'iso', name: 'Isolation forest', short: 'IF' },
}
export function EngineMark({ engine, size = 10, ink = false }) {
  if (engine === 'signature' || engine === 'sig')
    return <svg width={size} height={size} aria-hidden><rect x="0.5" y="0.5" width={size - 1} height={size - 1} fill={ink ? C.sigInk : C.sig} /></svg>
  if (engine === 'sur' || engine === 'suricata')
    return <svg width={size} height={size} aria-hidden><rect x="1" y="1" width={size - 2} height={size - 2} fill="none" stroke={ink ? C.sigInk : C.sig} strokeWidth="1.8" /></svg>
  if (engine === 'iso')
    return <svg width={size} height={size} aria-hidden><polygon points={`${size / 2},0.5 ${size - 0.5},${size - 0.5} 0.5,${size - 0.5}`} fill="none" stroke={ink ? C.mlInk : C.ml} strokeWidth="1.5" /></svg>
  return <svg width={size} height={size} aria-hidden><circle cx={size / 2} cy={size / 2} r={size / 2 - 0.5} fill={ink ? C.mlInk : C.ml} /></svg>
}
