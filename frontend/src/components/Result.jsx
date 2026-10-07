import {useState} from 'react';import {Link} from 'react-router-dom';
import {RiskBadge,Bar,Demo} from './ui';import {level,freqLabel} from '../utils/risk';
const nodes=r=>[['Brand',r.brand,50,20],['Campaign',r.campaign,50,75],['Domain',r.domain,20,135],['IP','192.0.2.10 (demo)',50,135],['Certificate','Self-signed (demo)',80,135],['VPA',r.upi,50,190]];
export default function Result({r,printMode}){
  const [sel,setSel]=useState(null),l=level(r.score),low=l==='LOW';
  const F=({k,v})=><div><dt className="text-xs text-slate-500">{k}</dt><dd className="break-all font-mono text-sm">{String(v)}</dd></div>;
  return <div className="space-y-4">
  <div className={`panel p-5 ${low?'border-emerald-500/50':'border-red-500/40'}`}><div className="flex flex-wrap items-center justify-between gap-3">
   <div><div className="text-sm font-semibold">{low?'✓ LOW RISK · no known threat indicators':`${l} RISK`}</div><div className="text-4xl font-bold">{r.score}<span className="text-lg text-slate-500"> / 100</span></div></div>
   <div className="flex gap-2 items-center"><RiskBadge score={r.score}/>{r.demo&&<Demo/>}{!printMode&&<Link to={`/report/${r.id}`} className="btn-p">Generate full report</Link>}</div></div>
   {r.backendUnavailable&&<p className="mt-2 text-sm text-amber-600">Intelligence backend unavailable. Demo mode enabled.</p>}
   <p className="mt-2 text-xs text-slate-500">Scores are demo values and are not scientifically validated. Low risk does not guarantee safety.</p></div>
  <div className="grid gap-4 md:grid-cols-2">
   <section className="panel p-4"><h3 className="mb-3 font-medium">Risk breakdown</h3><div className="space-y-3">{Object.entries(r.breakdown).map(([k,v])=><Bar key={k} label={k} v={v}/>)}</div></section>
   <section className="panel p-4"><h3 className="mb-3 font-medium">{low?'Why is this considered low risk?':'Why did we flag this?'}</h3><ul className="space-y-1 text-sm">{r.evidence.map(e=><li key={e}>✓ {e}</li>)}</ul></section>
   <section className="panel p-4"><h3 className="mb-3 font-medium">Target details</h3><dl className="grid grid-cols-2 gap-3"><F k="Input type" v={r.kind.toUpperCase()}/><F k="Decoded content" v={r.input}/><F k="Domain" v={r.domain}/><F k="Protocol" v={r.protocol}/><F k="UPI ID" v={r.upi}/><F k="Payee name" v={r.payee}/><F k="Redirects" v={r.redirects}/><F k="Brand" v={r.brand}/></dl></section>
   <section className="panel p-4"><h3 className="mb-3 font-medium">Threat frequency</h3><dl className="grid grid-cols-2 gap-3"><F k="Total reports" v={r.reports}/><F k="Unique reporters" v={r.users}/><F k="First detected" v={r.first}/><F k="Last detected" v={r.last}/><F k="Campaign" v={r.campaign}/><F k="Status" v={r.status}/></dl>
    <p className="mt-3 rounded bg-slate-100 p-2 text-sm dark:bg-ink-800">{freqLabel(r.reports)}. {r.status==='Confirmed Threat'?'Confirmed by threat intelligence.':'Report count alone does not confirm fraud.'}</p></section></div>
  {!low&&<section className="panel p-4"><h3 className="mb-2 font-medium">Infrastructure graph <span className="text-xs text-slate-500">(click a node)</span></h3><div className="grid gap-3 md:grid-cols-2">
   <svg viewBox="0 0 100 210" className="h-64 w-full" role="img" aria-label="Infrastructure graph">{[[0,1],[1,2],[1,3],[1,4],[3,5]].map(([a,b])=>{const A=nodes(r)[a],B=nodes(r)[b];return <line key={a+'-'+b} x1={A[2]} y1={A[3]} x2={B[2]} y2={B[3]} stroke="#64748b" strokeWidth=".6"/>})}
   {nodes(r).map(n=><g key={n[0]} tabIndex={0} role="button" aria-label={n[0]} className="cursor-pointer outline-none" onClick={()=>setSel(n)} onKeyDown={e=>e.key==='Enter'&&setSel(n)}><circle cx={n[2]} cy={n[3]} r="9" fill={sel===n?'#0891b2':'#1e2942'} stroke="#22d3ee" strokeWidth=".8"/><text x={n[2]} y={n[3]+2} fontSize="4" textAnchor="middle" fill="#fff">{n[0]}</text></g>)}</svg>
   <div className="rounded border border-dashed p-3 text-sm dark:border-ink-700">{sel?<dl className="space-y-1"><div><b>Type:</b> {sel[0]}</div><div className="break-all"><b>Value:</b> {sel[1]}</div><div><b>First seen:</b> {r.first}</div><div><b>Last seen:</b> {r.last}</div><div><b>Related threats:</b> {r.campaign}</div><div className="text-xs text-slate-500">Demo node. Replace with graph API (e.g. Neo4j).</div></dl>:'Select a node to inspect it.'}</div></div></section>}
  </div>}
