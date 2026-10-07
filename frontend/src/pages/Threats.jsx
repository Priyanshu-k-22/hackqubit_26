import {useEffect,useMemo,useState} from 'react';import {Link} from 'react-router-dom';
import {threatApi} from '../services/api';import {RiskBadge,Empty,Demo} from '../components/ui';import {freqLabel} from '../utils/risk';
export default function Threats(){
  const [all,setAll]=useState([]),[q,setQ]=useState(''),[type,setType]=useState('All'),[sort,setSort]=useState('reports');
  useEffect(()=>{threatApi.list().then(setAll)},[]);
  const rows=useMemo(()=>all.filter(t=>(type==='All'||t.type===type)&&[t.target,t.brand,t.campaign,t.type].join(' ').toLowerCase().includes(q.toLowerCase()))
   .sort((a,b)=>sort==='risk'?b.risk-a.risk:sort==='recent'?b.last.localeCompare(a.last):b.reports-a.reports),[all,q,type,sort]);
  return <div className="space-y-4"><div className="flex items-center gap-3"><h1 className="text-2xl font-semibold">Most reported threats</h1><Demo/></div>
  <div className="flex flex-wrap gap-2"><input className="inp max-w-xs" aria-label="Search" placeholder="Search domain, UPI ID, brand, CAM-017…" value={q} onChange={e=>setQ(e.target.value)}/>
   <select className="inp w-auto" aria-label="Type" value={type} onChange={e=>setType(e.target.value)}>{['All','URL','QR','UPI','Website','App'].map(x=><option key={x}>{x}</option>)}</select>
   <select className="inp w-auto" aria-label="Sort" value={sort} onChange={e=>setSort(e.target.value)}><option value="reports">Most reported</option><option value="risk">Highest risk</option><option value="recent">Recently detected</option></select></div>
  {!rows.length?<Empty text="No threats found. Try a different search or filter."/>:<div className="panel overflow-x-auto"><table className="w-full text-sm"><thead className="text-left text-xs text-slate-500"><tr>{['Rank','Target','Type','Brand','Reports','Last detected','Risk','Campaign','Status',''].map(h=><th key={h} className="px-3 py-2">{h}</th>)}</tr></thead>
  <tbody>{rows.map((r,i)=><tr key={r.id} className="border-t border-slate-200 dark:border-ink-700"><td className="px-3 py-2">#{i+1}</td><td className="max-w-[240px] truncate px-3 font-mono text-xs" title={r.target}>{r.target}</td><td className="px-3">{r.type}</td><td className="px-3">{r.brand}</td>
   <td className="px-3" title={freqLabel(r.reports)}>{r.reports}</td><td className="px-3">{r.last}</td><td className="px-3"><RiskBadge score={r.risk}/></td><td className="px-3">{r.campaign}</td><td className="px-3">{r.status}</td><td className="px-3"><Link className="text-cyan-600 underline" to={`/report/${r.id}`}>Open</Link></td></tr>)}</tbody></table></div>}
  <p className="text-xs text-slate-500">Report count is a frequency signal. "Confirmed Threat" is shown only when backend intelligence confirms it.</p></div>}
