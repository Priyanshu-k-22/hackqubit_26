import {useState} from 'react';import {applyTheme} from '../App';import {isDemo} from '../services/api';
const KEY='ups_settings';
export default function Settings(){
  const [s,setS]=useState(()=>({theme:localStorage.getItem('ups_theme')||'dark',threshold:65,timeout:30,auto:true,...JSON.parse(localStorage.getItem(KEY)||'{}')}));
  const set=(k,v)=>{const n={...s,[k]:v};setS(n);localStorage.setItem(KEY,JSON.stringify(n));if(k==='theme'){localStorage.setItem('ups_theme',v);applyTheme(v)}};
  const R=({l,children})=><label className="flex items-center justify-between gap-4 py-2 text-sm"><span>{l}</span>{children}</label>;
  return <div className="max-w-2xl space-y-4"><h1 className="text-2xl font-semibold">Settings</h1>
  <section className="panel p-4"><h2 className="font-medium">Appearance</h2><R l="Theme"><select className="inp w-auto" value={s.theme} onChange={e=>set('theme',e.target.value)}><option value="light">Light</option><option value="dark">Dark</option><option value="system">System</option></select></R></section>
  <section className="panel p-4"><h2 className="font-medium">Scanner</h2><R l={`Risk threshold: ${s.threshold}`}><input type="range" min="1" max="100" value={s.threshold} onChange={e=>set('threshold',+e.target.value)}/></R>
   <R l="Scan timeout (seconds)"><input className="inp w-24" type="number" min="5" value={s.timeout} onChange={e=>set('timeout',+e.target.value)}/></R><R l="Automatic analysis after QR decode"><input type="checkbox" checked={s.auto} onChange={e=>set('auto',e.target.checked)}/></R></section>
  <section className="panel p-4"><h2 className="font-medium">Backend (integration-ready)</h2>
   {[['API base URL',import.meta.env.VITE_API_BASE_URL||'Not set (VITE_API_BASE_URL)'],['Environment',isDemo?'Demo':'Configured'],['Backend status',isDemo?'Not connected':'Unknown'],['Database status','Not connected'],['AI engine status','Not connected'],['Threat intelligence status','Simulated']].map(([k,v])=><div key={k} className="flex justify-between border-t border-slate-200 py-2 text-sm first:border-0 dark:border-ink-700"><span>{k}</span><span className="font-mono text-xs">{v}</span></div>)}</section></div>}
