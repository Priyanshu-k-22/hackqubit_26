import {useParams,Link} from 'react-router-dom';import {Printer} from 'lucide-react';
import {reportApi,threatApi} from '../services/api';import Result from '../components/Result';import {Empty} from '../components/ui';import {level} from '../utils/risk';
export default function Report(){
  const {id}=useParams(),r=reportApi.get(id)||threatApi.getResult(id);
  if(!r)return <Empty text="Report not found. Run a scan first."/>;
  const tip={CRITICAL:'Do not pay or enter any credentials. Report to cybercrime.gov.in or call 1930 if money was lost.',HIGH:'Avoid paying. Verify the payee through an official channel.',MEDIUM:'Proceed only after verifying the payee independently.',LOW:'No known threat indicators. Still verify the payee before paying.'}[level(r.score)];
  return <div className="mx-auto max-w-4xl space-y-4"><div className="no-print flex gap-2"><button className="btn-p" onClick={()=>window.print()}><Printer size={16}/>Print / Save as PDF</button><Link to="/scan" className="btn-s">New scan</Link></div>
  <div className="print-only text-sm"><b>UPI SHIELD</b> · Investigation report {r.id} · Generated {new Date().toLocaleString()}</div>
  <h1 className="text-2xl font-semibold">Investigation report <span className="font-mono text-base text-slate-500">{r.id}</span></h1>
  <section className="panel p-4"><h2 className="font-medium">Executive summary</h2><p className="mt-1 text-sm">Target <span className="break-all font-mono">{r.input}</span> scored {r.score}/100 ({level(r.score)}). Campaign: {r.campaign}. Status: {r.status}. Based on {r.demo?'simulated demo intelligence':'backend intelligence'}.</p></section>
  <Result r={r} printMode/>
  <section className="panel p-4"><h2 className="font-medium">Recommended action</h2><p className="mt-1 text-sm">{tip}</p></section>
  <section className="panel p-4 text-xs text-slate-500"><h2 className="font-medium text-sm text-inherit">Scan metadata</h2>Scan ID {r.id} · {r.ts} · Source {r.demo?'Demo mock service':'Backend'}</section></div>}
