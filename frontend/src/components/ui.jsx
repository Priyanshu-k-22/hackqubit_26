import {level,COLORS} from '../utils/risk';
export const RiskBadge=({score})=>{const l=level(score);return <span className={`inline-flex items-center gap-1 rounded px-2 py-0.5 text-xs font-semibold ${COLORS[l]}`}>{l} · {score}</span>};
export const Bar=({label,v})=>{const l=level(v);return <div className="text-sm"><div className="flex justify-between"><span>{label}</span><span className="font-mono">{v}</span></div>
 <div className="mt-1 h-2 rounded bg-slate-200 dark:bg-ink-700" role="progressbar" aria-valuenow={v} aria-valuemin={0} aria-valuemax={100} aria-label={label}><div className={`h-2 rounded transition-all duration-700 ${COLORS[l].split(' ')[0]}`} style={{width:v+'%'}}/></div></div>};
export const Metric=({label,value,tone})=><div className="panel p-4 transition hover:-translate-y-0.5 hover:shadow-lg"><div className="text-xs text-slate-500">{label}</div><div className={`mt-1 text-2xl font-semibold ${tone||''}`}>{value}</div></div>;
export const Demo=()=><span className="rounded border border-amber-500/50 px-1.5 py-0.5 text-[10px] font-medium text-amber-600 dark:text-amber-400">DEMO INTELLIGENCE</span>;
export const Empty=({text})=><div className="panel p-8 text-center text-sm text-slate-500">{text}</div>;
export const ErrorBox=({text,retry})=><div role="alert" className="panel border-red-500/50 p-4 text-sm text-red-600 dark:text-red-400">{text} {retry&&<button className="btn-s ml-2" onClick={retry}>Try again</button>}</div>;
