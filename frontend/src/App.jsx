import {lazy,Suspense,useEffect,useState} from 'react';
import {NavLink,Route,Routes} from 'react-router-dom';
import {LayoutDashboard,ScanSearch,QrCode,Database,FileText,Settings as Cog,Sun,Moon,ShieldCheck} from 'lucide-react';
import {isDemo} from './services/api';
const P=n=>lazy(()=>import(`./pages/${n}.jsx`));
const Dashboard=P('Dashboard'),Scanner=P('Scanner'),Threats=P('Threats'),Reports=P('Reports'),Report=P('Report'),SettingsPage=P('Settings');
const nav=[['/','Overview',LayoutDashboard],['/scan','Scan',ScanSearch],['/qr','QR Shield',QrCode],['/threats','Threat Intelligence',Database],['/reports','Reports',FileText],['/settings','Settings',Cog]];
export const applyTheme=m=>{const d=m==='dark'||(m==='system'&&matchMedia('(prefers-color-scheme: dark)').matches);document.documentElement.classList.toggle('dark',d)};
export default function App(){
  const [theme,setTheme]=useState(localStorage.getItem('ups_theme')||'dark');
  useEffect(()=>{localStorage.setItem('ups_theme',theme);applyTheme(theme)},[theme]);
  const dark=document.documentElement.classList.contains('dark');
  return <div className="flex min-h-screen">
    <aside className="no-print hidden w-56 shrink-0 border-r border-slate-200 bg-white p-4 dark:border-ink-700 dark:bg-ink-900 md:block">
      <div className="mb-6 flex items-center gap-2"><ShieldCheck className="text-cyan-500"/><div><div className="font-bold tracking-wide">UPI SHIELD</div><div className="text-[11px] text-slate-500">Threat Intelligence Platform</div></div></div>
      <nav aria-label="Main" className="space-y-1">{nav.map(([to,l,I])=><NavLink key={to} to={to} end className={({isActive})=>`flex items-center gap-2 rounded-md px-3 py-2 text-sm transition ${isActive?'bg-cyan-500/10 text-cyan-600 dark:text-cyan-400 font-medium':'hover:bg-slate-100 dark:hover:bg-ink-800'}`}><I size={16}/>{l}</NavLink>)}</nav>
    </aside>
    <div className="min-w-0 flex-1">
      <header className="no-print flex flex-wrap items-center justify-between gap-2 border-b border-slate-200 bg-white/80 px-4 py-3 backdrop-blur dark:border-ink-700 dark:bg-ink-900/80">
        <div className="flex gap-1 md:hidden">{nav.map(([to,,I])=><NavLink key={to} to={to} end aria-label={to} className="rounded p-2 hover:bg-slate-100 dark:hover:bg-ink-800"><I size={18}/></NavLink>)}</div>
        <div className="text-sm"><span className={`mr-2 inline-block h-2 w-2 rounded-full ${isDemo?'bg-amber-500':'bg-emerald-500'}`}/>{isDemo?'Prototype · Demo mode (no backend connected)':'Backend configured'}</div>
        <button className="btn-s" aria-label="Toggle theme" onClick={()=>setTheme(dark?'light':'dark')}>{dark?<Sun size={16}/>:<Moon size={16}/>}{dark?'Light':'Dark'}</button>
      </header>
      <main className="p-4 md:p-6"><Suspense fallback={<div className="text-sm text-slate-500">Loading…</div>}>
        <Routes><Route path="/" element={<Dashboard/>}/><Route path="/scan" element={<Scanner/>}/><Route path="/qr" element={<Scanner initial="qr"/>}/>
        <Route path="/threats" element={<Threats/>}/><Route path="/reports" element={<Reports/>}/><Route path="/report/:id" element={<Report/>}/><Route path="/settings" element={<SettingsPage/>}/>
        <Route path="*" element={<div>Page not found.</div>}/></Routes></Suspense></main>
    </div></div>}
