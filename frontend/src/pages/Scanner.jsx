import {useEffect,useRef,useState} from 'react';import {useSearchParams} from 'react-router-dom';import jsQR from 'jsqr';
import {Camera,Upload,Loader2} from 'lucide-react';import {scannerApi} from '../services/api';import Result from '../components/Result';import {ErrorBox} from '../components/ui';
const STEPS=['Validating input','Checking local URL keywords and patterns','Preparing risk summary'];
const OTHER_STEPS=['Validating input','Checking local risk signals','Preparing risk summary'];
const urlError=input=>{
  if(input.length>2048)return 'URL must be 2048 characters or fewer.';
  if(/^[a-z][a-z\d+.-]*:/i.test(input)&&!/^https?:\/\//i.test(input))return 'Only HTTP and HTTPS URLs can be checked.';
  try{const candidate=/^https?:\/\//i.test(input)?input:`https://${input}`,parsed=new URL(candidate);
    if(!['http:','https:'].includes(parsed.protocol)||!parsed.hostname)return 'Enter a valid HTTP or HTTPS URL.';
    if(parsed.username||parsed.password)return 'URLs containing usernames or passwords cannot be checked.';
  }catch{return 'Enter a valid URL, such as https://example.com.'}
  return '';
};
const decode=file=>new Promise(res=>{const img=new Image(),url=URL.createObjectURL(file);img.onload=()=>{const c=document.createElement('canvas');c.width=img.width;c.height=img.height;const x=c.getContext('2d');x.drawImage(img,0,0);
  const d=x.getImageData(0,0,c.width,c.height),q=jsQR(d.data,d.width,d.height);URL.revokeObjectURL(url);res(q?q.data:null)};img.onerror=()=>res(undefined);img.src=url});
export default function Scanner({initial}){
  const [sp]=useSearchParams(),[tab,setTab]=useState(initial||sp.get('tab')||'url'),[val,setVal]=useState(''),[step,setStep]=useState(-1),[res,setRes]=useState(null),[err,setErr]=useState(''),[cam,setCam]=useState(false),[prev,setPrev]=useState(null),[file,setFile]=useState(null);
  const vid=useRef(),stream=useRef(),raf=useRef(),busy=step>=0,steps=tab==='url'?STEPS:OTHER_STEPS;
  const run=async fn=>{setErr('');setRes(null);setStep(0);const iv=setInterval(()=>setStep(s=>Math.min(s+1,steps.length-1)),350);
    try{setRes(await fn())}catch(error){setErr(error.message||'Unable to analyze target.')}finally{clearInterval(iv);setStep(-1)}};
  const stop=()=>{cancelAnimationFrame(raf.current);stream.current?.getTracks().forEach(t=>t.stop());setCam(false)};
  useEffect(()=>stop,[]);
  const open=async()=>{setErr('');setRes(null);try{stream.current=await navigator.mediaDevices.getUserMedia({video:{facingMode:'environment'}});setCam(true);
    requestAnimationFrame(()=>{const v=vid.current;v.srcObject=stream.current;v.play();const c=document.createElement('canvas');const tick=()=>{if(v.videoWidth){c.width=v.videoWidth;c.height=v.videoHeight;const x=c.getContext('2d');x.drawImage(v,0,0);const d=x.getImageData(0,0,c.width,c.height),q=jsQR(d.data,d.width,d.height);
      if(q){stop();run(()=>scannerApi.analyzeQr(q.data));return}}raf.current=requestAnimationFrame(tick)};tick()})}catch{setErr('Camera permission unavailable. Upload a QR image instead.')}};
  const pick=f=>{if(!f)return;if(!/^image\/(png|jpe?g|webp)$/.test(f.type)){setErr('Unsupported file. Use PNG, JPG or WEBP.');return}setErr('');setRes(null);setFile(f);setPrev(URL.createObjectURL(f))};
  const clear=()=>{setFile(null);setPrev(null);setRes(null);setErr('');setVal('')};
  const analyzeFile=async()=>{const code=await decode(file);if(code===undefined){setErr('Could not read this image.');return}
    if(tab==='qr'){if(!code){setErr('No valid QR code detected.');return}run(()=>scannerApi.analyzeQr(code))}else run(()=>code?scannerApi.analyzeQr(code):scannerApi.analyzeImage(file))};
  const tabs=[['url','URL'],['qr','QR code'],['upi','UPI ID'],['image','Image']];
  const Drop=<div onDragOver={e=>e.preventDefault()} onDrop={e=>{e.preventDefault();pick(e.dataTransfer.files[0])}} className="rounded-lg border-2 border-dashed border-slate-300 p-6 text-center text-sm dark:border-ink-700">
    {prev?<img src={prev} alt="Uploaded preview" className="mx-auto max-h-48 rounded"/>:<><Upload className="mx-auto mb-2" size={22}/>Drag and drop an image, or</>}
    <div className="mt-3 flex justify-center gap-2"><label className="btn-s cursor-pointer">Browse image<input type="file" accept="image/png,image/jpeg,image/webp" className="sr-only" onChange={e=>pick(e.target.files[0])}/></label>
    {file&&<><button className="btn-p" disabled={busy} onClick={analyzeFile}>{tab==='qr'?'Analyze QR':'Analyze image'}</button><button className="btn-s" onClick={clear}>Remove</button></>}</div></div>;
  return <div className="mx-auto max-w-5xl space-y-5"><div className="grid-bg rounded-lg border border-cyan-500/20 p-6"><h1 className="text-3xl font-bold">{tab==='qr'?'QR Shield':'Check before you pay'}</h1>
   <p className="mt-1 text-sm text-slate-500">{tab==='qr'?'Scan or upload any QR code before making a payment.':'Analyze a suspicious URL, QR code, UPI ID, screenshot or payment page.'} Never enter your UPI PIN or OTP on any page you reach from here.</p></div>
  <div role="tablist" className="flex gap-1 border-b border-slate-200 dark:border-ink-700">{tabs.map(([k,l])=><button key={k} role="tab" aria-selected={tab===k} onClick={()=>{stop();clear();setTab(k)}} className={`px-4 py-2 text-sm transition ${tab===k?'border-b-2 border-cyan-500 font-medium text-cyan-600 dark:text-cyan-400':'text-slate-500'}`}>{l}</button>)}</div>
  <div className="panel p-5">
   {(tab==='url'||tab==='upi')&&<form className="flex flex-wrap gap-2" onSubmit={e=>{e.preventDefault();const v=val.trim();if(!v){setErr(`Enter a ${tab==='url'?'URL':'UPI ID'}.`);return}
     if(tab==='url'){const message=urlError(v);if(message){setErr(message);return}}
     if(tab==='upi'&&!/^[\w.\-]{2,}@[a-zA-Z]{2,}$/.test(v)){setErr('Enter a valid UPI ID, e.g. name@bank.');return}run(()=>tab==='url'?scannerApi.analyzeUrl(v):scannerApi.analyzeUpi(v))}}>
     <input className="inp flex-1" aria-label={tab} value={val} onChange={e=>setVal(e.target.value)} placeholder={tab==='url'?'https://example-payment-site.com':'name@bank'}/><button className="btn-p" disabled={busy}>Analyze target</button><button type="button" className="btn-s" onClick={clear}>Clear</button></form>}
   {tab==='url'&&<p className="mt-3 text-xs text-slate-500">URL analysis runs locally on the backend using keyword and URL-structure rules. It does not open the site or query an external reputation service.</p>}
   {tab==='qr'&&<div className="space-y-4"><div className="flex gap-2">{!cam?<button className="btn-p" onClick={open}><Camera size={16}/>Open camera</button>:<button className="btn-s" onClick={stop}>Close camera</button>}</div>
     {cam&&<div className="relative mx-auto aspect-video max-w-md overflow-hidden rounded-lg bg-black"><video ref={vid} muted playsInline className="h-full w-full object-cover"/><div className="absolute inset-[22%] border-2 border-cyan-400"><div className="sweep absolute left-0 h-0.5 w-full bg-cyan-400 shadow-[0_0_8px_#22d3ee]"/></div></div>}{Drop}</div>}
   {tab==='image'&&<div className="space-y-2"><p className="text-sm text-slate-500">Upload a payment screenshot or suspicious page. QR codes inside are decoded in your browser first; otherwise the image goes to analysis.</p>{Drop}</div>}
   {err&&<div className="mt-3"><ErrorBox text={err}/></div>}</div>
  {busy&&<div className="panel p-5" aria-live="polite"><div className="mb-2 flex items-center gap-2 text-sm"><Loader2 className="animate-spin" size={16}/>{steps[step]}…</div><div className="h-2 rounded bg-slate-200 dark:bg-ink-700"><div className="h-2 rounded bg-cyan-500 transition-all" style={{width:((step+1)/steps.length*100)+'%'}}/></div></div>}
  {res&&<Result r={res}/>}</div>}
