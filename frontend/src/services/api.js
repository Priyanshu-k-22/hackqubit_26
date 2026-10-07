import {threats,campaigns} from '../data/mock';
const BASE=import.meta.env.VITE_API_BASE_URL||'';
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const hash=s=>[...s].reduce((a,c)=>(a*31+c.charCodeAt(0))>>>0,7);
const known=['official','sbi.co.in','google.com','paytm.com'];
// ---- mock layer: swap for real endpoints; UI code stays unchanged ----
function mockAnalyze(kind,input){
  const h=hash(input),m=threats.find(t=>input.includes(t.target.split('?')[0])||t.target.includes(input));
  let domain='-',upi='-',payee='-';
  try{const u=new URL(input.startsWith('upi://')?input.replace('upi://','https://x/'):input.includes('://')?input:'https://'+input);
    if(input.startsWith('upi://')){upi=u.searchParams.get('pa')||'-';payee=u.searchParams.get('pn')||'-'}else domain=u.hostname}catch{}
  if(kind==='upi')upi=input;
  const low=known.some(k=>input.includes(k)),score=m?m.risk:low?4:55+h%43,reports=m?m.reports:low?0:h%20;
  const ev=low?['No known threat indicators','No matching campaign found','Valid HTTPS certificate (simulated)','Domain matches official brand registry (simulated)']
   :[`Brand visual similarity: ${60+h%39}%`,'Suspicious redirect chain','Newly observed domain','Payment credential collection pattern','Shared infrastructure with known campaign',`Repeated reports: ${reports}`];
  const b=n=>Math.min(99,Math.max(1,score+((h>>n)%11)-5));
  return {id:'SCN-'+h.toString(16).toUpperCase(),kind,input,score,domain,upi,payee,redirects:low?0:h%4,protocol:input.startsWith('http://')?'HTTP':'HTTPS',
   brand:m?.brand||(low?'Official brand':'Unknown / possible impersonation'),reports,campaign:m?.campaign||(low?'None':'CAM-017'),status:m?.status||(low?'Low Risk':'Under Review'),
   first:m?.first||'2026-10-07',last:m?.last||'2026-10-07',users:Math.ceil(reports*.7),evidence:ev,demo:true,ts:new Date().toISOString(),
   breakdown:{'Visual similarity':b(1),'Domain risk':b(2),'Behavior':b(3),'Infrastructure':b(4),'Threat intelligence':b(5)}};
}
async function call(path,body,fallback){
  if(!BASE){await sleep(300);return fallback()}
  try{const r=await fetch(BASE+path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});if(!r.ok)throw new Error(r.status);return await r.json()}
  catch{const v=fallback();v.backendUnavailable=true;return v}
}
export const save=r=>{const all=JSON.parse(localStorage.getItem('ups_results')||'{}');all[r.id]=r;localStorage.setItem('ups_results',JSON.stringify(all));return r};
export const scannerApi={
  analyzeUrl:u=>call('/scan/url',{url:u},()=>mockAnalyze('url',u)).then(save),
  analyzeUpi:u=>call('/scan/upi',{upi:u},()=>mockAnalyze('upi',u)).then(save),
  analyzeQr:p=>call('/scan/qr',{payload:p},()=>mockAnalyze('qr',p)).then(save),
  analyzeImage:f=>call('/scan/image',{name:f.name},()=>mockAnalyze('image',f.name)).then(save)};
export const threatApi={list:async()=>threats,getResult:id=>{const t=threats.find(x=>x.id===id);return t&&save(mockAnalyze('url',t.target))}};
export const campaignApi={list:async()=>campaigns};
export const reportApi={get:id=>JSON.parse(localStorage.getItem('ups_results')||'{}')[id],list:()=>Object.values(JSON.parse(localStorage.getItem('ups_results')||'{}'))};
export const feedbackApi={submit:b=>call('/feedback',b,()=>({ok:true,demo:true}))};
export const isDemo=!BASE;
