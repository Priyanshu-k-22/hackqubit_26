export const level=s=>s>=85?'CRITICAL':s>=65?'HIGH':s>=40?'MEDIUM':'LOW';
export const COLORS={CRITICAL:'bg-red-600 text-white',HIGH:'bg-orange-500 text-white',MEDIUM:'bg-amber-400 text-black',LOW:'bg-emerald-600 text-white'};
// Frequency is a signal, NOT a verdict. "Confirmed Threat" only comes from backend intelligence (status field).
export const freqLabel=n=>n>=25?'Strong recurring threat signal':n>=12?'Frequently reported':n>=5?'Recurring suspicious target':n>=1?'Low confidence (seen once or twice)':'No reports';
