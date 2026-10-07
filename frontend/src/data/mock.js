// ALL DATA IS SYNTHETIC DEMO INTELLIGENCE. Domains use reserved/fictional names.
export const threats=[
{id:'T-001',target:'fake-sbi-payment.example',type:'URL',brand:'SBI',reports:47,risk:97,first:'2026-09-12',last:'2026-10-07',campaign:'CAM-017',status:'Confirmed Threat'},
{id:'T-002',target:'paytm-verification.example',type:'Website',brand:'Paytm',reports:32,risk:94,first:'2026-09-20',last:'2026-10-06',campaign:'CAM-017',status:'Frequently Reported'},
{id:'T-003',target:'sbi.refund.help@okdemo',type:'UPI',brand:'SBI',reports:17,risk:92,first:'2026-09-14',last:'2026-10-07',campaign:'CAM-017',status:'Frequently Reported'},
{id:'T-004',target:'upi://pay?pa=gpay.cashback@demo&pn=Cashback',type:'QR',brand:'Google Pay',reports:9,risk:81,first:'2026-09-28',last:'2026-10-05',campaign:'CAM-022',status:'Recurring'},
{id:'T-005',target:'phonepe-kyc-update.example',type:'App',brand:'PhonePe',reports:5,risk:73,first:'2026-10-01',last:'2026-10-04',campaign:'CAM-022',status:'Under Review'},
{id:'T-006',target:'hdfc-secure-login.example',type:'URL',brand:'HDFC',reports:2,risk:58,first:'2026-10-03',last:'2026-10-03',campaign:'-',status:'Under Review'}];
export const campaigns=[{id:'CAM-017',name:'SBI Impersonation Campaign',domains:8,ips:3,vpas:4,phones:6,risk:'CRITICAL',status:'Active'},{id:'CAM-022',name:'Cashback QR Campaign',domains:3,ips:2,vpas:5,phones:2,risk:'HIGH',status:'Active'}];
export const activity=[{d:'Mon',safe:120,suspicious:40,high:22,critical:9},{d:'Tue',safe:140,suspicious:36,high:25,critical:12},{d:'Wed',safe:110,suspicious:52,high:31,critical:14},{d:'Thu',safe:150,suspicious:44,high:28,critical:10},{d:'Fri',safe:170,suspicious:60,high:35,critical:18},{d:'Sat',safe:90,suspicious:30,high:20,critical:8},{d:'Sun',safe:100,suspicious:33,high:24,critical:11}];
export const brands=[{b:'SBI',n:210},{b:'PhonePe',n:160},{b:'Google Pay',n:140},{b:'Paytm',n:120},{b:'ICICI',n:80},{b:'HDFC',n:70}];
