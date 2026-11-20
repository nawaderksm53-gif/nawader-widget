// Usage: node enrich.js snapshot.json txns-file [more files...]  -> rewrites snapshot.json with month sales by payment
// txns files may be db_query output (JSON lines with {"id","data"}) or a saved tool-result JSON array of {type,text}.
const fs=require("fs");const snapF=process.argv[2];const snap=JSON.parse(fs.readFileSync(snapF,"utf8"));
const m=(snap.asOf||"").slice(0,7),from=m+"-01",to=snap.asOf;const seen=new Set();const tot={cash:0,knet:0,wamd:0,credit:0,other:0};let n=0;
function scan(text){for(const line of String(text).split(/\n/)){const t=line.trim();if(!t.startsWith("{"))continue;let o;try{o=JSON.parse(t);}catch(e){continue;}
  const d=o&&o.data;if(!d||!o.id||seen.has(o.id))continue;seen.add(o.id);if(d.type!=="sale"||!d.date||d.date<from||d.date>to)continue;
  const a=Number(d.amount)||0,k=d.method==="cash"?"cash":(d.method==="knet"||d.method==="card")?"knet":(d.method==="wamd"||d.method==="link")?"wamd":d.method==="credit"?"credit":"other";tot[k]+=a;n++;}}
for(const f of process.argv.slice(3)){const raw=fs.readFileSync(f,"utf8");let done=false;try{const j=JSON.parse(raw);if(Array.isArray(j)){j.forEach(x=>scan(x&&x.text!=null?x.text:JSON.stringify(x)));done=true;}}catch(e){}if(!done)scan(raw);}
const r=v=>Math.round(v*1000)/1000;const M=snap.month||{};
// The query only needs the KNET/Visa and WAMD/Link lines; credit and total come from the snapshot, cash is the remainder.
const credit=M.credit!=null?M.credit:tot.credit,knet=tot.knet,wamd=tot.wamd,cash=(M.sales||0)-credit-knet-wamd-tot.other;
snap.month=Object.assign({},M,{cash:r(cash),knet:r(knet),wamd:r(wamd),credit:r(credit),lines:n});
fs.writeFileSync(snapF,JSON.stringify(snap));console.log("month",m,"lines",n,JSON.stringify(snap.month));
