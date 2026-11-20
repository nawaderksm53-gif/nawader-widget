// Tiny ChaCha20 + HMAC-SHA256 (encrypt-then-MAC). Same code runs in Node and Scriptable.
function sha256(bytes){const K=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
  let H=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];const l=bytes.length,n=((l+9+63)>>6)<<6,m=new Uint8Array(n);m.set(bytes);m[l]=0x80;const bl=l*8;for(let i=0;i<4;i++)m[n-1-i]=(bl>>>(8*i))&255;m[n-5]=Math.floor(bl/2**32)&255;
  const W=new Uint32Array(64),r=(x,k)=>(x>>>k)|(x<<(32-k));for(let o=0;o<n;o+=64){for(let i=0;i<16;i++)W[i]=(m[o+4*i]<<24)|(m[o+4*i+1]<<16)|(m[o+4*i+2]<<8)|m[o+4*i+3];for(let i=16;i<64;i++){const s0=r(W[i-15],7)^r(W[i-15],18)^(W[i-15]>>>3),s1=r(W[i-2],17)^r(W[i-2],19)^(W[i-2]>>>10);W[i]=(W[i-16]+s0+W[i-7]+s1)>>>0;}
   let [a,b,c,d,e,f,g,h]=H;for(let i=0;i<64;i++){const S1=r(e,6)^r(e,11)^r(e,25),ch=(e&f)^(~e&g),t1=(h+S1+ch+K[i]+W[i])>>>0,S0=r(a,2)^r(a,13)^r(a,22),mj=(a&b)^(a&c)^(b&c),t2=(S0+mj)>>>0;h=g;g=f;f=e;e=(d+t1)>>>0;d=c;c=b;b=a;a=(t1+t2)>>>0;}
   H=H.map((x,i)=>(x+[a,b,c,d,e,f,g,h][i])>>>0);}
  const out=new Uint8Array(32);H.forEach((x,i)=>{out[4*i]=x>>>24;out[4*i+1]=(x>>>16)&255;out[4*i+2]=(x>>>8)&255;out[4*i+3]=x&255;});return out;}
function cat(...a){const n=a.reduce((s,x)=>s+x.length,0),o=new Uint8Array(n);let p=0;a.forEach(x=>{o.set(x,p);p+=x.length;});return o;}
function hmac(key,msg){if(key.length>64)key=sha256(key);const k=new Uint8Array(64);k.set(key);const ip=k.map(x=>x^0x36),op=k.map(x=>x^0x5c);return sha256(cat(op,sha256(cat(ip,msg))));}
function chacha20(key,nonce,data){const C=[0x61707865,0x3320646e,0x79622d32,0x6b206574],kw=[],nw=[];for(let i=0;i<8;i++)kw.push(key[4*i]|key[4*i+1]<<8|key[4*i+2]<<16|key[4*i+3]<<24);for(let i=0;i<3;i++)nw.push(nonce[4*i]|nonce[4*i+1]<<8|nonce[4*i+2]<<16|nonce[4*i+3]<<24);
  const out=new Uint8Array(data.length),rl=(x,k)=>(x<<k)|(x>>>(32-k));let ctr=1;for(let o=0;o<data.length;o+=64){const s=[...C,...kw,ctr,...nw].map(x=>x>>>0),x=s.slice();
   const q=(a,b,c,d)=>{x[a]=(x[a]+x[b])>>>0;x[d]=rl(x[d]^x[a],16)>>>0;x[c]=(x[c]+x[d])>>>0;x[b]=rl(x[b]^x[c],12)>>>0;x[a]=(x[a]+x[b])>>>0;x[d]=rl(x[d]^x[a],8)>>>0;x[c]=(x[c]+x[d])>>>0;x[b]=rl(x[b]^x[c],7)>>>0;};
   for(let i=0;i<10;i++){q(0,4,8,12);q(1,5,9,13);q(2,6,10,14);q(3,7,11,15);q(0,5,10,15);q(1,6,11,12);q(2,7,8,13);q(3,4,9,14);}
   for(let i=0;i<16;i++){const w=(x[i]+s[i])>>>0;for(let b=0;b<4;b++){const j=o+4*i+b;if(j<data.length)out[j]=data[j]^((w>>>(8*b))&255);}}ctr++;}return out;}
const te=s=>{const o=[];s=unescape(encodeURIComponent(s));for(let i=0;i<s.length;i++)o.push(s.charCodeAt(i));return new Uint8Array(o);};
const td=b=>{let s="";for(const x of b)s+=String.fromCharCode(x);return decodeURIComponent(escape(s));};
const hex=b=>Array.from(b).map(x=>x.toString(16).padStart(2,"0")).join(""),unhex=h=>new Uint8Array(h.match(/../g).map(x=>parseInt(x,16)));
function keys(masterHex){const m=unhex(masterHex);return {e:hmac(m,te("enc")),a:hmac(m,te("mac"))};}
function seal(masterHex,obj,nonce){const k=keys(masterHex),ct=chacha20(k.e,nonce,te(JSON.stringify(obj))),tag=hmac(k.a,cat(nonce,ct));return "NW1."+hex(nonce)+"."+hex(ct)+"."+hex(tag);}
function open(masterHex,str){const p=String(str).trim().split(".");if(p[0]!=="NW1")throw new Error("format");const k=keys(masterHex),n=unhex(p[1]),ct=unhex(p[2]),tag=hex(hmac(k.a,cat(n,ct)));if(tag!==p[3])throw new Error("wrong key");return JSON.parse(td(chacha20(k.e,n,ct)));}
if(typeof module!=="undefined")module.exports={seal,open,sha256,hmac,hex};
