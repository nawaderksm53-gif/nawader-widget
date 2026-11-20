// Usage: NW_KEY=<64 hex> node publish.js snapshot.json  -> writes data.enc
const fs=require("fs"),cr=require("crypto"),c=require("./nwcrypto.js");
const key=process.env.NW_KEY;if(!/^[0-9a-f]{64}$/.test(key||""))throw new Error("NW_KEY missing");
const snap=JSON.parse(fs.readFileSync(process.argv[2],"utf8"));snap.pub=Date.now();
fs.writeFileSync("data.enc",c.seal(key,snap,cr.randomBytes(12))+"\n");console.log("ok",snap.asOf);
