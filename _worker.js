const DATA_FILES = new Set(["news.json","editions.json","settings.json","today.json","banners.json","ads.json","poll.json","ticker.json"]);
const COOKIE = "um_admin";
const enc = new TextEncoder();
const json = (data, status=200, headers={}) => new Response(JSON.stringify(data), {status, headers:{"content-type":"application/json; charset=utf-8","cache-control":"no-store",...headers}});
function b64u(bytes){return btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"")}
async function sign(value, secret){
  const key=await crypto.subtle.importKey("raw",enc.encode(secret),{name:"HMAC",hash:"SHA-256"},false,["sign"]);
  return b64u(await crypto.subtle.sign("HMAC",key,enc.encode(value)));
}
async function valid(request, env){
  const token=(request.headers.get("Cookie")||"").split(";").map(x=>x.trim()).find(x=>x.startsWith(COOKIE+"="))?.slice(COOKIE.length+1);
  if(!token||!env.SESSION_SECRET)return false;
  const [payload,sig]=token.split(".");
  if(!payload||!sig)return false;
  let raw;try{raw=atob(payload.replace(/-/g,"+").replace(/_/g,"/"));}catch{return false}
  let data;try{data=JSON.parse(raw)}catch{return false}
  if(data.exp<Date.now())return false;
  return (await sign(payload,env.SESSION_SECRET))===sig;
}
const cookie=(v,maxAge)=>`${COOKIE}=${v}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;
export default {
 async fetch(request,env){
  const u=new URL(request.url), p=u.pathname;
  try{
   if(p==="/api/login" && request.method==="POST"){
    if(!env.ADMIN_PASSWORD||!env.SESSION_SECRET)return json({ok:false,error:"Cloudflare Secrets அமைக்கப்படவில்லை."},503);
    const body=await request.json();
    if(String(body.password||"")!==env.ADMIN_PASSWORD)return json({ok:false,error:"கடவுச்சொல் தவறு."},401);
    const payload=b64u(enc.encode(JSON.stringify({exp:Date.now()+8*60*60*1000,role:"admin"})));
    const token=payload+"."+await sign(payload,env.SESSION_SECRET);
    return json({ok:true},200,{"set-cookie":cookie(token,8*60*60)});
   }
   if(p==="/api/me")return json({ok:await valid(request,env)});
   if(p==="/api/logout"&&request.method==="POST")return json({ok:true},200,{"set-cookie":cookie("",0)});
   if(p.startsWith("/api/admin/")&&!await valid(request,env))return json({ok:false,error:"Admin login தேவை."},401);
   if(request.method==="GET" && DATA_FILES.has(p.slice(1)) && !p.slice(1).includes("/")){
    const saved=env.SITE_DATA?await env.SITE_DATA.get(p.slice(1)):null;
    if(saved!==null)return new Response(saved,{headers:{"content-type":"application/json; charset=utf-8","cache-control":"no-store"}});
   }
   if(p==="/api/vote"&&request.method==="POST"){
    if(!env.SITE_DATA)return json({error:"வாக்கெடுப்பு சேமிப்பு அமைக்கப்படவில்லை."},503);
    const body=await request.json();
    const raw=await env.SITE_DATA.get("poll.json");
    let poll;
    if(raw!==null){try{poll=JSON.parse(raw)}catch{return json({error:"Poll data error"},500)}}
    else {const r=await env.ASSETS.fetch(new Request(new URL("/poll.json",request.url)));poll=await r.json()}
    if(!poll||poll.active===false||poll.id!==body.poll)return json({error:"வாக்கெடுப்பு முடிந்துவிட்டது."},409);
    const option=(poll.opts||[]).find(o=>o.t===body.choice);
    if(!option)return json({error:"தவறான தேர்வு."},400);
    option.v=(Number(option.v)||0)+1;
    await env.SITE_DATA.put("poll.json",JSON.stringify(poll));
    return json({ok:true});
   }
   if(p.startsWith("/api/data/")){
    const name=decodeURIComponent(p.slice("/api/data/".length));
    if(!DATA_FILES.has(name))return json({error:"Invalid data file"},404);
    if(request.method==="GET"){
      const saved=env.SITE_DATA?await env.SITE_DATA.get(name):null;
      if(saved!==null)return new Response(saved,{headers:{"content-type":"application/json; charset=utf-8","cache-control":"no-store"}});
      return env.ASSETS.fetch(new Request(new URL("/"+name,request.url)));
    }
    if(request.method==="PUT"){
      if(!await valid(request,env))return json({error:"Admin login தேவை."},401);
      if(!env.SITE_DATA)return json({error:"SITE_DATA KV binding இல்லை."},503);
      const raw=await request.text();let parsed;try{parsed=JSON.parse(raw)}catch{return json({error:"JSON தவறு"},400)}
      await env.SITE_DATA.put(name,JSON.stringify(parsed));
      return json({ok:true});
    }
   }
   if(p==="/api/upload"&&request.method==="POST"){
    if(!await valid(request,env))return json({error:"Admin login தேவை."},401);
    if(!env.MEDIA)return json({error:"MEDIA R2 binding இல்லை."},503);
    const fileName=decodeURIComponent(request.headers.get("x-file-name")||"upload.bin").replace(/[^a-zA-Z0-9._-]/g,"_").slice(-100);
    const type=request.headers.get("content-type")||"application/octet-stream";
    if(!/^(image\/(jpeg|png|webp|gif)|application\/pdf)$/.test(type))return json({error:"படம் அல்லது PDF மட்டும் அனுமதி."},415);
    const key=Date.now().toString(36)+"-"+crypto.randomUUID()+"-"+fileName;
    await env.MEDIA.put(key,request.body,{httpMetadata:{contentType:type,cacheControl:"public, max-age=31536000, immutable"}});
    return json({ok:true,url:"/media/"+encodeURIComponent(key),key});
   }
   if(p.startsWith("/media/")&&request.method==="GET"){
    if(!env.MEDIA)return new Response("Media storage not configured",{status:503});
    const key=decodeURIComponent(p.slice(7)),obj=await env.MEDIA.get(key);
    if(!obj)return new Response("Not found",{status:404});
    const h=new Headers();obj.writeHttpMetadata(h);h.set("etag",obj.httpEtag);h.set("cache-control","public, max-age=31536000, immutable");
    return new Response(obj.body,{headers:h});
   }
   return env.ASSETS.fetch(request);
  }catch(e){return json({ok:false,error:"Server error",detail:String(e?.message||e)},500)}
 }
};
