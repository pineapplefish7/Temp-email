// ============== TempMail @madebymason.eu.cc (Hardened Edition) ==============

const MAIL_DOMAIN = "madebymason.eu.cc";
const EXPIRE_MS = 15 * 60 * 1000; // 15 minutes safety cleanup

const ADJ = ["swift","lucky","brave","cosmic","quiet","clever","fuzzy","gentle","mighty","silver","lunar","sunny","frosty","velvet","rapid","wild"];
const NOUN = ["fox","otter","raven","comet","willow","cedar","pixel","nova","echo","river","stone","spark","maple","jade","atlas","lynx"];

// ---------- helpers ----------
// Fix #3: Cryptographically secure random integer generator (unbiased)
function getRandomInt(max) {
  const arr = new Uint32Array(1);
  const range = 2 ** 32;
  const limit = range - (range % max);
  while (true) {
    crypto.getRandomValues(arr);
    if (arr[0] < limit) {
      return arr[0] % max;
    }
  }
}

const randId = (len=10) => {
  const c="abcdefghijklmnopqrstuvwxyz0123456789"; let s="";
  for(let i=0;i<len;i++) s+=c[getRandomInt(c.length)];
  return s;
};

function genAddress(){
  const a = ADJ[getRandomInt(ADJ.length)] + NOUN[getRandomInt(NOUN.length)] + (getRandomInt(9000) + 1000);
  return a + '@' + MAIL_DOMAIN;
}

function escapeHtml(s){
  return String(s||"").replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
}

// Fix #8: Normalize lengths via HMAC before constant-time comparison to prevent length leak
function safeEqualBuf(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for(let i=0; i<a.length; i++) r |= a[i] ^ b[i];
  return r === 0;
}

async function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const enc = new TextEncoder();
  // Use a dummy key for HMAC to normalize both to 32-byte digests
  const key = await crypto.subtle.importKey("raw", enc.encode("tempmail"), {name:"HMAC", hash:"SHA-256"}, false, ["sign"]);
  const aSig = await crypto.subtle.sign("HMAC", key, enc.encode(a));
  const bSig = await crypto.subtle.sign("HMAC", key, enc.encode(b));
  return safeEqualBuf(new Uint8Array(aSig), new Uint8Array(bSig));
}

async function sign(value, secret){
  const enc=new TextEncoder();
  const key=await crypto.subtle.importKey("raw",enc.encode(secret),{name:"HMAC",hash:"SHA-256"},false,["sign"]);
  const buf=await crypto.subtle.sign("HMAC",key,enc.encode(value));
  return [...new Uint8Array(buf)].map(b=>b.toString(16).padStart(2,'0')).join('');
}

// ---------- session ----------
async function makeSession(env){
  const token = randId(32);
  const expires = Date.now() + 30 * 60 * 1000; // 30 minutes
  const payload = token + '.' + expires;
  const sig = await sign(payload, env.ACCESS_KEY);
  
  // Fix #1: Store session in DB for hard-revocation
  await env.MAIL_DB.prepare("INSERT INTO sessions (token, expires) VALUES (?, ?)").bind(token, expires).run();
  
  return { cookie: payload + '.' + sig };
}

async function verifySession(req, env){
  const c = req.headers.get("cookie")||"";
  const m = c.match(/tm_session=([^;]+)/);
  if(!m) return null;
  const parts = m[1].split(".");
  if(parts.length !== 3) return null;
  const token = parts[0];
  const expires = parseInt(parts[1], 10);
  const sig = parts[2];
  if(!token || !expires || !sig) return null;
  
  // Fix #1: Check embedded expiry
  if(Date.now() > expires) return null;
  
  const payload = token + '.' + expires;
  const expected = await sign(payload, env.ACCESS_KEY);
  if(!await safeEqual(sig, expected)) return null;
  
  // Fix #1: Check DB for hard-revocation
  const row = await env.MAIL_DB.prepare("SELECT token FROM sessions WHERE token = ?").bind(token).first();
  if(!row) return null;
  
  return token;
}

// Fix #2: D1-backed rate limiting
async function checkRateLimit(env, ip) {
  const key = 'login_' + ip;
  const now = Date.now();
  const windowMs = 60 * 1000;
  const maxAttempts = 5;
  
  try {
    const row = await env.MAIL_DB.prepare("SELECT count, expires FROM rate_limits WHERE key = ?").bind(key).first();
    if (row && row.expires > now) {
      if (row.count >= maxAttempts) {
        return false; // Rate limited
      }
      await env.MAIL_DB.prepare("UPDATE rate_limits SET count = count + 1 WHERE key = ?").bind(key).run();
    } else {
      await env.MAIL_DB.prepare("INSERT OR REPLACE INTO rate_limits (key, count, expires) VALUES (?, ?, ?)").bind(key, 1, now + windowMs).run();
    }
  } catch(e) {
    console.error("Rate limit check failed:", e);
    // Fail open if DB is down to prevent locking everyone out
  }
  return true;
}

// ---------- D1 Database Layout ----------
async function cleanupOldMails(env) {
  try {
    const expireTime = Date.now() - EXPIRE_MS;
    await env.MAIL_DB.batch([
      env.MAIL_DB.prepare("DELETE FROM mails WHERE received_at < ?").bind(expireTime),
      env.MAIL_DB.prepare("DELETE FROM sessions WHERE expires < ?").bind(Date.now()),
      env.MAIL_DB.prepare("DELETE FROM rate_limits WHERE expires < ?").bind(Date.now())
    ]);
  } catch(e) {}
}

async function assignAddress(env, token){
  const existing = await env.MAIL_DB.prepare("SELECT address FROM addresses WHERE token = ?").bind(token).first();
  if(existing) return existing.address;
  
  // Fix #7: Retry loop for TOCTOU race condition on UNIQUE constraint
  for(let i=0;i<5;i++){
    const addr = genAddress();
    try {
      await env.MAIL_DB.prepare("INSERT INTO addresses (token, address) VALUES (?, ?)").bind(token, addr).run();
      return addr;
    } catch(e) {
      if (!e.message || !e.message.includes('UNIQUE constraint failed')) {
        throw e;
      }
    }
  }
  throw new Error("Failed to assign address after 5 attempts");
}

async function getAddress(env, token){
  const row = await env.MAIL_DB.prepare("SELECT address FROM addresses WHERE token = ?").bind(token).first();
  return row ? row.address : null;
}

async function wipeAddress(env, token) {
  try {
    const addr = await getAddress(env, token);
    if (addr) {
      await env.MAIL_DB.batch([
        env.MAIL_DB.prepare("DELETE FROM mails WHERE address = ?").bind(addr),
        env.MAIL_DB.prepare("DELETE FROM addresses WHERE token = ?").bind(token)
      ]);
    }
  } catch(e) {}
}

async function resetAddress(env, token){
  await wipeAddress(env, token);
  return await assignAddress(env, token);
}

async function listInbox(env, address){
  try {
    // Fix #4: Cap query size
    const { results } = await env.MAIL_DB.prepare("SELECT id, from_addr, subject, received_at FROM mails WHERE address = ? ORDER BY received_at DESC LIMIT 100").bind(address).all();
    return results.map(r => ({
      id: r.id,
      from: r.from_addr,
      subject: r.subject,
      receivedAt: r.received_at
    }));
  } catch(e) {
    throw e;
  }
}

async function getEmailAndDelete(env, address, id){
  // Fix #7: Atomic read-and-delete using RETURNING *
  const row = await env.MAIL_DB.prepare("DELETE FROM mails WHERE id = ? AND address = ? RETURNING *").bind(id, address).first();
  if(!row) return null;
  
  return {
    id: row.id,
    from: row.from_addr,
    subject: row.subject,
    body: row.body,
    receivedAt: row.received_at
  };
}

// ---------- Advanced MIME Parser ----------
function extractBody(rawSource) {
  try {
    const headerEnd = rawSource.indexOf("\r\n\r\n");
    let headers = "";
    let body = rawSource;
    
    if (headerEnd !== -1) {
      headers = rawSource.substring(0, headerEnd);
      body = rawSource.substring(headerEnd + 4);
    }
    
    const boundaryMatch = headers.match(/boundary="?([^\r\n;"]+)"?/i);
    if (boundaryMatch) {
      const boundary = "--" + boundaryMatch[1];
      const parts = body.split(boundary);
      let plainText = "";
      let htmlText = "";
      
      for (let i = 0; i < parts.length; i++) {
        let part = parts[i];
        if (part.indexOf("text/plain") !== -1) {
          const partHeaderEnd = part.indexOf("\r\n\r\n");
          if (partHeaderEnd !== -1) {
            plainText = part.substring(partHeaderEnd + 4);
          }
        } else if (part.indexOf("text/html") !== -1) {
          const partHeaderEnd = part.indexOf("\r\n\r\n");
          if (partHeaderEnd !== -1) {
            htmlText = part.substring(partHeaderEnd + 4);
          }
        }
      }
      
      let finalContent = plainText || htmlText;
      finalContent = finalContent.replace(/=\r?\n/g, '');
      finalContent = finalContent.replace(/=([0-9A-F]{2})/g, function(m, p1) {
        return String.fromCharCode(parseInt(p1, 16));
      });
      if (!plainText && htmlText) {
        finalContent = finalContent.replace(/<[^>]*>?/gm, '');
      }
      return finalContent.trim();
    } else {
      body = body.replace(/=\r?\n/g, '');
      body = body.replace(/=([0-9A-F]{2})/g, function(m, p1) {
        return String.fromCharCode(parseInt(p1, 16));
      });
      if (headers.indexOf("text/html") !== -1) {
        body = body.replace(/<[^>]*>?/gm, '');
      }
      return body.trim();
    }
  } catch(e) {
    return rawSource;
  }
}

// ---------- inbound mail handler ----------
async function emailHandler(message, env, ctx){
  let to = message.to || "";
  const matchTo = to.match(/<([^>]+)>/);
  if(matchTo) to = matchTo[1];
  to = to.toLowerCase().trim();
  
  let from = message.from || "";
  const matchFrom = from.match(/<([^>]+)>/);
  if(matchFrom) from = matchFrom[1];
  from = from.toLowerCase().trim();

  const subject = message.headers.get("subject") || "(no subject)";

  const owner = await env.MAIL_DB.prepare("SELECT token FROM addresses WHERE address = ?").bind(to).first();
  if(!owner) return; 

  // Fix #4: Per-address cap on inbound mail volume
  const countRow = await env.MAIL_DB.prepare("SELECT COUNT(*) as count FROM mails WHERE address = ?").bind(to).first();
  if (countRow && countRow.count >= 50) {
    return; // Silently drop if inbox is full
  }

  let rawBody = "";
  try{
    const reader = message.raw.getReader();
    const dec = new TextDecoder();
    while(true){
      const {done,value}=await reader.read();
      if(done) break;
      rawBody += dec.decode(value);
    }
  }catch(e){
    rawBody = "(could not read body)";
  }

  let cleanBody = extractBody(rawBody); 

  const id = randId(12);
  
  await env.MAIL_DB.prepare(
    "INSERT INTO mails (id, address, from_addr, subject, body, received_at) VALUES (?, ?, ?, ?, ?, ?)"
  ).bind(id, to, from, subject, cleanBody, Date.now()).run();
}

// ---------- HTTP API ----------
async function handleApi(req, env, ctx){
  const url = new URL(req.url);

  if(url.pathname === "/login" && req.method === "POST"){
    try {
      // Fix #2: Apply rate limiting (Note: pair with Cloudflare Rate Limiting Rule at the edge)
      const ip = req.headers.get('cf-connecting-ip') || 'unknown';
      const allowed = await checkRateLimit(env, ip);
      if (!allowed) {
        return json({error:"Too many attempts. Try again later."}, 429);
      }
      
      const body = await req.json();
      const key = (body.key || "").trim();
      
      // Fix #5: Generic error messages, log internals
      if(!env.ACCESS_KEY || !env.MAIL_DB) {
        console.error("Server config error: ACCESS_KEY or D1 database is missing");
        return json({error:"Server error"}, 500);
      }
      
      if(!await safeEqual(key, env.ACCESS_KEY.trim())){
        return json({error:"Invalid key"}, 401);
      }
      
      // Reset rate limit on successful login
      const ipKey = 'login_' + ip;
      await env.MAIL_DB.prepare("DELETE FROM rate_limits WHERE key = ?").bind(ipKey).run();
      
      const session = await makeSession(env);
      return json({ok:true}, 200, {
        "Set-Cookie": "tm_session=" + session.cookie + "; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=1800"
      });
    } catch(e) {
      console.error("Login error:", e);
      return json({error:"Something went wrong"}, 400);
    }
  }

  const token = await verifySession(req, env);
  if(!token) return json({error:"unauthorized"}, 401);

  if(url.pathname === "/logout" && req.method === "POST"){
    // Fix #1: Hard-revoke session from DB
    await env.MAIL_DB.prepare("DELETE FROM sessions WHERE token = ?").bind(token).run();
    await wipeAddress(env, token);
    return json({ok:true}, 200, {
      "Set-Cookie": "tm_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0"
    });
  }

  if(url.pathname === "/api/assign" && req.method === "POST"){
    const addr = await assignAddress(env, token);
    return json({ address: addr });
  }

  if(url.pathname === "/api/reset" && req.method === "POST"){
    const addr = await resetAddress(env, token);
    return json({ address: addr });
  }

  if(url.pathname === "/api/inbox"){
    try {
      await cleanupOldMails(env);
      const addr = await getAddress(env, token);
      if(!addr) return json({error:"no address"}, 400);
      const list = await listInbox(env, addr);
      return json({ address: addr, inbox: list });
    } catch(e) {
      // Fix #5: Generic error messages, log internals
      console.error("Inbox error:", e);
      return json({error:"Something went wrong"}, 500);
    }
  }

  if(url.pathname.startsWith("/api/email/")){
    const id = url.pathname.split("/").pop();
    const addr = await getAddress(env, token);
    if(!addr) return json({error:"no address"}, 400);
    const mail = await getEmailAndDelete(env, addr, id);
    if(!mail) return json({error:"not found"}, 404);
    return json({ email: mail });
  }

  return json({error:"not found"}, 404);
}

function json(obj, status=200, headers={}){
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type":"application/json", ...headers }
  });
}

// ---------- UI ----------
const HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>TempMail · @madebymason.eu.cc</title>
<style>
  :root{
    --bg:#0a0a14; --bg2:#13132a;
    --glass:rgba(255,255,255,0.06);
    --border:rgba(255,255,255,0.10);
    --txt:#e8e8f4; --muted:#8a8aab;
    --accent:#7c5cff; --accent2:#19d3ff;
    --ok:#22d39a; --err:#ff5c7c;
  }
  *{box-sizing:border-box;margin:0;padding:0}
  html,body{height:100%}
  body{
    font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Inter,system-ui,sans-serif;
    background:var(--bg); color:var(--txt);
    min-height:100vh; overflow-x:hidden;
    display:flex; align-items:center; justify-content:center;
    padding:20px; position:relative;
  }
  .blob{position:fixed; border-radius:50%; filter:blur(80px); opacity:0.5; z-index:0; pointer-events:none;}
  .b1{width:480px;height:480px;background:#7c5cff;top:-120px;left:-120px;animation:float 18s ease-in-out infinite;}
  .b2{width:420px;height:420px;background:#19d3ff;bottom:-120px;right:-100px;animation:float 22s ease-in-out infinite reverse;}
  .b3{width:360px;height:360px;background:#ff5c9c;top:40%;left:50%;transform:translate(-50%,-50%);animation:float 26s ease-in-out infinite;}
  @keyframes float{
    0%,100%{transform:translate(0,0) scale(1);}
    33%{transform:translate(60px,-40px) scale(1.08);}
    66%{transform:translate(-40px,30px) scale(0.95);}
  }

  .login{
    position:relative; z-index:2;
    background:var(--glass); backdrop-filter:blur(24px); -webkit-backdrop-filter:blur(24px);
    border:1px solid var(--border);
    border-radius:24px; padding:44px 40px;
    width:100%; max-width:420px;
    box-shadow:0 30px 80px rgba(0,0,0,0.5);
    animation:rise 0.6s cubic-bezier(.2,.8,.2,1);
  }
  @keyframes rise{from{opacity:0;transform:translateY(20px);}to{opacity:1;transform:translateY(0);}}

  .logo{display:flex;align-items:center;gap:12px;margin-bottom:8px;}
  .logo-mark{
    width:44px;height:44px;border-radius:12px;
    background:linear-gradient(135deg,var(--accent),var(--accent2));
    display:grid;place-items:center;
    box-shadow:0 8px 24px rgba(124,92,255,0.45);
  }
  .logo-mark svg{width:24px;height:24px;fill:#fff;}
  .logo h1{font-size:20px;font-weight:700;letter-spacing:-0.02em;}
  .logo span{color:var(--accent2);}
  .subtitle{color:var(--muted);font-size:14px;margin-bottom:28px;}

  label{display:block;font-size:13px;color:var(--muted);margin-bottom:8px;font-weight:500;}
  .input{
    width:100%; padding:14px 16px;
    background:rgba(0,0,0,0.3);
    border:1px solid var(--border);
    border-radius:12px; color:var(--txt);
    font-size:15px; font-family:inherit;
    transition:border-color 0.2s, box-shadow 0.2s;
  }
  .input:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 4px rgba(124,92,255,0.18);}
  .btn{
    width:100%; margin-top:18px;
    padding:14px 16px;
    background:linear-gradient(135deg,var(--accent),var(--accent2));
    color:#fff; border:none; border-radius:12px;
    font-size:15px; font-weight:600; cursor:pointer;
    transition:transform 0.15s, box-shadow 0.2s;
    box-shadow:0 8px 24px rgba(124,92,255,0.35);
  }
  .btn:hover{transform:translateY(-1px);box-shadow:0 12px 32px rgba(124,92,255,0.5);}
  .btn:active{transform:translateY(0);}

  .err{color:var(--err);font-size:13px;margin-top:10px;min-height:18px;}

  .app{display:none;position:relative;z-index:2;width:100%;max-width:1100px;}
  .app.active{display:block;animation:rise 0.5s cubic-bezier(.2,.8,.2,1);}

  .topbar{display:flex;align-items:center;justify-content:space-between;margin-bottom:24px;gap:16px;flex-wrap:wrap;}
  .brand{display:flex;align-items:center;gap:12px;}
  .brand .logo-mark{width:38px;height:38px;border-radius:10px;}
  .brand .logo-mark svg{width:20px;height:20px;}
  .brand h2{font-size:18px;font-weight:700;}
  .brand span{color:var(--accent2);}

  .top-actions{display:flex;gap:10px;}
  .pill-btn{
    padding:10px 16px; border-radius:10px; font-size:13px; font-weight:600;
    background:rgba(255,255,255,0.06); color:var(--txt);
    border:1px solid var(--border); cursor:pointer; transition:all 0.2s;
    display:inline-flex; align-items:center; gap:6px;
  }
  .pill-btn:hover{background:rgba(255,255,255,0.12);}
  .pill-btn.danger:hover{background:rgba(255,92,124,0.15);border-color:rgba(255,92,124,0.4);color:#ff8aa3;}

  .address-card{
    background:var(--glass); backdrop-filter:blur(24px); -webkit-backdrop-filter:blur(24px);
    border:1px solid var(--border); border-radius:20px;
    padding:24px 28px; margin-bottom:24px;
    display:flex; align-items:center; justify-content:space-between; gap:16px; flex-wrap:wrap;
    box-shadow:0 20px 60px rgba(0,0,0,0.35);
  }
  .addr-label{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:0.1em;margin-bottom:6px;font-weight:600;}
  .addr-value{
    font-size:22px; font-weight:700; letter-spacing:-0.02em;
    font-family:'SF Mono',Menlo,Monaco,Consolas,monospace;
    background:linear-gradient(135deg,#fff,var(--accent2));
    -webkit-background-clip:text; background-clip:text; -webkit-text-fill-color:transparent;
    word-break:break-all;
  }
  .copy-btn{
    padding:12px 18px; border-radius:12px; border:1px solid var(--border);
    background:rgba(124,92,255,0.15); color:#fff; font-weight:600; font-size:13px;
    cursor:pointer; transition:all 0.2s; display:inline-flex; align-items:center; gap:8px;
  }
  .copy-btn:hover{background:rgba(124,92,255,0.3);border-color:var(--accent);}
  .copy-btn.copied{background:rgba(34,211,154,0.2);border-color:var(--ok);color:var(--ok);}

  .countdown{font-size:12px;color:var(--muted);margin-top:10px;display:flex;align-items:center;gap:6px;}
  .countdown-dot{width:8px;height:8px;border-radius:50%;background:var(--ok);box-shadow:0 0 12px var(--ok);animation:pulse 1.6s ease-in-out infinite;}
  @keyframes pulse{0%,100%{opacity:1;}50%{opacity:0.4;}}

  .grid{display:grid;grid-template-columns:1fr 1.4fr;gap:20px;}
  @media(max-width:820px){.grid{grid-template-columns:1fr;}}

  .panel{
    background:var(--glass); backdrop-filter:blur(24px); -webkit-backdrop-filter:blur(24px);
    border:1px solid var(--border); border-radius:20px; overflow:hidden;
    box-shadow:0 20px 60px rgba(0,0,0,0.35);
  }
  .panel-head{padding:18px 22px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;}
  .panel-head h3{font-size:14px;font-weight:700;letter-spacing:0.02em;}
  .panel-head .count{font-size:12px;color:var(--muted);background:rgba(255,255,255,0.06);padding:4px 10px;border-radius:20px;}

  .mail-list{max-height:560px;overflow-y:auto;}
  .mail-list::-webkit-scrollbar{width:6px;}
  .mail-list::-webkit-scrollbar-thumb{background:rgba(255,255,255,0.15);border-radius:3px;}
  .mail-item{padding:16px 22px;border-bottom:1px solid rgba(255,255,255,0.05);cursor:pointer;transition:background 0.15s;}
  .mail-item:hover{background:rgba(255,255,255,0.04);}
  .mail-item.active{background:rgba(124,92,255,0.12);border-left:3px solid var(--accent);}
  .mail-item.unread{background:rgba(124,92,255,0.05);}
  .mail-from{font-size:13px;font-weight:600;margin-bottom:4px;color:var(--txt);}
  .mail-subj{font-size:13px;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
  .mail-time{font-size:11px;color:var(--muted);margin-top:6px;}

  .empty{padding:60px 22px;text-align:center;color:var(--muted);}
  .empty svg{width:48px;height:48px;opacity:0.4;margin-bottom:14px;}
  .empty-title{font-size:15px;font-weight:600;margin-bottom:6px;color:var(--txt);}
  .empty-sub{font-size:13px;}
  .spinner{
    width:32px;height:32px;border:3px solid rgba(255,255,255,0.1);
    border-top-color:var(--accent);border-radius:50%;
    margin:0 auto 14px;animation:spin 0.8s linear infinite;
  }
  @keyframes spin{to{transform:rotate(360deg);}}

  .reader{padding:24px 28px;min-height:400px;}
  .reader-empty{display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:400px;color:var(--muted);}
  .reader-empty svg{width:56px;height:56px;opacity:0.3;margin-bottom:14px;}
  .reader-subj{font-size:20px;font-weight:700;margin-bottom:8px;letter-spacing:-0.01em;}
  .reader-meta{font-size:13px;color:var(--muted);margin-bottom:20px;padding-bottom:16px;border-bottom:1px solid var(--border);}
  .reader-body{
    font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Inter,system-ui,sans-serif;
    font-size:14px; line-height:1.6; white-space:pre-wrap; word-break:break-word;
    background:rgba(0,0,0,0.25); padding:18px; border-radius:12px;
    border:1px solid var(--border); max-height:420px; overflow-y:auto;
  }
  .reader-body::-webkit-scrollbar{width:6px;}
  .reader-body::-webkit-scrollbar-thumb{background:rgba(255,255,255,0.15);border-radius:3px;}

  .toasts{position:fixed;bottom:24px;right:24px;z-index:50;display:flex;flex-direction:column;gap:10px;}
  .toast{
    background:rgba(20,20,40,0.95); backdrop-filter:blur(12px);
    border:1px solid var(--border); border-radius:12px;
    padding:14px 18px; min-width:240px; max-width:340px;
    display:flex; align-items:center; gap:10px;
    box-shadow:0 12px 40px rgba(0,0,0,0.5);
    animation:slideIn 0.3s cubic-bezier(.2,.8,.2,1);
    font-size:13px;
  }
  .toast.ok{border-left:3px solid var(--ok);}
  .toast.err{border-left:3px solid var(--err);}
  .toast.info{border-left:3px solid var(--accent2);}
  @keyframes slideIn{from{opacity:0;transform:translateX(40px);}to{opacity:1;transform:translateX(0);}}

  .footer-note{text-align:center;color:var(--muted);font-size:11px;margin-top:24px;}

  /* Info Modal */
  .modal-overlay{
    position:fixed; top:0; left:0; width:100%; height:100%;
    background:rgba(0,0,0,0.7); backdrop-filter:blur(8px); -webkit-backdrop-filter:blur(8px);
    display:none; align-items:center; justify-content:center; z-index:100; padding:20px;
  }
  .modal-overlay.active{display:flex;}
  .modal-card{
    background:var(--bg2); border:1px solid var(--border);
    border-radius:20px; padding:32px; max-width:380px; width:100%; text-align:center;
    animation:rise 0.4s cubic-bezier(.2,.8,.2,1);
  }
  .modal-card .logo-mark{margin:0 auto 16px;}
  .modal-card h3{font-size:20px; margin-bottom:16px; color:var(--accent2); font-weight:700;}
  .modal-card p{font-size:14px; color:var(--muted); margin-bottom:12px; line-height:1.5;}
  .modal-card strong{color:var(--txt);}

  /* ============ MOBILE OPTIMIZATIONS ============ */
  body.mobile {
    padding: 12px;
    align-items: flex-start;
  }
  body.mobile .login {
    margin-top: 20px;
    padding: 32px 24px;
  }
  body.mobile .app {
    max-width: 100%;
  }
  body.mobile .topbar {
    margin-bottom: 16px;
    flex-wrap: nowrap;
  }
  body.mobile .brand h2 {
    font-size: 16px;
  }
  body.mobile .top-actions {
    flex-shrink: 0;
  }
  body.mobile .pill-btn {
    padding: 8px 12px;
    font-size: 12px;
  }
  body.mobile .address-card {
    padding: 18px;
    flex-direction: column;
    align-items: stretch;
  }
  body.mobile .addr-value {
    font-size: 18px;
  }
  body.mobile .grid {
    gap: 16px;
  }
  body.mobile .mail-list {
    max-height: 35vh;
  }
  body.mobile .panel-head {
    padding: 14px 16px;
  }
  body.mobile .mail-item {
    padding: 14px 16px;
  }
  body.mobile .reader {
    padding: 18px;
    min-height: 300px;
  }
  body.mobile .reader-subj {
    font-size: 18px;
  }
  body.mobile .reader-body {
    padding: 14px;
    font-size: 12px;
  }
  body.mobile .toasts {
    bottom: 16px;
    right: 12px;
    left: 12px;
  }
  body.mobile .toast {
    min-width: auto;
    max-width: 100%;
  }
</style>
</head>
<body class="{{BODY_CLASS}}">
  <div class="blob b1"></div>
  <div class="blob b2"></div>
  <div class="blob b3"></div>

  <!-- INFO MODAL -->
  <div class="modal-overlay" id="infoModal">
    <div class="modal-card">
      <div class="logo-mark">
        <svg viewBox="0 0 24 24"><path d="M4 4h16a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2zm0 4l8 5 8-5"/></svg>
      </div>
      <h3>TempMail v1.4</h3>
      <p>This service is currently in development. We prioritize your privacy and will never access your information.</p>
      <p style="margin-bottom:24px;"><strong>Disclaimer:</strong> We strictly prohibit the use of our services for any illegal activities.</p>
      <button class="btn" id="modalCloseBtn">Understood</button>
    </div>
  </div>

  <div class="login" id="loginView">
    <div class="logo">
      <div class="logo-mark">
        <svg viewBox="0 0 24 24"><path d="M4 4h16a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2zm0 4l8 5 8-5"/></svg>
      </div>
      <h1>Temp<span>Mail</span></h1>
    </div>
    <div class="subtitle">Disposable inboxes · @madebymason.eu.cc · auto‑wiped every 15 mins</div>

    <form id="loginForm">
      <label for="key">Access key</label>
      <input class="input" id="key" type="password" placeholder="Enter your access key" autocomplete="off" autofocus>
      <button class="btn" type="submit">Enter inbox →</button>
      <div class="err" id="loginErr"></div>
    </form>
  </div>

  <div class="app" id="appView">
    <div class="topbar">
      <div class="brand">
        <div class="logo-mark"><svg viewBox="0 0 24 24"><path d="M4 4h16a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2zm0 4l8 5 8-5"/></svg></div>
        <h2>Temp<span>Mail</span></h2>
      </div>
      <div class="top-actions">
        <button class="pill-btn" id="infoBtn">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z"/></svg>
          Info
        </button>
        <button class="pill-btn danger" id="logoutBtn">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M16 17l5-5-5-5v3H9v4h7zM4 5h8V3H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h8v-2H4V5z"/></svg>
          Lock
        </button>
      </div>
    </div>

    <div class="address-card">
      <div>
        <div class="addr-label">Your temporary address</div>
        <div class="addr-value" id="addrValue">loading@madebymason.eu.cc</div>
        <div class="countdown"><span class="countdown-dot"></span><span id="countdown">Auto-wipes every 15 minutes</span></div>
      </div>
      <div style="display:flex;gap:10px;flex-wrap:wrap;">
        <button class="copy-btn" id="copyBtn">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M16 1H4a2 2 0 0 0-2 2v14h2V3h12V1zm3 4H8a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h11a2 2 0 0 0 2-2V7a2 2 0 0 0-2-2zm0 16H8V7h11v14z"/></svg>
          Copy
        </button>
        <button class="copy-btn" id="syncBtn" style="background:rgba(25, 211, 255, 0.15);">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2V1L8 5l4 4V7c3.31 0 6 2.69 6 6 0 1.01-.25 1.97-.7 2.8l1.46 1.46C19.54 15.97 20 14.54 20 13c0-4.42-3.58-8-8-8zm0 14c-3.31 0-6-2.69-6-6 0-1.01.25-1.97.7-2.8L5.24 5.74C4.46 7.03 4 8.46 4 10c0 4.42 3.58 8 8 8v1l4-4-4-4v3z"/></svg>
          Sync
        </button>
        <button class="copy-btn" id="resetBtn" style="background:rgba(255,92,124,0.15);">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M17.65 6.35A8 8 0 1 0 19.73 14h-2.08A6 6 0 1 1 12 6c1.66 0 3.14.69 4.22 1.78L13 11h7V4l-2.35 2.35z"/></svg>
          Reset
        </button>
      </div>
    </div>

    <div class="grid">
      <div class="panel">
        <div class="panel-head">
          <h3>Inbox</h3>
          <span class="count" id="mailCount">0</span>
        </div>
        <div class="mail-list" id="mailList">
          <div class="empty">
            <div class="spinner"></div>
            <div class="empty-title">Waiting for mail…</div>
            <div class="empty-sub">Send something to your address above.</div>
          </div>
        </div>
      </div>

      <div class="panel">
        <div class="panel-head">
          <h3>Message</h3>
        </div>
        <div class="reader" id="reader">
          <div class="reader-empty">
            <svg viewBox="0 0 24 24" fill="currentColor"><path d="M4 4h16a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2zm0 4l8 5 8-5"/></svg>
            <div>Select a message to read it</div>
          </div>
        </div>
      </div>
    </div>

    <div class="footer-note">Mail auto‑deletes every 15 minutes · one‑shot read · secured by access key</div>
  </div>

  <div class="toasts" id="toasts"></div>

<script>
  function byId(id) { return document.getElementById(id); }
  
  const toast = function(msg, type) {
    type = type || 'info';
    var t = document.createElement('div');
    t.className = 'toast ' + type;
    t.textContent = msg;
    byId('toasts').appendChild(t);
    setTimeout(function(){ 
      t.style.opacity='0'; 
      t.style.transform='translateX(40px)'; 
      t.style.transition='all 0.3s'; 
      setTimeout(function(){ t.remove(); }, 300); 
    }, 3200);
  };

  function playChime() {
    try {
      var AC = window.AudioContext || window.webkitAudioContext;
      var ctx = new AC();
      var osc = ctx.createOscillator();
      var gain = ctx.createGain();
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.type = 'sine';
      osc.frequency.setValueAtTime(880, ctx.currentTime); 
      osc.frequency.setValueAtTime(1320, ctx.currentTime + 0.1);
      gain.gain.setValueAtTime(0.1, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.2);
      osc.start();
      osc.stop(ctx.currentTime + 0.2);
    } catch(e) {}
  }

  if (!localStorage.getItem('tm_seen_info_v1_4')) {
    byId('infoModal').classList.add('active');
  }
  byId('modalCloseBtn').addEventListener('click', function() {
    localStorage.setItem('tm_seen_info_v1_4', '1');
    byId('infoModal').classList.remove('active');
  });
  byId('infoBtn').addEventListener('click', function() {
    byId('infoModal').classList.add('active');
  });

  byId('loginForm').addEventListener('submit', async function(e){
    e.preventDefault();
    var keyVal = byId('key').value;
    byId('loginErr').textContent = '';
    try {
      var r = await fetch('/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key: keyVal })
      });
      if(r.ok){
        byId('loginView').style.display='none';
        byId('appView').classList.add('active');
        initApp();
      } else {
        var d = await r.json().catch(function(){ return {error:'Invalid key'}; });
        byId('loginErr').textContent = d.error;
      }
    } catch(err) {
      byId('loginErr').textContent = 'Network error';
    }
  });

  var pollTimer = null;
  var currentAddress = '';
  var lastMailCount = 0;

  async function fetchInbox() {
    try {
      var r = await fetch('/api/inbox');
      if(!r.ok) {
        if(r.status === 401) {
          clearInterval(pollTimer);
          toast('Session expired. Reloading...', 'err');
          setTimeout(function(){ location.reload(); }, 1500);
        } else if (r.status === 400) {
          // Address lost. Re-assign immediately.
          var a = await fetch('/api/assign', {method:'POST'});
          var ad = await a.json();
          currentAddress = ad.address;
          byId('addrValue').textContent = currentAddress;
          renderInbox([]);
          toast('Session lost. New address assigned.', 'info');
        } else if (r.status === 500) {
          var err = await r.json().catch(function(){ return {error:'Server error'}; });
          toast('Inbox error: ' + err.error, 'err');
        }
        return;
      }
      var d = await r.json();
      
      if(!d.address) {
        var a = await fetch('/api/assign', {method:'POST'});
        var ad = await a.json();
        currentAddress = ad.address;
        byId('addrValue').textContent = currentAddress;
        renderInbox([]);
      } else {
        currentAddress = d.address;
        byId('addrValue').textContent = currentAddress;
        renderInbox(d.inbox||[]);
      }
    } catch(e) {
      // Silent network error
    }
  }

  async function initApp(){
    await fetchInbox();
    startPolling();
  }

  function startPolling(){
    if(pollTimer) clearInterval(pollTimer);
    pollTimer = setInterval(fetchInbox, 4000);
  }

  // Instantly sync the moment the user switches back to the tab
  document.addEventListener('visibilitychange', function() {
    if (document.visibilityState === 'visible') {
      fetchInbox();
    }
  });

  function renderInbox(list){
    var el = byId('mailList');
    byId('mailCount').textContent = list.length;
    
    if(list.length > lastMailCount && lastMailCount !== 0) {
      playChime();
      toast('New mail received!', 'ok');
    }
    lastMailCount = list.length;
    
    var titleBase = 'TempMail · @madebymason.eu.cc';
    document.title = list.length > 0 ? '(' + list.length + ') ' + titleBase : titleBase;

    if(list.length===0){
      el.innerHTML = '<div class="empty">'+
        '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M4 4h16a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2zm0 4l8 5 8-5"/></svg>'+
        '<div class="empty-title">No messages yet</div>'+
        '<div class="empty-sub">Send something to your address above.</div></div>';
      return;
    }
    
    var html = '';
    for(var i=0; i<list.length; i++){
      var m = list[i];
      var ago = timeAgo(m.receivedAt);
      html += '<div class="mail-item unread" data-id="'+m.id+'">'+
        '<div class="mail-from">'+escapeHtml(m.from)+'</div>'+
        '<div class="mail-subj">'+escapeHtml(m.subject)+'</div>'+
        '<div class="mail-time">'+ago+'</div></div>';
    }
    el.innerHTML = html;
    
    var items = el.querySelectorAll('.mail-item');
    for(var j=0; j<items.length; j++){
      (function(it){
        it.addEventListener('click', function(){ openMail(it.dataset.id, it); });
      })(items[j]);
    }
  }

  function timeAgo(ts){
    var s = Math.floor((Date.now()-ts)/1000);
    if(s<60) return s+'s ago';
    if(s<3600) return Math.floor(s/60)+'m ago';
    return Math.floor(s/3600)+'h ago';
  }
  
  function escapeHtml(s){
    return String(s||'').replace(/[&<>"']/g,function(m){
      return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m];
    });
  }

  async function openMail(id, el){
    var allItems = document.querySelectorAll('.mail-item');
    for(var i=0; i<allItems.length; i++){
      allItems[i].classList.remove('active');
    }
    el.classList.remove('unread');
    el.classList.add('active');
    
    var r = await fetch('/api/email/'+id);
    if(!r.ok){ toast('Could not load message','err'); return; }
    var d = await r.json();
    var mail = d.email;
    byId('reader').innerHTML = 
      '<div class="reader-subj">'+escapeHtml(mail.subject)+'</div>'+
      '<div class="reader-meta">From <b>'+escapeHtml(mail.from)+'</b> · '+new Date(mail.receivedAt).toLocaleString()+'</div>'+
      '<div class="reader-body">'+escapeHtml(mail.body)+'</div>';
    toast('Message opened — it has been deleted from storage', 'info');
    
    setTimeout(async function(){
      var rr = await fetch('/api/inbox');
      if(rr.ok){ 
        var dd = await rr.json(); 
        renderInbox(dd.inbox||[]); 
      }
    }, 800);
  }

  async function resetAddress(){
    var r = await fetch('/api/reset', {method:'POST'});
    if(!r.ok){ toast('Reset failed','err'); return; }
    var d = await r.json();
    currentAddress = d.address;
    byId('addrValue').textContent = currentAddress;
    byId('reader').innerHTML = '<div class="reader-empty"><svg viewBox="0 0 24 24" fill="currentColor"><path d="M4 4h16a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2zm0 4l8 5 8-5"/></svg><div>Select a message to read it</div></div>';
    lastMailCount = 0;
    renderInbox([]);
    toast('Old address wiped. New address assigned', 'ok');
  }

  byId('resetBtn').addEventListener('click', resetAddress);
  byId('syncBtn').addEventListener('click', fetchInbox);

  byId('copyBtn').addEventListener('click', async function(e){
    try {
      await navigator.clipboard.writeText(currentAddress);
    } catch(_) {
      var ta = document.createElement('textarea'); 
      ta.value = currentAddress; 
      document.body.appendChild(ta); 
      ta.select(); 
      document.execCommand('copy'); 
      ta.remove();
    }
    var btn = e.currentTarget;
    btn.classList.add('copied');
    btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41L9 16.17z"/></svg> Copied';
    setTimeout(function(){
      btn.classList.remove('copied');
      btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M16 1H4a2 2 0 0 0-2 2v14h2V3h12V1zm3 4H8a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h11a2 2 0 0 0 2-2V7a2 2 0 0 0-2-2zm0 16H8V7h11v14z"/></svg> Copy';
    }, 1600);
  });

  byId('logoutBtn').addEventListener('click', async function(){
    await fetch('/logout', {method:'POST'});
    location.reload();
  });

  (async function(){
    var r = await fetch('/api/inbox');
    if(r.ok){
      byId('loginView').style.display='none';
      byId('appView').classList.add('active');
      var d = await r.json();
      if(!d.address){
        var a = await fetch('/api/assign',{method:'POST'});
        var ad = await a.json();
        currentAddress = ad.address;
      } else {
        currentAddress = d.address;
      }
      byId('addrValue').textContent = currentAddress;
      renderInbox(d.inbox||[]);
      startPolling();
    }
  })();
</script>
</body>
</html>`;

// ---------- router ----------
export default {
  async fetch(req, env, ctx){
    const url = new URL(req.url);

    if(url.pathname === "/health") return new Response("ok");

    if(url.pathname.startsWith("/api/") || url.pathname === "/login" || url.pathname === "/logout"){
      return handleApi(req, env, ctx);
    }

    // Detect if user is on a mobile device (iPhone, Android, iPad, etc.)
    const ua = req.headers.get('User-Agent') || '';
    const isMobile = /Mobile|Android|iPhone|iPad|iPod|Windows Phone/i.test(ua);
    
    // Inject the body class based on device
    const finalHtml = HTML.replace('{{BODY_CLASS}}', isMobile ? 'mobile' : 'desktop');

    // Fix #6: Added X-Frame-Options and Content-Security-Policy to prevent clickjacking
    return new Response(finalHtml, {
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-store",
        "Referrer-Policy": "no-referrer",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Content-Security-Policy": "frame-ancestors 'none';"
      }
    });
  },
  async email(message, env, ctx){
    try{
      await emailHandler(message, env, ctx);
    }catch(e){
      // swallow so Email Routing doesn't bounce
    }
  }
};
