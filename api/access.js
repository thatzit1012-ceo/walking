const crypto = require('crypto');
const json = (res, status, body) => { res.statusCode=status; res.setHeader('Content-Type','application/json; charset=utf-8'); res.setHeader('Cache-Control','no-store'); res.end(JSON.stringify(body)); };
const safeEqual = (left,right) => { const a=Buffer.from(String(left)); const b=Buffer.from(String(right)); return a.length===b.length && crypto.timingSafeEqual(a,b); };
module.exports = async (req,res) => {
  if(req.method!=='POST'){res.setHeader('Allow','POST');return json(res,405,{message:'지원하지 않는 요청입니다.'});}
  const code=String(req.body?.code||'').trim();
  if(!/^\d{4,12}$/.test(code)) return json(res,401,{message:'접속 코드를 확인할 수 없습니다. 담당자에게 문의해 주세요.'});
  const pepper=process.env.ACCESS_CODE_PEPPER;
  let entries; try{entries=JSON.parse(process.env.HEALTH_CENTER_ACCESS||'[]');}catch(_){return json(res,503,{message:'접속 서비스 설정을 확인하고 있습니다. 담당자에게 문의해 주세요.'});}
  if(!pepper) return json(res,503,{message:'접속 서비스 설정을 확인하고 있습니다. 담당자에게 문의해 주세요.'});
  const submittedDigest=crypto.createHmac('sha256',pepper).update(code).digest('hex');
  const matched=Array.isArray(entries)?entries.find(entry=>entry&&safeEqual(entry.digest,submittedDigest)):null;
  if(!matched) return json(res,401,{message:'접속 코드를 확인할 수 없습니다. 담당자에게 문의해 주세요.'});
  const secret=process.env.ACCESS_SESSION_SECRET; const destination=matched.redirect||process.env.SWS_DESTINATION_URL;
  if(!secret||!destination||!/^https:\/\//.test(destination)) return json(res,503,{message:'접속 서비스 설정을 확인하고 있습니다. 담당자에게 문의해 주세요.'});
  const expires=Date.now()+30*60*1000; const payload=Buffer.from(JSON.stringify({center:matched.center,expires})).toString('base64url'); const signature=crypto.createHmac('sha256',secret).update(payload).digest('base64url');
  res.setHeader('Set-Cookie',`walk_access=${payload}.${signature}; Path=/; Max-Age=1800; HttpOnly; Secure; SameSite=Lax`); return json(res,200,{redirect:destination});
};
