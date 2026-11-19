const { createHash, createHmac, timingSafeEqual } = require('node:crypto');

const equal = (a, b) => {
  const digest = value => createHash('sha256').update(value).digest();
  return timingSafeEqual(digest(a), digest(b));
};

module.exports = async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  const send = (status, value) => res.status(status).json(value);
  if (req.method !== 'POST') return send(405, {error:'請從薪資頁操作'});
  if (!String(req.headers['content-type']).startsWith('application/json'))
    return send(415, {error:'格式錯誤'});
  const { PAYROLL_PASSWORD, PAYROLL_API_URL, PAYROLL_API_SECRET } = process.env;
  if (!PAYROLL_PASSWORD || !PAYROLL_API_URL || !PAYROLL_API_SECRET)
    return send(503, {error:'薪資網站的試算表連線尚未設定'});
  const body = req.body;
  if (!body || typeof body !== 'object') return send(400, {error:'格式錯誤'});
  const cookie = value => 'payroll_session='+value+'; Path=/api/payroll; HttpOnly; Secure; SameSite=Strict';
  const sign = expiry => createHmac('sha256', PAYROLL_API_SECRET)
    .update('payroll:'+PAYROLL_PASSWORD+':'+expiry).digest('hex');
  if (body.action === 'login') {
    if (typeof body.password !== 'string' || !equal(body.password,PAYROLL_PASSWORD))
      return send(401, {error:'密碼不正確'});
    const expiry = Date.now()+7*86400000;
    res.setHeader('Set-Cookie',cookie(expiry+'.'+sign(expiry))+'; Max-Age=604800');
    return send(200,{ok:true});
  }
  if (body.action === 'logout') {
    res.setHeader('Set-Cookie',cookie('')+'; Max-Age=0');
    return send(200,{ok:true});
  }
  const token = /(?:^|;\s*)payroll_session=(\d+)\.([\da-f]{64})(?:;|$)/.exec(req.headers.cookie || '');
  if (!token || Number(token[1]) <= Date.now() || !equal(token[2],sign(token[1])))
    return send(401,{error:'請輸入薪資頁密碼'});
  if (!['loadMonth','saveRecord'].includes(body.action) || !Array.isArray(body.args))
    return send(400,{error:'操作錯誤'});
  try {
    const url = new URL(PAYROLL_API_URL);
    if (url.origin !== 'https://script.google.com' || !/^\/macros\/s\/[\w-]+\/exec$/.test(url.pathname))
      throw new Error('Invalid backend URL');
    const response = await fetch(url,{
      method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({...body,secret:PAYROLL_API_SECRET}),
      signal:AbortSignal.timeout(20000)
    });
    if (!response.ok) throw new Error('Backend unavailable');
    const result = await response.json();
    if (!result.ok) return send(400,{error:result.error || '資料處理失敗'});
    return send(200,result.data);
  } catch {
    return send(502,{error:'試算表連線失敗，請稍後再試'});
  }
};
