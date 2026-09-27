import { DEFAULTS } from './config.js';
import { sha256Hex, clientIp } from './helpers.js';

async function getSecret(env) {
  if (env.SECRET_KEY) return env.SECRET_KEY;
  let s = await env.CNM_KV.get('secret');
  if (!s) {
    s = Array.from(crypto.getRandomValues(new Uint8Array(32)))
      .map(b => b.toString(16).padStart(2, '0')).join('');
    await env.CNM_KV.put('secret', s);
  }
  return s;
}

async function getPasswordHash(env) {
  const stored = await env.CNM_KV.get('password_hash');
  if (stored) return stored;
  const secret = await getSecret(env);
  const initial = env.ADMIN_PASSWORD || DEFAULTS.ADMIN_PASSWORD;
  const h = await sha256Hex(initial + secret);
  await env.CNM_KV.put('password_hash', h);
  return h;
}

async function hashPassword(env, pw) {
  const secret = await getSecret(env);
  return await sha256Hex(pw + secret);
}

export async function isAuthenticated(req, env) {
  const cookie = req.headers.get('cookie') || '';
  const m = cookie.match(new RegExp(DEFAULTS.SESSION_COOKIE + '=([^;]+)'));
  if (!m) return false;
  const sess = await env.CNM_KV.get('s:' + m[1], 'json');
  if (!sess) return false;
  if (sess.exp < Date.now()) {
    await env.CNM_KV.delete('s:' + m[1]);
    return false;
  }
  return true;
}

export async function requireAuth(req, env) {
  if (!await isAuthenticated(req, env)) {
    return Response.json({ detail: 'unauthorized' }, { status: 401 });
  }
  return null;
}

async function createSession(env) {
  const token = Array.from(crypto.getRandomValues(new Uint8Array(32)))
    .map(b => b.toString(16).padStart(2, '0')).join('');
  await env.CNM_KV.put('s:' + token, JSON.stringify({
    exp: Date.now() + DEFAULTS.SESSION_TTL * 1000,
  }), { expirationTtl: DEFAULTS.SESSION_TTL });
  return token;
}

async function destroySession(req, env) {
  const cookie = req.headers.get('cookie') || '';
  const m = cookie.match(new RegExp(DEFAULTS.SESSION_COOKIE + '=([^;]+)'));
  if (m) await env.CNM_KV.delete('s:' + m[1]);
}

async function logActivity(env, kind, message, level) {
  const stub = env.STATE_DO.get(env.STATE_DO.idFromName('global'));
  await stub.fetch('https://do/log-activity', {
    method: 'POST',
    body: JSON.stringify({ kind, message, level: level || 'info' }),
  });
}

export async function handleLogin(req, env) {
  const body = await req.json();
  const ip = clientIp(req);
  const expected = await getPasswordHash(env);
  const provided = await hashPassword(env, String(body.password || ''));
  if (provided !== expected) {
    await logActivity(env, 'auth', 'login failed from ' + ip, 'err');
    return Response.json({ detail: 'رمز عبور اشتباه است' }, { status: 401 });
  }
  const token = await createSession(env);
  await logActivity(env, 'auth', 'login success from ' + ip, 'ok');
  return new Response(JSON.stringify({ ok: true }), {
    headers: {
      'content-type': 'application/json',
      'set-cookie': DEFAULTS.SESSION_COOKIE + '=' + token + '; Path=/; HttpOnly; SameSite=Lax; Max-Age=' + DEFAULTS.SESSION_TTL,
    },
  });
}

export async function handleLogout(req, env) {
  await destroySession(req, env);
  return new Response(JSON.stringify({ ok: true }), {
    headers: {
      'content-type': 'application/json',
      'set-cookie': DEFAULTS.SESSION_COOKIE + '=; Path=/; HttpOnly; Max-Age=0',
    },
  });
}

export async function handleMe(req, env) {
  return Response.json({ authenticated: await isAuthenticated(req, env) });
}

export async function changePassword(req, env) {
  const body = await req.json();
  const expected = await getPasswordHash(env);
  const provided = await hashPassword(env, String(body.current_password || ''));
  if (provided !== expected) {
    return Response.json({ detail: 'رمز فعلی اشتباه است' }, { status: 400 });
  }
  const newPw = String(body.new_password || '');
  if (newPw.length < 4) {
    return Response.json({ detail: 'رمز جدید باید حداقل ۴ کاراکتر باشد' }, { status: 400 });
  }
  await env.CNM_KV.put('password_hash', await hashPassword(env, newPw));
  await logActivity(env, 'auth', 'password changed', 'ok');
  return Response.json({ ok: true });
}

export { logActivity };
