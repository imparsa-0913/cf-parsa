import { clientIp } from './helpers.js';
import { kvGetProfile, isLinkAllowed } from './profiles.js';

async function xhttpSessionStub(uid, sessionId, env) {
  return env.SESSION_DO.get(env.SESSION_DO.idFromName(uid + ':' + sessionId));
}

export async function handleXhttpDownlink(uid, sessionId, req, env, ctx) {
  const link = await kvGetProfile(env, uid);
  if (!link || !isLinkAllowed(link)) return new Response('not authorized', { status: 403 });
  const ip = clientIp(req);
  const stub = await xhttpSessionStub(uid, sessionId, env);
  await stub.fetch('https://do/init', {
    method: 'POST',
    body: JSON.stringify({ uuid: uid, session_id: sessionId, mode: 'auto', ip }),
  });
  const upstream = await stub.fetch('https://do/downlink', {
    method: 'POST',
    body: JSON.stringify({}),
  });
  return new Response(upstream.body, {
    headers: {
      'content-type': 'application/octet-stream',
      'cache-control': 'no-store',
      'x-accel-buffering': 'no',
    },
  });
}

export async function handleXhttpStreamUp(uid, sessionId, req, env, ctx) {
  const link = await kvGetProfile(env, uid);
  if (!link || !isLinkAllowed(link)) return new Response('not authorized', { status: 403 });
  const ip = clientIp(req);
  const stub = await xhttpSessionStub(uid, sessionId, env);
  await stub.fetch('https://do/init', {
    method: 'POST',
    body: JSON.stringify({ uuid: uid, session_id: sessionId, mode: 'stream-up', ip }),
  });

  const reader = req.body.getReader();
  const chunks = [];
  while (true) {
    const r = await reader.read();
    if (r.done) break;
    const value = r.value;
    if (value && value.length) {
      let binary = '';
      for (let i = 0; i < value.length; i++) binary += String.fromCharCode(value[i]);
      chunks.push(btoa(binary));
    }
  }
  const resp = await stub.fetch('https://do/stream-up', {
    method: 'POST',
    body: JSON.stringify({ chunks }),
  });
  return new Response(resp.body, {
    status: resp.status,
    headers: { 'content-type': 'application/json' },
  });
}

export async function handleXhttpPacketUp(uid, sessionId, seq, req, env, ctx) {
  const link = await kvGetProfile(env, uid);
  if (!link || !isLinkAllowed(link)) return new Response('not authorized', { status: 403 });
  const ip = clientIp(req);
  const stub = await xhttpSessionStub(uid, sessionId, env);
  await stub.fetch('https://do/init', {
    method: 'POST',
    body: JSON.stringify({ uuid: uid, session_id: sessionId, mode: 'packet-up', ip }),
  });
  const buf = new Uint8Array(await req.arrayBuffer());
  let binary = '';
  for (let i = 0; i < buf.length; i++) binary += String.fromCharCode(buf[i]);
  const resp = await stub.fetch('https://do/packet-up', {
    method: 'POST',
    body: JSON.stringify({ seq, data: btoa(binary) }),
  });
  return new Response(resp.body, {
    status: resp.status,
    headers: { 'content-type': 'application/json' },
  });
}
