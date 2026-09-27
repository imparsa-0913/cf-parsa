import { DEFAULTS } from './config.js';
import { generateUuid, getHost, parseSizeToBytes, parseSpeedToBytes, fmtBytes } from './helpers.js';

export function isLinkExpired(link) {
  if (!link.expires_at) return false;
  return Date.now() > new Date(link.expires_at).getTime();
}

export function isLinkAllowed(link) {
  if (!link) return false;
  if (!link.active) return false;
  if (isLinkExpired(link)) return false;
  if (link.limit_bytes > 0 && (link.used_bytes || 0) >= link.limit_bytes) return false;
  return true;
}

export function makeShareLink(uid, link, host) {
  const fp = link.fingerprint || DEFAULTS.DEFAULT_FINGERPRINT;
  const alpn = link.alpn || DEFAULTS.DEFAULT_ALPN[link.protocol || 'ws'] || 'http/1.1';
  const port = link.port || DEFAULTS.DEFAULT_PORT;
  const proto = link.protocol || 'ws';
  const remark = encodeURIComponent(link.label || '');
  let path, params;
  if (proto === 'ws') {
    path = '/ws/' + uid;
    params = { encryption: 'none', security: 'tls', type: 'ws', host, path, sni: host, fp, alpn };
  } else {
    path = '/xhttp-siz10/' + uid;
    params = { encryption: 'none', security: 'tls', type: 'xhttp', mode: 'auto', host, path, sni: host, fp, alpn };
  }
  const q = Object.entries(params).map(([k, v]) => k + '=' + encodeURIComponent(v)).join('&');
  return 'vless://' + uid + '@' + host + ':' + port + '?' + q + '#' + remark;
}

export async function kvGetProfile(env, uid) {
  return await env.CNM_KV.get('p:' + uid, 'json');
}

export async function kvPutProfile(env, uid, link) {
  await env.CNM_KV.put('p:' + uid, JSON.stringify(link));
}

export async function kvListProfiles(env) {
  const out = {};
  let cursor = undefined;
  while (true) {
    const list = await env.CNM_KV.list({ prefix: 'p:', cursor });
    for (const k of list.keys) {
      const uid = k.name.slice(2);
      const link = await env.CNM_KV.get(k.name, 'json');
      if (link) out[uid] = link;
    }
    if (list.list_complete) break;
    cursor = list.cursor;
  }
  return out;
}

async function logActivity(env, kind, message, level) {
  const stub = env.STATE_DO.get(env.STATE_DO.idFromName('global'));
  await stub.fetch('https://do/log-activity', {
    method: 'POST',
    body: JSON.stringify({ kind, message, level: level || 'info' }),
  });
}

export async function createProfile(req, env) {
  const body = await req.json();
  const lv = parseFloat(body.limit_value || 0);
  const lu = body.limit_unit || 'GB';
  const limit_bytes = lv <= 0 ? 0 : parseSizeToBytes(lv, lu);
  const exp_days = parseInt(body.expires_days || 0);
  const expires_at = exp_days > 0 ? new Date(Date.now() + exp_days * 86400000).toISOString() : null;
  const sv = parseFloat(body.speed_limit_value || 0);
  const su = body.speed_limit_unit || 'MBIT';
  const speed_limit_bytes = sv <= 0 ? 0 : parseSpeedToBytes(sv, su);

  const uid = generateUuid();
  let fp = String(body.fingerprint || DEFAULTS.DEFAULT_FINGERPRINT).toLowerCase();
  if (DEFAULTS.FINGERPRINTS.indexOf(fp) === -1) fp = DEFAULTS.DEFAULT_FINGERPRINT;

  const link = {
    label: (body.label || 'پروفایل جدید').slice(0, 60),
    limit_bytes: Math.max(0, limit_bytes),
    used_bytes: 0,
    created_at: new Date().toISOString(),
    active: true,
    expires_at,
    note: (body.note || '').slice(0, 200),
    is_default: false,
    protocol: DEFAULTS.PROTOCOLS.indexOf(body.protocol) !== -1 ? body.protocol : DEFAULTS.DEFAULT_PROTOCOL,
    fingerprint: fp,
    alpn: (body.alpn || '').slice(0, 100),
    port: parseInt(body.port || DEFAULTS.DEFAULT_PORT),
    ip_limit: Math.max(0, parseInt(body.ip_limit || 0)),
    speed_limit_bytes: Math.max(0, speed_limit_bytes),
  };
  if (link.port < DEFAULTS.MIN_PORT || link.port > DEFAULTS.MAX_PORT) link.port = DEFAULTS.DEFAULT_PORT;

  await kvPutProfile(env, uid, link);
  await logActivity(env, 'profile', 'profile created: ' + link.label, 'ok');

  const host = getHost(req);
  return Response.json({
    uuid: uid,
    ...link,
    expired: false,
    share_link: makeShareLink(uid, link, host),
    sub_url: 'https://' + host + '/p/' + uid,
    raw_sub_url: 'https://' + host + '/sub/' + uid,
  });
}

export async function listProfiles(req, env) {
  const host = getHost(req);
  const all = await kvListProfiles(env);
  const stateStub = env.STATE_DO.get(env.STATE_DO.idFromName('global'));
  const result = [];
  for (const uid of Object.keys(all)) {
    const d = all[uid];
    const ipsResp = await stateStub.fetch('https://do/ips-for-uuid?uuid=' + uid);
    const ipsData = await ipsResp.json();
    result.push({
      uuid: uid,
      ...d,
      protocol: d.protocol || DEFAULTS.DEFAULT_PROTOCOL,
      expired: isLinkExpired(d),
      share_link: makeShareLink(uid, d, host),
      sub_url: 'https://' + host + '/p/' + uid,
      raw_sub_url: 'https://' + host + '/sub/' + uid,
      connected_ips: (ipsData.ips || []).length,
    });
  }
  result.sort((a, b) => (b.created_at || '').localeCompare(a.created_at || ''));
  return Response.json({ items: result });
}

export async function updateProfile(uid, req, env) {
  const body = await req.json();
  const link = await kvGetProfile(env, uid);
  if (!link) return Response.json({ detail: 'not found' }, { status: 404 });

  if ('active' in body) link.active = !!body.active;
  if ('label' in body) link.label = String(body.label).slice(0, 60);
  if ('note' in body) link.note = String(body.note).slice(0, 200);
  if (body.reset_usage) link.used_bytes = 0;
  if ('limit_value' in body) {
    const lv = parseFloat(body.limit_value || 0);
    const lu = body.limit_unit || 'GB';
    link.limit_bytes = lv <= 0 ? 0 : parseSizeToBytes(lv, lu);
  }
  if ('expires_days' in body) {
    const ed = parseInt(body.expires_days || 0);
    link.expires_at = ed > 0 ? new Date(Date.now() + ed * 86400000).toISOString() : null;
  }
  if ('fingerprint' in body) {
    const fp = String(body.fingerprint || '').toLowerCase();
    link.fingerprint = DEFAULTS.FINGERPRINTS.indexOf(fp) !== -1 ? fp : DEFAULTS.DEFAULT_FINGERPRINT;
  }
  if ('alpn' in body) link.alpn = String(body.alpn || '').slice(0, 100);
  if ('port' in body) {
    const p = parseInt(body.port || DEFAULTS.DEFAULT_PORT);
    link.port = (p >= DEFAULTS.MIN_PORT && p <= DEFAULTS.MAX_PORT) ? p : DEFAULTS.DEFAULT_PORT;
  }
  if ('ip_limit' in body) link.ip_limit = Math.max(0, parseInt(body.ip_limit || 0));
  if ('speed_limit_value' in body) {
    const sv = parseFloat(body.speed_limit_value || 0);
    const su = body.speed_limit_unit || 'MBIT';
    link.speed_limit_bytes = sv <= 0 ? 0 : parseSpeedToBytes(sv, su);
  }
  await kvPutProfile(env, uid, link);
  await logActivity(env, 'profile', 'profile updated: ' + link.label, 'info');
  return Response.json({ ok: true });
}

export async function deleteProfile(uid, req, env) {
  const link = await kvGetProfile(env, uid);
  if (!link) return Response.json({ detail: 'not found' }, { status: 404 });
  await env.CNM_KV.delete('p:' + uid);
  await logActivity(env, 'profile', 'profile deleted: ' + link.label, 'err');
  return Response.json({ ok: true, deleted: uid });
}

export async function publicSubData(uid, req, env) {
  const link = await kvGetProfile(env, uid);
  if (!link) return Response.json({ detail: 'not found' }, { status: 404 });
  const host = getHost(req);
  const allowed = isLinkAllowed(link);
  const stateStub = env.STATE_DO.get(env.STATE_DO.idFromName('global'));
  const r = await stateStub.fetch('https://do/ips-for-uuid?uuid=' + uid);
  const ipsData = await r.json();
  const connCount = (ipsData.ips || []).length;

  const itemOut = {
    uuid: uid,
    label: link.label,
    active: allowed,
    protocol: link.protocol || DEFAULTS.DEFAULT_PROTOCOL,
    used_bytes: link.used_bytes || 0,
    used_fmt: fmtBytes(link.used_bytes || 0),
    limit_bytes: link.limit_bytes || 0,
    limit_fmt: !link.limit_bytes ? '∞' : fmtBytes(link.limit_bytes),
    expires_at: link.expires_at,
    share_link: makeShareLink(uid, link, host),
    sub_url: 'https://' + host + '/sub/' + uid,
    connections: connCount,
    ip_limit: link.ip_limit || 0,
    speed_limit_bytes: link.speed_limit_bytes || 0,
  };
  return Response.json({
    locked: false,
    name: link.label,
    desc: link.note || '',
    sub_url: 'https://' + host + '/p/' + uid,
    active_connections: connCount,
    total_used_fmt: fmtBytes(link.used_bytes || 0),
    items: [itemOut],
  });
}

export async function getStats(env) {
  const stateStub = env.STATE_DO.get(env.STATE_DO.idFromName('global'));
  const r = await stateStub.fetch('https://do/stats');
  const s = await r.json();
  const all = await kvListProfiles(env);
  const arr = Object.values(all);
  return Response.json({
    active_connections: s.active_connections,
    total_traffic_mb: Math.round(s.total_traffic_mb * 100) / 100,
    total_requests: s.total_requests,
    total_errors: s.total_errors,
    uptime: s.uptime,
    timestamp: new Date().toISOString(),
    hourly: s.hourly,
    recent_errors: s.recent_errors,
    items_count: arr.length,
    active_items: arr.filter(isLinkAllowed).length,
    expired_items: arr.filter(isLinkExpired).length,
  });
}
