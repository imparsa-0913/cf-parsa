import { DEFAULTS } from './config.js';
import { getHost, clientIp } from './helpers.js';
import {
  handleLogin, handleLogout, handleMe, changePassword, requireAuth, isAuthenticated,
} from './auth.js';
import {
  createProfile, listProfiles, updateProfile, deleteProfile,
  publicSubData, getStats, kvGetProfile, kvListProfiles,
  makeShareLink, isLinkAllowed,
} from './profiles.js';
import { handleWebSocketTunnel } from './relay.js';
import { handleXhttpDownlink, handleXhttpStreamUp, handleXhttpPacketUp } from './h2.js';
import { LOGIN_HTML } from './html/login.js';
import { DASHBOARD_HTML } from './html/dashboard.js';
import { getPublicPageHTML } from './html/public.js';
import { StateDO } from './do/state.js';
import { SessionDO } from './do/session.js';

export { StateDO, SessionDO };

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,PATCH,OPTIONS',
          'Access-Control-Allow-Headers': '*',
        },
      });
    }

    if (path === '/' && request.method === 'GET') {
      return Response.json({ service: 'NodeManager', version: '1.0', status: 'active' });
    }
    if (path === '/health') {
      const state = env.STATE_DO.get(env.STATE_DO.idFromName('global'));
      return state.fetch('https://do/health');
    }

    // Auth
    if (path === '/api/login' && request.method === 'POST') return handleLogin(request, env);
    if (path === '/api/logout' && request.method === 'POST') return handleLogout(request, env);
    if (path === '/api/me') return handleMe(request, env);
    if (path === '/api/change-password' && request.method === 'POST') {
      const e = await requireAuth(request, env);
      if (e) return e;
      return changePassword(request, env);
    }

    // Pages
    if (path === '/login' && request.method === 'GET') {
      if (await isAuthenticated(request, env)) {
        return Response.redirect(new URL('/dashboard', url).toString(), 302);
      }
      return new Response(LOGIN_HTML, { headers: { 'content-type': 'text/html; charset=utf-8' } });
    }
    if (path === '/dashboard' && request.method === 'GET') {
      if (!(await isAuthenticated(request, env))) {
        return Response.redirect(new URL('/login', url).toString(), 302);
      }
      return new Response(DASHBOARD_HTML, { headers: { 'content-type': 'text/html; charset=utf-8' } });
    }

    // Items API
    if (path === '/api/items' && request.method === 'POST') {
      const e = await requireAuth(request, env); if (e) return e;
      return createProfile(request, env);
    }
    if (path === '/api/items' && request.method === 'GET') {
      const e = await requireAuth(request, env); if (e) return e;
      return listProfiles(request, env);
    }
    const itemM = path.match(/^\/api\/items\/([^/]+)$/);
    if (itemM) {
      const e = await requireAuth(request, env); if (e) return e;
      if (request.method === 'PATCH') return updateProfile(itemM[1], request, env);
      if (request.method === 'DELETE') return deleteProfile(itemM[1], request, env);
    }

    // Stats
    if (path === '/stats') {
      const e = await requireAuth(request, env); if (e) return e;
      return getStats(env);
    }
    if (path === '/api/connections') {
      const e = await requireAuth(request, env); if (e) return e;
      const state = env.STATE_DO.get(env.STATE_DO.idFromName('global'));
      return state.fetch('https://do/connections');
    }
    if (path === '/api/activity') {
      const e = await requireAuth(request, env); if (e) return e;
      const state = env.STATE_DO.get(env.STATE_DO.idFromName('global'));
      return state.fetch('https://do/activity');
    }

    // Sub
    const subM = path.match(/^\/sub\/([^/]+)$/);
    if (subM && request.method === 'GET') {
      const link = await kvGetProfile(env, subM[1]);
      if (!link || !isLinkAllowed(link)) return new Response('not found', { status: 404 });
      const host = getHost(request);
      const share = makeShareLink(subM[1], link, host);
      const b64 = btoa(unescape(encodeURIComponent(share)));
      return new Response(b64, {
        headers: {
          'content-type': 'text/plain',
          'profile-title': encodeURIComponent(link.label),
        },
      });
    }

    // Sub-all
    if (path === '/sub-all' && request.method === 'GET') {
      const e = await requireAuth(request, env); if (e) return e;
      const all = await kvListProfiles(env);
      const host = getHost(request);
      const lines = [];
      for (const uid of Object.keys(all)) {
        if (isLinkAllowed(all[uid])) lines.push(makeShareLink(uid, all[uid], host));
      }
      const b64 = btoa(unescape(encodeURIComponent(lines.join('\n'))));
      return new Response(b64, { headers: { 'content-type': 'text/plain' } });
    }

    // Public page
    const pM = path.match(/^\/p\/([^/]+)$/);
    if (pM && request.method === 'GET') {
      const exists = await kvGetProfile(env, pM[1]);
      if (!exists) {
        return new Response('<h2 style="font-family:sans-serif;padding:40px">یافت نشد</h2>', {
          status: 404,
          headers: { 'content-type': 'text/html; charset=utf-8' },
        });
      }
      return new Response(getPublicPageHTML(pM[1]), {
        headers: { 'content-type': 'text/html; charset=utf-8' },
      });
    }
    const pubApiM = path.match(/^\/api\/public\/sub\/([^/]+)$/);
    if (pubApiM && request.method === 'GET') return publicSubData(pubApiM[1], request, env);

    // WS
    const wsM = path.match(/^\/ws\/([^/]+)$/);
    if (wsM && (request.headers.get('Upgrade') || '').toLowerCase() === 'websocket') {
      return handleWebSocketTunnel(wsM[1], request, env, ctx);
    }

    // H2
    const xgM = path.match(/^\/xhttp-siz10\/([^/]+)\/([^/]+)$/);
    if (xgM && request.method === 'GET') return handleXhttpDownlink(xgM[1], xgM[2], request, env, ctx);
    if (xgM && request.method === 'POST') return handleXhttpStreamUp(xgM[1], xgM[2], request, env, ctx);
    const xpM = path.match(/^\/xhttp-siz10\/([^/]+)\/([^/]+)\/(\d+)$/);
    if (xpM && request.method === 'POST') {
      return handleXhttpPacketUp(xpM[1], xpM[2], parseInt(xpM[3]), request, env, ctx);
    }

    return new Response('Not Found', { status: 404 });
  },
};
