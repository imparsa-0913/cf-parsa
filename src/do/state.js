import { fmtBytes } from '../helpers.js';

export class StateDO {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.connections = new Map();
    this.activity = [];
    this.errors = [];
    this.hourly = {};
    this.totalBytes = 0;
    this.totalRequests = 0;
    this.totalErrors = 0;
    this.startTime = Date.now();
    this.blockConcurrencyWhile(async () => {
      const saved = await this.state.storage.get('state');
      if (saved) {
        this.connections = new Map(saved.connections || []);
        this.activity = saved.activity || [];
        this.errors = saved.errors || [];
        this.hourly = saved.hourly || {};
        this.totalBytes = saved.totalBytes || 0;
        this.totalRequests = saved.totalRequests || 0;
        this.totalErrors = saved.totalErrors || 0;
        this.startTime = saved.startTime || Date.now();
      }
    });
  }

  async _save() {
    await this.state.storage.put('state', {
      connections: Array.from(this.connections.entries()),
      activity: this.activity.slice(-200),
      errors: this.errors.slice(-50),
      hourly: this.hourly,
      totalBytes: this.totalBytes,
      totalRequests: this.totalRequests,
      totalErrors: this.totalErrors,
      startTime: this.startTime,
    });
  }

  async fetch(req) {
    const url = new URL(req.url);
    const p = url.pathname;

    if (p === '/health') {
      return Response.json({
        status: 'ok',
        connections: this.connections.size,
        uptime: this._uptime(),
      });
    }
    if (p === '/connections') return Response.json(this._groupConnections());
    if (p === '/activity') return Response.json({ logs: this.activity.slice(-150) });

    if (p === '/register-conn' && req.method === 'POST') {
      const c = await req.json();
      this.connections.set(c.conn_id, {
        uuid: c.uuid, ip: c.ip, bytes: 0,
        transport: c.transport, connected_at: c.connected_at,
      });
      await this._save();
      return Response.json({ ok: true });
    }
    if (p === '/update-conn' && req.method === 'POST') {
      const c = await req.json();
      const existing = this.connections.get(c.conn_id);
      if (existing) {
        existing.bytes += c.bytes || 0;
        if (c.transport) existing.transport = c.transport;
      }
      await this._save();
      return Response.json({ ok: true });
    }
    if (p === '/unregister-conn' && req.method === 'POST') {
      const c = await req.json();
      this.connections.delete(c.conn_id);
      await this._save();
      return Response.json({ ok: true });
    }
    if (p === '/add-traffic' && req.method === 'POST') {
      const b = await req.json();
      this.totalBytes += b.bytes;
      this.totalRequests += 1;
      this.hourly[b.hour] = (this.hourly[b.hour] || 0) + b.bytes;
      await this._save();
      return Response.json({ ok: true });
    }
    if (p === '/add-error' && req.method === 'POST') {
      const e = await req.json();
      this.totalErrors += 1;
      this.errors.push({ error: e.error, url: e.url, time: new Date().toISOString() });
      if (this.errors.length > 50) this.errors = this.errors.slice(-50);
      await this._save();
      return Response.json({ ok: true });
    }
    if (p === '/log-activity' && req.method === 'POST') {
      const a = await req.json();
      this.activity.push({
        kind: a.kind, level: a.level, message: a.message,
        time: new Date().toISOString(),
      });
      if (this.activity.length > 200) this.activity = this.activity.slice(-200);
      await this._save();
      return Response.json({ ok: true });
    }
    if (p === '/stats') {
      return Response.json({
        active_connections: this.connections.size,
        total_traffic_mb: this.totalBytes / (1024 * 1024),
        total_requests: this.totalRequests,
        total_errors: this.totalErrors,
        uptime: this._uptime(),
        hourly: this.hourly,
        recent_errors: this.errors.slice(-10),
      });
    }
    if (p === '/ips-for-uuid') {
      const uuid = url.searchParams.get('uuid');
      const ips = new Set();
      for (const c of this.connections.values()) {
        if (c.uuid === uuid && c.ip) ips.add(c.ip);
      }
      return Response.json({ ips: Array.from(ips) });
    }
    return new Response('Not Found', { status: 404 });
  }

  _uptime() {
    const s = Math.floor((Date.now() - this.startTime) / 1000);
    const h = String(Math.floor(s / 3600)).padStart(2, '0');
    const m = String(Math.floor((s % 3600) / 60)).padStart(2, '0');
    const ss = String(s % 60).padStart(2, '0');
    return h + ':' + m + ':' + ss;
  }

  _groupConnections() {
    const byUuid = new Map();
    for (const c of this.connections.values()) {
      const uid = c.uuid || 'unknown';
      const ip = c.ip || 'unknown';
      let cfg = byUuid.get(uid);
      if (!cfg) {
        cfg = {
          uuid: uid, label: uid.slice(0, 8), protocol: '?',
          sessions: 0, bytes: 0, ips: new Map(),
          first_connected_at: c.connected_at, last_connected_at: c.connected_at,
        };
        byUuid.set(uid, cfg);
      }
      cfg.sessions += 1;
      cfg.bytes += c.bytes || 0;

      let ipEntry = cfg.ips.get(ip);
      if (!ipEntry) {
        ipEntry = {
          ip, sessions: 0, bytes: 0, transports: new Set(),
          first_connected_at: c.connected_at, last_connected_at: c.connected_at,
        };
        cfg.ips.set(ip, ipEntry);
      }
      ipEntry.sessions += 1;
      ipEntry.bytes += c.bytes || 0;
      ipEntry.transports.add(c.transport || 'ws');
    }

    const configs = [];
    for (const cfg of byUuid.values()) {
      const ipList = [];
      for (const e of cfg.ips.values()) {
        ipList.push({
          ip: e.ip, sessions: e.sessions, bytes: e.bytes,
          bytes_fmt: fmtBytes(e.bytes),
          transports: Array.from(e.transports),
          connected_at: e.first_connected_at, last_connected_at: e.last_connected_at,
        });
      }
      configs.push({
        uuid: cfg.uuid, label: cfg.label, protocol: cfg.protocol,
        ip_count: ipList.length, sessions: cfg.sessions, bytes: cfg.bytes,
        bytes_fmt: fmtBytes(cfg.bytes),
        connected_at: cfg.first_connected_at, last_connected_at: cfg.last_connected_at,
        connections: ipList,
      });
    }
    configs.sort((a, b) => (b.last_connected_at || '').localeCompare(a.last_connected_at || ''));
    return { configs, count: configs.length, raw_count: this.connections.size };
  }
}
