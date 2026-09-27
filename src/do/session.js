import { connect } from 'cloudflare:sockets';
import { DEFAULTS } from '../config.js';
import { concatBytes, parseHeader, hourTehran } from '../helpers.js';

export class SessionDO {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.sessionId = null;
    this.uuid = null;
    this.mode = 'auto';
    this.tcpWriter = null;
    this.tcpReader = null;
    this.closed = false;
    this.lastSeen = Date.now();
    this.connId = null;
    this.downQueue = [];
    this.downWaiters = [];
    this.seqBuf = {};
    this.nextSeq = 0;
    this.tcpOpen = false;
    this.ip = 'unknown';
    this.gatePending = 0;
    this.gateLastCheck = Date.now();
    this.gateOk = true;
    this.gateBatch = 64 * 1024;
    this.gateRateEwma = 0;

    this.blockConcurrencyWhile(async () => {
      const saved = await this.state.storage.get('meta');
      if (saved) {
        this.sessionId = saved.sessionId;
        this.uuid = saved.uuid;
        this.mode = saved.mode;
        this.lastSeen = saved.lastSeen;
      }
    });
    this.state.storage.setAlarm(Date.now() + DEFAULTS.SESSION_IDLE_TIMEOUT * 1000);
  }

  async _meta() {
    await this.state.storage.put('meta', {
      sessionId: this.sessionId, uuid: this.uuid,
      mode: this.mode, lastSeen: this.lastSeen,
    });
  }

  async alarm() {
    if (Date.now() - this.lastSeen > DEFAULTS.SESSION_IDLE_TIMEOUT * 1000 && !this.tcpOpen) {
      await this._teardown();
      return;
    }
    this.state.storage.setAlarm(Date.now() + DEFAULTS.SESSION_IDLE_TIMEOUT * 1000);
  }

  _stateStub() {
    return this.env.STATE_DO.get(this.env.STATE_DO.idFromName('global'));
  }

  async _registerConn() {
    if (this.connId) return;
    this.connId = crypto.randomUUID().slice(0, 8);
    await this._stateStub().fetch('https://do/register-conn', {
      method: 'POST',
      body: JSON.stringify({
        conn_id: this.connId, uuid: this.uuid, ip: this.ip,
        transport: this.mode, connected_at: new Date().toISOString(),
      }),
    });
  }

  async _updateConn(bytes) {
    if (!this.connId) return;
    await this._stateStub().fetch('https://do/update-conn', {
      method: 'POST',
      body: JSON.stringify({ conn_id: this.connId, bytes }),
    });
  }

  async _unregisterConn() {
    if (!this.connId) return;
    await this._stateStub().fetch('https://do/unregister-conn', {
      method: 'POST',
      body: JSON.stringify({ conn_id: this.connId }),
    });
    this.connId = null;
  }

  async _checkAndUse(n) {
    const link = await this.env.CNM_KV.get('p:' + this.uuid, 'json');
    if (!link) return false;
    if (!link.active) return false;
    if (link.expires_at && Date.now() > new Date(link.expires_at).getTime()) return false;
    if (link.limit_bytes > 0 && (link.used_bytes || 0) >= link.limit_bytes) return false;
    link.used_bytes = (link.used_bytes || 0) + n;
    await this.env.CNM_KV.put('p:' + this.uuid, JSON.stringify(link));
    await this._stateStub().fetch('https://do/add-traffic', {
      method: 'POST',
      body: JSON.stringify({ bytes: n, hour: hourTehran() }),
    });
    return true;
  }

  async _throttle(n) {
    const link = await this.env.CNM_KV.get('p:' + this.uuid, 'json');
    if (!link || !link.speed_limit_bytes) return;
    const rate = Math.max(link.speed_limit_bytes, DEFAULTS.MIN_RATE);
    const capacity = Math.max(rate, DEFAULTS.MIN_BURST);
    const bucketKey = 'b:' + this.uuid;
    const now = Date.now();
    const bucket = (await this.env.CNM_KV.get(bucketKey, 'json')) || { tokens: capacity, last: now };
    const elapsed = (now - bucket.last) / 1000;
    bucket.tokens = Math.min(capacity, bucket.tokens + elapsed * rate);
    bucket.last = now;
    while (bucket.tokens < n) {
      const deficit = n - bucket.tokens;
      const waitMs = Math.min(Math.max((deficit / rate) * 1000, 4), 500);
      await new Promise(r => setTimeout(r, waitMs));
      const now2 = Date.now();
      const e2 = (now2 - bucket.last) / 1000;
      bucket.tokens = Math.min(capacity, bucket.tokens + e2 * rate);
      bucket.last = now2;
    }
    bucket.tokens -= n;
    await this.env.CNM_KV.put(bucketKey, JSON.stringify(bucket), { expirationTtl: 60 });
  }

  async _gateAdd(n) {
    if (!this.gateOk) return false;
    this.gatePending += n;
    const now = Date.now();
    const elapsed = (now - this.gateLastCheck) / 1000;
    if (this.gatePending >= this.gateBatch || elapsed >= 0.2) {
      const flush = this.gatePending;
      this.gatePending = 0;
      if (elapsed > 0) {
        const inst = flush / elapsed;
        this.gateRateEwma = this.gateRateEwma === 0 ? inst : 0.7 * this.gateRateEwma + 0.3 * inst;
        const target = Math.floor(this.gateRateEwma * 0.2);
        this.gateBatch = Math.max(32 * 1024, Math.min(1024 * 1024, target || 32 * 1024));
      }
      this.gateLastCheck = now;
      this.gateOk = await this._checkAndUse(flush);
      return this.gateOk;
    }
    return true;
  }

  async _gateFlush() {
    if (this.gatePending) {
      const f = this.gatePending;
      this.gatePending = 0;
      this.gateOk = this.gateOk && await this._checkAndUse(f);
    }
    return this.gateOk;
  }

  async _openTcp(firstChunk) {
    const parsed = parseHeader(new Uint8Array(firstChunk));
    if (!parsed) throw new Error('invalid header');
    const socket = connect({ hostname: parsed.address, port: parsed.port }, { secureTransport: 'off' });
    this.tcpWriter = socket.writable.getWriter();
    this.tcpReader = socket.readable.getReader();
    this.tcpOpen = true;
    if (parsed.payload && parsed.payload.length) await this.tcpWriter.write(parsed.payload);
    this._pumpDown();
    await this._registerConn();
    return { address: parsed.address, port: parsed.port };
  }

  async _pumpDown() {
    let first = true;
    try {
      while (true) {
        const r = await this.tcpReader.read();
        if (r.done) break;
        const value = r.value;
        if (!value || !value.length) continue;
        if (!await this._gateAdd(value.length)) break;
        await this._throttle(value.length);
        await this._updateConn(value.length);
        const payload = first ? concatBytes(new Uint8Array([0, 0]), value) : value;
        first = false;
        this._enqueueDown(payload);
      }
    } catch (e) {} finally {
      await this._gateFlush();
      await this._teardown();
    }
  }

  _enqueueDown(chunk) {
    if (this.downWaiters.length) this.downWaiters.shift().resolve(chunk);
    else this.downQueue.push(chunk);
  }

  _dequeueDown() {
    if (this.downQueue.length) return Promise.resolve(this.downQueue.shift());
    return new Promise(resolve => this.downWaiters.push({ resolve }));
  }

  async _teardown() {
    if (this.closed) return;
    this.closed = true;
    try { if (this.tcpWriter) await this.tcpWriter.close(); } catch (e) {}
    try { if (this.tcpReader) await this.tcpReader.cancel(); } catch (e) {}
    this._enqueueDown(null);
    await this._unregisterConn();
  }

  async fetch(req) {
    const url = new URL(req.url);
    const action = url.searchParams.get('action') || url.pathname.slice(1);

    try {
      const body = await req.json().catch(() => ({}));
      if (action === 'init') return await this._init(body);
      if (action === 'downlink') return this._downlink(body);
      if (action === 'packet-up') return await this._packetUp(body);
      if (action === 'stream-up') return await this._streamUp(body);
      if (action === 'close') { await this._teardown(); return Response.json({ ok: true }); }
      return new Response('Not Found', { status: 404 });
    } catch (e) {
      await this._teardown();
      return Response.json({ error: String(e) }, { status: 500 });
    }
  }

  async _init(body) {
    if (!this.sessionId) {
      this.sessionId = body.session_id;
      this.uuid = body.uuid;
      this.mode = body.mode || 'auto';
      this.ip = body.ip || 'unknown';
      await this._meta();
    }
    this.lastSeen = Date.now();
    return Response.json({ ok: true, mode: this.mode });
  }

  _downlink(_body) {
    const self = this;
    const stream = new ReadableStream({
      async pull(controller) {
        const chunk = await self._dequeueDown();
        if (chunk === null) controller.close();
        else { self.lastSeen = Date.now(); controller.enqueue(chunk); }
      },
      cancel() { self._teardown(); },
    });
    return new Response(stream, {
      headers: {
        'content-type': 'application/octet-stream',
        'cache-control': 'no-store',
        'x-accel-buffering': 'no',
      },
    });
  }

  async _packetUp(body) {
    this.lastSeen = Date.now();
    const seq = body.seq;
    const bytes = Uint8Array.from(atob(body.data), c => c.charCodeAt(0));
    if (!bytes.length) return Response.json({ ok: true });
    if (!await this._checkAndUse(bytes.length)) {
      await this._teardown();
      return Response.json({ error: 'quota' }, { status: 403 });
    }
    await this._throttle(bytes.length);
    await this._updateConn(bytes.length);
    if (!this.tcpOpen) {
      if (seq !== 0) {
        this.seqBuf[seq] = bytes;
        return Response.json({ ok: true, buffered: true });
      }
      try { await this._openTcp(bytes); }
      catch (e) { return Response.json({ error: String(e) }, { status: 502 }); }
      let nxt = 1;
      while (this.seqBuf[nxt]) {
        await this.tcpWriter.write(this.seqBuf[nxt]);
        delete this.seqBuf[nxt];
        nxt += 1;
      }
      this.nextSeq = nxt;
      return Response.json({ ok: true, connected: true });
    }
    if (seq === this.nextSeq) {
      await this.tcpWriter.write(bytes);
      this.nextSeq += 1;
      while (this.seqBuf[this.nextSeq]) {
        await this.tcpWriter.write(this.seqBuf[this.nextSeq]);
        delete this.seqBuf[this.nextSeq];
        this.nextSeq += 1;
      }
    } else {
      this.seqBuf[seq] = bytes;
    }
    return Response.json({ ok: true });
  }

  async _streamUp(body) {
    this.lastSeen = Date.now();
    const chunks = body.chunks || [];
    const bufs = chunks.map(b => Uint8Array.from(atob(b), c => c.charCodeAt(0)));
    for (let i = 0; i < bufs.length; i++) {
      const chunk = bufs[i];
      if (!chunk.length) continue;
      if (!await this._gateAdd(chunk.length)) {
        await this._gateFlush();
        await this._teardown();
        return Response.json({ error: 'quota' }, { status: 403 });
      }
      await this._throttle(chunk.length);
      await this._updateConn(chunk.length);
      if (!this.tcpOpen) {
        try { await this._openTcp(chunk); }
        catch (e) { return Response.json({ error: String(e) }, { status: 502 }); }
      } else {
        await this.tcpWriter.write(chunk);
      }
    }
    return Response.json({ ok: true });
  }
}
