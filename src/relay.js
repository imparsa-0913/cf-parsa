import { connect } from 'cloudflare:sockets';
import { clientIp, parseHeader, concatBytes, hourTehran } from './helpers.js';
import { kvGetProfile, kvPutProfile, isLinkAllowed } from './profiles.js';

export async function handleWebSocketTunnel(uid, req, env, ctx) {
  const link = await kvGetProfile(env, uid);
  if (!link || !isLinkAllowed(link)) {
    return new Response('not authorized', { status: 403 });
  }

  const ip = clientIp(req);
  if (link.ip_limit > 0) {
    const stateStub = env.STATE_DO.get(env.STATE_DO.idFromName('global'));
    const r = await stateStub.fetch('https://do/ips-for-uuid?uuid=' + uid);
    const ipsData = await r.json();
    const ipsArr = ipsData.ips || [];
    if (ipsArr.indexOf(ip) === -1 && ipsArr.length >= link.ip_limit) {
      return new Response('limit reached', { status: 403 });
    }
  }

  const pair = new WebSocketPair();
  const client = pair[0];
  const server = pair[1];
  server.accept();

  const connId = crypto.randomUUID().slice(0, 8);
  const stateStub = env.STATE_DO.get(env.STATE_DO.idFromName('global'));
  await stateStub.fetch('https://do/register-conn', {
    method: 'POST',
    body: JSON.stringify({
      conn_id: connId, uuid: uid, ip, transport: 'ws',
      connected_at: new Date().toISOString(),
    }),
  });

  let tcpWriter = null, tcpReader = null, tcpOpen = false;

  const cleanup = async () => {
    try { if (tcpWriter) await tcpWriter.close(); } catch (e) {}
    try { if (tcpReader) await tcpReader.cancel(); } catch (e) {}
    await stateStub.fetch('https://do/unregister-conn', {
      method: 'POST',
      body: JSON.stringify({ conn_id: connId }),
    });
  };

  server.addEventListener('message', async (ev) => {
    try {
      let data;
      if (ev.data instanceof ArrayBuffer) data = new Uint8Array(ev.data);
      else data = new Uint8Array(await new Response(ev.data).arrayBuffer());
      if (!data.length) return;

      const lk = await kvGetProfile(env, uid);
      if (!lk || !isLinkAllowed(lk)) {
        server.close(1008, 'quota');
        return;
      }
      lk.used_bytes = (lk.used_bytes || 0) + data.length;
      await kvPutProfile(env, uid, lk);
      await stateStub.fetch('https://do/add-traffic', {
        method: 'POST',
        body: JSON.stringify({ bytes: data.length, hour: hourTehran() }),
      });
      await stateStub.fetch('https://do/update-conn', {
        method: 'POST',
        body: JSON.stringify({ conn_id: connId, bytes: data.length }),
      });

      if (!tcpOpen) {
        const parsed = parseHeader(data);
        if (!parsed) { server.close(1008, 'bad header'); return; }
        const socket = connect({ hostname: parsed.address, port: parsed.port }, { secureTransport: 'off' });
        tcpWriter = socket.writable.getWriter();
        tcpReader = socket.readable.getReader();
        tcpOpen = true;
        if (parsed.payload && parsed.payload.length) {
          await tcpWriter.write(parsed.payload);
        }
        (async () => {
          let first = true;
          try {
            while (true) {
              const r = await tcpReader.read();
              if (r.done) break;
              const value = r.value;
              if (!value || !value.length) continue;
              const lk2 = await kvGetProfile(env, uid);
              if (!lk2 || !isLinkAllowed(lk2)) {
                server.close(1008, 'quota');
                break;
              }
              lk2.used_bytes = (lk2.used_bytes || 0) + value.length;
              await kvPutProfile(env, uid, lk2);
              await stateStub.fetch('https://do/update-conn', {
                method: 'POST',
                body: JSON.stringify({ conn_id: connId, bytes: value.length }),
              });
              const payload = first ? concatBytes(new Uint8Array([0, 0]), value) : value;
              first = false;
              try { server.send(payload); } catch (e) { break; }
            }
          } catch (e) {} finally {
            await cleanup();
            try { server.close(); } catch (e) {}
          }
        })();
      } else {
        await tcpWriter.write(data);
      }
    } catch (e) {
      try { server.close(1011, String(e)); } catch (e2) {}
      await cleanup();
    }
  });

  server.addEventListener('close', cleanup);
  server.addEventListener('error', cleanup);

  return new Response(null, { status: 101, webSocket: client });
}
