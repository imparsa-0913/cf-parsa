export function fmtBytes(b) {
  if (!b) return '0 B';
  if (b < 1024) return b + ' B';
  if (b < 1024 * 1024) return (b / 1024).toFixed(1) + ' KB';
  if (b < 1024 * 1024 * 1024) return (b / 1024 / 1024).toFixed(2) + ' MB';
  return (b / 1024 / 1024 / 1024).toFixed(2) + ' GB';
}

export function hourTehran() {
  const now = new Date();
  const teh = new Date(now.toLocaleString('en-US', { timeZone: 'Asia/Tehran' }));
  return String(teh.getHours()).padStart(2, '0') + ':00';
}

export function getHost(req) {
  const h = req.headers.get('x-forwarded-host') || req.headers.get('host') || 'localhost';
  return h.split(':')[0];
}

export function clientIp(req) {
  return req.headers.get('cf-connecting-ip')
    || (req.headers.get('x-forwarded-for') || '').split(',')[0].trim()
    || req.headers.get('x-real-ip')
    || 'unknown';
}

export async function sha256Hex(str) {
  const data = new TextEncoder().encode(str);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
}

export function generateUuid() {
  const h = Array.from(crypto.getRandomValues(new Uint8Array(16)))
    .map(b => b.toString(16).padStart(2, '0')).join('');
  return h.slice(0, 8) + '-' + h.slice(8, 12) + '-' + h.slice(12, 16) + '-' + h.slice(16, 20) + '-' + h.slice(20, 32);
}

export function concatBytes(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

export function parseHeader(buf) {
  if (buf.length < 24) return null;
  let pos = 1 + 16;
  const addonLen = buf[pos]; pos += 1 + addonLen;
  const command = buf[pos]; pos += 1;
  const port = (buf[pos] << 8) | buf[pos + 1]; pos += 2;
  const addrType = buf[pos]; pos += 1;
  let address;
  if (addrType === 1) {
    address = buf[pos] + '.' + buf[pos + 1] + '.' + buf[pos + 2] + '.' + buf[pos + 3];
    pos += 4;
  } else if (addrType === 2) {
    const dl = buf[pos]; pos += 1;
    address = new TextDecoder().decode(buf.slice(pos, pos + dl));
    pos += dl;
  } else if (addrType === 3) {
    const ab = buf.slice(pos, pos + 16);
    address = Array.from({ length: 8 }, (_, i) =>
      ((ab[i * 2] << 8) | ab[i * 2 + 1]).toString(16).padStart(4, '0')
    ).join(':');
    pos += 16;
  } else return null;
  return { command, address, port, payload: buf.slice(pos) };
}

export function parseSizeToBytes(value, unit) {
  unit = (unit || 'GB').toUpperCase();
  if (unit === 'GB') return Math.floor(value * 1024 * 1024 * 1024);
  if (unit === 'MB') return Math.floor(value * 1024 * 1024);
  if (unit === 'KB') return Math.floor(value * 1024);
  return Math.floor(value);
}

export function parseSpeedToBytes(value, unit) {
  if (value <= 0) return 0;
  unit = (unit || 'MBIT').toUpperCase();
  if (unit === 'MBIT') return Math.floor(value * 1024 * 1024 / 8);
  if (unit === 'KB') return Math.floor(value * 1024);
  if (unit === 'MB') return Math.floor(value * 1024 * 1024);
  return Math.floor(value);
}
