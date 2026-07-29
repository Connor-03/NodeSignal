// nodeps.js — express/ws replacements built on Node's standard library only
// ============================================================================
// NodeSignal originally required `express` and `ws`, which pulled 66 packages
// onto a machine running a Bitcoin node. That was flagged in the threat model,
// and on Windows it made `npm install` a hard prerequisite that frequently
// failed (no network, corporate proxy, OneDrive-synced folder, stale PATH).
//
// This module removes the dependency completely:
//   · serveStatic()  — safe static file serving with correct MIME types and
//                      path-traversal rejection
//   · WSServer       — a minimal RFC 6455 WebSocket server (text frames, ping/
//                      pong, close, fragmentation, masking) sufficient for the
//                      daemon's JSON API
//
// The daemon prefers real express/ws when present and silently falls back to
// this, so existing installs are unaffected.
// ============================================================================
'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { EventEmitter } = require('events');

/* ------------------------------------------------------------ static files */
const MIME = {
  '.html': 'text/html; charset=utf-8', '.htm': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8', '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
  '.gif': 'image/gif', '.webp': 'image/webp', '.ico': 'image/x-icon',
  '.woff': 'font/woff', '.woff2': 'font/woff2', '.ttf': 'font/ttf',
  '.txt': 'text/plain; charset=utf-8', '.md': 'text/plain; charset=utf-8',
};
const mimeFor = (f) => MIME[path.extname(f).toLowerCase()] || 'application/octet-stream';

// Resolve a URL path inside root, refusing anything that escapes it.
function safeResolve(root, urlPath) {
  let p;
  try { p = decodeURIComponent(urlPath.split('?')[0].split('#')[0]); }
  catch { return null; }
  if (p.indexOf('\0') !== -1) return null;
  const full = path.resolve(root, '.' + path.posix.normalize('/' + p));
  const rootRes = path.resolve(root);
  // must stay within root
  if (full !== rootRes && !full.startsWith(rootRes + path.sep)) return null;
  // refuse dotfiles anywhere in the path
  if (path.relative(rootRes, full).split(path.sep).some(s => s.startsWith('.') && s !== '')) return null;
  return full;
}
function sendFile(res, file, status = 200, extraHeaders) {
  fs.stat(file, (err, st) => {
    if (err || !st.isFile()) { res.writeHead(404, { 'Content-Type': 'text/plain' }); res.end('not found'); return; }
    const headers = Object.assign({
      'Content-Type': mimeFor(file),
      'Content-Length': st.size,
      'Cache-Control': 'no-cache',
      'X-Content-Type-Options': 'nosniff',
    }, extraHeaders || {});
    res.writeHead(status, headers);
    fs.createReadStream(file).pipe(res);
  });
}
function serveStatic(root, urlPath, res) {
  const file = safeResolve(root, urlPath);
  if (!file) { res.writeHead(403, { 'Content-Type': 'text/plain' }); res.end('forbidden'); return true; }
  if (!fs.existsSync(file) || !fs.statSync(file).isFile()) return false;
  sendFile(res, file);
  return true;
}

/* ------------------------------------------------------------ tiny helpers */
function sendJson(res, obj, status = 200) {
  const body = Buffer.from(JSON.stringify(obj));
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': body.length });
  res.end(body);
}
function sendText(res, text, status = 200, headers) {
  const body = Buffer.from(String(text));
  res.writeHead(status, Object.assign({ 'Content-Type': 'text/plain; charset=utf-8', 'Content-Length': body.length }, headers || {}));
  res.end(body);
}
function sendHtml(res, html, status = 200, headers) {
  const body = Buffer.from(String(html));
  res.writeHead(status, Object.assign({ 'Content-Type': 'text/html; charset=utf-8', 'Content-Length': body.length }, headers || {}));
  res.end(body);
}
// application/x-www-form-urlencoded body, size-capped
function readForm(req, limit = 16 * 1024) {
  return new Promise((resolve) => {
    let size = 0; const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) { req.destroy(); resolve({}); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      const out = {};
      const raw = Buffer.concat(chunks).toString('utf8');
      for (const pair of raw.split('&')) {
        if (!pair) continue;
        const i = pair.indexOf('=');
        const k = i < 0 ? pair : pair.slice(0, i);
        const v = i < 0 ? '' : pair.slice(i + 1);
        try { out[decodeURIComponent(k.replace(/\+/g, ' '))] = decodeURIComponent(v.replace(/\+/g, ' ')); } catch { }
      }
      resolve(out);
    });
    req.on('error', () => resolve({}));
  });
}

/* ------------------------------------------------------------ WebSocket */
const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
const acceptKey = (key) => crypto.createHash('sha1').update(key + GUID).digest('base64');

class WSConn extends EventEmitter {
  constructor(socket) {
    super();
    this.socket = socket;
    this.readyState = 1;                 // OPEN
    this._buf = Buffer.alloc(0);
    this._frags = [];
    this._fragOp = 0;
    socket.on('data', (d) => this._onData(d));
    socket.on('close', () => { this.readyState = 3; this.emit('close'); });
    socket.on('error', (e) => { this.readyState = 3; this.emit('error', e); });
  }
  _onData(d) {
    this._buf = Buffer.concat([this._buf, d]);
    // Cap unparsed buffer so a peer cannot make us hold unbounded memory.
    if (this._buf.length > 8 * 1024 * 1024) return this.close();
    for (;;) {
      const f = this._readFrame();
      if (!f) break;
      this._handleFrame(f);
    }
  }
  _readFrame() {
    const b = this._buf;
    if (b.length < 2) return null;
    const fin = (b[0] & 0x80) !== 0;
    const opcode = b[0] & 0x0f;
    const masked = (b[1] & 0x80) !== 0;
    let len = b[1] & 0x7f;
    let off = 2;
    if (len === 126) { if (b.length < off + 2) return null; len = b.readUInt16BE(off); off += 2; }
    else if (len === 127) {
      if (b.length < off + 8) return null;
      const big = b.readBigUInt64BE(off);
      if (big > 8n * 1024n * 1024n) { this.close(); return null; }
      len = Number(big); off += 8;
    }
    let mask = null;
    if (masked) { if (b.length < off + 4) return null; mask = b.slice(off, off + 4); off += 4; }
    if (b.length < off + len) return null;
    let payload = b.slice(off, off + len);
    if (masked) {
      const out = Buffer.allocUnsafe(len);
      for (let i = 0; i < len; i++) out[i] = payload[i] ^ mask[i & 3];
      payload = out;
    }
    this._buf = b.slice(off + len);
    return { fin, opcode, payload };
  }
  _handleFrame(f) {
    switch (f.opcode) {
      case 0x0:                                  // continuation
        this._frags.push(f.payload);
        if (f.fin) {
          const full = Buffer.concat(this._frags);
          this._frags = [];
          if (this._fragOp === 0x1) this.emit('message', full.toString('utf8'));
          else this.emit('message', full);
        }
        break;
      case 0x1:                                  // text
      case 0x2:                                  // binary
        if (f.fin) {
          if (f.opcode === 0x1) this.emit('message', f.payload.toString('utf8'));
          else this.emit('message', f.payload);
        } else { this._fragOp = f.opcode; this._frags = [f.payload]; }
        break;
      case 0x8: this.close(); break;              // close
      case 0x9: this._send(0xA, f.payload); break; // ping -> pong
      case 0xA: break;                            // pong
      default: this.close();
    }
  }
  _send(opcode, payload) {
    if (this.readyState !== 1) return;
    const len = payload.length;
    let header;
    if (len < 126) { header = Buffer.alloc(2); header[1] = len; }
    else if (len < 65536) { header = Buffer.alloc(4); header[1] = 126; header.writeUInt16BE(len, 2); }
    else { header = Buffer.alloc(10); header[1] = 127; header.writeBigUInt64BE(BigInt(len), 2); }
    header[0] = 0x80 | opcode;                    // FIN + opcode; server frames unmasked
    try { this.socket.write(Buffer.concat([header, payload])); } catch { }
  }
  send(data) {
    if (typeof data === 'string') this._send(0x1, Buffer.from(data, 'utf8'));
    else this._send(0x2, Buffer.from(data));
  }
  ping() { this._send(0x9, Buffer.alloc(0)); }
  close() {
    if (this.readyState === 3) return;
    this.readyState = 3;
    try { this._send(0x8, Buffer.alloc(0)); } catch { }
    try { this.socket.end(); } catch { }
    this.emit('close');
  }
  terminate() { try { this.socket.destroy(); } catch { } }
}

// Mirrors the small slice of the `ws` API the daemon uses.
class WSServer extends EventEmitter {
  constructor() { super(); }
  handleUpgrade(req, socket, head, cb) {
    const key = req.headers['sec-websocket-key'];
    const ver = req.headers['sec-websocket-version'];
    if (!key || String(ver) !== '13') {
      try { socket.write('HTTP/1.1 400 Bad Request\r\n\r\n'); socket.destroy(); } catch { }
      return;
    }
    const headers = [
      'HTTP/1.1 101 Switching Protocols',
      'Upgrade: websocket',
      'Connection: Upgrade',
      'Sec-WebSocket-Accept: ' + acceptKey(key),
      '', '',
    ].join('\r\n');
    socket.write(headers);
    socket.setNoDelay(true);
    const conn = new WSConn(socket);
    if (head && head.length) conn._onData(head);
    cb(conn);
  }
}

module.exports = {
  serveStatic, safeResolve, sendFile, sendJson, sendText, sendHtml, readForm, mimeFor,
  WSServer, WSConn,
};
