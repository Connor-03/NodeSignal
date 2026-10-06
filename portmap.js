// portmap.js: ask the home router to forward NodeSignal's peer port (TCP 8788)
// ============================================================================
// OPT-IN ONLY, OFF BY DEFAULT. A forwarded port publishes this machine's public
// IP address on clearnet: anyone who learns it can see that a NodeSignal (and
// so very likely a Bitcoin node) runs there, and can connect to the peer port.
// Only enable it when the operator asked for it explicitly.
//
// Protocols spoken (Node standard library only, no dependencies):
//   UPnP IGD v1 and v2 : SSDP M-SEARCH on UDP 239.255.255.250:1900, device
//                        description over HTTP, SOAP to WANIPConnection:1/:2 or
//                        WANPPPConnection:1 (GetExternalIPAddress,
//                        AddPortMapping, GetSpecificPortMappingEntry,
//                        DeletePortMapping)
//   NAT-PMP (RFC 6886) : UDP to the default gateway on port 5351 (opcode 0 for
//                        the external address, opcode 2 for a TCP mapping,
//                        lifetime 0 to delete). PCP (RFC 6887) is not spoken.
//
// API
//   await map(opts)   -> one mapping { method, externalIp, externalPort,
//                        internalClient, internalPort, leaseSeconds, gateway,
//                        warning, remove(), renew() }
//   start(opts)       -> controller { status(), stop() } that maps, renews,
//                        retries with backoff and removes the mapping on stop
//   Small pure parsers are exported for tests.
'use strict';

const dgram = require('dgram');
const http = require('http');
const net = require('net');
const fs = require('fs');
const os = require('os');
const cp = require('child_process');

const MAX_BODY = 256 * 1024;   // cap on every HTTP response we read
const MAX_SSDP = 8 * 1024;     // cap on one SSDP datagram
const UA = 'NodeSignal/1.0 UPnP/1.1';
const SEARCH_TARGETS = [
  'urn:schemas-upnp-org:device:InternetGatewayDevice:1',
  'urn:schemas-upnp-org:device:InternetGatewayDevice:2',
  'urn:schemas-upnp-org:service:WANIPConnection:1',
  'urn:schemas-upnp-org:service:WANIPConnection:2',
  'urn:schemas-upnp-org:service:WANPPPConnection:1',
];
// Preference order when a device offers several WAN connection services.
const WAN_SERVICES = [
  'urn:schemas-upnp-org:service:WANIPConnection:2',
  'urn:schemas-upnp-org:service:WANIPConnection:1',
  'urn:schemas-upnp-org:service:WANPPPConnection:1',
];
const UPNP_ERRORS = {
  401: 'InvalidAction', 402: 'InvalidArgs', 501: 'ActionFailed', 606: 'ActionNotAuthorized',
  714: 'NoSuchEntryInArray', 715: 'WildCardNotPermittedInSrcIP', 716: 'WildCardNotPermittedInExtPort',
  718: 'ConflictInMappingEntry', 724: 'SamePortValuesRequired', 725: 'OnlyPermanentLeasesSupported',
  726: 'RemoteHostOnlySupportsWildcard', 727: 'ExternalPortOnlySupportsWildcard',
  728: 'NoPortMapsAvailable', 729: 'ConflictWithOtherMechanisms',
};
const NATPMP_RESULTS = {
  1: 'unsupported version (the router may only speak PCP)',
  2: 'not authorized or refused (NAT-PMP disabled on the router?)',
  3: 'network failure (the router has no WAN address yet)',
  4: 'out of resources',
  5: 'unsupported opcode',
};
const DEFAULT_TIMING = {
  renewFraction: 0.5,                 // renew at this fraction of the granted lease
  permanentRenewMs: 20 * 60 * 1000,   // re-check a permanent (lease 0) mapping this often
  backoffMs: [30e3, 60e3, 120e3, 300e3, 600e3],   // retry delays after failures; last repeats
  minRenewMs: 1000,                   // never renew faster than this
  stopTimeoutMs: 2500,                // stop() always finishes within this
};

/* ------------------------------------------------------------------ helpers */

const noop = () => {};
const secs = (ms) => `${Math.round(ms / 100) / 10}s`;
function fmtDur(ms) {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60e3) return secs(ms);
  return `${Math.round(ms / 6000) / 10}m`;
}
function later(ms, fn) {
  const t = setTimeout(fn, ms);
  if (t && typeof t.unref === 'function') t.unref();
  return t;
}
const sleep = (ms) => new Promise((resolve) => later(ms, resolve));
const normIp = (a) => (typeof a === 'string' && a.startsWith('::ffff:') && net.isIPv4(a.slice(7)) ? a.slice(7) : a || null);

function ipv4Octets(ip) { return net.isIPv4(ip) ? ip.split('.').map(Number) : null; }
// RFC 1918, loopback, link-local and RFC 6598 shared (CGNAT) space.
function isPrivateV4(ip) {
  const o = ipv4Octets(ip);
  if (!o) return false;
  return o[0] === 10 || o[0] === 127 || (o[0] === 172 && o[1] >= 16 && o[1] <= 31) ||
    (o[0] === 192 && o[1] === 168) || (o[0] === 169 && o[1] === 254) || (o[0] === 100 && o[1] >= 64 && o[1] <= 127);
}
function isLocalHost(host) {
  if (net.isIPv4(host)) return isPrivateV4(host);
  if (net.isIPv6(host)) return /^(::1$|fe[89ab][0-9a-f]:|f[cd][0-9a-f]{2}:)/i.test(host);
  return false;
}
function natWarning(externalIp) {
  if (!externalIp || !isPrivateV4(externalIp)) return null;
  return `the router's WAN address ${externalIp} is private or CGNAT, so another NAT sits upstream; this mapping alone will not make the node reachable from the internet`;
}

function decodeXml(s) {
  return String(s).replace(/&(#[xX][0-9a-fA-F]{1,6}|#\d{1,7}|lt|gt|amp|quot|apos);/g, (m, e) => {
    if (e[0] === '#') {
      const n = e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      return n > 0 && n <= 0x10ffff ? String.fromCodePoint(n) : '';
    }
    return { lt: '<', gt: '>', amp: '&', quot: '"', apos: "'" }[e];
  });
}
function escXml(s) {
  return String(s).replace(/[<>&"']/g, (c) => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&apos;' }[c]));
}
// Drop comments and unwrap CDATA (re-escaped) so the tag regexes below see plain markup.
function stripXmlNoise(xml) {
  return xml.replace(/<!--[\s\S]*?-->/g, '').replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, (m, t) => escXml(t));
}
const NS = '(?:[A-Za-z_][\\w.-]*:)?';   // optional namespace prefix on a tag name
const SAFE_NAME = /^[A-Za-z_][\w.-]*$/;
const BAD_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
function tagText(xml, name) {
  const m = new RegExp(`<${NS}${name}(?:\\s[^>]*)?>([^<]*)</${NS}${name}\\s*>`).exec(xml);
  return m ? decodeXml(m[1]).trim() : null;
}

/* ------------------------------------------------------------- pure parsers */

// One SSDP M-SEARCH reply -> { statusCode, location, st, usn, server, headers } or null.
function parseSsdpResponse(text) {
  if (Buffer.isBuffer(text)) text = text.toString('latin1');
  if (typeof text !== 'string' || text.length > MAX_SSDP) return null;
  const lines = text.split(/\r?\n/);
  const m = /^HTTP\/1\.[01]\s+(\d{3})\b/i.exec(lines[0] || '');
  if (!m) return null;
  const headers = {};
  for (const line of lines.slice(1)) {
    if (!line) break;
    const i = line.indexOf(':');
    if (i <= 0) continue;
    const k = line.slice(0, i).trim().toLowerCase();
    if (!/^[a-z0-9._-]+$/.test(k) || BAD_KEYS.has(k)) continue;
    headers[k] = line.slice(i + 1).trim();
  }
  return {
    statusCode: Number(m[1]), location: headers.location || null, st: headers.st || null,
    usn: headers.usn || null, server: headers.server || null, headers,
  };
}
const isIgdReply = (r) => r && r.statusCode === 200 && r.location &&
  /InternetGatewayDevice|WAN(IP|PPP)Connection/.test(`${r.st || ''} ${r.usn || ''}`);

function resolveControlUrl(ctl, urlBase, location) {
  const loc = new URL(location);
  let base = loc;
  if (urlBase) {
    try { const b = new URL(urlBase); if (b.protocol === 'http:') base = b; } catch { /* fall back to LOCATION */ }
  }
  let u;
  try { u = new URL(ctl, base); } catch { throw new Error(`invalid controlURL ${JSON.stringify(String(ctl).slice(0, 80))}`); }
  if (u.protocol !== 'http:') throw new Error(`controlURL ${u.href.slice(0, 80)} is not http`);
  if (u.hostname !== loc.hostname) {
    throw new Error(`controlURL host ${u.hostname} differs from the device description host ${loc.hostname}; refusing`);
  }
  return u.href;
}

// Device description XML -> { controlURL, serviceType, urlBase, candidates }.
// controlURL is absolute when `location` is given (resolved against URLBase,
// else LOCATION), otherwise as written. candidates lists every WAN connection
// service in preference order. Throws on malformed, oversized or IGD-less XML.
function parseDeviceDescription(xml, location) {
  if (typeof xml !== 'string') throw new Error('device description is not text');
  if (xml.length > MAX_BODY) throw new Error(`device description too large (over ${MAX_BODY / 1024} KB)`);
  const doc = stripXmlNoise(xml);
  if (!new RegExp(`<${NS}root[\\s>]`).test(doc) || !new RegExp(`</${NS}root\\s*>`).test(doc)) {
    throw new Error('malformed device description: no complete <root> element');
  }
  const urlBase = tagText(doc, 'URLBase') || null;
  const services = [];
  const re = new RegExp(`<${NS}service(?:\\s[^>]*)?>([\\s\\S]*?)</${NS}service\\s*>`, 'g');
  for (const m of doc.matchAll(re)) {
    const serviceType = tagText(m[1], 'serviceType');
    const ctl = tagText(m[1], 'controlURL');
    if (serviceType) services.push({ serviceType, ctl });
  }
  if (!services.length) throw new Error('malformed device description: no <service> entries');
  const wan = services
    .filter((s) => WAN_SERVICES.includes(s.serviceType))
    .sort((a, b) => WAN_SERVICES.indexOf(a.serviceType) - WAN_SERVICES.indexOf(b.serviceType));
  if (!wan.length) {
    const seen = services.slice(0, 4).map((s) => s.serviceType.replace(/^urn:schemas-upnp-org:service:/, '')).join(', ');
    throw new Error(`not an internet gateway: no WANIPConnection/WANPPPConnection service (found ${seen})`);
  }
  const candidates = [];
  for (const s of wan) {
    if (!s.ctl) continue;
    candidates.push({ serviceType: s.serviceType, controlURL: location ? resolveControlUrl(s.ctl, urlBase, location) : s.ctl });
  }
  if (!candidates.length) throw new Error('malformed device description: WAN service has no controlURL');
  return { controlURL: candidates[0].controlURL, serviceType: candidates[0].serviceType, urlBase, candidates };
}

// SOAP request body. args: array of [name, value] pairs (order matters to some
// routers) or a plain object.
function buildSoapEnvelope(serviceType, action, args = []) {
  if (!/^urn:[\w.:-]+$/.test(String(serviceType))) throw new Error('bad serviceType');
  if (!/^[A-Za-z]\w*$/.test(String(action))) throw new Error('bad SOAP action');
  const pairs = Array.isArray(args) ? args : Object.entries(args || {});
  const body = pairs.map(([k, v]) => {
    if (!SAFE_NAME.test(k)) throw new Error(`bad SOAP argument name ${k}`);
    return `<${k}>${escXml(v == null ? '' : v)}</${k}>`;
  }).join('');
  return '<?xml version="1.0"?>\r\n' +
    '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">' +
    `<s:Body><u:${action} xmlns:u="${serviceType}">${body}</u:${action}></s:Body></s:Envelope>\r\n`;
}

// SOAP response -> { Name: value, ... } for <ActionResponse>, or
// { errorCode, errorDescription } for a Fault. Throws when neither is present.
function parseSoapResponse(xml, action) {
  if (typeof xml !== 'string') throw new Error('SOAP response is not text');
  if (xml.length > MAX_BODY) throw new Error(`SOAP response too large (over ${MAX_BODY / 1024} KB)`);
  if (action != null && !/^[A-Za-z]\w*$/.test(String(action))) throw new Error('bad SOAP action');
  const doc = stripXmlNoise(xml);
  if (!new RegExp(`<${NS}Envelope[\\s>]`).test(doc)) throw new Error('malformed SOAP response: no Envelope');
  if (new RegExp(`<${NS}Fault[\\s>]`).test(doc)) {
    const code = tagText(doc, 'errorCode');
    const n = code !== null && /^\d{1,4}$/.test(code) ? Number(code) : null;
    const desc = tagText(doc, 'errorDescription') || tagText(doc, 'faultstring') || (n !== null && UPNP_ERRORS[n]) || '';
    return { errorCode: n, errorDescription: desc.slice(0, 200) };
  }
  const name = action ? `${action}Response` : '[A-Za-z_][\\w.-]*Response';
  const m = new RegExp(`<${NS}(${name})(?:\\s[^>]*)?>([\\s\\S]*?)</${NS}\\1\\s*>`).exec(doc);
  if (!m) {
    if (new RegExp(`<${NS}${name}(?:\\s[^>]*)?/>`).test(doc)) return {};
    throw new Error(`malformed SOAP response: no ${action ? action + 'Response' : 'response'} element`);
  }
  const out = {};
  const child = new RegExp(`<${NS}([A-Za-z_][\\w.-]*)(?:\\s[^>]*?)?(?:/>|>([^<]*)</${NS}\\1\\s*>)`, 'g');
  for (const c of m[2].matchAll(child)) {
    if (BAD_KEYS.has(c[1])) continue;
    out[c[1]] = c[2] === undefined ? '' : decodeXml(c[2]).trim();
  }
  return out;
}

// /proc/net/route text -> IPv4 default routes [{ iface, gateway, metric }],
// lowest metric first. Fields are printed in host byte order.
function parseProcNetRoute(text, endianness = os.endianness()) {
  const out = [];
  for (const line of String(text).split('\n').slice(1)) {
    const f = line.trim().split(/\s+/);
    if (f.length < 8) continue;
    const [iface, dest, gw, flags, , , metric, mask] = f;
    if (dest !== '00000000' || mask !== '00000000' || !/^[0-9A-Fa-f]{8}$/.test(gw)) continue;
    const fl = parseInt(flags, 16);
    if (!(fl & 0x1) || !(fl & 0x2)) continue;   // RTF_UP and RTF_GATEWAY
    const n = parseInt(gw, 16);
    const b = [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255];
    const ip = (endianness === 'LE' ? b.reverse() : b).join('.');
    if (ip === '0.0.0.0') continue;
    out.push({ iface, gateway: ip, metric: Number(metric) || 0 });
  }
  return out.sort((a, b) => a.metric - b.metric);
}
// `route -n get default` (macOS / BSD) -> gateway or null.
function parseRouteGetDefault(text) {
  const m = /^\s*gateway:\s*(\d{1,3}(?:\.\d{1,3}){3})\s*$/m.exec(String(text));
  return m && net.isIPv4(m[1]) ? m[1] : null;
}
// `route print -4 0.0.0.0` (Windows) -> lowest-metric default gateway or null.
function parseWindowsRoutePrint(text) {
  let best = null;
  const re = /^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+(\d+)\s*$/gm;
  for (const m of String(text).matchAll(re)) {
    if (!net.isIPv4(m[1])) continue;
    const metric = Number(m[2]);
    if (!best || metric < best.metric) best = { gateway: m[1], metric };
  }
  return best ? best.gateway : null;
}
// `ip -4 route show default` (Linux fallback) -> gateway or null.
function parseIpRouteDefault(text) {
  const m = /^default\s+via\s+(\d{1,3}(?:\.\d{1,3}){3})\b/m.exec(String(text));
  return m && net.isIPv4(m[1]) ? m[1] : null;
}

/* ------------------------------------------------------------------- I/O */

function run(cmd, args, timeoutMs) {
  return new Promise((resolve, reject) => {
    cp.execFile(cmd, args, {
      timeout: timeoutMs, windowsHide: true, maxBuffer: MAX_BODY, env: { ...process.env, LC_ALL: 'C' },
    }, (err, stdout) => (err ? reject(new Error(`${cmd} ${args.join(' ')}: ${err.killed ? 'timed out' : err.message.split('\n')[0]}`)) : resolve(String(stdout))));
  });
}

async function discoverGateway(timeoutMs = 2000) {
  const t = Math.min(timeoutMs, 3000);
  if (process.platform === 'linux' || process.platform === 'android') {
    let why = 'no IPv4 default route in /proc/net/route';
    try {
      const routes = parseProcNetRoute(fs.readFileSync('/proc/net/route', 'utf8'));
      if (routes.length) return routes[0].gateway;
    } catch (e) { why = `cannot read /proc/net/route (${e.code || e.message})`; }
    try {
      const gw = parseIpRouteDefault(await run('ip', ['-4', 'route', 'show', 'default'], t));
      if (gw) return gw;
    } catch { /* keep the /proc reason */ }
    throw new Error(why);
  }
  if (process.platform === 'win32') {
    const gw = parseWindowsRoutePrint(await run('route', ['print', '-4', '0.0.0.0'], t));
    if (!gw) throw new Error('no IPv4 default route in `route print`');
    return gw;
  }
  const gw = parseRouteGetDefault(await run('route', ['-n', 'get', 'default'], t));
  if (!gw) throw new Error('no IPv4 gateway in `route -n get default`');
  return gw;
}

// Bounded HTTP request. Resolves { status, body, localAddress }.
function httpRequest(url, { method = 'GET', headers = {}, body = null, timeoutMs = 4000 } = {}) {
  return new Promise((resolve, reject) => {
    let u;
    try { u = new URL(url); } catch { reject(new Error(`bad URL ${String(url).slice(0, 80)}`)); return; }
    if (u.protocol !== 'http:') { reject(new Error(`refusing non-http URL ${u.href.slice(0, 80)}`)); return; }
    let done = false, timer = null, req = null;
    const finish = (err, val) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      if (err) { if (req) req.destroy(); reject(err); } else resolve(val);
    };
    const hdrs = { 'User-Agent': UA, Connection: 'close', ...headers };
    if (body != null) hdrs['Content-Length'] = Buffer.byteLength(body);
    timer = later(timeoutMs, () => finish(new Error(`${u.host} did not respond in ${secs(timeoutMs)}`)));
    req = http.request({
      hostname: u.hostname.replace(/^\[|\]$/g, ''), port: u.port || 80, path: u.pathname + u.search,
      method, agent: false, headers: hdrs,
    }, (res) => {
      const len = Number(res.headers['content-length']);
      if (len > MAX_BODY) { finish(new Error(`response from ${u.host} too large (${len} bytes, limit ${MAX_BODY / 1024} KB)`)); return; }
      const localAddress = normIp(res.socket && res.socket.localAddress);
      const chunks = [];
      let size = 0;
      res.on('data', (c) => {
        size += c.length;
        if (size > MAX_BODY) { finish(new Error(`response from ${u.host} too large (over ${MAX_BODY / 1024} KB)`)); return; }
        chunks.push(c);
      });
      res.on('end', () => finish(null, { status: res.statusCode, body: Buffer.concat(chunks).toString('utf8'), localAddress }));
      res.on('error', (e) => finish(new Error(`${u.host}: ${e.message}`)));
    });
    req.on('error', (e) => finish(new Error(`${u.host}: ${e.message}`)));
    req.end(body == null ? undefined : body);
  });
}

/* ------------------------------------------------------------------- UPnP */

function ssdpDiscover(o) {
  return new Promise((resolve, reject) => {
    const sock = dgram.createSocket('udp4');
    const found = new Map();
    const ignored = [];
    let done = false, grace = null, resend = null;
    const finish = (err) => {
      if (done) return;
      done = true;
      clearTimeout(deadline); clearTimeout(grace); clearTimeout(resend);
      try { sock.close(); } catch { /* already closed */ }
      if (err) reject(err); else resolve([...found.values()]);
    };
    const deadline = later(o.timeoutMs, () => {
      if (found.size) { finish(); return; }
      const extra = ignored.length ? ` (ignored ${ignored.length} repl${ignored.length === 1 ? 'y' : 'ies'}: ${ignored.slice(0, 2).join('; ')})` : '';
      finish(new Error(`no gateway answered the SSDP search in ${secs(o.timeoutMs)}${extra}`));
    });
    sock.on('error', (e) => finish(new Error(`SSDP socket error: ${e.message}`)));
    sock.on('message', (buf, rinfo) => {
      if (done || buf.length > MAX_SSDP) return;
      const r = parseSsdpResponse(buf.toString('latin1'));
      if (!isIgdReply(r)) return;
      let host = null;
      try { const u = new URL(r.location); if (u.protocol === 'http:') host = u.hostname.replace(/^\[|\]$/g, ''); } catch { /* bad URL */ }
      if (!host || !(host === rinfo.address || isLocalHost(host))) {
        const why = `LOCATION ${String(r.location).slice(0, 60)} from ${rinfo.address} is not a local http address`;
        if (ignored.length < 8 && !ignored.includes(why)) ignored.push(why);
        return;
      }
      if (!found.has(r.location)) found.set(r.location, { location: r.location, st: r.st, server: r.server, from: rinfo.address });
      if (!grace) grace = later(Math.min(300, o.timeoutMs), () => finish());
    });
    const mx = Math.max(1, Math.min(3, Math.floor(o.timeoutMs / 1000) - 1));
    const send = () => {
      for (const st of SEARCH_TARGETS) {
        const msg = Buffer.from(`M-SEARCH * HTTP/1.1\r\nHOST: ${o.ssdpAddress}:${o.ssdpPort}\r\nMAN: "ssdp:discover"\r\nMX: ${mx}\r\nST: ${st}\r\nUSER-AGENT: ${UA}\r\n\r\n`);
        sock.send(msg, o.ssdpPort, o.ssdpAddress, (e) => { if (e && !done) o.log(`upnp: SSDP send failed: ${e.message}`); });
      }
    };
    sock.bind(0, () => {
      if (done) return;
      try { sock.setMulticastTTL(2); } catch { /* unicast target */ }
      send();
      resend = later(Math.min(1000, o.timeoutMs / 2), () => { if (!done && !found.size) send(); });
    });
  });
}

async function soapCall(svc, action, args, timeoutMs) {
  const body = buildSoapEnvelope(svc.serviceType, action, args);
  const res = await httpRequest(svc.controlURL, {
    method: 'POST', body, timeoutMs,
    headers: { 'Content-Type': 'text/xml; charset="utf-8"', SOAPAction: `"${svc.serviceType}#${action}"` },
  });
  let parsed;
  try { parsed = parseSoapResponse(res.body, action); } catch (e) {
    throw new Error(`${action}: ${res.status !== 200 ? `HTTP ${res.status}, ` : ''}${e.message}`);
  }
  if (Object.prototype.hasOwnProperty.call(parsed, 'errorCode') && Object.prototype.hasOwnProperty.call(parsed, 'errorDescription')) {
    const code = parsed.errorCode;
    const err = new Error(`${action} failed: UPnP error ${code == null ? '?' : code} ${parsed.errorDescription || UPNP_ERRORS[code] || ''}`.trim());
    err.upnpCode = code;
    throw err;
  }
  if (res.status !== 200) throw new Error(`${action}: HTTP ${res.status}`);
  return parsed;
}

async function readExternalIp(svc, timeoutMs) {
  const v = await soapCall(svc, 'GetExternalIPAddress', [], timeoutMs);
  const ip = String(v.NewExternalIPAddress || '').trim();
  if (!net.isIPv4(ip) || ip === '0.0.0.0') throw new Error(`no external address (got ${JSON.stringify(ip.slice(0, 40))})`);
  return ip;
}

async function loadGateway(location, o) {
  const res = await httpRequest(location, { timeoutMs: o.timeoutMs });
  if (res.status !== 200) throw new Error(`device description: HTTP ${res.status}`);
  const desc = parseDeviceDescription(res.body, location);
  const internalClient = o.internalClient || res.localAddress;
  if (!net.isIPv4(internalClient)) {
    throw new Error(`cannot tell this machine's IPv4 address toward the router (got ${internalClient || 'nothing'})`);
  }
  // With several WAN services (DSL routers list IP and PPP), use the one that is connected.
  const errs = [];
  for (const c of desc.candidates) {
    try {
      const externalIp = await readExternalIp(c, o.timeoutMs);
      return { ...c, location, internalClient, externalIp };
    } catch (e) { errs.push(`${c.serviceType.replace(/^urn:schemas-upnp-org:service:/, '')}: ${e.message}`); }
  }
  o.log(`upnp: could not read the external address (${errs.join('; ')}); trying AddPortMapping anyway`);
  return { ...desc.candidates[0], location, internalClient, externalIp: null };
}

async function mappingOwner(gw, o, timeoutMs) {
  const v = await soapCall(gw, 'GetSpecificPortMappingEntry',
    [['NewRemoteHost', ''], ['NewExternalPort', o.externalPort], ['NewProtocol', 'TCP']], timeoutMs);
  return { client: normIp(String(v.NewInternalClient || '')), port: Number(v.NewInternalPort) };
}

function conflictError(o, owner) {
  const who = owner && owner.client ? `${owner.client}:${owner.port}` : 'another device';
  const err = new Error(`external port ${o.externalPort}/TCP is already forwarded to ${who} (UPnP 718 ConflictInMappingEntry); ` +
    'not taking it over. Pick a different external port or remove that forward in the router');
  err.code = 'EPORTCONFLICT';
  return err;
}

async function upnpAdd(gw, o, prev) {
  let externalIp = prev.externalIp || null;
  if (prev.refreshIp) {
    try { externalIp = await readExternalIp(gw, o.timeoutMs); } catch (e) { o.log(`upnp: GetExternalIPAddress: ${e.message}`); }
  }
  let lease = prev.permanentOnly ? 0 : o.leaseSeconds;
  const add = (l) => soapCall(gw, 'AddPortMapping', [
    ['NewRemoteHost', ''], ['NewExternalPort', o.externalPort], ['NewProtocol', 'TCP'],
    ['NewInternalPort', o.internalPort], ['NewInternalClient', gw.internalClient], ['NewEnabled', 1],
    ['NewPortMappingDescription', o.description], ['NewLeaseDuration', l],
  ], o.timeoutMs);
  const addWithLeaseFallback = async () => {
    try { await add(lease); return; } catch (e) {
      if (e.upnpCode !== 725 || lease === 0) throw e;
      o.log('upnp: router only supports permanent mappings (725 OnlyPermanentLeasesSupported); retrying with lease 0, it will be deleted on stop');
      lease = 0;
    }
    await add(0);
  };
  try {
    await addWithLeaseFallback();
  } catch (e) {
    if (e.upnpCode !== 718) throw e;
    // Some routers answer 718 even for our own stale entry. Only replace it when it points at us.
    let owner = null;
    try { owner = await mappingOwner(gw, o, o.timeoutMs); } catch { /* unknown owner: do not touch it */ }
    if (!owner || owner.client !== gw.internalClient || owner.port !== o.internalPort) throw conflictError(o, owner);
    o.log(`upnp: external port ${o.externalPort} already points at this host (stale entry); replacing it`);
    await soapCall(gw, 'DeletePortMapping', [['NewRemoteHost', ''], ['NewExternalPort', o.externalPort], ['NewProtocol', 'TCP']], o.timeoutMs).catch(noop);
    try { await addWithLeaseFallback(); } catch (e2) { if (e2.upnpCode === 718) throw conflictError(o, null); throw e2; }
  }
  o.log(`upnp: AddPortMapping ${o.externalPort}/TCP -> ${gw.internalClient}:${o.internalPort} ` +
    `${lease ? `lease ${lease}s` : 'permanent'} ok, external address ${externalIp || 'unknown'}`);
  return upnpResult(gw, o, { externalIp, leaseSeconds: lease, permanentOnly: lease === 0 && o.leaseSeconds !== 0 });
}

async function upnpDelete(gw, o, timeoutMs) {
  // Check the entry is still ours first, so a lapsed lease never deletes someone else's forward.
  try {
    const owner = await mappingOwner(gw, o, timeoutMs);
    if (owner.client && (owner.client !== gw.internalClient || owner.port !== o.internalPort)) {
      o.log(`upnp: external port ${o.externalPort} now belongs to ${owner.client}:${owner.port}; leaving it alone`);
      return;
    }
  } catch (e) {
    if (e.upnpCode === 714) { o.log(`upnp: mapping ${o.externalPort}/TCP already gone`); return; }
  }
  try {
    await soapCall(gw, 'DeletePortMapping', [['NewRemoteHost', ''], ['NewExternalPort', o.externalPort], ['NewProtocol', 'TCP']], timeoutMs);
  } catch (e) {
    if (e.upnpCode === 714) return;
    throw e;
  }
  o.log(`upnp: DeletePortMapping ${o.externalPort}/TCP ok`);
}

function upnpResult(gw, o, r) {
  let removing = null;
  return {
    method: 'upnp',
    externalIp: r.externalIp,
    externalPort: o.externalPort,
    internalClient: gw.internalClient,
    internalPort: o.internalPort,
    leaseSeconds: r.leaseSeconds,
    gateway: new URL(gw.controlURL).hostname,
    controlURL: gw.controlURL,
    warning: natWarning(r.externalIp),
    remove(ro = {}) {
      if (!removing) {
        removing = upnpDelete(gw, o, ro.timeoutMs || o.timeoutMs);
        removing.catch(() => { removing = null; });
      }
      return removing;
    },
    renew() { return upnpAdd(gw, o, { externalIp: r.externalIp, permanentOnly: r.permanentOnly, refreshIp: true }); },
  };
}

async function upnpMap(o) {
  const replies = await ssdpDiscover(o);
  const errs = [];
  for (const r of replies) {
    try {
      const gw = await loadGateway(r.location, o);
      o.log(`upnp: gateway ${gw.controlURL} (${gw.serviceType.replace(/^urn:schemas-upnp-org:service:/, '')}), this host is ${gw.internalClient}`);
      return await upnpAdd(gw, o, { externalIp: gw.externalIp });
    } catch (e) {
      if (e.code === 'EPORTCONFLICT') throw e;
      errs.push(`${r.location}: ${e.message}`);
    }
  }
  throw new Error(errs.join('; '));
}

/* --------------------------------------------------------------- NAT-PMP */

function natpmpRequest(o, gateway, req, expectOp, minLen, timeoutMs) {
  return new Promise((resolve, reject) => {
    const sock = dgram.createSocket('udp4');
    let done = false, rt = null, wait = 250, local = null;
    const finish = (err, val) => {
      if (done) return;
      done = true;
      clearTimeout(deadline); clearTimeout(rt);
      try { sock.close(); } catch { /* already closed */ }
      if (err) reject(err); else resolve(val);
    };
    const deadline = later(timeoutMs, () => finish(new Error(`gateway ${gateway} did not answer in ${secs(timeoutMs)}`)));
    sock.on('error', (e) => finish(new Error(`gateway ${gateway}: ${e.code === 'ECONNREFUSED' ? `port ${o.natpmpPort} closed (NAT-PMP not enabled)` : e.message}`)));
    sock.on('message', (msg) => {
      if (msg.length >= 4 && msg[1] === expectOp) {
        const rc = msg.readUInt16BE(2);
        if (rc !== 0) { finish(new Error(`gateway ${gateway} refused: result ${rc} ${NATPMP_RESULTS[rc] || ''}`.trim())); return; }
      }
      if (msg[0] !== 0 || msg[1] !== expectOp || msg.length < minLen) return;
      finish(null, { msg, local });
    });
    const send = () => {
      if (done) return;
      sock.send(req, (e) => { if (e) finish(new Error(`gateway ${gateway}: ${e.message}`)); });
      rt = later(wait, send);   // RFC 6886 retransmit: 250ms, doubling
      wait *= 2;
    };
    try {
      sock.connect(o.natpmpPort, gateway, () => {
        try { local = normIp(sock.address().address); } catch { /* closed */ }
        send();
      });
    } catch (e) { finish(new Error(`gateway ${gateway}: ${e.message}`)); }
  });
}

async function natpmpExternalIp(o, gateway) {
  const r = await natpmpRequest(o, gateway, Buffer.from([0, 0]), 128, 12, o.timeoutMs);
  return { externalIp: Array.from(r.msg.subarray(8, 12)).join('.'), local: r.local };
}

function natpmpMappingRequest(internalPort, externalPort, lifetime) {
  const b = Buffer.alloc(12);
  b[0] = 0; b[1] = 2;   // version 0, opcode 2 = map TCP
  b.writeUInt16BE(internalPort, 4);
  b.writeUInt16BE(externalPort, 6);
  b.writeUInt32BE(lifetime, 8);
  return b;
}

async function natpmpAdd(o, gateway, externalIp, suggestedPort) {
  // NAT-PMP lifetime 0 means delete, so a "permanent" request becomes the RFC's recommended 2 hours.
  const lifetime = o.leaseSeconds > 0 ? o.leaseSeconds : 7200;
  const r = await natpmpRequest(o, gateway, natpmpMappingRequest(o.internalPort, suggestedPort, lifetime), 130, 16, o.timeoutMs);
  const internalPort = r.msg.readUInt16BE(8), mapped = r.msg.readUInt16BE(10), granted = r.msg.readUInt32BE(12);
  if (internalPort !== o.internalPort) throw new Error(`gateway ${gateway} answered for internal port ${internalPort}, expected ${o.internalPort}`);
  if (!mapped || !granted) throw new Error(`gateway ${gateway} granted no mapping`);
  if (mapped !== o.externalPort) o.log(`natpmp: router assigned external port ${mapped} instead of ${o.externalPort}`);
  o.log(`natpmp: mapped ${mapped}/TCP -> ${r.local}:${o.internalPort} lifetime ${granted}s via ${gateway}, external address ${externalIp}`);
  let removing = null;
  return {
    method: 'natpmp',
    externalIp,
    externalPort: mapped,
    internalClient: r.local,
    internalPort: o.internalPort,
    leaseSeconds: granted,
    gateway,
    warning: natWarning(externalIp),
    remove(ro = {}) {
      if (!removing) {
        const t = Math.min(ro.timeoutMs || o.timeoutMs, o.timeoutMs);
        removing = natpmpRequest(o, gateway, natpmpMappingRequest(o.internalPort, 0, 0), 130, 16, t)
          .then(() => o.log(`natpmp: deleted mapping for internal port ${o.internalPort}`));
        removing.catch(() => { removing = null; });
      }
      return removing;
    },
    async renew() {
      const ext = await natpmpExternalIp(o, gateway);
      return natpmpAdd(o, gateway, ext.externalIp, mapped);
    },
  };
}

async function natpmpMap(o) {
  let gateway = o.gateway;
  if (!gateway) {
    try { gateway = await discoverGateway(o.timeoutMs); } catch (e) { throw new Error(`could not find the default gateway (${e.message}); NAT-PMP skipped`); }
  }
  if (!net.isIPv4(gateway)) throw new Error(`gateway ${gateway} is not an IPv4 address; NAT-PMP skipped`);
  const ext = await natpmpExternalIp(o, gateway);
  return natpmpAdd(o, gateway, ext.externalIp, o.externalPort);
}

/* --------------------------------------------------------------- public API */

const METHOD_LABEL = { upnp: 'UPnP', natpmp: 'NAT-PMP' };

function normalize(opts) {
  if (!opts || typeof opts !== 'object') throw new TypeError('portmap: an options object is required');
  const port = (v, name) => {
    const n = Number(v);
    if (!Number.isInteger(n) || n < 1 || n > 65535) throw new TypeError(`portmap: ${name} must be a port number 1-65535`);
    return n;
  };
  const internalPort = port(opts.internalPort, 'internalPort');
  const leaseSeconds = opts.leaseSeconds == null ? 3600 : Number(opts.leaseSeconds);
  if (!Number.isInteger(leaseSeconds) || leaseSeconds < 0 || leaseSeconds > 604800) {
    throw new TypeError('portmap: leaseSeconds must be an integer 0-604800');
  }
  const timeoutMs = opts.timeoutMs == null ? 4000 : Number(opts.timeoutMs);
  if (!(timeoutMs >= 50 && timeoutMs <= 60000)) throw new TypeError('portmap: timeoutMs must be 50-60000');
  const methods = opts.methods == null ? ['upnp', 'natpmp'] : opts.methods;
  if (!Array.isArray(methods) || !methods.length || methods.some((m) => !METHOD_LABEL[m])) {
    throw new TypeError("portmap: methods must be a non-empty list of 'upnp' and/or 'natpmp'");
  }
  for (const k of ['gateway', 'internalClient']) {
    if (opts[k] != null && !net.isIPv4(opts[k])) throw new TypeError(`portmap: ${k} must be an IPv4 address`);
  }
  const userLog = typeof opts.log === 'function' ? opts.log : noop;
  return {
    internalPort,
    externalPort: opts.externalPort == null ? internalPort : port(opts.externalPort, 'externalPort'),
    description: String(opts.description == null ? 'NodeSignal' : opts.description).replace(/[^\x20-\x7e]/g, '').slice(0, 64) || 'NodeSignal',
    leaseSeconds,
    timeoutMs,
    ssdpAddress: opts.ssdpAddress || '239.255.255.250',
    ssdpPort: opts.ssdpPort == null ? 1900 : port(opts.ssdpPort, 'ssdpPort'),
    natpmpPort: opts.natpmpPort == null ? 5351 : port(opts.natpmpPort, 'natpmpPort'),
    gateway: opts.gateway || null,
    internalClient: opts.internalClient || null,
    methods: [...methods],
    log: (m) => { try { userLog(m); } catch { /* a logger must never break mapping */ } },
  };
}

async function mapNormalized(o) {
  const attempts = [];
  for (const m of o.methods) {
    try {
      return m === 'upnp' ? await upnpMap(o) : await natpmpMap(o);
    } catch (e) {
      attempts.push({ method: m, message: e.message, code: e.code });
      o.log(`${m}: ${e.message}`);
    }
  }
  const err = new Error(`port mapping failed: ${attempts.map((a) => `${METHOD_LABEL[a.method]}: ${a.message}`).join('; ')}`);
  err.attempts = attempts;
  if (attempts.some((a) => a.code === 'EPORTCONFLICT')) err.code = 'EPORTCONFLICT';
  throw err;
}

// One-shot mapping. Tries each method in order and returns the first success.
async function map(opts) {
  return mapNormalized(normalize(opts));
}

// Long-running controller: map, renew, retry with backoff, remove on stop.
function start(opts) {
  const o = normalize(opts);
  const timing = { ...DEFAULT_TIMING, ...((opts && opts.timing) || {}) };
  if (!Array.isArray(timing.backoffMs) || !timing.backoffMs.length) timing.backoffMs = DEFAULT_TIMING.backoffMs;
  const onChange = typeof opts.onChange === 'function' ? opts.onChange : noop;
  const st = {
    state: 'mapping', method: null, externalIp: null, externalPort: null, internalClient: null,
    error: null, warning: null, lastOk: null, nextRenew: null,
  };
  const WATCHED = ['state', 'method', 'externalIp', 'externalPort', 'internalClient', 'error', 'warning'];
  let current = null, timer = null, inflight = null, stopping = null;
  let stopped = false, stopFinished = false, failures = 0;

  const status = () => ({ ...st });
  const emit = () => { try { onChange(status()); } catch (e) { o.log(`portmap: onChange threw: ${e.message}`); } };
  const set = (patch) => {
    let changed = false;
    for (const [k, v] of Object.entries(patch)) {
      if (WATCHED.includes(k) && st[k] !== v) changed = true;
      st[k] = v;
    }
    if (changed) emit();
  };
  const schedule = (ms) => {
    clearTimeout(timer);
    st.nextRenew = Date.now() + ms;
    timer = later(ms, () => { timer = null; run(); });
  };
  const ok = (r, verb) => {
    const renewMs = r.leaseSeconds > 0
      ? Math.max(timing.minRenewMs, Math.round(r.leaseSeconds * 1000 * timing.renewFraction))
      : timing.permanentRenewMs;
    failures = 0;
    st.lastOk = Date.now();
    schedule(renewMs);
    set({
      state: 'mapped', method: r.method, externalIp: r.externalIp, externalPort: r.externalPort,
      internalClient: r.internalClient, error: null, warning: r.warning || null,
    });
    o.log(`portmap: ${verb} ${r.externalIp || '?'}:${r.externalPort} -> ${r.internalClient}:${r.internalPort} via ${r.method}, ` +
      `${r.leaseSeconds ? `lease ${r.leaseSeconds}s` : 'permanent'}, next check in ${fmtDur(renewMs)}`);
    if (r.warning) o.log(`portmap: warning: ${r.warning}`);
  };
  const adopt = (r) => {   // a mapping finished after stop() gave up waiting: clean it up
    if (stopFinished) { r.remove({ timeoutMs: Math.min(o.timeoutMs, timing.stopTimeoutMs) }).catch(noop); return; }
    current = r;
  };

  async function cycle() {
    if (stopped) return;
    if (current) {
      try {
        const r = await current.renew();
        if (stopped) { adopt(r); return; }
        current = r;
        ok(r, 'renewed');
        return;
      } catch (e) {
        if (stopped) return;
        o.log(`portmap: renew failed (${e.message}); mapping again from scratch`);
        current = null;
      }
    }
    set({ state: 'mapping', error: null });
    try {
      const r = await mapNormalized(o);
      if (stopped) { adopt(r); return; }
      current = r;
      ok(r, 'mapped');
    } catch (e) {
      if (stopped) return;
      failures++;
      const b = timing.backoffMs;
      const wait = e.code === 'EPORTCONFLICT' ? b[b.length - 1] : b[Math.min(failures - 1, b.length - 1)];
      schedule(wait);
      set({ state: 'failed', method: null, externalIp: null, externalPort: null, internalClient: null, warning: null, error: e.message });
      o.log(`portmap: ${e.message}; retrying in ${fmtDur(wait)}`);
    }
  }
  function run() {
    inflight = cycle()
      .catch((e) => o.log(`portmap: internal error: ${e.message}`))
      .finally(() => { inflight = null; });
  }

  function stop() {
    if (stopping) return stopping;
    stopped = true;
    clearTimeout(timer);
    timer = null;
    stopping = (async () => {
      const work = (async () => {
        if (inflight) await inflight;
        const c = current;
        current = null;
        if (!c) return;
        try {
          await c.remove({ timeoutMs: Math.min(o.timeoutMs, timing.stopTimeoutMs) });
          o.log('portmap: mapping removed');
        } catch (e) { o.log(`portmap: could not remove the mapping (${e.message})`); }
      })();
      await Promise.race([work, sleep(timing.stopTimeoutMs)]);
      stopFinished = true;
      set({ state: 'stopped', method: null, externalIp: null, externalPort: null, internalClient: null, warning: null, error: null, nextRenew: null });
    })();
    return stopping;
  }

  queueMicrotask(() => { if (stopped) return; emit(); run(); });
  return { status, stop };
}

module.exports = {
  map,
  start,
  discoverGateway,
  parseSsdpResponse,
  parseDeviceDescription,
  buildSoapEnvelope,
  parseSoapResponse,
  parseProcNetRoute,
  parseRouteGetDefault,
  parseWindowsRoutePrint,
  parseIpRouteDefault,
  MAX_BODY,
  DEFAULT_TIMING,
};
