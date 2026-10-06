// portmap.test.js: UPnP IGD + NAT-PMP port mapping against local mocks. Plain node, no deps.
//   node tests/portmap.test.js
// Never touches a real router: every test sets `methods` explicitly and points
// SSDP at a mock on 127.0.0.1 and NAT-PMP at a mock gateway 127.0.0.1.
'use strict';
const assert = require('assert');
const dgram = require('dgram');
const http = require('http');
const path = require('path');
const fs = require('fs');
const cp = require('child_process');
const portmap = require('../portmap.js');

let failed = 0;
const tests = [];
const test = (name, fn) => tests.push({ name, fn });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const until = async (cond, ms = 3000, what = 'condition') => {
  const end = Date.now() + ms;
  while (!cond()) { if (Date.now() > end) throw new Error('timed out waiting for ' + what); await sleep(10); }
};

/* ------------------------------------------------------------ fixtures */

const DESC = (opts = {}) => `<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <specVersion><major>1</major><minor>0</minor></specVersion>
  ${opts.urlBase ? `<URLBase>${opts.urlBase}</URLBase>` : ''}
  <!-- <controlURL>/decoy-in-comment</controlURL> -->
  <device>
    <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:${opts.v || 1}</deviceType>
    <friendlyName>Mock Router &amp; Co</friendlyName>
    <serviceList>
      <service>
        <serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType>
        <serviceId>urn:upnp-org:serviceId:L3Forwarding1</serviceId>
        <controlURL>/ctl/L3F</controlURL>
      </service>
    </serviceList>
    <deviceList>
      <device>
        <deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
        <serviceList>
          <service>
            <serviceType>urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1</serviceType>
            <controlURL>/ctl/CmnIfCfg</controlURL>
          </service>
        </serviceList>
        <deviceList>
          <device>
            <deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
            <serviceList>
              <service>
                <serviceType>urn:schemas-upnp-org:service:WANIPConnection:${opts.v || 1}</serviceType>
                <serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId>
                <SCPDURL>/WANIPCn.xml</SCPDURL>
                <controlURL>${opts.controlURL || '/ctl/IPConn'}</controlURL>
                <eventSubURL>/evt/IPConn</eventSubURL>
              </service>
            </serviceList>
          </device>
        </deviceList>
      </device>
    </deviceList>
  </device>
</root>`;

const soapOk = (action, st, inner = '') =>
  `<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:${action}Response xmlns:u="${st}">${inner}</u:${action}Response></s:Body></s:Envelope>`;
const soapFault = (code, desc) =>
  `<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><s:Fault><faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring><detail><UPnPError xmlns="urn:schemas-upnp-org:control-1-0"><errorCode>${code}</errorCode><errorDescription>${desc}</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>`;

// Mock IGD: SSDP responder (UDP, 127.0.0.1, random port) + HTTP description and SOAP control.
async function startIgd(cfg = {}) {
  const igd = {
    cfg, calls: [], searches: [], mappings: new Map(), extIp: '203.0.113.7',
    descPath: cfg.descPath || '/rootDesc.xml',
    handlers: {},   // action -> (args, call) => {status, body} | undefined (fall through to default)
  };
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      const port = server.address().port;
      if (req.method === 'GET' && req.url === igd.descPath) {
        const xml = typeof cfg.desc === 'function' ? cfg.desc(port) : DESC(cfg.descOpts || {});
        res.writeHead(200, { 'Content-Type': 'text/xml' });
        res.end(xml);
        return;
      }
      if (req.method === 'POST') {
        const sa = String(req.headers.soapaction || '').replace(/"/g, '');
        const action = sa.split('#')[1];
        const st = sa.split('#')[0];
        const args = {};
        for (const m of body.matchAll(/<(New\w+)>([^<]*)<\/\1>/g)) args[m[1]] = m[2];
        for (const m of body.matchAll(/<(New\w+)\/>/g)) args[m[1]] = '';
        const call = { action, args, path: req.url, soapAction: sa, contentType: req.headers['content-type'], remote: req.socket.remoteAddress };
        igd.calls.push(call);
        const custom = igd.handlers[action] && igd.handlers[action](args, call);
        const send = (status, xml) => { res.writeHead(status, { 'Content-Type': 'text/xml; charset="utf-8"' }); res.end(xml); };
        if (custom) return send(custom.status, custom.body);
        const key = `${args.NewExternalPort}/${args.NewProtocol}`;
        switch (action) {
          case 'GetExternalIPAddress':
            return send(200, soapOk(action, st, `<NewExternalIPAddress>${igd.extIp}</NewExternalIPAddress>`));
          case 'AddPortMapping': {
            const cur = igd.mappings.get(key);
            if (cur && cur.client !== args.NewInternalClient) return send(500, soapFault(718, 'ConflictInMappingEntry'));
            igd.mappings.set(key, { client: args.NewInternalClient, port: args.NewInternalPort, lease: args.NewLeaseDuration, desc: args.NewPortMappingDescription });
            return send(200, soapOk(action, st));
          }
          case 'GetSpecificPortMappingEntry': {
            const cur = igd.mappings.get(key);
            if (!cur) return send(500, soapFault(714, 'NoSuchEntryInArray'));
            return send(200, soapOk(action, st, `<NewInternalPort>${cur.port}</NewInternalPort><NewInternalClient>${cur.client}</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>${cur.desc}</NewPortMappingDescription><NewLeaseDuration>${cur.lease}</NewLeaseDuration>`));
          }
          case 'DeletePortMapping':
            if (!igd.mappings.delete(key)) return send(500, soapFault(714, 'NoSuchEntryInArray'));
            return send(200, `<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:DeletePortMappingResponse xmlns:u="${st}"/></s:Body></s:Envelope>`);
          default:
            return send(500, soapFault(401, 'Invalid Action'));
        }
      }
      res.writeHead(404); res.end();
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const udp = dgram.createSocket('udp4');
  udp.on('message', (msg, rinfo) => {
    const text = msg.toString();
    igd.searches.push(text);
    if (cfg.silent) return;
    const st = (/^ST:\s*(.+)$/mi.exec(text) || [])[1];
    if (!st || !/InternetGatewayDevice:1/.test(st)) return;   // answer one target, like many routers
    const location = cfg.location || `http://127.0.0.1:${server.address().port}${igd.descPath}`;
    const reply = `HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nST: ${st.trim()}\r\nUSN: uuid:00000000-0000-0000-0000-000000000001::${st.trim()}\r\nEXT:\r\nSERVER: Mock/1.0 UPnP/1.0 MiniUPnPd/2.3\r\nLOCATION: ${location}\r\n\r\n`;
    udp.send(reply, rinfo.port, rinfo.address);
  });
  await new Promise((r) => udp.bind(0, '127.0.0.1', r));
  igd.ssdpPort = udp.address().port;
  igd.httpPort = server.address().port;
  igd.opts = (extra = {}) => ({ internalPort: 8788, methods: ['upnp'], ssdpAddress: '127.0.0.1', ssdpPort: igd.ssdpPort, timeoutMs: 1500, ...extra });
  igd.count = (action) => igd.calls.filter((c) => c.action === action).length;
  igd.close = () => { try { udp.close(); } catch {} server.close(); };
  cleanup.push(igd.close);
  return igd;
}

// Mock NAT-PMP gateway on 127.0.0.1 (random port).
async function startNatpmp(cfg = {}) {
  const gw = { reqs: [], silent: false, extIp: '203.0.113.7', epoch: 1000, assignPort: cfg.assignPort || null };
  const udp = dgram.createSocket('udp4');
  udp.on('message', (msg, rinfo) => {
    gw.reqs.push(Buffer.from(msg));
    if (gw.silent || msg[0] !== 0) return;
    if (msg[1] === 0 && msg.length >= 2) {
      const r = Buffer.alloc(12);
      r[0] = 0; r[1] = 128; r.writeUInt16BE(0, 2); r.writeUInt32BE(gw.epoch, 4);
      gw.extIp.split('.').forEach((o, i) => { r[8 + i] = Number(o); });
      udp.send(r, rinfo.port, rinfo.address);
    } else if (msg[1] === 2 && msg.length >= 12) {
      const internal = msg.readUInt16BE(4), ext = msg.readUInt16BE(6), life = msg.readUInt32BE(8);
      const r = Buffer.alloc(16);
      r[0] = 0; r[1] = 130; r.writeUInt16BE(0, 2); r.writeUInt32BE(gw.epoch, 4);
      r.writeUInt16BE(internal, 8);
      r.writeUInt16BE(life === 0 ? 0 : (gw.assignPort || ext), 10);
      r.writeUInt32BE(life === 0 ? 0 : Math.min(life, 3600), 12);
      udp.send(r, rinfo.port, rinfo.address);
    }
  });
  await new Promise((r) => udp.bind(0, '127.0.0.1', r));
  gw.port = udp.address().port;
  gw.opts = (extra = {}) => ({ internalPort: 8788, methods: ['natpmp'], gateway: '127.0.0.1', natpmpPort: gw.port, timeoutMs: 1000, ...extra });
  gw.close = () => { try { udp.close(); } catch {} };
  cleanup.push(gw.close);
  return gw;
}

// A UDP port that is bound but never answers (no ICMP refusal, so a true timeout).
async function silentUdp() {
  const s = dgram.createSocket('udp4');
  await new Promise((r) => s.bind(0, '127.0.0.1', r));
  cleanup.push(() => { try { s.close(); } catch {} });
  return s.address().port;
}

let cleanup = [];

/* ------------------------------------------------------------ pure helpers */

test('parseSsdpResponse reads status and headers case-insensitively', () => {
  const r = portmap.parseSsdpResponse('HTTP/1.1 200 OK\r\nCache-Control: max-age=120\r\nst: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nUSN: uuid:x::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nLocation: http://192.0.2.1:5000/rootDesc.xml\r\nServer: Linux UPnP/1.0\r\n\r\n');
  assert.strictEqual(r.statusCode, 200);
  assert.strictEqual(r.location, 'http://192.0.2.1:5000/rootDesc.xml');
  assert.strictEqual(r.st, 'urn:schemas-upnp-org:device:InternetGatewayDevice:1');
  assert.strictEqual(r.server, 'Linux UPnP/1.0');
  assert.strictEqual(portmap.parseSsdpResponse('M-SEARCH * HTTP/1.1\r\n\r\n'), null);
  assert.strictEqual(portmap.parseSsdpResponse('x'.repeat(9000)), null);
  const p = portmap.parseSsdpResponse('HTTP/1.1 200 OK\r\n__proto__: polluted\r\n\r\n');
  assert.strictEqual(({}).polluted, undefined);
  assert.strictEqual(Object.getPrototypeOf(p.headers), Object.prototype);
});

test('parseDeviceDescription finds the nested WAN service and resolves relative controlURL', () => {
  const d = portmap.parseDeviceDescription(DESC(), 'http://192.0.2.1:5000/rootDesc.xml');
  assert.strictEqual(d.serviceType, 'urn:schemas-upnp-org:service:WANIPConnection:1');
  assert.strictEqual(d.controlURL, 'http://192.0.2.1:5000/ctl/IPConn');
  const raw = portmap.parseDeviceDescription(DESC());
  assert.strictEqual(raw.controlURL, '/ctl/IPConn');
});

test('parseDeviceDescription honours URLBase for a path-relative controlURL', () => {
  const d = portmap.parseDeviceDescription(DESC({ urlBase: 'http://192.0.2.1:49000/base/', controlURL: 'upnp/control/WANIPConn1' }), 'http://192.0.2.1:5000/igd.xml');
  assert.strictEqual(d.controlURL, 'http://192.0.2.1:49000/base/upnp/control/WANIPConn1');
  assert.strictEqual(d.urlBase, 'http://192.0.2.1:49000/base/');
});

test('parseDeviceDescription prefers WANIPConnection:2 and also accepts PPP-only devices', () => {
  const v2 = portmap.parseDeviceDescription(DESC({ v: 2 }), 'http://192.0.2.1/x.xml');
  assert.strictEqual(v2.serviceType, 'urn:schemas-upnp-org:service:WANIPConnection:2');
  const ppp = DESC().replace('WANIPConnection:1', 'WANPPPConnection:1').replace('/ctl/IPConn', '/ctl/PPPConn');
  const d = portmap.parseDeviceDescription(ppp, 'http://192.0.2.1/x.xml');
  assert.strictEqual(d.serviceType, 'urn:schemas-upnp-org:service:WANPPPConnection:1');
  assert.strictEqual(d.controlURL, 'http://192.0.2.1/ctl/PPPConn');
  const both = DESC().replace('</serviceList>\n          </device>', `<service><serviceType>urn:schemas-upnp-org:service:WANPPPConnection:1</serviceType><controlURL>/ctl/PPP</controlURL></service></serviceList>\n          </device>`);
  assert.deepStrictEqual(portmap.parseDeviceDescription(both, 'http://192.0.2.1/x.xml').candidates.map((c) => c.controlURL),
    ['http://192.0.2.1/ctl/IPConn', 'http://192.0.2.1/ctl/PPP']);
});

test('parseDeviceDescription rejects malformed, foreign-host, non-IGD and oversized XML', () => {
  assert.throws(() => portmap.parseDeviceDescription('<root><device>', 'http://192.0.2.1/'), /malformed/);
  assert.throws(() => portmap.parseDeviceDescription('not xml at all', 'http://192.0.2.1/'), /malformed/);
  assert.throws(() => portmap.parseDeviceDescription(DESC().slice(0, 900), 'http://192.0.2.1/'), /malformed/);
  assert.throws(() => portmap.parseDeviceDescription(DESC().replace(/WANIPConnection/g, 'Printer'), 'http://192.0.2.1/'), /not an internet gateway/);
  assert.throws(() => portmap.parseDeviceDescription(DESC({ controlURL: 'http://198.51.100.9/ctl' }), 'http://192.0.2.1/'), /differs/);
  assert.throws(() => portmap.parseDeviceDescription(DESC({ controlURL: 'file:///etc/passwd' }), 'http://192.0.2.1/'), /not http/);
  const big = DESC().replace('<specVersion>', '<!--' + 'x'.repeat(300 * 1024) + '--><specVersion>');
  assert.throws(() => portmap.parseDeviceDescription(big, 'http://192.0.2.1/'), /too large/);
  assert.throws(() => portmap.parseDeviceDescription(null), /not text/);
});

test('buildSoapEnvelope orders and escapes arguments', () => {
  const xml = portmap.buildSoapEnvelope('urn:schemas-upnp-org:service:WANIPConnection:1', 'AddPortMapping',
    [['NewRemoteHost', ''], ['NewExternalPort', 8788], ['NewPortMappingDescription', 'a<b>&"c\'']]);
  assert(xml.includes('<u:AddPortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">'));
  assert(xml.indexOf('<NewRemoteHost>') < xml.indexOf('<NewExternalPort>8788</NewExternalPort>'));
  assert(xml.includes('<NewPortMappingDescription>a&lt;b&gt;&amp;&quot;c&apos;</NewPortMappingDescription>'));
  assert(xml.includes('<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"'));
  assert.throws(() => portmap.buildSoapEnvelope('urn:x" onload="', 'A'), /serviceType/);
  assert.throws(() => portmap.buildSoapEnvelope('urn:x:y', 'A', [['bad name', 1]]), /argument/);
});

test('parseSoapResponse returns values, faults, and rejects junk', () => {
  const st = 'urn:schemas-upnp-org:service:WANIPConnection:1';
  assert.deepStrictEqual(portmap.parseSoapResponse(soapOk('GetExternalIPAddress', st, '<NewExternalIPAddress>203.0.113.7</NewExternalIPAddress>'), 'GetExternalIPAddress'),
    { NewExternalIPAddress: '203.0.113.7' });
  assert.deepStrictEqual(portmap.parseSoapResponse(soapOk('GetSpecificPortMappingEntry', st, '<NewInternalPort>8788</NewInternalPort><NewInternalClient>192.0.2.20</NewInternalClient><NewPortMappingDescription>A &amp; B</NewPortMappingDescription><NewRemoteHost/>')),
    { NewInternalPort: '8788', NewInternalClient: '192.0.2.20', NewPortMappingDescription: 'A & B', NewRemoteHost: '' });
  assert.deepStrictEqual(portmap.parseSoapResponse(soapOk('AddPortMapping', st), 'AddPortMapping'), {});
  assert.deepStrictEqual(portmap.parseSoapResponse(`<s:Envelope xmlns:s="x"><s:Body><u:DeletePortMappingResponse xmlns:u="y"/></s:Body></s:Envelope>`, 'DeletePortMapping'), {});
  assert.deepStrictEqual(portmap.parseSoapResponse(soapFault(725, 'OnlyPermanentLeasesSupported')), { errorCode: 725, errorDescription: 'OnlyPermanentLeasesSupported' });
  assert.throws(() => portmap.parseSoapResponse('<html>404</html>', 'AddPortMapping'), /malformed/);
  assert.throws(() => portmap.parseSoapResponse('<s:Envelope><s:Body></s:Body></s:Envelope>', 'AddPortMapping'), /no AddPortMappingResponse/);
  assert.throws(() => portmap.parseSoapResponse('<s:Envelope>' + 'x'.repeat(300 * 1024)), /too large/);
});

test('parseProcNetRoute picks the lowest-metric default gateway', () => {
  const sample = [
    'Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT',
    'wlan0\t00000000\t016433C6\t0003\t0\t0\t600\t00000000\t0\t0\t0',
    'eth0\t00000000\t010200C0\t0003\t0\t0\t100\t00000000\t0\t0\t0',
    'eth0\t000200C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0',
    'tun0\t00000000\t00000000\t0001\t0\t0\t50\t00000000\t0\t0\t0',
    'down0\t00000000\t017100CB\t0002\t0\t0\t1\t00000000\t0\t0\t0',
  ].join('\n');
  assert.deepStrictEqual(portmap.parseProcNetRoute(sample, 'LE'), [
    { iface: 'eth0', gateway: '192.0.2.1', metric: 100 },
    { iface: 'wlan0', gateway: '198.51.100.1', metric: 600 },
  ]);
  assert.strictEqual(portmap.parseProcNetRoute(sample, 'BE')[0].gateway, '1.2.0.192');
  assert.deepStrictEqual(portmap.parseProcNetRoute(''), []);
});

test('macOS/BSD, Windows and ip(8) route output parsers', () => {
  assert.strictEqual(portmap.parseRouteGetDefault('   route to: default\ndestination: default\n       mask: default\n    gateway: 192.0.2.1\n  interface: en0\n'), '192.0.2.1');
  assert.strictEqual(portmap.parseRouteGetDefault('route: writing to routing socket: not in table'), null);
  const win = [
    'IPv4 Route Table', '===========================================================================', 'Active Routes:',
    'Network Destination        Netmask          Gateway       Interface  Metric',
    '          0.0.0.0          0.0.0.0     198.51.100.1    198.51.100.20     50',
    '          0.0.0.0          0.0.0.0        192.0.2.1       192.0.2.20     25',
    '===========================================================================', 'Persistent Routes:', '  None',
  ].join('\r\n');
  assert.strictEqual(portmap.parseWindowsRoutePrint(win), '192.0.2.1');
  assert.strictEqual(portmap.parseIpRouteDefault('default via 192.0.2.1 dev eth0 proto dhcp metric 100\n'), '192.0.2.1');
});

test('options are validated', async () => {
  await assert.rejects(portmap.map({}), /internalPort/);
  await assert.rejects(portmap.map({ internalPort: 8788, methods: ['stratum'] }), /methods/);
  await assert.rejects(portmap.map({ internalPort: 8788, leaseSeconds: -1, methods: ['upnp'] }), /leaseSeconds/);
  await assert.rejects(portmap.map({ internalPort: 8788, gateway: 'router.lan', methods: ['natpmp'] }), /gateway/);
});

/* ------------------------------------------------------------ UPnP against the mock IGD */

test('UPnP map: correct SOAP fields, external IP, M-SEARCH targets', async () => {
  const igd = await startIgd();
  const logs = [];
  const r = await portmap.map(igd.opts({ description: 'NodeSignal test', leaseSeconds: 1800, log: (m) => logs.push(m) }));
  assert.strictEqual(r.method, 'upnp');
  assert.strictEqual(r.externalIp, '203.0.113.7');
  assert.strictEqual(r.externalPort, 8788);
  assert.strictEqual(r.internalClient, '127.0.0.1');
  assert.strictEqual(r.leaseSeconds, 1800);
  assert.strictEqual(r.warning, null);
  assert.strictEqual(typeof r.remove, 'function');
  assert.strictEqual(typeof r.renew, 'function');
  const add = igd.calls.find((c) => c.action === 'AddPortMapping');
  assert.deepStrictEqual(add.args, {
    NewRemoteHost: '', NewExternalPort: '8788', NewProtocol: 'TCP', NewInternalPort: '8788',
    NewInternalClient: '127.0.0.1', NewEnabled: '1', NewPortMappingDescription: 'NodeSignal test', NewLeaseDuration: '1800',
  });
  assert.strictEqual(add.path, '/ctl/IPConn');
  assert.strictEqual(add.soapAction, 'urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping');
  assert(/text\/xml/.test(add.contentType));
  assert(igd.calls.findIndex((c) => c.action === 'GetExternalIPAddress') < igd.calls.indexOf(add), 'external IP read first');
  const s = igd.searches.join('\n');
  for (const st of ['InternetGatewayDevice:1', 'InternetGatewayDevice:2', 'WANIPConnection:1', 'WANIPConnection:2', 'WANPPPConnection:1']) assert(s.includes(st), st);
  assert(/MAN: "ssdp:discover"/.test(s) && /^M-SEARCH \* HTTP\/1\.1/m.test(s));
  assert(logs.some((l) => /AddPortMapping 8788\/TCP -> 127\.0\.0\.1:8788 lease 1800s ok/.test(l)), logs.join('\n'));
});

test('UPnP map honours externalPort and URLBase', async () => {
  const igd = await startIgd({ desc: (port) => DESC({ urlBase: `http://127.0.0.1:${port}/base/`, controlURL: 'ctl/IPConn' }) });
  igd.handlers.AddPortMapping = (a, call) => (call.path === '/base/ctl/IPConn' ? undefined : { status: 404, body: '' });
  const r = await portmap.map(igd.opts({ externalPort: 18788 }));
  assert.strictEqual(r.externalPort, 18788);
  assert.strictEqual(r.controlURL, `http://127.0.0.1:${igd.httpPort}/base/ctl/IPConn`);
  const add = igd.calls.find((c) => c.action === 'AddPortMapping');
  assert.strictEqual(add.args.NewExternalPort, '18788');
  assert.strictEqual(add.args.NewInternalPort, '8788');
});

test('remove() sends DeletePortMapping (once) after checking ownership', async () => {
  const igd = await startIgd();
  const r = await portmap.map(igd.opts());
  assert.strictEqual(igd.mappings.size, 1);
  await r.remove();
  await r.remove();
  const del = igd.calls.filter((c) => c.action === 'DeletePortMapping');
  assert.strictEqual(del.length, 1);
  assert.deepStrictEqual(del[0].args, { NewRemoteHost: '', NewExternalPort: '8788', NewProtocol: 'TCP' });
  assert.strictEqual(igd.mappings.size, 0);
});

test('remove() leaves a forward that now belongs to someone else', async () => {
  const igd = await startIgd();
  const r = await portmap.map(igd.opts());
  igd.mappings.set('8788/TCP', { client: '127.0.0.99', port: '8788', lease: '0', desc: 'other' });
  await r.remove();
  assert.strictEqual(igd.count('DeletePortMapping'), 0);
  assert.strictEqual(igd.mappings.get('8788/TCP').client, '127.0.0.99');
});

test('UPnP 725 OnlyPermanentLeasesSupported retries with lease 0', async () => {
  const igd = await startIgd();
  igd.handlers.AddPortMapping = (a) => (a.NewLeaseDuration !== '0' ? { status: 500, body: soapFault(725, 'OnlyPermanentLeasesSupported') } : undefined);
  const logs = [];
  const r = await portmap.map(igd.opts({ leaseSeconds: 3600, log: (m) => logs.push(m) }));
  assert.strictEqual(r.leaseSeconds, 0);
  assert.deepStrictEqual(igd.calls.filter((c) => c.action === 'AddPortMapping').map((c) => c.args.NewLeaseDuration), ['3600', '0']);
  assert(logs.some((l) => /725/.test(l) && /lease 0/.test(l)));
  // renew keeps using lease 0 without another failed attempt
  const r2 = await r.renew();
  assert.strictEqual(r2.leaseSeconds, 0);
  assert.deepStrictEqual(igd.calls.filter((c) => c.action === 'AddPortMapping').map((c) => c.args.NewLeaseDuration), ['3600', '0', '0']);
  await r2.remove();
  assert.strictEqual(igd.count('DeletePortMapping'), 1);
});

test('UPnP 718 conflict with another host is reported, not retried or stolen', async () => {
  const igd = await startIgd();
  igd.mappings.set('8788/TCP', { client: '127.0.0.99', port: '8788', lease: '0', desc: 'someone else' });
  const err = await portmap.map(igd.opts()).then(() => null, (e) => e);
  assert(err, 'should fail');
  assert.strictEqual(err.code, 'EPORTCONFLICT');
  assert(/already forwarded to 127\.0\.0\.99:8788/.test(err.message), err.message);
  assert(/718/.test(err.message) && /not taking it over/.test(err.message));
  assert.strictEqual(igd.count('AddPortMapping'), 1);
  assert.strictEqual(igd.count('DeletePortMapping'), 0);
  assert.strictEqual(igd.mappings.get('8788/TCP').client, '127.0.0.99');
});

test('UPnP 718 on our own stale entry is replaced once', async () => {
  const igd = await startIgd();
  igd.mappings.set('8788/TCP', { client: '127.0.0.1', port: '8788', lease: '60', desc: 'NodeSignal' });
  let first = true;
  igd.handlers.AddPortMapping = () => (first ? ((first = false), { status: 500, body: soapFault(718, 'ConflictInMappingEntry') }) : undefined);
  const r = await portmap.map(igd.opts());
  assert.strictEqual(r.method, 'upnp');
  assert.strictEqual(igd.count('AddPortMapping'), 2);
  assert.strictEqual(igd.count('DeletePortMapping'), 1);
});

test('other UPnP faults surface the code and description', async () => {
  const igd = await startIgd();
  igd.handlers.AddPortMapping = () => ({ status: 500, body: soapFault(606, 'Action not authorized') });
  await assert.rejects(portmap.map(igd.opts()), /UPnP: .*AddPortMapping failed: UPnP error 606 Action not authorized/);
});

test('malformed and oversized device descriptions are rejected over HTTP', async () => {
  const bad = await startIgd({ desc: () => '<root><device><serviceList>' });
  await assert.rejects(portmap.map(bad.opts()), /malformed device description/);
  const big = await startIgd({ desc: () => DESC() + ' '.repeat(300 * 1024) });
  await assert.rejects(portmap.map(big.opts()), /too large/);
  assert.strictEqual(bad.count('AddPortMapping') + big.count('AddPortMapping'), 0);
});

test('oversized SOAP response is rejected', async () => {
  const igd = await startIgd();
  igd.handlers.GetExternalIPAddress = () => ({ status: 200, body: 'x'.repeat(300 * 1024) });
  igd.handlers.AddPortMapping = () => ({ status: 200, body: '<s:Envelope>' + 'y'.repeat(300 * 1024) + '</s:Envelope>' });
  await assert.rejects(portmap.map(igd.opts()), /AddPortMapping|too large/);
});

test('SSDP timeout gives a clear error', async () => {
  const port = await silentUdp();
  const t0 = Date.now();
  const err = await portmap.map({ internalPort: 8788, methods: ['upnp'], ssdpAddress: '127.0.0.1', ssdpPort: port, timeoutMs: 500 }).then(() => null, (e) => e);
  assert(err);
  assert.strictEqual(err.message, 'port mapping failed: UPnP: no gateway answered the SSDP search in 0.5s');
  assert(Date.now() - t0 < 1500);
});

test('SSDP reply pointing off the local network is ignored', async () => {
  const igd = await startIgd({ location: 'http://203.0.113.50/rootDesc.xml' });
  const err = await portmap.map(igd.opts({ timeoutMs: 500 })).then(() => null, (e) => e);
  assert(/no gateway answered.*ignored 1 reply.*not a local http address/.test(err.message), err.message);
});

test('both methods failing names each one', async () => {
  const s = await silentUdp();
  const n = await silentUdp();
  const err = await portmap.map({ internalPort: 8788, methods: ['upnp', 'natpmp'], ssdpAddress: '127.0.0.1', ssdpPort: s, gateway: '127.0.0.1', natpmpPort: n, timeoutMs: 400 }).then(() => null, (e) => e);
  assert.strictEqual(err.message, 'port mapping failed: UPnP: no gateway answered the SSDP search in 0.4s; NAT-PMP: gateway 127.0.0.1 did not answer in 0.4s');
  assert.deepStrictEqual(err.attempts.map((a) => a.method), ['upnp', 'natpmp']);
});

test('UPnP failure falls back to NAT-PMP', async () => {
  const s = await silentUdp();
  const gw = await startNatpmp();
  const r = await portmap.map(gw.opts({ methods: ['upnp', 'natpmp'], ssdpAddress: '127.0.0.1', ssdpPort: s, timeoutMs: 400 }));
  assert.strictEqual(r.method, 'natpmp');
  await r.remove();
});

/* ------------------------------------------------------------ NAT-PMP against the mock gateway */

test('NAT-PMP: external address, mapping request fields, delete', async () => {
  const gw = await startNatpmp();
  const r = await portmap.map(gw.opts({ leaseSeconds: 1200 }));
  assert.strictEqual(r.method, 'natpmp');
  assert.strictEqual(r.externalIp, '203.0.113.7');
  assert.strictEqual(r.externalPort, 8788);
  assert.strictEqual(r.internalClient, '127.0.0.1');
  assert.strictEqual(r.leaseSeconds, 1200);
  assert.strictEqual(r.gateway, '127.0.0.1');
  assert.deepStrictEqual([...gw.reqs[0]], [0, 0]);
  const m = gw.reqs[1];
  assert.strictEqual(m.length, 12);
  assert.deepStrictEqual([m[0], m[1], m.readUInt16BE(2)], [0, 2, 0]);
  assert.deepStrictEqual([m.readUInt16BE(4), m.readUInt16BE(6), m.readUInt32BE(8)], [8788, 8788, 1200]);
  await r.remove();
  const d = gw.reqs[2];
  assert.deepStrictEqual([d[1], d.readUInt16BE(4), d.readUInt16BE(6), d.readUInt32BE(8)], [2, 8788, 0, 0]);
});

test('NAT-PMP: router-assigned port and granted lifetime are reported; renew re-requests it', async () => {
  const gw = await startNatpmp({ assignPort: 40000 });
  const logs = [];
  const r = await portmap.map(gw.opts({ leaseSeconds: 7200, log: (m) => logs.push(m) }));
  assert.strictEqual(r.externalPort, 40000);
  assert.strictEqual(r.leaseSeconds, 3600);
  assert(logs.some((l) => /assigned external port 40000 instead of 8788/.test(l)));
  const r2 = await r.renew();
  assert.strictEqual(r2.externalPort, 40000);
  assert.strictEqual(gw.reqs[gw.reqs.length - 1].readUInt16BE(6), 40000, 'renew suggests the port we hold');
});

test('NAT-PMP: lease 0 is never sent as lifetime 0 (that would delete)', async () => {
  const gw = await startNatpmp();
  await portmap.map(gw.opts({ leaseSeconds: 0 }));
  assert.strictEqual(gw.reqs[1].readUInt32BE(8), 7200);
});

test('NAT-PMP: error result codes are explained', async () => {
  const gw = await startNatpmp();
  gw.silent = true;
  const port = gw.port;
  const udp = dgram.createSocket('udp4');
  udp.on('message', (msg, rinfo) => { const r = Buffer.alloc(8); r[1] = msg[1] + 128; r.writeUInt16BE(2, 2); udp.send(r, rinfo.port, rinfo.address); });
  await new Promise((r) => udp.bind(0, '127.0.0.1', r));
  cleanup.push(() => udp.close());
  await assert.rejects(portmap.map({ internalPort: 8788, methods: ['natpmp'], gateway: '127.0.0.1', natpmpPort: udp.address().port, timeoutMs: 800 }),
    /NAT-PMP: gateway 127\.0\.0\.1 refused: result 2 not authorized/);
  assert(port);
});

/* ------------------------------------------------------------ controller */

test('controller maps, renews, recovers from failure, and stop() deletes once', async () => {
  const igd = await startIgd();
  const states = [];
  const ctl = portmap.start(igd.opts({
    leaseSeconds: 1, timeoutMs: 400,
    timing: { renewFraction: 0.2, minRenewMs: 50, backoffMs: [60, 120] },
    onChange: (s) => states.push(s),
  }));
  assert.strictEqual(ctl.status().state, 'mapping');
  await until(() => ctl.status().state === 'mapped', 3000, 'mapped');
  const s = ctl.status();
  assert.strictEqual(s.method, 'upnp');
  assert.strictEqual(s.externalIp, '203.0.113.7');
  assert.strictEqual(s.externalPort, 8788);
  assert.strictEqual(s.internalClient, '127.0.0.1');
  assert.strictEqual(s.error, null);
  assert(s.lastOk > 0 && s.nextRenew > s.lastOk);
  // renews at about 0.2 x 1s
  await until(() => igd.count('AddPortMapping') >= 3, 3000, 'renewals');
  // router starts refusing: renew fails, full re-map fails, controller reports failed
  igd.handlers.AddPortMapping = () => ({ status: 500, body: soapFault(501, 'ActionFailed') });
  await until(() => ctl.status().state === 'failed', 3000, 'failed');
  assert(/ActionFailed/.test(ctl.status().error));
  // router recovers: backoff retry maps again
  delete igd.handlers.AddPortMapping;
  await until(() => ctl.status().state === 'mapped', 3000, 'mapped again');
  const seq = states.map((x) => x.state).filter((x, i, a) => x !== a[i - 1]);
  assert.deepStrictEqual(seq.slice(0, 5), ['mapping', 'mapped', 'mapping', 'failed', 'mapping'], seq.join(','));
  assert.strictEqual(seq[seq.length - 1], 'mapped');
  const delBefore = igd.count('DeletePortMapping');
  await Promise.all([ctl.stop(), ctl.stop()]);
  await ctl.stop();
  assert.strictEqual(igd.count('DeletePortMapping') - delBefore, 1);
  assert.strictEqual(ctl.status().state, 'stopped');
  assert.strictEqual(states[states.length - 1].state, 'stopped');
  assert.strictEqual(igd.mappings.size, 0);
  const n = igd.calls.length;
  await sleep(300);
  assert.strictEqual(igd.calls.length, n, 'no activity after stop');
});

test('controller conflict uses the longest backoff', async () => {
  const igd = await startIgd();
  igd.mappings.set('8788/TCP', { client: '127.0.0.99', port: '8788', lease: '0', desc: 'other' });
  const ctl = portmap.start(igd.opts({ timeoutMs: 400, timing: { backoffMs: [50, 100, 5000] } }));
  await until(() => ctl.status().state === 'failed', 3000, 'failed');
  assert(/already forwarded/.test(ctl.status().error));
  const wait = ctl.status().nextRenew - Date.now();
  assert(wait > 3000, 'expected the 5s backoff, got ' + wait);
  await sleep(200);
  assert.strictEqual(igd.count('AddPortMapping'), 1, 'no retry loop');
  await ctl.stop();
  assert.strictEqual(igd.count('DeletePortMapping'), 0);
});

test('controller stop() finishes quickly when the router is gone', async () => {
  const gw = await startNatpmp();
  const ctl = portmap.start(gw.opts({ timeoutMs: 4000 }));
  await until(() => ctl.status().state === 'mapped', 3000, 'mapped');
  assert.strictEqual(ctl.status().method, 'natpmp');
  gw.silent = true;
  const t0 = Date.now();
  await ctl.stop();
  const took = Date.now() - t0;
  assert(took < 3000, 'stop took ' + took + 'ms');
  assert.strictEqual(ctl.status().state, 'stopped');
});

test('controller stop() during the first attempt leaves nothing behind', async () => {
  const igd = await startIgd();
  const ctl = portmap.start(igd.opts());
  await ctl.stop();
  await sleep(400);
  assert.strictEqual(ctl.status().state, 'stopped');
  assert.strictEqual(igd.mappings.size, 0);
});

test('controller timers never keep the process alive', async () => {
  const port = await silentUdp();
  const script = `const p=require(${JSON.stringify(path.join(__dirname, '..', 'portmap.js'))});
    p.start({internalPort:8788,methods:['natpmp'],gateway:'127.0.0.1',natpmpPort:${port},timeoutMs:200,timing:{backoffMs:[60000]}});`;
  const t0 = Date.now();
  const r = cp.spawnSync(process.execPath, ['-e', script], { timeout: 5000 });
  assert.strictEqual(r.status, 0, 'child did not exit by itself: ' + (r.signal || r.stderr));
  assert(Date.now() - t0 < 4000);
});

test('no em dashes in portmap sources', () => {
  for (const f of ['portmap.js', 'tests/portmap.test.js']) {
    assert(!fs.readFileSync(path.join(__dirname, '..', f), 'utf8').includes(String.fromCharCode(0x2014)), f);
  }
});

/* ------------------------------------------------------------ runner */

(async () => {
  const t0 = Date.now();
  for (const { name, fn } of tests) {
    try {
      await Promise.race([fn(), sleep(10000).then(() => { throw new Error('test timed out'); })]);
      console.log('  ok   ' + name);
    } catch (e) {
      failed++;
      console.log('  FAIL ' + name + '\n       ' + String(e && e.message).split('\n').join('\n       '));
    }
    for (const c of cleanup.splice(0)) { try { c(); } catch {} }
  }
  console.log(failed ? `\n${failed} failed` : `\nall passed (${((Date.now() - t0) / 1000).toFixed(1)}s)`);
  process.exit(failed ? 1 : 0);
})();
