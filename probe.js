// probe.js — is that host:port actually reachable from this machine?
// ============================================================================
// Run:  node probe.js 108.203.190.226 8333 3333 22 80
//       node probe.js 192.168.1.50 8333
//
// Or double-click probe.bat.
//
// Tests each port and tells you what the result means. This talks only to the
// address you give it and reads nothing — it just opens a TCP connection and
// closes it.
// ============================================================================

const net = require('net');

const args = process.argv.slice(2);
const host = args[0];
const ports = args.slice(1).map(Number).filter(Boolean);

if (!host || !ports.length) {
  console.log('\nUsage:  node probe.js <host> <port> [port2 port3 ...]');
  console.log('Example: node probe.js 108.203.190.226 8333 3333\n');
  process.exit(1);
}

const TIMEOUT = 8000;

function probe(port) {
  return new Promise((resolve) => {
    const t0 = Date.now();
    const sock = new net.Socket();
    let done = false;
    const finish = (state, detail) => {
      if (done) return; done = true;
      sock.destroy();
      resolve({ port, state, detail, ms: Date.now() - t0 });
    };
    sock.setTimeout(TIMEOUT);
    sock.once('connect', () => finish('OPEN', 'something is listening and accepted the connection'));
    sock.once('timeout', () => finish('TIMEOUT', 'no reply at all — dropped by a firewall, not forwarded, or NAT loopback'));
    sock.once('error', (e) => {
      if (e.code === 'ECONNREFUSED') finish('REFUSED', 'host reachable, but nothing listening on this port');
      else if (e.code === 'EHOSTUNREACH') finish('UNREACHABLE', 'no route to that host');
      else if (e.code === 'ENOTFOUND') finish('DNS FAIL', 'hostname could not be resolved');
      else finish(e.code || 'ERROR', e.message);
    });
    sock.connect(port, host);
  });
}

(async () => {
  console.log(`\nProbing ${host} ...  (${TIMEOUT / 1000}s timeout per port)\n`);
  const results = [];
  for (const p of ports) {
    process.stdout.write(`  port ${String(p).padEnd(6)} ... `);
    const r = await probe(p);
    results.push(r);
    console.log(`${r.state.padEnd(12)} ${r.ms}ms   ${r.detail}`);
  }

  const open = results.filter(r => r.state === 'OPEN').map(r => r.port);
  const timeout = results.filter(r => r.state === 'TIMEOUT').map(r => r.port);

  console.log('\n--- what this means ---');
  if (open.length && timeout.length) {
    console.log(`  Port(s) ${open.join(', ')} are reachable, but ${timeout.join(', ')} time out.`);
    console.log('  Since some ports get through, your route and NAT loopback are FINE.');
    console.log('  The blocked port specifically is not forwarded, not listening,');
    console.log('  or blocked by the firewall on the node machine.');
  } else if (!open.length && timeout.length === results.length) {
    console.log('  Every port timed out. That points at something in front of the host:');
    console.log('    - you may be on the same LAN as it and your router cannot loop back');
    console.log('      to its own public IP  ->  try the local IP (192.168.x.x) or 127.0.0.1');
    console.log('    - or the whole host is firewalled from where you are sitting');
  } else if (open.length === results.length) {
    console.log('  All ports reachable. If NodeSignal still fails, the problem is in the');
    console.log('  protocol layer, not the network.');
  } else {
    const refused = results.filter(r => r.state === 'REFUSED').map(r => r.port);
    if (open.length && refused.length) {
      console.log(`  Port(s) ${open.join(', ')} are open; ${refused.join(', ')} refused.`);
      console.log('  Refused means you REACHED the machine and it said "nothing here".');
      console.log('  So routing and firewall are fine — the service just is not listening');
      console.log('  on that port. Start it, or check the port number.');
    } else if (refused.length === results.length) {
      console.log('  Every port refused. You are reaching the machine fine, but nothing is');
      console.log('  listening on any port you tested. Check that the service is running.');
    } else {
      console.log('  Mixed results — see the per-port detail above.');
    }
  }
  console.log('');
})();
