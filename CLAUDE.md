# CLAUDE.md: NodeSignal project guide

Read this whole file before changing anything. It records the maintainer's
vision, the decisions already made, and the known gaps. Where this file and
the code disagree, this file states the intent; fix the code.

## 0. Locked decisions, quick list

Settled deliberately. Preserve them in every change. If a task seems to
require breaking one, stop and ask.

1. Implementation colours: Core `#f7931a` (orange), Knots `#22a95a` (deep
   green), btcd `#4dd2ff` (cyan), libbitcoin `#b48cff` (violet), Bcoin
   `#ff7ab8` (pink). Online state is shown by line style and the blinking
   dot, never by recolouring a node.
2. Demo nodes show one of each implementation; btcd, libbitcoin and Bcoin
   are capped at one each. (Demo build only, currently retired.)
3. Protocol chatter from live nodes never triggers unread badges, the title
   count, or notifications.
4. The composer is always enabled. With the daemon disconnected a message is
   held and labelled "queued", then sent on reconnect. Never call an
   in-flight message "queued".
5. No "mined block" indicator and no mining pool option.
6. The daemon settings panel is invisible: no URL, token or connection
   fields. The page auto-connects to same-origin `/ws` and keeps retrying.
7. Fake AI demo replies only from chatty demo peers, never from a node the
   operator added. (Demo build only.)
8. P2P identification on port 8333 fires automatically when a contact is
   added. The "identify" button is a manual re-run.
9. The constellation radar's behaviour (layout, rings, pan/zoom, click to
   chat) is frozen. Visual work around it must not change its code.

There is no Bitcoin node in cloud sessions. Never run against live RPC;
mock `getnetworkinfo`, `getblockchaininfo`, `getpeerinfo` and the 8333
`version` reply instead. Use documentation address ranges (192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32) in any fixture or screenshot.

---

## 1. The vision

NodeSignal is encrypted chat between Bitcoin node operators, built as a
companion daemon that runs beside Bitcoin Core or Bitcoin Knots.

The founding insight, and the thing every design choice protects:

**The Bitcoin P2P protocol cannot carry chat.** It has no message type for
arbitrary data, and nodes disconnect peers that send unknown messages.
Stuffing chat into Bitcoin messages would harm the network. So NodeSignal
splits the job honestly:

| Layer | Where it comes from |
|---|---|
| Discovery | `getpeerinfo` over RPC. The map IS the node's real peer list. |
| Identity | A real `version`/`verack` handshake on the peer's port 8333. Read-only. |
| Transport | A separate encrypted daemon-to-daemon channel on TCP 8788. |

The goal is software that "just works" beside a node, the way mempool or
Electrum do: install it, open a browser, see your node's peers, click one,
message its operator. It should be genuinely useful, not a toy, while being
openly honest about its limits.

The maintainer is presenting it to a Bitcoin audience. That audience
respects a project that names its own weaknesses far more than one that
claims security it has not earned. Keep that tone everywhere: in the UI, the
docs, and commit messages.

---

## 2. Non-negotiable principles

1. **Never touch the Bitcoin P2P protocol for messaging.** The only P2P
   traffic is the read-only identify handshake on 8333.
2. **RPC is read-only and minimal.** Exactly three methods:
   `getpeerinfo`, `getnetworkinfo`, `getblockchaininfo`. Never add wallet
   calls. Pruned nodes must keep working, so never add a call that needs
   block history.
3. **Zero dependencies.** Node.js standard library only. `nodeps.js`
   replaced express and ws specifically to remove 66 npm packages from a
   machine running a Bitcoin node. Do not add a dependency without a strong,
   stated reason.
4. **Identity data is derived, never invented.** Implementation, version,
   height, services, and declared BIPs come from what a node actually
   reported. The one exception, `--impersonate`, must stay flagged
   `simulated: true` in the protocol.
5. **Fail honestly.** Undeliverable messages say why. Unknown data shows as
   unknown or N/A. Nothing silently disappears.
6. **Never put secrets on a command line.** Credentials live in
   `nodesignal-config.json` (locked to the user) or the cookie file.
7. **No personal data in the repo.** No real IPs, hostnames, or usernames
   in code, placeholders, or docs. This repo is public.

---

## 3. Architecture

```
Bitcoin node --RPC (3 read methods)--> nodesignald.js
                                         |-- :8789  web UI + WebSocket /ws + GET /health
                                         |-- :8788  Noise-encrypted daemon <-> daemon messaging
                                         `-- :8333  outbound only, identify peers
```

The daemon serves its own web interface. The browser connects back to `/ws`
on the same origin it loaded from (`location.host`), so it works behind an
IP, a hostname, a domain, or a reverse proxy with no configuration.

### Files

| File | Role |
|---|---|
| `nodesignald.js` | The daemon. RPC discovery, identify, messaging, web server. |
| `noise.js` | Noise-XX handshake: X25519, HKDF-SHA256, ChaCha20-Poly1305. |
| `nodeps.js` | Static file server + RFC 6455 WebSocket server, stdlib only. |
| `nodesignal.html` | **Operator console.** Real data only. Goes on a node. |
| `nodesignal-demo.html` | **Retired.** Removed from the tree in `2d479c6`; the maintainer considers it obsolete. Do not restore it. The demo-only rules below apply only if it ever returns. |
| `install.js` + `install-windows.bat` | Interactive Windows installer that verifies each answer. |
| `install-node.sh` | Linux installer, writes a systemd unit. |
| `start-node.bat` / `start-daemon.bat` | Manual Windows launchers. (`start-daemon.bat` still expects the retired demo file; fix when touched.) |
| `site/` | Static project page for nodesignal.connoraherne.com. Served by Caddy from `/var/www/nodesignal`. Not served by the daemon. |

### Two interfaces, deliberately separate

- `nodesignal.html` performs **no browser cryptography**. This is load-bearing:
  the Web Crypto API (`crypto.subtle`) only exists in a secure context.
  `http://<ip>:8789` is not one, and an earlier build died on load there
  because of it. Keep all crypto in the daemon.
- `nodesignal-demo.html` uses `crypto.subtle` for its fake peers, so it only
  works from `file://` or `localhost`. It must never be installed on a node.
  `install-node.sh` refuses it and deletes stale copies.

### Daemon options worth knowing

`--config <file>` (flags override the file), `--nick`, `--web-port`,
`--peer-port`, `--web-token`, `--bind`, `--no-rpc`, `--rpc-user`,
`--rpc-pass`, `--rpc-cookie`, `--rpc-conf`, `--tor-proxy`, `--tor-all`,
`--impersonate`, `--impersonate-height`, `--max-conns`, `--rl-burst`,
`--rl-refill-ms`.

State (contacts, history, private identity key) lives in
`~/.nodesignal/state.json`. Upgrades must never touch it.

---

## 4. UI decisions to preserve

These were each decided explicitly. Do not regress them.

**Map ("peer constellation")**
- Peers placed by latency on rings at **even radial spacing**, ring steps
  `[10, 25, 50, 100, 200, 350, 550, 800, 1200]` ms, log-interpolated within
  each band. An earlier near-log curve crushed high-latency peers together
  at the edge; do not reintroduce it.
- Colour = implementation. Final palette: Core orange, Knots deep green
  `#22a95a`, btcd cyan, libbitcoin violet, Bcoin pink.
- Collision-relaxation layout. Verified at 40 peers with zero label
  overlaps and nothing out of frame.
- Drag to pan, wheel and pinch to zoom anchored on the cursor, double-click
  to zoom, refit button. Once the user moves the view, stop auto-refitting.
- **Click any node to open its chat.** Pointer capture is taken only after a
  4px drag threshold. Capturing on `pointerdown` retargets the click and
  breaks this; that bug happened once already.
- Each node carries an invisible hit disc of radius `nodeR + 12`, so the
  click area scales with the circle at every zoom and peer count.

**Connection state**
- **Dashed line:** a node peer, or a contact who has never replied.
- **Solid green line:** `established`, meaning a confirmed two-way NodeSignal
  exchange (their daemon acked our message, or sent us one). An inbound
  `hello` alone does NOT count. Established persists after they go offline.
- **Blinking green dot:** `online`, meaning established AND seen within the
  last 5 minutes. Only on peers you could message right now.
- Messages and peer info stay in the Messages tab after a peer drops off
  `getpeerinfo`. History is never tied to the live peer list.

**Notifications**
- Slide-in cards per incoming message, colour-striped, click to open, dismiss,
  auto-fade at 9s, capped at 4. HTML-escaped. Locked messages never leak text.
- Unread badge with count and a pop animation; page title shows `(N) NodeSignal`.
- No notification while the user is already reading that conversation.
- Protocol chatter from live nodes must never raise unread badges.

**Demo build only**
- Starts with a colourful demo constellation, one of each implementation
  (rare ones capped at one each).
- Canned AI replies come only from the built-in demo peers and dev-tool
  spawns, never from a node the user added by hand.

**Removed on purpose, do not bring back**
- The "mined block" indicator (logically impossible).
- The mining pool connection option.
- The visible daemon settings panel. The console auto-connects with no setup.
- The `?daemon=` URL parameter workflow.
- A separate probe tool. `/health` replaces it.

---

## 5. Security model

The repo contains `SECURITY-CRITIQUE.md`, an adversarial self-audit with a
status table. Keep it current whenever security changes.

**Done**
- Noise-XX handshake replaced the shared PIN: mutual authentication, forward
  secrecy, persistent X25519 identity per daemon.
- TOFU key pinning. A changed key is REJECTED with a red banner.
- No persisted state before a completed handshake (closes the disk-exhaustion
  DoS that could take bitcoind down with it).
- Rate limiting per source block (/32 IPv4, /64 IPv6), which defeats IPv6
  address spraying. Connection cap.
- Auto-binds to the Tailscale interface when present; otherwise the web UI
  binds to localhost.
- Tor: SOCKS5 for outbound `.onion` (DNS cannot resolve them), hidden service
  for inbound. Both halves are required.
- Zero dependencies.
- Optional web login token; HttpOnly SameSite=Strict session cookie also
  authenticates the `/ws` upgrade. Never put the token in a query string.

**Still open, in honest terms**
- Messages are stored decrypted at rest in `state.json`.
- Running NodeSignal links a social identity to a node IP. Inherent to the
  design; Tor is the mitigation.
- Metadata (who, when, how often) is not hidden.
- Every peer claim about its node is self-declared.

---

## 6. Open work, in priority order

### Fix first: places where the code contradicts the vision

1. **Remove the PIN UI.** The daemon ignores PINs between current daemons,
   but the console still shows a "shared PIN" field in the add-contact
   dialog, a "set PIN" button, a "PIN-encrypted" pill, and locked messages
   reading "set the shared PIN to read it". This misdescribes the encryption.
   Replace with the real state: end-to-end Noise encryption, the peer's
   pinned fingerprint, and the mismatch banner. Same in `nodesignal-demo.html`
   for real (non-demo) contacts. Fake demo peers may keep their demo PIN.
2. **Composer must queue, not drop.** Decided: the composer is always
   enabled, and when the daemon is disconnected the message is held and
   labeled honestly as "queued", then sent on reconnect. Currently
   `sendMsg()` toasts "daemon not connected" and discards it.
3. **Add a real test suite.** There are no tests in the repo. Add a
   `tests/` folder runnable with plain `node` (no test framework, keep zero
   deps) covering at least:
   - Noise handshake: mutual auth, matching keys, tamper rejection
   - two-daemon delivery and reply
   - TOFU: a reinstalled peer with a new key is rejected
   - DoS: a flood of handshake-less connections persists zero contacts
   - `established` only after a real reply; history survives peer loss
   - Tor: delivery to a `.onion` through a mock SOCKS5 proxy
   - WebSocket server against framing sizes 5 KB and 200 KB, UTF-8, ping
   - static server rejects path traversal and dotfiles
   - layout: 40 peers, zero overlaps, nothing out of frame

### Then

4. **Encrypt state at rest**, or stop persisting decrypted plaintext.
5. **Retire the legacy v1 PIN code path** in `nodesignald.js` once nothing
   depends on it, along with `encMsg`/`decMsg` and the `contact.pin` message.
6. **Reinstall flow for TOFU.** Today a peer who reinstalls must be removed
   and re-added. Consider an explicit, deliberate "accept new key" action
   that shows both fingerprints.
7. **Docs:** add `rpcwhitelist=nodesignal:getpeerinfo,getnetworkinfo,getblockchaininfo`
   to the Linux installer's output as a recommended hardening step.

### Direction decided with the maintainer (Oct 2026)

- **Installers:** bundled Node. Windows gets a single `.exe` (Node single
  executable application, no separate Node install) that registers a
  background service; Ubuntu gets a `.deb` with a systemd unit. Both find the
  cookie or `bitcoin.conf`, connect, and start with no questions in the common
  case. Built by GitHub Actions and attached to GitHub Releases; the site's
  download buttons point at `releases/latest/download/<asset>`.
- **Encryption, all wanted:** encrypt history and the identity key at rest;
  retire the v1 PIN path; a deliberate "accept new key" flow showing both
  fingerprints; check `noise.js` against Noise spec test vectors and get an
  outside review before presenting it as reviewed.
- **Making it actually work, all four are real blockers:** reaching operators
  behind NAT (8788 unreachable without Tailscale or Tor); finding which peers
  run NodeSignal at all; offline delivery (hold and retry instead of failing);
  setup friction (RPC credentials, ports, launch steps).

---

## 7. Conventions for this repo

- **Never use em dashes** in anything you write: code comments, UI text,
  docs, commit messages. Use commas, colons, or parentheses. Existing files
  still contain many; when you touch a file, convert the em dashes in the
  lines you change, and do a full cleanup pass as a separate commit.
- When editing an existing doc, keep the wording of lines that are still
  correct. Only rephrase lines that are stale, and add new points.
- Every shell command in docs must say where it runs (for example "Linux,
  on the node" or "Windows PowerShell").
- `.bat` files must keep CRLF line endings.
- Check syntax before committing:
  `node --check` on every `.js`, `bash -n install-node.sh`, and extract the
  `<script>` block from each HTML file and `node --check` it.
- When you fix a bug, say what the root cause was in the commit message, and
  add a test that would have caught it.
- Update `SECURITY-CRITIQUE.md` whenever a risk changes state.
- Do not commit `nodesignal-config.json`, `state.json`, `run-nodesignal.*`,
  or `node_modules/`. `.gitignore` covers them.
- Security invariants: escape every peer-supplied string before it reaches
  `innerHTML` (prefer `textContent`); RPC credentials never reach the browser
  or `/health`; inbound 8788 data is length-capped and a bad frame closes that
  socket, never the daemon.
