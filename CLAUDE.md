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
10. The web console is this machine's only (decided Oct 2026): it binds
   127.0.0.1 and nothing else (`--bind` applies to the peer port only),
   accepts Host `localhost:<web-port>` / `127.0.0.1:<web-port>` only
   (DNS rebinding), refuses any other Origin, and every state-changing
   WebSocket op needs the per-launch `ACTION_TOKEN` that the daemon writes
   into the page it serves (`<meta name="ns-action-token">`). Only `hello`
   and `ping` are exempt. Never add a remote web bind; remote access is an
   SSH tunnel with the same port. `tests/websecurity.test.js` guards this.
11. NodeSignal never runs as root and never reads the node's cookie
   (decided Oct 2026). Linux: setup (`cli.js setup`, run by the .deb
   postinst and `install-node.sh`) creates the `nodesignal` system user;
   the unit says `User=nodesignal`, `StateDirectory=nodesignal`
   (`/var/lib/nodesignal`), `ProtectHome=yes`. RPC: setup generates a
   random password for user `nodesignal`, keeps it in NodeSignal's 0600
   config (`rpc-user`/`rpc-pass`, plus `rpc-url` because the daemon cannot
   read bitcoin.conf), and writes a marked block to bitcoin.conf:
   `rpcauth=nodesignal:<salt>$<hmac>`, `rpcwhitelist=nodesignal:` with
   exactly the methods the daemon calls (below), and `rpcwhitelistdefault=0`
   only when the conf has no whitelist settings of its own (otherwise the
   first whitelist line locks every other RPC user out). Setup tells the
   operator to restart bitcoind, as advertise does, and never restarts it.
   Purge removes the block; it never deletes identity or history. Windows
   has no dedicated account: the daemon runs as the signed-in user, the
   same rpcauth block is written, and both Windows installers refuse an
   administrator window. `nodesignal rpc-access show|add|remove` manages
   the block by hand.
   The RPC methods the daemon calls, from `grep "rpcCall('" nodesignald.js`
   (`tests/setup-core.test.js` fails if this drifts from `RPC_METHODS`):
   `getblockchaininfo`, `getnetworkinfo`, `getpeerinfo`. setup-core's own
   install-time check uses `getblockchaininfo` and `getnetworkinfo`.

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
   NodeSignal's own config (`/etc/nodesignal/config.json` 0600 owned by
   `nodesignal`, `%LOCALAPPDATA%\NodeSignal\config.json` or
   `nodesignal-config.json` locked to the user). The node's cookie file is
   never read; bitcoin.conf only ever gets the rpcauth hash.
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

The daemon serves its own web interface on 127.0.0.1 only. The browser
connects back to `/ws` on the same origin it loaded from (`location.host`),
which must be `localhost:<port>` or `127.0.0.1:<port>`: other hostnames,
IPs, .onion names and reverse proxies are refused on purpose (decision 10).
From another computer: `ssh -L 8789:127.0.0.1:8789 <node>`.

### Files

| File | Role |
|---|---|
| `nodesignald.js` | The daemon. RPC discovery, identify, messaging, web server. |
| `noise.js` | Noise_XX_25519_ChaChaPoly_SHA256 (v3, standard, test-vector checked) plus the v1.2 handshake as `noise.legacy` for one release. |
| `store.js` | History at rest: scrypt passphrase vault + X25519 sealed boxes per message. |
| `portmap.js` | Opt-in UPnP IGD / NAT-PMP port mapping. |
| `nodeps.js` | Static file server + RFC 6455 WebSocket server, stdlib only. |
| `nodesignal.html` | **Operator console.** Real data only. Goes on a node. |
| `nodesignal-demo.html` | **Retired.** Removed from the tree in `2d479c6`; the maintainer considers it obsolete. Do not restore it. The demo-only rules below apply only if it ever returns. |
| `packaging/` | One-download installers. `files.json` is THE list of program files (update it when adding a module). `build-sea.js` + `windows/sea-main.js` build `NodeSignal-Setup-windows-x64.exe` (Node SEA; `windows/win-resources.js` and `windows/make-icon.js` give it its version resource and icon at build time); `deb/` builds `nodesignal-linux-{amd64,arm64}.deb` with the official Node binary. Both require a Bitcoin node. |
| `setup-core.js` + `cli.js` | Shared node detection / RPC check / config / uacomment and rpcauth editing, and the `nodesignal` command (status, advertise, port-mapping, rpc-access, setup). |
| `.github/workflows/` | `ci.yml` (all tests, deb install under systemd, Windows exe selftest) and `release.yml` (tag `v*` -> release assets with stable names + SHA256SUMS.txt). |
| `install.js` + `install-windows.bat`, `install-node.sh` | From-source installers; also require a node. |
| `start-node.bat` | Manual Windows launcher for a from-source copy. |
| `CHANGELOG.md`, `RELEASING.md` | Release notes per version (the release workflow publishes the `## <version>` section) and the maintainer's release checklist. `release.yml` run by hand is a dry run by default. |
| `tools/screenshots/` | Publishable screenshots of the console from a fake daemon (`fixture-ws.js`). Optional Playwright. |
| `tests/` | `run-all.js` runs every `*.test.js` with plain node; `console.e2e.js` (optional Playwright); `mock-node.js` (mock RPC that applies rpcauth/rpcwhitelist from a bitcoin.conf like bitcoind, and a :8333 identify listener); `harness.js` (shared helpers: spawned daemons, a raw WebSocket client, raw Noise peers). |

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
`--peer-port`, `--web-token`, `--bind` (peer port only), `--no-rpc`,
`--rpc-url`, `--rpc-user`, `--rpc-pass` (normally in the config, never on a
command line), `--rpc-conf`, `--tor-proxy`, `--tor-all`,
`--impersonate`, `--impersonate-height`, `--max-conns`, `--rl-burst`,
`--rl-refill-ms`, `--port-mapping` (opt-in), `--checkin-ms` (default 180000,
0 disables), `--retry-scale` (tests only).

Peer protocol (v3): length-prefixed frames, Noise XX handshake (msg1 32
bytes; a 44-byte msg1 is the v1.2 handshake), then JSON frames `hello`,
`msg` {id, ts, text}, `ack` {id}, `ping`/`pong`. Either side of a link may
send `msg`; the dialling side hangs up when idle. Outgoing message status:
`sending` -> `delivered`, or `pending` (retrying, with `error` and
`nextTry`) -> `failed` (gave up or cancelled). The console adds its own
`queued` for messages typed while the daemon is unreachable.

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
  secrecy, persistent X25519 identity per daemon. Since v1.3 it is the
  standard Noise_XX_25519_ChaChaPoly_SHA256, checked against the cacophony and
  snow vectors (`tests/noise.test.js`). v1.2 peers are still answered; remove
  `noise.legacy` and the v2 branches in the release after v1.3.
- TOFU key pinning. A changed key is REJECTED with a red banner and held as
  `pendingFp` until the operator accepts it (echoing the exact fingerprint)
  or keeps the old one.
- History at rest (v1.3): optional passphrase; text sealed on arrival, the
  daemon receives while locked. The PIN code is gone.
- Every peer-supplied field is validated and capped; claimed node info never
  overwrites what we measured over :8333.
- No persisted state before a completed handshake (closes the disk-exhaustion
  DoS that could take bitcoind down with it). Since the v1.3 self-review,
  authenticated strangers are capped too: 256 inbound-only contacts, 50
  messages each, 200 messages per connection.
- A `state.json` that exists but cannot be read or parsed stops the daemon;
  it is never replaced by a fresh identity. Only a missing file means a new
  install.
- Rate limiting per source block (/32 IPv4, /64 IPv6), which defeats IPv6
  address spraying. Connection cap.
- Auto-binds to the Tailscale interface when present; otherwise the web UI
  binds to localhost.
- Tor: SOCKS5 for outbound `.onion` (DNS cannot resolve them), hidden service
  for inbound. Both halves are required.
- Zero dependencies.
- Optional web login token; HttpOnly SameSite=Strict session cookie also
  authenticates the `/ws` upgrade. Never put the token in a query string.
- Least RPC privilege (v1.3): own rpcauth user with an `rpcwhitelist` of the
  three methods, no cookie, dedicated `nodesignal` system user on Linux.
- Web front door (v1.3): loopback-only bind, Host and Origin checks,
  per-launch action token on every state-changing op, `no-store` and
  frame-blocking headers on the console page. A console socket error can
  no longer crash the daemon. The web server hands out the console page,
  `/health` and the login routes only: no static files from the program
  folder, where a from-source install keeps `nodesignal-config.json`.

**Still open, in honest terms**
- Without a passphrase, messages are stored in the clear in `state.json`;
  with one, metadata and the identity key are still readable by the daemon's
  user.
- No outside review of the daemon yet (vectors only prove `noise.js`).
- Opt-in features that cost privacy: `uacomment=nodesignal` advertising and
  router port mapping. Keep both off by default.
- Running NodeSignal links a social identity to a node IP. Inherent to the
  design; Tor is the mitigation.
- Metadata (who, when, how often) is not hidden.
- Every peer claim about its node is self-declared.

---

## 6. Open work, in priority order

### Fix first: places where the code contradicts the vision

1. **[DONE in the console, Oct 2026]** **Remove the PIN UI.** The daemon ignores PINs between current daemons,
   but the console still shows a "shared PIN" field in the add-contact
   dialog, a "set PIN" button, a "PIN-encrypted" pill, and locked messages
   reading "set the shared PIN to read it". This misdescribes the encryption.
   Replace with the real state: end-to-end Noise encryption, the peer's
   pinned fingerprint, and the mismatch banner. Same in `nodesignal-demo.html`
   for real (non-demo) contacts. Fake demo peers may keep their demo PIN.
2. **[DONE, Oct 2026]** **Composer must queue, not drop.** Decided: the composer is always
   enabled, and when the daemon is disconnected the message is held and
   labeled honestly as "queued", then sent on reconnect. Currently
   `sendMsg()` toasts "daemon not connected" and discards it.
3. **[DONE, Oct 2026]** **Add a real test suite.** v1.3 adds `noise.test.js` (vectors),
   `store.test.js`, `daemon.test.js` (real daemons: delivery, reply over the
   peer's link, retry, dedupe, v1.2 interop, key change, vault, hostile
   input) and `portmap.test.js`. Earlier: `tests/console.test.js` (static
   checks, plain node), `tests/console.e2e.js` (two daemons + mock node,
   optional Playwright, skips without it) and `tests/mock-node.js` (mock
   RPC and :8333). Still to add, in the same `tests/` folder runnable with plain `node` (no test framework, keep zero
   deps) covering at least (all now done; `tests/harness.js` holds the
   helpers the newer suites share, and each suite has its own port range):
   - [DONE, `noise.test.js`] Noise handshake: mutual auth, matching keys, tamper rejection
   - [DONE, `daemon.test.js`] two-daemon delivery and reply
   - [DONE, `daemon.test.js`] TOFU: a reinstalled peer with a new key is rejected
   - [DONE, `dos.test.js`] DoS: a flood of handshake-less connections persists zero contacts
     (state.json untouched, `/health` answering), plus `--max-conns` and the
     per-source rate limit
   - [DONE, `established.test.js`] `established` only after a real reply; history survives peer loss
     (an inbound hello alone, or a hello exchange, establishes nobody; history
     survives leaving getpeerinfo and a restart)
   - [DONE, `tor.test.js`] Tor: delivery to a `.onion` through a mock SOCKS5 proxy
     (domain-name CONNECT, reply over the same circuit, no DNS lookup of the
     onion; found and fixed a split-reply bug)
   - [DONE, `websocket.test.js`] WebSocket server against framing sizes 5 KB and 200 KB, UTF-8, ping
     (found and fixed: unmasked frames accepted, fragmented messages unbounded,
     no close frame sent)
   - [DONE, `static.test.js`] static server rejects path traversal and dotfiles
     (POSIX and Windows path rules; found and fixed: the daemon served any file
     in its program folder, including `nodesignal-config.json`)
   - [DONE, `layout.test.js`] layout: 40 peers, zero overlaps, nothing out of frame
     (runs the page's own layout code in a vm, seeded; holds for realistic
     latency spreads. Known limit, not fixed because the radar is frozen: 40
     peers crowded into one narrow band, such as all within 5 ms or all
     unmeasured, can still overlap)

### Then

4. **[DONE v1.3, passphrase-to-read]** Encrypt state at rest.
5. **[DONE v1.3]** Retire the legacy v1 PIN code path.
6. **[DONE v1.3]** Reinstall flow for TOFU ("accept new key" with both
   fingerprints shown).
6b. **Next release:** drop `noise.legacy` and the v2 dial/answer branches.
6c. **Outside review** of `nodesignald.js` + `noise.js` before calling it
   reviewed anywhere.
7. **[DONE v1.3, stronger than planned]** The installers now write
   `rpcwhitelist=nodesignal:getblockchaininfo,getnetworkinfo,getpeerinfo`
   themselves, for NodeSignal's own rpcauth user.

### Direction decided with the maintainer (Oct 2026)

- **Installers:** bundled Node. Windows gets a single `.exe` (Node single
  executable application, no separate Node install) that registers a
  background service; Ubuntu gets a `.deb` with a systemd unit. Both find
  `bitcoin.conf`, add NodeSignal's own rpcauth login to it, and start with no
  questions in the common case (one bitcoind restart needed, which they ask
  the operator to do). Built by GitHub Actions and attached to GitHub Releases; the site's
  download buttons point at `releases/latest/download/<asset>`.
- **Encryption, all wanted:** encrypt history and the identity key at rest;
  retire the v1 PIN path; a deliberate "accept new key" flow showing both
  fingerprints; check `noise.js` against Noise spec test vectors and get an
  outside review before presenting it as reviewed.
- **Making it actually work** (v1.3 builds all four: reply over the peer's
  own connection so only one side needs to be reachable, daemon retry queue
  with check-ins, `uacomment=nodesignal` advertising, opt-in UPnP/NAT-PMP).
  The original blockers: reaching operators
  behind NAT (8788 unreachable without Tailscale or Tor); finding which peers
  run NodeSignal at all; offline delivery (hold and retry instead of failing);
  setup friction (RPC credentials, ports, launch steps).

### Open questions for the maintainer (from the v1.3 installer work)

- **Decided:** `.deb` Maintainer is `Connor-03 <143026739+Connor-03@users.noreply.github.com>`
  (GitHub's noreply form; filled in at the maintainer's request) and Homepage
  is https://github.com/Connor-03/NodeSignal.
- **Decided (Oct 2026): never run as root.** Dedicated `nodesignal` user,
  rpcauth + rpcwhitelist instead of the cookie; see locked decision 11.
- **Decided (Oct 2026): Windows supervisor.** `nodesignal.exe run` (what the
  sign-in launcher starts) is a parent that spawns the daemon as a child
  (`__daemon`) and respawns it on exit, backoff 1s doubling to 60s (reset after
  10 minutes up), giving up after 5 crashes within 10 minutes and logging the
  reason. The selftest covers restart and give-up.
- **Done (Oct 2026): .exe icon and version resource.** `build-sea.js` stamps
  the copied node.exe before postject injects the blob (that order is
  required): ProductName NodeSignal, the package.json version, CompanyName and
  LegalCopyright from LICENSE, and the icon drawn by
  `packaging/windows/make-icon.js` (stdlib only; `nodesignal.ico` is its
  committed output, `tests/winexe.test.js` checks they match). The editor is
  resedit, fetched by npm at build time and pinned exactly, like postject; it
  is never shipped. CI checks `VersionInfo` and the icon on windows-latest.
  Still open: the .exe is not code-signed.
- Not yet run on real Windows or real arm64 hardware; CI covers the
  Windows selftest.

### Website handoff (do this when NodeSignal is finished, not before)

The maintainer's site **nodesignal.connoraherne.com** is built by a separate
Claude instance on his home server (Caddy, static files from
`/var/www/nodesignal`). Do **not** build the page in this repo. When the
product is finished, hand that instance:

1. **Screenshots.** Run `node tools/screenshots/shoot.js <outDir>` (needs
   Playwright; renders `nodesignal.html` against `fixture-ws.js`, so every
   address is a documentation range and every fingerprint is fake). Add
   scenes to the fixture if new features need showing. Export WebP, keep the
   set under about 300 KB, and never use a real node's data.
2. **A handoff document** with: a one-line pitch, the "why" story, how it
   works in 3 to 5 steps naming the real mechanisms (`getpeerinfo`
   discovery, read-only `version`/`verack` on :8333, Noise-XX with X25519,
   HKDF-SHA256 and ChaCha20-Poly1305 on :8788, TOFU key pinning), a features
   list where every line is checked against the code, the honest limits, the
   install steps and download links (GitHub Releases assets once the
   installers exist), and a list of anything unverified.

Rules the site instance enforces, so the handoff must already follow them:
no em dashes; plain direct copy, no hype; never invent facts (no user counts,
dates, partners); no tokens, private hostnames, IPs or peer addresses; the
daemon's own web app is private and must not be linked; BIP-110 is a failed
proposal, mention only as history.

Maintainer's approved copy, to be kept word for word where used:

> Inspired by my research into the Core vs Knots debate, I wanted an
> effective communication system, carried by the Bitcoin P2P network, that
> lets verified node operators talk to each other, display what they are
> signaling for, and hold a proper discussion on relay and consensus. It uses
> node peers for contact discovery, maps the connections, and opens its own
> authenticated channel between daemons so two operators can chat with no
> third party in between.

Short version: "Encrypted messaging between node operators, carried by the
P2P network they already run. No third party in the middle."

**Flag this, do not silently fix it:** "carried by the (Bitcoin) P2P network"
contradicts the README and section 1 of this file. Messages never travel over
Bitcoin P2P; the node only provides discovery and identity. Propose wording
such as "found through the P2P network they already run" and let the
maintainer approve it. Related story link: https://bpi.connoraherne.com.

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
- Run `node tests/console.test.js` (and `tests/console.e2e.js` where
  Playwright exists) after touching `nodesignal.html`.
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
