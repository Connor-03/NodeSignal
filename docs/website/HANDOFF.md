# NodeSignal: website handoff

For the site instance that builds nodesignal.connoraherne.com. Everything
below was checked against the code in this repository (v1.4.0, the version
in `package.json`, released 2026-10-31). The file references after each
feature are for verification; they do not need to appear on the site.

## What changed since the 1.3 handoff

Update the site for these; everything not listed here is as before.

- **1.4.0 is the current release.** The download links below are unchanged
  and already serve it.
- **New features** (details under Features): NodeSignal makes its own Tor
  onion address so operators reach each other with no port forwarding;
  mailboxes for operators who cannot be reached; a feed of signed posts;
  topic rooms; contact links with QR codes; introductions; the same-onion
  proof; identity backup; in-app update checks.
- **Check it with your own AI agent:** a new install route and guide
  (`docs/AGENT-SETUP.md`), with a plain warning that the agent can read
  NodeSignal's secrets.
- **A security review before release**, by AI agents run by the project:
  33 problems found and fixed. Present it as what it is (see Honest limits);
  it is not an outside audit.
- **Honest limits changed:** several new ones for 1.4, and two corrections:
  without Tailscale the peer port listens on every interface, and the 1.2
  handshake is still answered in 1.4.0 (it goes in 1.5).
- **Screenshots:** three new ones (feed, room, contact link with QR code),
  the status panel shows the 1.4 cards, and all were re-rendered. Replace the
  whole set.

---

## Approved copy (use word for word)

The maintainer's original copy said messages are "carried by the Bitcoin P2P
network". That is not how NodeSignal works: the node only provides
**discovery** (`getpeerinfo`) and **identity** (a read-only
`version`/`verack` handshake on port 8333), and messages go daemon to daemon
on TCP 8788 in a separate encrypted channel. The maintainer asked for the copy
to be corrected (Oct 2026). These are the versions to use, word for word.

**Long version:**

> Inspired by my research into the Core vs Knots debate, I wanted an
> effective communication system, found through the Bitcoin P2P network, that
> lets operators of verified nodes talk to each other, display what their
> nodes declare support for, and hold a proper discussion on relay and
> consensus. It uses node peers for contact discovery, maps the connections,
> and opens its own authenticated channel between daemons so two operators
> can chat with no third party in between.

What changed from the original, and why:

- "carried by" became "found through": peers are found through the P2P
  network; messages never travel over it.
- "verified node operators" became "operators of verified nodes": NodeSignal
  verifies that an address answers a real Bitcoin handshake and keeps the same
  key; the person behind it is not verified.
- "display what they are signaling for" became "display what their nodes
  declare support for": these are BIP numbers an operator writes into their
  node's user agent, a declaration, not version-bit or miner signalling.

**Short version (also the one-line pitch):**

> Encrypted messaging between node operators, found through the P2P network
> they already run. No third party in the middle.

Related story link (from the maintainer): https://bpi.connoraherne.com

---

## One-line pitch

Encrypted messaging between node operators, found through the P2P network
they already run. No third party in the middle.

## The why

Bitcoin node operators argue about relay policy and consensus in places run
by someone else: social networks, chat servers, mailing lists. The people
running nodes are already connected to each other, through their nodes, but
there is no way to talk over those connections.

There is a reason for that. The Bitcoin P2P protocol cannot carry chat. It
has no message type for arbitrary data, and nodes disconnect peers that send
unknown messages. Pushing chat into Bitcoin messages would harm the network.

So NodeSignal splits the job and says so plainly. Your node tells it who
your peers are and what software they run. NodeSignal then opens its own
encrypted connection, daemon to daemon, so two operators can talk directly
with no server in the middle.

## How it works

1. **Discovery.** NodeSignal asks your node for its peer list with
   `getpeerinfo` over RPC, read-only. The map is your node's real peer list.
2. **Identity.** For a contact, NodeSignal opens a short, read-only
   `version`/`verack` handshake on the peer's port 8333 and reads what that
   node reports: user agent, implementation, version, block height, service
   bits and the capability messages it sends. It never sends chat over
   Bitcoin P2P.
3. **Transport.** Messages go daemon to daemon on TCP port 8788 inside a
   standard Noise_XX_25519_ChaChaPoly_SHA256 session: X25519 key agreement,
   HKDF-SHA256, and ChaCha20-Poly1305 encryption. Both sides authenticate
   with a long-term key, and each session uses fresh ephemeral keys.
4. **Key pinning (TOFU).** The first time two daemons connect, each pins the
   other's key fingerprint. If that key ever changes, the connection is
   rejected and the operator sees both fingerprints and decides.
5. **Reaching each other.** Either side's connection carries messages both
   ways, so only one of the two operators needs to be reachable. With Tor
   installed, NodeSignal gives itself an onion address through Tor's control
   socket, so it is reachable behind any router with no port forwarding.
   Messages that cannot be delivered yet wait and retry, or wait sealed at a
   contact's mailbox, and the console says which.

## Features

Every line was checked in the code; the reference is where.

**Map and identity**

- The peer map comes from your own node's `getpeerinfo`, refreshed every 30
  seconds. (`nodesignald.js`: `pollRpc`)
- Peers sit on rings by round-trip latency (10 ms to 1200 ms) and are
  coloured by implementation: Bitcoin Core, Bitcoin Knots, btcd, libbitcoin
  and Bcoin. (`nodesignal.html`: `RING_STEPS`; `nodesignald.js`: `implFromUA`)
- Drag to pan, scroll or pinch to zoom, click any peer to open a chat with
  its operator. (`nodesignal.html`: wheel, pinch and click handlers)
- Adding a contact identifies their node over port 8333 automatically, with
  a few retries if it is not reachable yet; an "identify" button re-runs it.
  (`nodesignald.js`: `identifyP2P`, `scheduleIdentify`, `contact.add`)
- Identification reads the user agent, version, start height and service
  bits, and lists supported BIPs from the service bits and capability
  messages (for example BIP-141, BIP-152, BIP-159, BIP-339).
  (`nodesignald.js`: `SERVICE_BIPS`, `MSG_BIPS`)
- BIP numbers an operator put in their user agent are shown as "signaling",
  labelled as declared. (`nodesignald.js`: `declaredFromUA`)
- What a peer's daemon claims about its node never overwrites what NodeSignal
  measured itself over port 8333. (`nodesignald.js`: `applyHello`)
- Find other operators: peers whose user agent carries `nodesignal` are
  marked. Advertising your own node is opt-in (`nodesignal advertise on`
  adds `uacomment=nodesignal` to bitcoin.conf, with your onion address when
  you have one, so operators whose nodes peer with yours can message you
  over Tor). (`nodesignald.js`: `nodesignalFromUA`; `setup-core.js`:
  `setUaComment`, `uaCommentFor`; `cli.js`)
- Peers that cannot be messaged say why on the map: "via Tor", "this
  machine", "via I2P", "local network". (`nodesignal.html`: `reachOf`)

**Encryption and keys**

- Standard Noise_XX_25519_ChaChaPoly_SHA256, checked byte for byte against
  the published cacophony and snow test vectors. (`noise.js`;
  `tests/noise.test.js`)
- Mutual authentication with a persistent X25519 identity key per daemon,
  and forward secrecy from fresh ephemeral keys each session. (`noise.js`)
- A changed key is rejected, with a red banner. The operator sees the pinned
  and the presented fingerprint side by side and either accepts the new key
  or keeps the old one; accepting must name the exact fingerprint that was
  shown. (`nodesignald.js`: `tofuCheck`, `contact.acceptKey`;
  `nodesignal.html`)
- A contact is recognised by its pinned key even if its IP address changes.
  (`nodesignald.js`: `contactFor`)
- Optional history passphrase: message text is sealed on disk (scrypt, X25519
  sealed boxes, ChaCha20-Poly1305), and the daemon keeps receiving while
  locked. Wrong passphrases are slowed down. (`store.js`; `nodesignald.js`:
  `vaultUnlock`)

**Delivery**

- Only one of two operators needs to be reachable: the reply rides back on
  the other side's connection. (`nodesignald.js`: `openLink`, `flushPending`)
- Undelivered messages retry on their own (30 s, 1, 2, 5, 10 and 30 minutes,
  then hourly) and give up after 7 days for an established contact, 1 day
  for one that has never replied. The console shows the reason and the next
  try, with "retry now" and "cancel". (`nodesignald.js`: `RETRY_MS`,
  `GIVE_UP_MS`, `chat.retry`, `chat.cancel`)
- Established contacts get a check-in about every 3 minutes, so someone
  behind NAT can collect what is waiting for them. (`nodesignald.js`:
  `checkinTick`, `--checkin-ms`)
- Message states are honest: sending, delivered (only after the other daemon
  acknowledges it), retrying with the reason, or not delivered. A message
  typed while the console cannot reach its own daemon is kept in the browser
  and labelled "queued" until it can be handed over. (`nodesignald.js`: `ack`
  handling, `deferMsg`, `failMsg`; `nodesignal.html`: outbox)
- A message delivered twice by a retry is stored once. (`nodesignald.js`:
  `msg` handling)
- A solid line on the map means a confirmed two-way exchange; a green dot
  means that contact was seen in the last 5 minutes. (`nodesignald.js`:
  `uiContact`; `nodesignal.html`)
- Notification cards for new messages, an unread count on the tab and in the
  page title. Locked history never shows message text in a notification.
  (`nodesignal.html`: `notify`, `updateTitle`)

**Reaching each other (1.4)**

- Its own onion address, with no port forwarding and no torrc editing:
  install Tor and NodeSignal asks Tor's control socket for an onion service,
  the way bitcoind's `-listenonion` does. The address stays the same across
  restarts. `nodesignal onion` shows it. (`torcontrol.js`;
  `nodesignald.js`: `startOnion`, `torCandidates`)
- A contact is tried at its address first and its onion second. `.onion`
  addresses go through Tor's SOCKS5 proxy, never DNS. (`nodesignald.js`:
  `attemptDial`, `socks5Connect`)
- Mailboxes, opt-in on both sides: a reachable contact can hold sealed mail
  for an operator who cannot be reached right now. The mailbox cannot read
  it (X25519 and ChaCha20-Poly1305, sender authenticated to the recipient),
  items expire after 7 days, and the sender sees "held at" and then
  "delivered" once collected. (`mailbox.js`; `nodesignald.js`:
  `depositMessage`)
- Several operators reaching you over Tor at once are told apart by their
  keys. (`nodesignald.js`: `strangerHost`)

**Networks**

- IPv4 and IPv6 (receiving over IPv6 needs `"bind": "::"`). (`nodesignald.js`:
  `uiHost`, `sourceBlock`)
- Tailscale: when a Tailscale interface exists, the peer port listens only
  there (and on 127.0.0.1, where Tor hands onion peers over) by default.
  Without Tailscale it listens on every interface; behind a home router
  nobody reaches it unless the port is forwarded, and `"bind": "127.0.0.1"`
  keeps it to Tor. (`nodesignald.js`: `tailscaleAddr`, `PEER_BIND`)
- Opt-in router port mapping (UPnP IGD or NAT-PMP), off by default.
  (`portmap.js`; `cli.js`: `port-mapping`)

**Talking to more than one operator (1.4)**

- Feed: short posts (up to 1000 characters) signed with your key, passed to
  your contacts and at most one hop further by contacts who follow you. No
  server keeps them and nobody on the way can change them. A post from
  someone you have not talked to shows "name not verified" with its key.
  (`social.js`; `nodesignald.js`: `createPost`, `uiPost`)
- Rooms: topic rooms kept by their members' daemons. Start one, invite with
  a `nodesignal-room:` link, read the history when you join; every message
  is signed by its author. (`social.js`; `nodesignald.js`: `fanOutRoom`,
  `parseRoomLink`)
- Contact links and QR codes: `nodesignal:<address>?port=...&fp=...&nick=...`.
  Whoever adds it has your key pinned before the first connection.
  (`qr.js`; `nodesignald.js`: `parseContactLink`)
- Introductions, opt-in on both sides: contacts who turned them on pass
  each other's address and key, so adding one pins the right key.
  (`nodesignald.js`: `who-req` handling)
- Same-onion proof: when a contact's NodeSignal answers on the onion address
  of a Bitcoin node, the console says that operator runs that node; only the
  holder of the onion key can serve both. `nodesignal same-onion` explains
  the setup. (`nodesignald.js`: `noteSameOnion`)

**Keeping it (1.4)**

- Identity backup: your identity keys and contacts in a passphrase-sealed
  file (scrypt and ChaCha20-Poly1305), from the console or
  `nodesignal backup`; `nodesignal restore` keeps the history already on
  the machine. Message history is not in the backup. (`backup.js`; `cli.js`)
- Update checks: once a day NodeSignal asks GitHub Releases whether a newer
  version exists (through Tor while its onion is up) and shows it in the
  console with its notes. It installs only a release signed with a release
  key the installed copy ships with, and never anything older. 1.4.0 ships
  no release key yet, so it announces new versions without installing
  them. (`updater.js`; `nodesignald.js`: `checkForUpdate`, `installUpdate`;
  `cli.js`: `update-apply`)

**Check it yourself, or with your own AI agent (1.4)**

- `docs/AGENT-SETUP.md` is written for an AI coding agent the operator
  chooses (Claude Code, Codex, or an open-source one): run the tests, read
  the code and the self-audit, verify the download, install, and report. It
  lists what NodeSignal does on purpose, so a reviewer does not mistake it
  for hidden behaviour. The Windows installer offers this as its first
  question; on Linux, `nodesignal agent-brief` prints a brief with the
  machine's details. Both say first, plainly, that the agent will be able to
  read NodeSignal's secrets (the RPC password, the console token, the
  identity keys), and that a cloud agent sends what it reads to its
  provider. (`docs/AGENT-SETUP.md`; `cli.js`: `agentBrief`;
  `packaging/windows/sea-main.js`: `offerAgent`)
- `nodesignal rpc-access rotate` and `nodesignal web-token new` replace the
  RPC password and console token afterwards. (`cli.js`)

**Running beside a node**

- Works with Bitcoin Core and Bitcoin Knots, including pruned nodes: it only
  uses RPC methods that need no block history. (`nodesignald.js`: `pollRpc`;
  `setup-core.js`: `detectBitcoinNode`)
- RPC is read-only and limited to three methods: `getpeerinfo`,
  `getnetworkinfo`, `getblockchaininfo`. Setup gives NodeSignal its own RPC
  login (an `rpcauth` line) with an `rpcwhitelist` of exactly those methods.
  The node's cookie file is never read. (`setup-core.js`: `RPC_METHODS`,
  `setRpcAccess`; `tests/setup-core.test.js`)
- Never runs as root. On Linux it runs as its own `nodesignal` system user
  under a hardened systemd unit; on Windows it runs as your account, and the
  installer refuses an administrator window. (`packaging/deb/nodesignal.service`;
  `packaging/windows/sea-main.js`)
- The web console is reachable from the same machine only, and refuses other
  sites and other host names. Use an SSH tunnel from another computer.
  (`nodesignald.js`: `WEB_BIND`, `hostOk`, `originOk`, `ACTION_TOKEN`;
  `tests/websecurity.test.js`)
- Linux: the console asks for a login token, so other accounts on the same
  machine cannot use it. `sudo nodesignal web-token` shows it. Windows needs
  no login. (`cli.js`: `cmdWebToken`; `tests/setup-core.test.js`)
- No central server and no accounts: daemons connect to each other directly.
  (`nodesignald.js`: `peerServer`, `connectTo`)
- Zero runtime dependencies: Node.js standard library only. (`package.json`;
  `nodeps.js`)
- Inbound connections are rate limited per source (/32 for IPv4, /64 for
  IPv6) and capped, and nothing is saved to disk before a completed
  handshake. (`nodesignald.js`: `rateOk`, `MAX_CONNS`, `peerServer`)
- Installers include their own Node.js and stop, with directions, if no
  Bitcoin node is installed. (`packaging/deb/preinst`;
  `packaging/windows/sea-main.js`: `refuseNoNode`)
- On Windows a small supervisor restarts the daemon if it stops, and gives up
  with a logged reason after repeated crashes. (`packaging/windows/sea-main.js`)
- A `nodesignal` command: `status`, `advertise`, `port-mapping`,
  `rpc-access`, `open`, `onion`, `same-onion`, `updates`, `update`,
  `agent-brief`, `backup`, `restore`, `web-token`, `logs`, `version`,
  `uninstall`. (`cli.js`)
- The console asks no other server for anything: its fonts are inside the
  page, and its Content-Security-Policy lets it fetch only from its own
  daemon. (`nodesignald.js`: `CSP`; `LICENSE-fonts.txt`)
- Works on a phone-sized screen. (`tests/console.test.js`: mobile check)

## Honest limits

From `SECURITY-CRITIQUE.md` and the project guide. These belong on the site.

- **No outside review yet.** The test vectors prove `noise.js` computes the
  Noise specification correctly. They say nothing about the daemon around
  it. Nobody outside the project has audited it.
- **The 1.4 review was done by AI agents the project ran.** Before 1.4.0,
  four of them attacked one area each, and a fifth checked the result the
  way an operator's own agent would. They found 33 problems, among them a
  way for a stranger to receive messages meant for someone else and ways
  to get root on Linux; all were fixed with tests, and
  `SECURITY-CRITIQUE.md` section 10 lists each one and what is still open.
  Say it this way: useful, not an audit.
- **Posts and room messages are public** to everyone they reach, and a
  signing key says nothing about who holds it. Anyone with a room link can
  join that room and read it from then on.
- **A mailbox sees who writes to whom**, when and how much, though not what.
- **A message to someone whose key is not pinned yet goes to the first
  NodeSignal that proves a key at that address** (trust on first use).
  Behind a shared IP that can be someone else. A contact link or QR code
  pins the key first.
- **Reading a peer's node announces NodeSignal:** the port 8333 handshake
  sends `/NodeSignal:1.4/` as its user agent, so nodes it reads learn that
  this IP runs NodeSignal even with advertising off.
- **History is stored in the clear unless you set a passphrase.** With one,
  message text is sealed, but who you talk to and when, and the identity key
  (the daemon needs it unattended), stay readable by the daemon's user.
- **Metadata is not hidden.** Content is encrypted; who talks to whom, when
  and how often is visible to anyone positioned to watch. Check-ins make
  presence more visible to your own contacts.
- **It links a social identity to a node's IP address.** That is inherent to
  the design. Tor is the mitigation.
- **Every claim a peer makes about its node is self-declared.** The port 8333
  handshake is real, but a user agent is a free-form string the operator
  sets.
- **Two opt-in features cost privacy:** advertising NodeSignal in your user
  agent tells every peer of your node that you run it, and router port
  mapping opens the peer port to the internet. Both are off by default.
- **New software on a machine that runs a node.** It opens a listening port
  (8788) on that machine, on every interface unless Tailscale is present or
  the operator keeps it to Tor. A bug in the daemon would put an attacker
  on the same host as the node.
- **Joining Tor's group lets NodeSignal control the local Tor** (on Debian,
  to make its onion). `sudo nodesignal onion off` turns that off.
- **The installers are not code-signed.** Windows SmartScreen will warn.
  Check the SHA-256 against `SHA256SUMS.txt`.
- **Older peers:** 1.4.0 still answers the 1.2 handshake, which is not
  standard Noise. 1.3's notes said it would go in 1.4; it goes in 1.5.
- **In-app installs are not active yet.** 1.4.0 ships no release signing
  key, so it tells you about new versions and you install them by hand.

## Install

NodeSignal requires Bitcoin Core or Bitcoin Knots on the same machine (pruned
is fine). Each download includes its own Node.js.

Download links (stable names attached to each GitHub Release by
`.github/workflows/release.yml`):

| For | Link |
|---|---|
| Windows 10 or 11, 64-bit | https://github.com/Connor-03/NodeSignal/releases/latest/download/NodeSignal-Setup-windows-x64.exe |
| Ubuntu, Debian and other 64-bit PCs | https://github.com/Connor-03/NodeSignal/releases/latest/download/nodesignal-linux-amd64.deb |
| Raspberry Pi OS 64-bit and other arm64 boards | https://github.com/Connor-03/NodeSignal/releases/latest/download/nodesignal-linux-arm64.deb |
| Checksums | https://github.com/Connor-03/NodeSignal/releases/latest/download/SHA256SUMS.txt |

Source and install guides: https://github.com/Connor-03/NodeSignal

**Windows** (on the machine that runs the node):

1. Download `NodeSignal-Setup-windows-x64.exe` and `SHA256SUMS.txt`.
2. Check the file. Windows PowerShell, in the download folder:
   `Get-FileHash .\NodeSignal-Setup-windows-x64.exe -Algorithm SHA256`
   and compare with the line in `SHA256SUMS.txt`.
3. Double-click the .exe, with a normal double-click (not "Run as
   administrator"). SmartScreen warns because the file is not signed: choose
   More info, then Run anyway.
4. Answer the questions: whether to hand the setup to your own AI agent
   instead (it then writes a brief for the agent and installs nothing), a
   display name, and two optional extras that default to No (advertising
   NodeSignal in your user agent, router port mapping).
5. Restart your Bitcoin node once, so it reads NodeSignal's new RPC login.
   The installer tells you this and does not do it for you.

It installs to `%LOCALAPPDATA%\NodeSignal`, starts hidden when you sign in,
and opens the console in its own window (Microsoft Edge's app mode: no tabs
or address bar, its own taskbar icon) from a Desktop and Start menu shortcut.
Closing the window does not stop NodeSignal receiving messages.
(`packaging/windows/sea-main.js`: `openApp`, `writeAppShortcut`)

**Linux** (on the node):

1. Download the .deb for your machine and `SHA256SUMS.txt`.
2. Check it. Linux, in the download folder:
   `sha256sum -c SHA256SUMS.txt --ignore-missing`
3. Install it. Linux, on the node:
   `sudo apt install ./nodesignal-linux-amd64.deb`
   (or `nodesignal-linux-arm64.deb`)
4. Restart bitcoind once so it reads the new RPC login. The installer says so
   and does not restart it for you. If bitcoin.conf uses `includeconf` or
   sets RPC whitelists in a section or on bitcoind's command line, the
   installer leaves it alone and prints the lines to add by hand.
5. Check it. Linux, on the node: `sudo nodesignal status`

apt also installs Tor (the package recommends it), and NodeSignal then makes
its own onion address. If `nodesignal onion` shows none, run
`sudo nodesignal onion on` (Linux, on the node).

**Opening the console.** The console is served by the daemon on the node
itself, on port 8789, and answers only on that machine (`localhost:8789`).
From another computer, use an SSH tunnel. Linux or macOS terminal, or
Windows PowerShell, on your other computer:
`ssh -L 8789:127.0.0.1:8789 <your node>`, then browse to `localhost:8789`
there. On Linux, sign in once with the token from `sudo nodesignal web-token`
(Linux, on the node).

Note for the site: do not make `localhost:8789` a link, and do not link the
daemon's web app in any form. It is private to each operator's machine.

**Optional extras**, both off by default. Linux: `sudo nodesignal ...` on the
node. Windows: `%LOCALAPPDATA%\NodeSignal\nodesignal.exe ...` in Command
Prompt.

- `nodesignal advertise on`: lets peers see you run NodeSignal. Public to
  every peer; takes effect when you restart your node.
- `nodesignal port-mapping on`: asks your router to forward the peer port.
  Exposes your IP on clearnet. Tor and Tailscale need no port mapping.

**With your own AI agent** (1.4): give it `docs/AGENT-SETUP.md` from the
repository, or on Linux run `nodesignal agent-brief` (Linux, on the node) and
paste what it prints. Read its warning first: the agent will be able to read
NodeSignal's secrets.

## Not verified yet

State these honestly, or keep them off the site.

- **1.4.0 is published** on GitHub Releases (2026-10-31); the
  `releases/latest/download/...` links above serve it, checked against
  `SHA256SUMS.txt`.
- **In-app updates have not run for real.** 1.4.0 ships no release key, so
  no installed copy can install an update from the console yet; the path is
  tested against signed fake releases (`tests/update-apply.test.js`).
- **Not run on real Windows.** CI builds the .exe and runs its selftest on a
  Windows runner against a mock node; no one has installed it on a real
  Windows PC with a real node.
- **Not run on real arm64 hardware** (Raspberry Pi or other). The arm64 .deb
  is built in CI but not installed or run there.
- **Run on one real Linux node** (amd64, beside several other programs that
  use the node's RPC). Otherwise the tests use a mock node (`tests/mock-node.js`) that applies rpcauth and
  rpcwhitelist the way bitcoind does. Pruned-node support is by code
  reading (only three methods, none needs block history), not tested on a
  pruned node.
- **Not run against real routers.** UPnP and NAT-PMP are tested against
  mocks (`tests/portmap.test.js`).
- **Tor is tested against mocks** (a SOCKS5 proxy in `tests/tor.test.js`, a
  control port in `tests/torcontrol.test.js`), not the real Tor network.
- **Posts, rooms, mailboxes and introductions** are tested between three
  real daemons on one machine (`tests/network.test.js`,
  `tests/peerabuse.test.js`), not between operators on the internet.
- **No outside security review** of the daemon or `noise.js`. Do not call it
  reviewed or audited anywhere. The 1.4 review by AI agents may be
  mentioned as exactly that.
- **Not code-signed.** Windows SmartScreen warns on first run.
- **macOS is not a target.** There is no macOS installer; do not list it.

## Screenshots

Files in `docs/website/screenshots/` (WebP, 11 files, about 299 KB in all).
They are rendered from the real console (`nodesignal.html`) against a fake
daemon (`tools/screenshots/fixture-ws.js`), so every address is a
documentation range (198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32), every
fingerprint is made up, and the nicknames, messages, times and dates are
sample data. Do not present any of it as real activity. Regenerate with
`node tools/screenshots/shoot.js <outDir> --webp docs/website/screenshots`
(Linux or Windows, from the repository root; needs Playwright).

| File | Size (px) | Caption | Alt text |
|---|---|---|---|
| `desktop-constellation.webp` | 1600 x 1000 | Your node's real peer list, placed by latency and coloured by implementation. | NodeSignal peer map: the operator's node in the centre, peers on latency rings coloured by implementation (Bitcoin Core orange, Knots green, btcd cyan, libbitcoin violet, Bcoin pink), with a legend of counts. |
| `desktop-constellation-tooltip.webp` | 1280 x 800 | What a peer's node reported over a read-only handshake on port 8333. | Peer map with a details card for a contact: implementation Bitcoin Knots, version, latency, height, network, identity fingerprint, user agent, and supported BIPs. |
| `desktop-chat.webp` | 1280 x 800 | A conversation with another node operator, encrypted daemon to daemon. | Chat window with a contact marked online, a Noise key badge with a short fingerprint, and five delivered messages about running Bitcoin Knots. |
| `desktop-key-change-review.webp` | 1280 x 800 | A changed identity key is rejected until you compare both fingerprints. | Security warning: a contact presented a different identity key. The pinned and presented fingerprints are shown, with buttons to accept the new key or keep the old one. |
| `desktop-chat-retrying.webp` | 1280 x 800 | Undelivered messages say why, and retry on their own. | A sent message marked not delivered yet, with the reason (nothing listening on the peer port) and the time of the next retry, plus retry now and cancel. |
| `desktop-history-locked.webp` | 1280 x 800 | With a passphrase set, history stays sealed on disk and new messages still arrive. | Chat view with history locked: each message reads locked, unlock your history to read this message, and an Unlock button. |
| `desktop-status.webp` | 1280 x 800 | The status panel: handshake, identity fingerprint, its own onion address and the mailbox. | Status panel showing the daemon version, the Noise_XX_25519_ChaChaPoly_SHA256 handshake, this daemon's fingerprint, its onion address with no port forwarding, and a mailbox holding sealed mail for a contact. |
| `desktop-feed.webp` | 1280 x 800 | Posts signed by their authors and passed on by contacts, with no server. | Feed with three signed posts: one from a contact, one marked name not verified that came via that contact, and one of your own, beside introductions to people your contacts know. |
| `desktop-room.webp` | 1280 x 800 | A topic room kept by its members' daemons; every message is signed. | Room called relay policy with three members and three messages comparing mempool policy settings. |
| `desktop-share.webp` | 1280 x 800 | A contact link and its QR code carry your address and pin your key. | Dialog titled Your contact link with a QR code and a nodesignal link holding an onion address, a port, a key fingerprint and a nickname. |
| `phone-chat.webp` | 540 x 1169 | The same console on a phone-sized screen. | NodeSignal chat on a narrow phone screen with an online contact and delivered messages. |

## Rules this handoff follows (for the site to keep)

- No em dashes. Plain, direct copy. No user counts, dates, partners or other
  invented facts.
- No tokens, private host names, IP addresses or peer addresses. The only
  addresses in the images are documentation ranges; the only one in the text
  is the loopback address in the SSH tunnel command.
- The daemon's own web app is private and is not linked.
- BIP-110 is a failed proposal. This handoff does not mention it otherwise;
  if the site does, it is as history only.
