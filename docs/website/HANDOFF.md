# NodeSignal: website handoff

For the site instance that builds nodesignal.connoraherne.com. Everything
below was checked against the code in this repository (v1.3.0, the version
in `package.json`). The file references after each feature are for
verification; they do not need to appear on the site.

---

## Needs the maintainer's approval (read first)

The maintainer's approved copy says messages are "carried by the Bitcoin P2P
network". **That is not how NodeSignal works.** Messages never travel over
Bitcoin P2P: the Bitcoin protocol has no message type that can carry chat,
and nodes disconnect peers that send unknown messages. The node only
provides **discovery** (`getpeerinfo`) and **identity** (a read-only
`version`/`verack` handshake on port 8333). The messages themselves go
daemon to daemon on TCP 8788, in a separate encrypted channel. The README
says this in bold, and it is the project's founding design decision.

Until the maintainer approves new wording, use the approved text exactly as
written below, or leave it out. Do not reword it on your own.

**Long version, approved copy (word for word):**

> Inspired by my research into the Core vs Knots debate, I wanted an
> effective communication system, carried by the Bitcoin P2P network, that
> lets verified node operators talk to each other, display what they are
> signaling for, and hold a proper discussion on relay and consensus. It uses
> node peers for contact discovery, maps the connections, and opens its own
> authenticated channel between daemons so two operators can chat with no
> third party in between.

Proposed change, for the maintainer to approve or reject: replace "carried by
the Bitcoin P2P network" with "found through the Bitcoin P2P network".

**Short version, approved copy (word for word):**

> Encrypted messaging between node operators, carried by the P2P network
> they already run. No third party in the middle.

Proposed change: "Encrypted messaging between node operators, found through
the P2P network they already run. No third party in the middle."

Two smaller points in the long version, for the maintainer to consider (no
change proposed without him):

- "verified node operators": what NodeSignal verifies is that an address
  answers a real Bitcoin `version` handshake and holds the same identity key
  as last time. Who the operator is, and what their node claims to be, is
  self-declared.
- "display what they are signaling for": this is BIP numbers that an
  operator wrote into their node's user agent. It is a declaration, not
  version-bit or miner signalling.

Related story link (from the maintainer): https://bpi.connoraherne.com

---

## One-line pitch

Pending the approval above, use the proposed short version:

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
5. **Delivery.** Either side's connection carries messages both ways, so only
   one of the two operators needs to be reachable. Messages that cannot be
   delivered yet wait and retry, and the console says why.

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
  adds `uacomment=nodesignal` to bitcoin.conf). (`nodesignald.js`:
  `nodesignalFromUA`; `setup-core.js`: `setUaComment`; `cli.js`)

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

**Networks**

- IPv4 and IPv6. (`nodesignald.js`: `uiHost`, `sourceBlock`)
- Tor: `.onion` contacts are reached through Tor's SOCKS5 proxy; receiving
  over Tor needs a hidden service, set up by hand as `TorSetupGuide.txt`
  describes. (`nodesignald.js`: `socks5Connect`, `dial`)
- Tailscale: when a Tailscale interface exists, the peer port listens only
  there by default. (`nodesignald.js`: `tailscaleAddr`, `PEER_BIND`)
- Opt-in router port mapping (UPnP IGD or NAT-PMP), off by default.
  (`portmap.js`; `cli.js`: `port-mapping`)

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
  `rpc-access`, `open`, `logs`, `version`, `uninstall`. (`cli.js`)
- Works on a phone-sized screen. (`tests/console.test.js`: mobile check)

## Honest limits

From `SECURITY-CRITIQUE.md` and the project guide. These belong on the site.

- **No outside review yet.** The test vectors prove `noise.js` computes the
  Noise specification correctly. They say nothing about the daemon around
  it. Nobody outside the project has audited it.
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
  (8788) on that machine. A bug in the daemon would put an attacker on the
  same host as the node.
- **The installers are not code-signed.** Windows SmartScreen will warn.
  Check the SHA-256 against `SHA256SUMS.txt`.
- **Older peers:** v1.3 still answers the previous (v1.2) handshake for one
  release; that path is not standard Noise and will be removed.

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
4. Answer the questions: a display name, and two optional extras that
   default to No (advertising NodeSignal in your user agent, router port
   mapping).
5. Restart your Bitcoin node once, so it reads NodeSignal's new RPC login.
   The installer tells you this and does not do it for you.

It installs to `%LOCALAPPDATA%\NodeSignal`, starts hidden when you sign in,
and opens the console in your browser.

**Linux** (on the node):

1. Download the .deb for your machine and `SHA256SUMS.txt`.
2. Check it. Linux, in the download folder:
   `sha256sum -c SHA256SUMS.txt --ignore-missing`
3. Install it. Linux, on the node:
   `sudo apt install ./nodesignal-linux-amd64.deb`
   (or `nodesignal-linux-arm64.deb`)
4. Restart bitcoind once so it reads the new RPC login. The installer says so
   and does not restart it for you.
5. Check it. Linux, on the node: `sudo nodesignal status`

**Opening the console.** The console is served by the daemon on the node
itself, on port 8789, and answers only on that machine (`localhost:8789`).
From another computer, use an SSH tunnel. Linux or macOS terminal, or
Windows PowerShell, on your other computer:
`ssh -L 8789:127.0.0.1:8789 <your node>`, then browse to `localhost:8789`
there.

Note for the site: do not make `localhost:8789` a link, and do not link the
daemon's web app in any form. It is private to each operator's machine.

**Optional extras**, both off by default. Linux: `sudo nodesignal ...` on the
node. Windows: `%LOCALAPPDATA%\NodeSignal\nodesignal.exe ...` in Command
Prompt.

- `nodesignal advertise on`: lets peers see you run NodeSignal. Public to
  every peer; takes effect when you restart your node.
- `nodesignal port-mapping on`: asks your router to forward the peer port.
  Exposes your IP on clearnet. Tor and Tailscale need no port mapping.

## Not verified yet

State these honestly, or keep them off the site.

- **No release has been published yet.** When this handoff was written the
  repository had no GitHub Releases, so every
  `releases/latest/download/...` link above returns 404 until the maintainer
  pushes a `v*` tag. Check the links before the site goes live.
- **Not run on real Windows.** CI builds the .exe and runs its selftest on a
  Windows runner against a mock node; no one has installed it on a real
  Windows PC with a real node.
- **Not run on real arm64 hardware** (Raspberry Pi or other). The arm64 .deb
  is built in CI but not installed or run there.
- **Not run against a real bitcoind or Knots node** in this work: the tests
  use a mock node (`tests/mock-node.js`) that applies rpcauth and
  rpcwhitelist the way bitcoind does. Pruned-node support is by code
  reading (only three methods, none needs block history), not tested on a
  pruned node.
- **Not run against real routers.** UPnP and NAT-PMP are tested against
  mocks (`tests/portmap.test.js`).
- **Tor is not covered by the test suite.** Outbound `.onion` dialling
  through SOCKS5 is in the code, but no test exercises it; inbound needs a
  hidden service the operator sets up by hand.
- **No outside security review** of the daemon or `noise.js`. Do not call it
  reviewed or audited anywhere.
- **Not code-signed**, and the Windows .exe has no icon or version resource.
- **Linux package Maintainer field** still has a placeholder GitHub id
  (`packaging/deb/build-deb.sh`); the maintainer has to fill it in.
- **macOS is not a target.** There is no macOS installer; do not list it.

## Screenshots

Files in `docs/website/screenshots/` (WebP, 8 files, about 222 KB in all).
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
| `desktop-status.webp` | 1280 x 800 | The status panel: handshake, identity fingerprint, history and the node. | Status panel showing the daemon version, the Noise_XX_25519_ChaChaPoly_SHA256 handshake, this daemon's fingerprint, sealed history unlocked, and the Bitcoin node's implementation, height and connections. |
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
