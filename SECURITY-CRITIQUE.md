# NodeSignal: adversarial review

> **Update (v1.2):** several of the risks below are now addressed in code. Each
> is tagged **[FIXED]**, **[MITIGATED]**, or **[OPEN]**. The handshake, DDoS,
> default-bind, and dependency-removal work is done; at-rest encryption
> remains. The honest framing for a presentation is: "here is a
> proof of concept, here is the threat model, here is what I have already
> hardened, and here is what I would still not trust it with."

> **Update (v1.3):** the handshake is now standard Noise_XX_25519_ChaChaPoly_SHA256,
> checked against published test vectors; message text can be sealed at rest
> under a passphrase; the shared-PIN code is gone; a changed key is reviewed and
> accepted deliberately instead of remove-and-re-add; every peer-supplied field
> is validated. Two new opt-in features (user-agent advertising and router port
> mapping) trade privacy for reach, and are listed below as new risks.

> **Update (v1.3 self-review, Oct 2026):** a line-by-line adversarial read of
> `nodesignald.js` by the same tool that wrote most of it. It is not an outside
> review and must not be presented as one. Findings and fixes are in section 8;
> each fix has a test in `tests/hardening.test.js` that fails on the code before
> it.

## Status summary

| Risk | State |
|---|---|
| Weak PIN / no key exchange | **[FIXED]**: replaced with a Noise-XX X25519 handshake |
| Custom "Noise-like" handshake, unverifiable | **[FIXED in v1.3]**: standard Noise_XX_25519_ChaChaPoly_SHA256, passes the cacophony and snow test vectors. The old handshake is still answered for one release so v1.2 peers keep working |
| Legacy PIN code path still shipped | **[FIXED in v1.3]**: PBKDF2/AES-GCM line protocol, `contact.pin` and stored PINs removed |
| Reinstalled peer = remove and re-add | **[FIXED in v1.3]**: the new key is held for review; accepting must echo the exact presented fingerprint |
| Web console reachable from the network; DNS rebinding; cross-site actions | **[FIXED in v1.3]**: the console listens on 127.0.0.1 only, checks Host (localhost/127.0.0.1 on its port) and Origin, and every state-changing action needs a random per-launch token served only inside the page (`tests/websecurity.test.js`) |
| Daemon holds full RPC power (cookie or rpcuser/rpcpassword); ran as the node's user or root | **[FIXED in v1.3]**: its own `rpcauth` user, limited by `rpcwhitelist` to the three methods it calls (`tests/setup-core.test.js` checks the list against every `rpcCall`); the cookie is never read; on Linux it runs as a dedicated `nodesignal` system user with no access to /home; the installers refuse root and Windows administrator. Needs one bitcoind restart after install |
| Web server handed out any file in the program folder, including a from-source install's `nodesignal-config.json` (RPC password, web token) and `state.json` if `--data` pointed there | **[FIXED in v1.3]**: the console page, `/health` and the login routes are all it serves; there is no static file fallback (`tests/static.test.js`). Readable only from this machine, but it bypassed the config file's 0600 permissions for any local user |
| Console WebSocket accepted unmasked frames and unbounded fragmented messages | **[FIXED in v1.3]**: unmasked client frames close the socket (RFC 6455 5.1); the 8 MiB cap covers a whole message, not one frame (`tests/websocket.test.js`) |
| A browser tab dropping mid-write could crash the daemon | **[FIXED in v1.3]**: an EPIPE on a console socket was re-emitted as an unhandled `'error'` event |
| Corrupt `state.json` silently replaced by a fresh identity | **[FIXED in v1.3, self-review]**: only a missing file means a fresh install; anything else stops the daemon and leaves the file untouched (section 8) |
| Authenticated strangers grow state without limit | **[FIXED in v1.3, self-review]**: at most 256 contacts you never added or wrote to, 50 messages kept each, 200 messages and 1000 frames per connection (section 8) |
| Hostile field values from authenticated peers | **[FIXED in v1.3]**: every field type-checked, length-capped, control characters stripped; claims never overwrite measured node data |
| No forward secrecy | **[FIXED]**: ephemeral keys per session |
| No peer authentication / MITM | **[FIXED]**: mutual static-key auth + TOFU pinning |
| Unauthenticated disk-exhaustion DoS | **[FIXED]**: no persisted state before a completed handshake (`tests/dos.test.js`: a flood of handshake-less connections leaves state.json untouched) |
| IPv6 spray defeats per-IP limits | **[FIXED]**: rate limit per /64 source block |
| No connection cap | **[FIXED]**: `--max-conns`, default 128 |
| Clearnet-exposed by default | **[MITIGATED]**: binds to Tailscale/localhost by default |
| Plaintext at rest | **[MITIGATED in v1.3]**: with a passphrase, message text is sealed (scrypt + X25519 sealed boxes) and the daemon still receives while locked. Without one it is still plaintext. Metadata, and the identity key (needed unattended), stay readable by the daemon's user |
| 66-package supply chain | **[FIXED]**: express and ws removed; zero dependencies |
| Identity ↔ node-IP linkage | **[OPEN by design]**: inherent to the concept |
| Metadata (timing/presence) leakage | **[OPEN]**: inherent to any direct-connection design. v1.3 check-ins (every ~3 min to established contacts) make presence more visible to those contacts |
| User-agent advertising (`uacomment=nodesignal`) | **[NEW, opt-in]**: tells every peer of your node that you run NodeSignal. Makes enumeration trivial for anyone connected to you; off by default |
| Router port mapping (UPnP / NAT-PMP) | **[NEW, opt-in]**: opens the peer port to the internet and publishes your IP to every contact; off by default, never needed on Tailscale or Tor |
| No independent review | **[OPEN]**: the vector tests prove `noise.js` computes the Noise spec correctly; they say nothing about the daemon around it. Nobody outside the project has audited it yet |
| Inbound Tor peers indistinguishable (all from 127.0.0.1) | **[FIXED in v1.4]**: told apart by key and the onion their hello names; the second Tor peer is no longer refused as a "key change" of the first (`tests/network.test.js`) |
| Reaching operators behind NAT needed port forwarding | **[FIXED in v1.4]**: NodeSignal's own onion service through Tor's control port; costs control of the local Tor (section 9) |
| Tor control access (debian-tor group) | **[NEW in v1.4]**: needed to create the onion; it lets the daemon's user reconfigure the local Tor. `onion off` declines it (section 9) |
| Public posts and rooms | **[NEW in v1.4]**: signed and bounded, but public to everyone they reach and as Sybil-prone as any key-based identity (section 9) |
| Mailbox metadata | **[NEW in v1.4, opt-in]**: a mailbox cannot read mail but sees who writes to whom, when and how much (section 9) |
| Update supply chain | **[NEW in v1.4]**: in-app installs need a release manifest signed with a key shipped in the app; root re-checks everything; no downgrades. A key kept as a GitHub Actions secret means a compromised GitHub account can sign (section 9) |

---

Notes for presenting the threat model honestly. Every number below was measured
against the code as shipped, not estimated.

The strongest position on stage is not "here is my secure project." It is
**"here is a working proof of concept, here is precisely why you should not run
it on a node holding real value yet, and here is what it would take to fix."**
A Bitcoin audience rewards that. Claiming security you have not earned is the
one move that loses the room.

---

## 1. The headline risk: this is a new attack surface on a hardened machine

Bitcoin Core/Knots has had roughly fifteen years of adversarial review, fuzzing,
DoS hardening, and reproducible builds. NodeSignal is a weekend project with a
hand-rolled line protocol.

Installing it opens **two new listening ports on the machine running your node**:

| Port | Purpose | Auth by default |
|---|---|---|
| 8788 | daemon-to-daemon messaging | **none** |
| 8789 | web UI + WebSocket API | Since v1.3: loopback only, Host/Origin checked, per-launch action token, and on Linux a login token set at install (`nodesignal web-token`; optional on Windows) |

The failure mode is not "someone reads my chats." It is **lateral movement**: a
bug in the daemon puts an attacker on the same host as the node, likely as the
same user that holds the RPC credentials.

**Say this out loud.** A judge who has run a node will be thinking it, and
saying it first is worth more than any feature demo.

---

## 2. Measured weaknesses in the code as it stands

(Measured against v1.0. Sections 2.1 and 2.2 describe the PIN design that
v1.2 replaced and v1.3 removed; they are kept as the record.)

### 2.1 The PIN is not key exchange

`PBKDF2-SHA256(120k) -> AES-256-GCM`, keyed by a shared PIN.

Measured on one CPU core: **56 ms per candidate derivation.**

- 4-digit PIN = 10,000 candidates = **9.4 minutes on a single core**
- 8-digit PIN = 10^8 candidates ≈ 1,559 CPU-hours: hours on a GPU, less on rented hardware

Worse, the salt is a **compile-time constant** (`NodeSignal/1`), because both
sides must derive the same key from the PIN alone. That means one precomputed
table works against **every NodeSignal user who ever exists**. This is the
textbook argument for per-conversation salts, and this design cannot have them
without a real handshake.

Also missing: forward secrecy (one PIN compromise decrypts all past and future
traffic), replay protection, and any authentication of the peer.

### 2.2 Encrypted in transit, plaintext at rest

Verified: send a message, then read the daemon's `state.json`: the cleartext is
sitting there. Once decrypted, the plaintext is persisted next to the
ciphertext.

So the "PIN-encrypted" badge is honest about the wire and misleading about the
disk. Anyone with filesystem access (a backup, a snapshot, a stolen drive, a
different process running as the same user) reads everything.

### 2.3 Unauthenticated, unbounded state growth

Any inbound `hello` creates a **persisted contact record**. There is no auth, no
rate limit, and no cap on the number of contacts.

Measured: 400 connections from one host in **520 ms**, growing `state.json` to
**1.6 MB**.

Per-IP de-duplication limits a single attacker, but **IPv6 defeats it
entirely**. One `/64` allocation is 1.8×10^19 source addresses. At ~200 bytes
per record, filling 10 GB needs about 50 million distinct sources, well within
reach at the observed rate.

**Disk exhaustion on a node is not a chat outage. It is a node outage**, and
potentially chainstate corruption.

Related gaps in the same file: no `maxConnections` anywhere, and each socket may
buffer up to 1 MB before being dropped, so N connections hold N MB.

**[FIXED, in two steps]**: v1.2 stopped persisting anything before a completed
handshake and added the connection cap and per-/64 rate limit. That still left
the authenticated case: a key costs nothing, so every address that completes a
handshake could create a contact. The v1.3 self-review capped that too (section
8).

### 2.4 The daemon holds far more RPC power than it uses

It calls exactly three read-only methods: `getnetworkinfo`,
`getblockchaininfo`, `getpeerinfo`.

But `rpcuser`/`rpcpassword` grants **full RPC access, including wallet
commands**. A compromised daemon inherits all of it.

Concrete mitigation, worth showing on a slide because it is one line:

```
rpcwhitelist=nodesignal:getpeerinfo,getnetworkinfo,getblockchaininfo
```

Better still: run the daemon as an unprivileged user, on a machine that is not
the node, talking to the node over the LAN.

**[FIXED in v1.3]**: the installers now do this themselves. Setup adds a block
to bitcoin.conf:

```
# NodeSignal RPC access: begin. ...
rpcauth=nodesignal:<salt>$<hmac-sha256>
rpcwhitelist=nodesignal:getblockchaininfo,getnetworkinfo,getpeerinfo
rpcwhitelistdefault=0
# NodeSignal RPC access: end
```

The password is random (256 bits), lives only in NodeSignal's own 0600 config,
and never appears in bitcoin.conf or on a command line. The cookie file, which
grants everything, is never read. `rpcwhitelistdefault=0` is there because the
first `rpcwhitelist` line otherwise gives every other RPC user an empty
whitelist; it is written only when bitcoin.conf had no whitelist settings of its
own, so an operator's existing choice stands. On Linux the daemon runs as a
dedicated `nodesignal` system user (`ProtectHome=yes`), so it cannot read the
node's data directory at all. Purging the package removes the block; it never
removes the identity or history.

What is left: a compromised daemon can still read the peer list, network info
and chain tip, and the daemon's user can read its own RPC password. Running it
on a separate machine remains the stronger setup.

### 2.5 Supply chain

**[FIXED in v1.2]**: this previously pulled **66 packages** onto the machine
running your node. The daemon now uses only Node's standard library: `nodeps.js`
provides static file serving and an RFC 6455 WebSocket server in ~250 lines,
verified against the reference `ws` client for framing, 16/64-bit payload
lengths, UTF-8, ping/pong and fragmentation, plus path-traversal and dotfile
rejection. There is nothing to `npm install`.

The original finding, kept for the record:

Node operators verify GPG signatures and reproducible builds for Core. Then this
project asks them to trust a dependency tree they will never read. That is an
inconsistency a serious judge will notice. The honest fix is zero dependencies:
Node's built-in `http` module can serve the app and a minimal WebSocket
implementation is a few hundred lines.

---

## 3. The Bitcoin-specific critiques: these matter most

### 3.1 It links a social identity to a node IP

This is the deepest problem, and it is a design property, not a bug.

Bitcoin privacy practice works hard to *unlink* things. NodeSignal
deliberately links:

**persistent nickname → IP address → running a Bitcoin node → a real operator
who is awake and responsive right now.**

An internet-wide scan for port 8788 enumerates every NodeSignal user. That set is
strictly more identifiable than the node set, because each entry carries an
operator-chosen name and a social graph.

For you specifically this compounds: your node shares an RPC with **ckpool**. A
scanner correlating pool operator ↔ node IP ↔ nickname ↔ message timing assembles
a targeting package that none of those facts provide alone.

### 3.2 Metadata leaks even though content is encrypted

The content is encrypted. **Who talks to whom, when, and how often is not.**

Message timing reveals timezone, sleep schedule, and presence or absence.
For an audience that takes wrench attacks seriously, "this IP belongs to a
named human who is at their desk right now" is operationally significant.

### 3.3 Every identity claim is self-declared and spoofable

Two separate claims, with very different strength:

- **The 8333 handshake is real**: you connect and read the peer's `version`
  message. But the user agent is a free-form string the operator sets. It proves
  "something at this IP speaks Bitcoin P2P and *claims* to be Knots signaling
  BIP-110." Nothing more.
- **The daemon's `hello` is pure assertion.** Nickname and node identity are
  whatever the sender types.

Your own demo proves this: `--impersonate` makes a Windows laptop with **no
Bitcoin node at all** appear on the map as Knots signaling BIP-110 + UASF.
Do not hide that flag: **demo it deliberately**. It is the most honest thing in
the project, and it preempts the question rather than being caught by it.

### 3.4 Sybil-farmable "signaling" is worse than no signaling

Nothing prevents one entity running 10,000 daemons all claiming Knots +
BIP-110. If NodeSignal ever aggregated signaling across operators, that number
would look like measurement while being pure self-report: cheaper to fake than
hashrate, cheaper than running real nodes.

**Fake consensus data is more dangerous than absent consensus data**, because
people act on it.

### 3.5 A social layer is a consensus attack surface

This is the critique I would lead with if I were judging.

Bitcoin's security model deliberately minimizes social trust. Nodes follow
consensus rules, not other operators. NodeSignal builds a trusted-feeling
channel *between node operators, keyed to node identity*: exactly the substrate
for coordinated social pressure during a contentious fork.

Picture a chain split with messages circulating: "connect to this peer," "the
other chain is dead," "upgrade to this binary." SegWit2x and the NYA showed that
social coordination among a visible minority can be mistaken for consensus. A
purpose-built operator chat makes that easier, not harder.

The counter-argument is real and worth making: operators already coordinate on
IRC, Twitter, Telegram, and mailing lists. NodeSignal does not create the
capability; it decentralizes a thing currently centralized on corporate
platforms. That is a genuinely good answer, but only if you raise the risk
first rather than being cornered by it.

---

## 4. Smaller items a sharp judge may still catch

- **Web UI has no auth by default** and no TLS. The session cookie cannot carry
  the `Secure` flag over plain http, so it is sniffable on a shared segment.
  Defensible on a tailnet; indefensible the moment someone port-forwards it.
- **`/health` is unauthenticated** and returns nickname, peer count, and contact
  count: a free fingerprint.
- **Contacts are keyed by IP address, and IP is not identity.** Dynamic IPs, NAT
  changes, or BGP hijacks silently repoint a conversation at someone else.
- **Tor-hostile by construction.** Operators who run Tor-only do so precisely to
  avoid IP exposure; adopting NodeSignal as designed would undo that. An onion
  service version is the correct design, not an afterthought.
- **An inbound `hello` causes an outbound 8333 connection** back to the sender
  (auto-identify). Minor, but it is an unauthenticated action-at-a-distance
  primitive and a liveness oracle.

---

## 5. What honest mitigation looks like

Ordered by value per unit of work:

(Progress as of v1.3: 1, 2, 4 and 6 are done; 3 is done when a passphrase is
set; 5 is documentation; 7 has outbound SOCKS5 and hidden-service setup.)

1. **Noise_XX or similar handshake with static keys.** Kills §2.1 entirely.
   Identity becomes a keypair, not an IP and a shared PIN. This is the single
   change that upgrades the project from toy to plausible.
2. **Bind to localhost or the tailnet by default.** Clearnet exposure should be
   opt-in with a warning, not the default.
3. **Encrypt at rest, or do not persist plaintext.** Fixes §2.2.
4. **Cap contacts, connections, and per-source rate; require a handshake before
   allocating any state.** Fixes §2.3.
5. **`rpcwhitelist`, and run the daemon off the node box.** Fixes §2.4.
6. **Drop the npm dependencies.** Fixes §2.5.
7. **Onion service support**, so privacy-conscious operators are not excluded.

---

## 6. What the design already gets right: defend this confidently

- **It does not touch the Bitcoin P2P protocol.** No custom messages to peers,
  no risk of bans, no consensus-adjacent behavior. Chat rides an entirely
  separate channel. This was the correct architectural call and it is worth
  stating plainly, because the naive version of this project (stuffing chat
  into Bitcoin messages) would be actively harmful to the network.
- **Node access is read-only**, three methods, no wallet interaction.
- **Identity data is derived, not invented.** Implementation, version, height,
  service bits, and declared BIPs are parsed from what the node actually
  reported. The one simulated element is flagged as simulated in the protocol.
- **It fails honestly.** Undeliverable messages say so; messages without a PIN
  display as locked rather than silently dropping.

---

## 7. A closing line worth using

> This works, and on a small scale it is genuinely fun. But the reason I would
> not run it on a node holding real value is that it links a social identity to
> a node IP, and Bitcoin spent fifteen years trying to keep those apart. The
> interesting question is not whether operators *can* chat. It is whether a
> social layer keyed to node identity is something the network should want at
> all.

That question is more memorable than any feature, and it is one you can defend
from either side.

---

## 8. v1.3 self-review of `nodesignald.js`

What was read: everything a remote peer can reach on :8788 (frames, handshake,
hello, msg, ack), what answers on :8333 when we identify, the web front door and
every WebSocket op, the retry queue and the vault. Each fix below has a test that fails on the code before the fix: items 1 to 5
in `tests/hardening.test.js`, items 7 to 9 in the suites named. Items 7 to 9
came from writing the missing test suites the same night.

| # | Finding | Severity | Fix |
|---|---|---|---|
| 1 | Any error reading `state.json` (bad JSON after a disk fault, a permission problem) was treated as a fresh install, and the new identity was saved over the old file: identity key, pins and history gone | High (data loss) | Only a missing file is a fresh install. Otherwise the daemon refuses to start, says why, and leaves the file as it is |
| 2 | Authenticated strangers could create unlimited contacts, one per source address (an IPv6 /64 is plenty), and one connection could carry unlimited messages | Medium (disk exhaustion on the node's machine) | Contacts created by an inbound peer are marked `inbound`: at most 256 of them, 50 messages kept each. Per connection: 200 messages, 1000 frames. Adding or writing to a contact lifts its budget |
| 3 | A malformed `Cookie` header made `decodeURIComponent` throw on the WebSocket upgrade path, which nothing caught: the daemon exited | Medium (local crash, with a web token set) | Bad cookie values are ignored |
| 4 | `vault.change` checked the old passphrase outside the unlock backoff, so it could test guesses at full speed | Medium (needs the action token, so local only) | Unlock and change share one backoff |
| 5 | The user agent in a :8333 `version` reply was stored, logged and shown unbounded (up to the 4 MB frame cap) and with control characters, so it could inject fake log lines | Low | Cleaned and capped at 256, as Bitcoin Core does |
| 6 | `probe.js` and `probeTester.bat` were still in the tree, with a real public IP in their examples. CLAUDE.md lists the probe tool as removed on purpose | Low (personal data in a public repo) | Deleted. The address remains in git history |
| 7 | The web server's static fallback served any file in the web root, which is the program folder: a from-source install's `nodesignal-config.json` (RPC password, web token), the launcher, and `state.json` when `--data` pointed there. Found by `tests/static.test.js` | High (local secret disclosure past 0600 permissions) | No static fallback: the daemon serves the console page, `/health` and the login routes only |
| 8 | SOCKS5 replies were assumed to arrive in one read; a split reply corrupted the Noise stream and the message to the .onion contact never arrived. Found by `tests/tor.test.js` | Low (reliability) | Both replies are buffered until complete |
| 9 | The console WebSocket accepted unmasked client frames, capped single frames but not fragmented messages (unbounded memory), and dropped its own close frame. Found by `tests/websocket.test.js` | Low (needs the loopback console) | Unmasked frames close the socket, the 8 MiB cap covers the whole message, the close frame is sent once |

The first install on a real node (Oct 2026, upgrading a 1.2 from-source
install, with Tailscale, a USB data disk and several other RPC users) found
three more. Tests: item 10 in `tests/setup-core.test.js`, items 11 and 12 in
`tests/hardening.test.js`.

| # | Finding | Severity | Fix |
|---|---|---|---|
| 10 | With no login token, every account on the machine could use the console: the action token is written into the page, and any local process can fetch the page from 127.0.0.1. The real node also ran a game server under its own account | Medium (local: read history, send as the operator) | Linux setup creates a login token at install and on upgrade (`nodesignal web-token` shows, replaces or turns it off; off is kept across upgrades). Windows, a single-user desktop, stays open |
| 11 | On a machine with Tailscale, the peer port listened only on the tailnet address, so a Tor hidden service (which forwards to 127.0.0.1) reached nothing | Low (reliability) | The peer port also listens on 127.0.0.1 in that case |
| 12 | A 5 s RPC timeout, and a new poll every 30 s whether or not the last finished. A node on a USB disk stalls RPC while it connects a block | Low (reliability) | 30 s timeout, one poll at a time |
| 13 | Nothing compared a dialled peer's key with our own. A Tor inbound peer shows in getpeerinfo as 127.0.0.1, and messaging it reached this daemon, which acked its own message: "delivered", and the contact counted as established. Found from a real node's map after 1.3.0 | Low (a false "delivered" and "established") | A handshake with our own key is refused on both sides, the message fails with the reason, and a contact established this way is reset at start (`tests/hardening.test.js`) |

Also from that install: setup did not carry a 1.2 install's history over
(its settings lived on the unit's command line), which the release notes
promised. Fixed, with a test.

Read and left as they are, on purpose:

- **`/login` has no attempt limit.** The console listens on loopback only, so
  only local processes can try. A long random `web-token` is the defence.
- **A peer chooses the port we call it back on** (`peerPort` in hello). The host
  stays the peer's own address, so this only points us at another port on the
  peer's own machine.
- **An inbound hello still triggers an outbound :8333 identify** (section 4).
  The stranger cap now bounds how many distinct addresses can trigger it.
- **`contact.remove` while that peer's link is open** lets messages on that link
  land on the removed record until it closes. They are not saved. Cosmetic.

This review cannot replace an outside one: it shares the author's blind spots.

## 9. v1.4: new surfaces, and what bounds them

1.4 adds a feed, rooms, mailboxes, introductions, NodeSignal's own onion
service, identity backups and in-app updates. Each is listed with what it
exposes and what keeps it in check. Tests named in brackets.

| # | Surface | What an attacker gets | What bounds it |
|---|---|---|---|
| 1 | Tor control port | The daemon's user can reconfigure the local Tor (on Debian, any member of debian-tor can) | Setup adds the group only when Tor is installed, and says so; `nodesignal onion off` declines it. The onion key is kept in state.json (0600) beside the identity key [torcontrol] |
| 2 | Inbound over Tor | Every onion peer arrives from 127.0.0.1 | Contacts from loopback are matched by key only; a new key from loopback is a new contact, not a key change; the 127.0.0.1 rate-limit bucket is eight times larger, MAX_CONNS still caps it [network] |
| 3 | Posts | Anyone you or your contacts talk to can send signed posts | Ed25519 signature over a canonical body, unknown fields refused, 1000 characters, 30 posts per author per day, 200 per author, 2000 in total (own posts never dropped), 30-day window, at most two hops; a stranger may pass on only its own posts. Public by design [social, network] |
| 4 | Rooms | Anyone with a room link can join and read from then on | Room ids bind creator, name and nonce; membership entries and messages are signed; non-members' messages refused; 20 rooms, 100 members, 1000 messages each [social, network] |
| 5 | Names | A post or room message names a nick and fingerprint it chose | Shown as "your contact" only when the signing key matches the one that contact announced over its own authenticated link; otherwise "name not verified" with the key id |
| 6 | Mailboxes | The mailbox sees recipient and sender fingerprints, sizes and times | Opt-in on both sides; sealed with X25519 + ChaCha20-Poly1305, the sender authenticated to the recipient by static-static DH; 16 KiB per item, 200 per recipient, 256 recipients, 32 MiB, 7 days; register, fetch and ack answer only the fingerprint proven in the handshake; deposit ids are random. No forward secrecy for held mail [mailbox, network] |
| 7 | Introductions | Your opted-in contacts' addresses and keys reach your other opted-in contacts | Both sides must opt in, only established contacts who opted in themselves are shared, 100 per answer, 300 kept [network] |
| 8 | Contact and room links | Whoever has the link learns the address in it | The key in a contact link is pinned before the first connection, so a wrong key is held for review instead of trusted [network] |
| 9 | Identity backup | The file plus the passphrase is your identity | scrypt (N=2^17) + ChaCha20-Poly1305; import refuses KDF parameters that would exhaust memory; no message history in it [backup] |
| 10 | Update check | GitHub (or a Tor exit) learns that a NodeSignal copy checks daily | Through Tor when available, jittered; `nodesignal updates off` |
| 11 | Update install | A malicious package would run as root on the node | Only a manifest signed by a key in release-keys.json; the daemon (no root) downloads and checks, then root copies the files with O_NOFOLLOW into a root-only directory and checks signature, version (strictly newer), size, SHA-256 and the package name itself before calling apt. Release keys can be rotated. Open: the signing key is a GitHub Actions secret, so a compromised GitHub account can sign; an Actions environment with required reviewers, or signing offline, narrows that [updater, update-apply] |
| 12 | Same onion | The badge could be faked if the proof were weak | Only set after we dialled the onion ourselves and it answered with the pinned key, and the same onion is a Bitcoin node (a peer of our node, or it answered the :8333 handshake) |

