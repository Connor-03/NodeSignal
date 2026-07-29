# NodeSignal — adversarial review

> **Update (v1.2):** several of the risks below are now addressed in code. Each
> is tagged **[FIXED]**, **[MITIGATED]**, or **[OPEN]**. The handshake, DDoS,
> default-bind, and dependency-removal work is done; at-rest encryption
> remains. The honest framing for a presentation is: "here is a
> proof of concept, here is the threat model, here is what I have already
> hardened, and here is what I would still not trust it with."

## Status summary

| Risk | State |
|---|---|
| Weak PIN / no key exchange | **[FIXED]** — replaced with a Noise-XX X25519 handshake |
| No forward secrecy | **[FIXED]** — ephemeral keys per session |
| No peer authentication / MITM | **[FIXED]** — mutual static-key auth + TOFU pinning |
| Unauthenticated disk-exhaustion DoS | **[FIXED]** — no persisted state before a completed handshake |
| IPv6 spray defeats per-IP limits | **[FIXED]** — rate limit per /64 source block |
| No connection cap | **[FIXED]** — `--max-conns`, default 128 |
| Clearnet-exposed by default | **[MITIGATED]** — binds to Tailscale/localhost by default |
| Plaintext at rest | **[OPEN]** — messages still stored decrypted on disk |
| 66-package supply chain | **[FIXED]** — express and ws removed; zero dependencies |
| Identity ↔ node-IP linkage | **[OPEN by design]** — inherent to the concept |
| Metadata (timing/presence) leakage | **[OPEN]** — inherent to any direct-connection design |

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
| 8789 | web UI + WebSocket API | **none** (`--web-token` optional) |

The failure mode is not "someone reads my chats." It is **lateral movement**: a
bug in the daemon puts an attacker on the same host as the node, likely as the
same user that holds the RPC credentials.

**Say this out loud.** A judge who has run a node will be thinking it, and
saying it first is worth more than any feature demo.

---

## 2. Measured weaknesses in the code as it stands

### 2.1 The PIN is not key exchange

`PBKDF2-SHA256(120k) -> AES-256-GCM`, keyed by a shared PIN.

Measured on one CPU core: **56 ms per candidate derivation.**

- 4-digit PIN = 10,000 candidates = **9.4 minutes on a single core**
- 8-digit PIN = 10^8 candidates ≈ 1,559 CPU-hours — hours on a GPU, less on rented hardware

Worse, the salt is a **compile-time constant** (`NodeSignal/1`), because both
sides must derive the same key from the PIN alone. That means one precomputed
table works against **every NodeSignal user who ever exists**. This is the
textbook argument for per-conversation salts, and this design cannot have them
without a real handshake.

Also missing: forward secrecy (one PIN compromise decrypts all past and future
traffic), replay protection, and any authentication of the peer.

### 2.2 Encrypted in transit, plaintext at rest

Verified: send a message, then read the daemon's `state.json` — the cleartext is
sitting there. Once decrypted, the plaintext is persisted next to the
ciphertext.

So the "PIN-encrypted" badge is honest about the wire and misleading about the
disk. Anyone with filesystem access — a backup, a snapshot, a stolen drive, a
different process running as the same user — reads everything.

### 2.3 Unauthenticated, unbounded state growth

Any inbound `hello` creates a **persisted contact record**. There is no auth, no
rate limit, and no cap on the number of contacts.

Measured: 400 connections from one host in **520 ms**, growing `state.json` to
**1.6 MB**.

Per-IP de-duplication limits a single attacker — but **IPv6 defeats it
entirely**. One `/64` allocation is 1.8×10^19 source addresses. At ~200 bytes
per record, filling 10 GB needs about 50 million distinct sources, well within
reach at the observed rate.

**Disk exhaustion on a node is not a chat outage. It is a node outage**, and
potentially chainstate corruption.

Related gaps in the same file: no `maxConnections` anywhere, and each socket may
buffer up to 1 MB before being dropped — so N connections hold N MB.

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

### 2.5 Supply chain

**[FIXED in v1.2]** — this previously pulled **66 packages** onto the machine
running your node. The daemon now uses only Node's standard library: `nodeps.js`
provides static file serving and an RFC 6455 WebSocket server in ~250 lines,
verified against the reference `ws` client for framing, 16/64-bit payload
lengths, UTF-8, ping/pong and fragmentation, plus path-traversal and dotfile
rejection. There is nothing to `npm install`.

The original finding, kept for the record:

Node operators verify GPG signatures and reproducible builds for Core. Then this
project asks them to trust a dependency tree they will never read. That is an
inconsistency a serious judge will notice. The honest fix is zero dependencies —
Node's built-in `http` module can serve the app and a minimal WebSocket
implementation is a few hundred lines.

---

## 3. The Bitcoin-specific critiques — these matter most

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

- **The 8333 handshake is real** — you connect and read the peer's `version`
  message. But the user agent is a free-form string the operator sets. It proves
  "something at this IP speaks Bitcoin P2P and *claims* to be Knots signaling
  BIP-110." Nothing more.
- **The daemon's `hello` is pure assertion.** Nickname and node identity are
  whatever the sender types.

Your own demo proves this: `--impersonate` makes a Windows laptop with **no
Bitcoin node at all** appear on the map as Knots signaling BIP-110 + UASF.
Do not hide that flag — **demo it deliberately**. It is the most honest thing in
the project, and it preempts the question rather than being caught by it.

### 3.4 Sybil-farmable "signaling" is worse than no signaling

Nothing prevents one entity running 10,000 daemons all claiming Knots +
BIP-110. If NodeSignal ever aggregated signaling across operators, that number
would look like measurement while being pure self-report — cheaper to fake than
hashrate, cheaper than running real nodes.

**Fake consensus data is more dangerous than absent consensus data**, because
people act on it.

### 3.5 A social layer is a consensus attack surface

This is the critique I would lead with if I were judging.

Bitcoin's security model deliberately minimizes social trust. Nodes follow
consensus rules, not other operators. NodeSignal builds a trusted-feeling
channel *between node operators, keyed to node identity* — exactly the substrate
for coordinated social pressure during a contentious fork.

Picture a chain split with messages circulating: "connect to this peer," "the
other chain is dead," "upgrade to this binary." SegWit2x and the NYA showed that
social coordination among a visible minority can be mistaken for consensus. A
purpose-built operator chat makes that easier, not harder.

The counter-argument is real and worth making: operators already coordinate on
IRC, Twitter, Telegram, and mailing lists. NodeSignal does not create the
capability; it decentralizes a thing currently centralized on corporate
platforms. That is a genuinely good answer — but only if you raise the risk
first rather than being cornered by it.

---

## 4. Smaller items a sharp judge may still catch

- **Web UI has no auth by default** and no TLS. The session cookie cannot carry
  the `Secure` flag over plain http, so it is sniffable on a shared segment.
  Defensible on a tailnet; indefensible the moment someone port-forwards it.
- **`/health` is unauthenticated** and returns nickname, peer count, and contact
  count — a free fingerprint.
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

## 6. What the design already gets right — defend this confidently

- **It does not touch the Bitcoin P2P protocol.** No custom messages to peers,
  no risk of bans, no consensus-adjacent behavior. Chat rides an entirely
  separate channel. This was the correct architectural call and it is worth
  stating plainly, because the naive version of this project — stuffing chat
  into Bitcoin messages — would be actively harmful to the network.
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
> a node IP — and Bitcoin spent fifteen years trying to keep those apart. The
> interesting question is not whether operators *can* chat. It is whether a
> social layer keyed to node identity is something the network should want at
> all.

That question is more memorable than any feature, and it is one you can defend
from either side.
