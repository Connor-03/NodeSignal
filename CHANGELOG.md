# Changelog

Every release lists what changed for an operator, then what changed under the
hood. Security changes are tracked in more depth in `SECURITY-CRITIQUE.md`.

## 1.4.0 (not yet released)

NodeSignal 1.4 turns operator-to-operator chat into a small social network
that the operators' own daemons carry: posts, topic rooms, introductions, and
reaching each other through Tor with no port forwarding. It still needs a
Bitcoin node on the same machine and still calls only the three read-only
RPC methods.

### Before you upgrade

- **Install 1.4.0 by hand, and the next release too.** From 1.4 on,
  NodeSignal tells you in the console when a newer version is out and can
  install it for you, but only a release signed with a NodeSignal release key
  built into your copy (see Updates below). 1.3 has no updater, and 1.4.0
  ships with no release key yet, so it announces the next release without
  installing it. Once a release carries the key, the ones after it install
  from the console.
- **Linux: NodeSignal joins the debian-tor group when Tor is installed**, so
  it can ask Tor for its own onion address. That lets it control the local
  Tor. Turn the onion off with `sudo nodesignal onion off` (Linux, on the
  node) if you do not want that.
- **Peers see a new signing key** in your hello, used for posts and rooms.
  Your identity key and fingerprint do not change.

### Reaching other operators, with no port forwarding

- NodeSignal gives itself an onion address through Tor's control port, the
  way bitcoind's `-listenonion` does: install Tor (`sudo apt install tor` on
  Linux) and it just happens, behind any router, with no torrc editing and no
  forwarded port. The address stays the same across restarts.
  `nodesignal onion` shows it.
- A contact is reached at its address first and its onion second.
- `nodesignal advertise on` now puts your onion in your node's user agent
  (`uacomment=nodesignal:<onion>`). Any operator whose node peers with yours
  can then message you over Tor, and the map does that by itself.
- Mailboxes: a contact can offer to hold sealed mail for operators who cannot
  be reached (no Tor, no forwarded port, or switched off). Messages waiting
  there show as "held at <mailbox>", and the sender sees "delivered" once you
  collect them. The mailbox cannot read them, but it does see who writes to
  whom, when and how much. Off unless you offer one, and you choose which
  contact's mailbox you use.
- Several operators reaching you through Tor at once used to look like one
  peer at 127.0.0.1 changing its key, and all but the first were refused.
  They are now told apart by key and by the onion they name.

### Posts, rooms, introductions

- **Feed**: short posts signed with your key, pushed to your contacts and
  passed on at most one hop further, by contacts who follow you. No server
  keeps them and nobody on the way can change them. Your established
  contacts are followed automatically; follow or unfollow anyone. A post from
  someone you have not talked to shows its signing key and "name not
  verified".
- **Rooms**: topic rooms shared by their members' daemons. Start one, invite
  people with a `nodesignal-room:` link, read the history when you join.
  Every message is signed by its author.
- **Contact links**: share `nodesignal:<address>?port=...&fp=...&nick=...` or
  its QR code (the share button). Whoever adds it has your key pinned before
  the first connection, so nobody else can answer in your place.
- **Introductions** (opt-in on both sides): contacts who turned them on swap
  their other opted-in contacts, with address and key, so adding one pins the
  right key.
- **Same onion**: when a contact's NodeSignal answers on the onion address of
  a Bitcoin node, the console says that operator runs that node. Only the
  holder of the onion key can serve both. `nodesignal same-onion` explains
  how to set it up for your own node.

### Identity backup

- Back up your identity and contacts to a passphrase-sealed file from the
  console's status panel, or `nodesignal backup <file>`. Restore it with
  `nodesignal restore <file>`, which keeps the history already on the
  machine. Message history is not in the backup.

### Updates

- Once a day NodeSignal asks GitHub Releases whether a newer version exists
  (through Tor when it has an onion address) and shows it in the console with
  its notes. It installs nothing by itself.
- "Install" works only for a release whose manifest is signed with a release
  key listed in `release-keys.json`, the list your copy shipped with. On
  Linux the daemon (no root) downloads and checks the package, and a small
  root service checks the signature, version, size and SHA-256 again itself
  before installing; older versions are refused. On Windows the new .exe
  replaces the program and restarts NodeSignal. A copy installed from source
  is told about new versions only.
- `nodesignal update` checks by hand; `sudo nodesignal update install`
  installs on Linux; `nodesignal updates off` turns the daily check off.

### Windows installer

- The setup window is in colour now: the NodeSignal logo, numbered steps, a
  tick per finished step, a spinner while NodeSignal starts, and a green
  summary panel. Anything you have to do yourself (restart Bitcoin Core or
  Knots so it reads NodeSignal's login, or add the lines by hand) comes last,
  in a yellow double-framed panel that flashes a few times, just above
  "Press Enter". Errors (no node found, started as administrator) get a red
  panel. Without a terminal, or with NO_COLOR set, the output is plain text
  with the same words.

### Check it with your own AI agent

- If you would rather not take NodeSignal on trust, hand the setup to an AI
  coding agent you choose (Claude Code, Codex, or an open-source one).
  `docs/AGENT-SETUP.md` tells it how to run the tests, read the code and the
  self-audit, verify the download, install, finish setup and report, and
  lists what NodeSignal does on purpose so it is not mistaken for something
  hidden. The Windows installer offers this first and writes
  `NodeSignal-agent-brief.txt` beside itself; elsewhere,
  `nodesignal agent-brief` prints the brief with this machine's details.
- Both say plainly, before anything else, that the agent **will** be able to
  read NodeSignal's secrets (the RPC password, the console token, the
  identity, signing and onion keys, and unlocked history), and that a cloud
  agent sends what it reads to its provider.
- `nodesignal rpc-access rotate` makes a new RPC password for NodeSignal's
  own login (restart bitcoind afterwards), for when someone else may have
  read the old one. `nodesignal web-token new` already did this for the
  console token.
- The .deb now carries `md5sums`, so `dpkg -V nodesignal` can check the
  installed files.

### Security fixes from a review before release

Before 1.4.0 went out, four independent reviewers (AI agents told to attack
it, each on one area: the peer protocol, the console, the root-run install
and update paths, and the cryptography and parsers) went through the new
code. What they found and what changed:

- **Console: a mailbox operator could run script in your console.** A
  message waiting at a contact's mailbox showed "held at <name>" with that
  operator's chosen name not escaped, so a hostile name ran in the
  console's page, which can act as you. Fixed, and a new test renders every
  view with hostile text in every field a peer chooses.
- **The console now loads nothing from the internet.** It used to fetch its
  fonts from Google Fonts each time it opened; they are now inside the page
  (`LICENSE-fonts.txt`). A Content-Security-Policy lets the page talk to
  your daemon and nothing else, so even an escaping bug could not send
  anything away.
- **Tor: another account on the machine could pose as Tor** on TCP port
  9051 while Tor was down and be handed NodeSignal's onion key. On Linux
  NodeSignal now talks only to Tor's control socket unless you name a TCP
  port yourself.
- **The Windows build fetched a build tool's dependency by version range**,
  with install scripts on. It is now pinned exactly, scripts off.

### Fixes

- A peer that connected to your node through Tor shows on the map as
  127.0.0.1, because Tor hands the connection over locally. Messaging it
  reached your own NodeSignal, which acknowledged its own message: it showed
  as delivered and the contact as established. A handshake with your own key
  is now refused, the message fails with that explanation, and a contact
  wrongly marked established this way is reset.
- A peer that has sent no block headers (BTCPay's NBXplorer, light clients)
  showed height -1. It now shows unknown.
- A ping under half a millisecond (a peer on the same machine or LAN) showed
  as "0 ms" on the map, in the peer card and in the chat header, which read
  like a missing value. It now says "<1 ms". Unmeasured pings were already
  shown as unmeasured and drawn at the map's outer edge.

### Map

- Peers that are not another operator you can message are labelled on the
  map: "via Tor" (someone who connected to your node through Tor; it shows as
  127.0.0.1 because Tor hides the real address), "this machine" (a program on
  your computer, such as an indexer), "via I2P", and "local network" (a
  private address, usually a program in a container, which can still be
  messaged). The peer card and the conversation say why, and they get no
  "add as contact" button. This uses the `network` field bitcoind reports
  for each peer (Bitcoin Core 22 and later, and Knots); an older node's
  inbound 127.0.0.1 peer is labelled "local or Tor".

### Known limits

- Still no outside review of the daemon. 1.4 adds several new pieces
  (posts, rooms, mailboxes, the Tor control client, the updater); the
  self-review is in `SECURITY-CRITIQUE.md` section 9.
- Posts and room messages are public to everyone they reach, and a signing
  key says nothing about who holds it. One person can run many nodes and
  many keys.
- Anyone with a room link can join that room and read it from then on.
- A mailbox learns who writes to whom and when.
- In-app installs need a release signed with the NodeSignal release key. If
  the copy you installed lists no key, it announces new versions only.
- Not yet run on real Windows, real arm64 hardware or a real Tor; CI runs
  mocks for all three.

## 1.3.0 (2026-10-30)

NodeSignal still requires a Bitcoin node (Bitcoin Core or Bitcoin Knots) on the
same machine, and still only calls three read-only RPC methods:
`getblockchaininfo`, `getnetworkinfo` and `getpeerinfo`.

### Before you upgrade

- **Restart your Bitcoin node once after installing.** NodeSignal now logs in to
  your node as its own RPC user, so setup adds an `rpcauth` line and an
  `rpcwhitelist` line to bitcoin.conf, and bitcoind only reads bitcoin.conf
  when it starts. Until you restart it, NodeSignal shows "Bitcoin RPC not
  connected" and keeps retrying. Setup never restarts the node for you.
- **The web console is now this machine only.** It listens on 127.0.0.1 and
  answers only to `localhost` or `127.0.0.1` on its port. From another
  computer, use an SSH tunnel: `ssh -L 8789:127.0.0.1:8789 <node>` (on the
  other computer). Bookmarks that used the node's IP, a hostname or a reverse
  proxy stop working on purpose.
- **v1.2 peers still work, for this release only.** The next release drops the
  old handshake.
- **Linux: your history moves to `/var/lib/nodesignal`.** The .deb copies an
  older install's `~/.nodesignal` there once and leaves the original alone.
- **Linux: the console now asks for a login token.** Other accounts on the
  machine can reach 127.0.0.1 too, so setup creates one. Show it with
  `sudo nodesignal web-token` (on the node). `web-token off` removes it, and
  upgrades keep that choice.
- **With Tailscale, the peer port stays on your tailnet** (as before), plus
  127.0.0.1 for a Tor hidden service. Operators found on clearnet cannot dial
  in then, though you can still message them and they reply over your link.
  `"bind": "0.0.0.0"` in the config takes clearnet peers too.

### Installing

- One-download installers that bring their own Node.js:
  `NodeSignal-Setup-windows-x64.exe`, `nodesignal-linux-amd64.deb` and
  `nodesignal-linux-arm64.deb`, attached to the GitHub Release with
  `SHA256SUMS.txt`. None of them is code-signed.
- Every installer refuses to continue on a machine without a Bitcoin node.
- Linux: NodeSignal runs as its own `nodesignal` system user, never as root and
  never as the node's user, under a hardened systemd unit.
- Windows: installs for your account only, without admin rights, and refuses an
  administrator window. It starts hidden at sign-in under a small supervisor
  that restarts the daemon if it stops (1s, doubling to 60s; it gives up after
  5 crashes in 10 minutes and logs why).
- NodeSignal never reads the node's cookie file. Its RPC password lives only in
  its own locked config; bitcoin.conf gets the salted hash. The whitelist line
  allows exactly the three methods above, and `rpcwhitelistdefault=0` is added
  only when bitcoin.conf has no whitelist settings of its own, so other RPC
  users keep working.
- Purging the package (or `uninstall --purge` on Windows) removes NodeSignal's
  lines from bitcoin.conf. It never deletes your identity key or history.
- Windows: NodeSignal opens in its own window (Microsoft Edge's app mode, no
  tabs or address bar, its own taskbar icon) from a Desktop and Start menu
  shortcut, which also starts it if it was not running. Closing the window
  does not stop NodeSignal; it keeps receiving in the background.
- The Windows .exe now carries its own icon and version details
  (ProductName NodeSignal, the release version) instead of Node's.
- New `nodesignal` command: `status`, `advertise on|off`, `port-mapping on|off`,
  `rpc-access show|add|remove`, `web-token [show|new|off]`, `open`, `logs`.

### Encryption

- The handshake is now standard `Noise_XX_25519_ChaChaPoly_SHA256`, checked
  against the published cacophony and snow test vectors. Existing pinned
  fingerprints stay valid.
- Optional passphrase for history at rest: message text is sealed as it
  arrives (scrypt, then X25519 sealed boxes), and a locked daemon still
  receives. Metadata and the identity key are still readable by the daemon's
  user.
- A peer whose key changed is still rejected, but now held for review: the
  conversation shows both fingerprints, and accepting must echo the exact new
  one.
- The shared-PIN scheme and all its code are gone.

### Reaching other operators

- Only one side needs to be reachable: a connection carries messages both ways.
- Messages that cannot be delivered are held and retried (30s up to hourly, for
  7 days), with the reason and the next try shown. Established contacts get a
  check-in every 3 minutes.
- Opt-in, both off by default: `uacomment=nodesignal` advertising in your
  node's user agent (public to every peer), and UPnP / NAT-PMP router port
  mapping (publishes your IP).

### Console

- With more than 40 peers, the map draws the 40 you have exchanged the most
  messages with (then contacts, then peers advertising NodeSignal, then the
  closest), so labels stay readable. The open chat always stays on the map,
  and the counts above it say how many are not drawn.

- Redesigned console, including the mobile layout. The composer is always
  enabled: a message typed while the daemon is unreachable is held as
  "queued" and sent on reconnect.

### Security fixes

- Web console: loopback-only bind, Host and Origin checks (blocks DNS
  rebinding and cross-site requests), and a per-launch token on every action
  that changes something.
- A browser tab closing mid-update could stop the daemon (EPIPE). Fixed.
- A short `version` message on :8333 could throw inside a socket handler.
  Fixed.
- From the self-review (`SECURITY-CRITIQUE.md` section 8; not an outside
  review):
  - a corrupt `state.json` no longer gets replaced by a new identity: the
    daemon refuses to start and leaves it alone;
  - contacts created by strangers are capped (256, 50 messages each, 200
    messages per connection), so nobody can fill the disk your node shares;
  - a malformed Cookie header can no longer stop the daemon;
  - the passphrase-change form shares the unlock backoff;
  - the user agent read on :8333 is cleaned and capped at 256 characters;
  - the web server no longer serves files from its program folder, where a
    from-source install keeps its config with the RPC password;
  - a split SOCKS5 reply no longer breaks delivery to a `.onion` contact;
  - the console WebSocket refuses unmasked frames and caps fragmented
    messages;
  - `probe.js` and `probeTester.bat` are removed.
- From the first install on a real node (`SECURITY-CRITIQUE.md` section 8,
  items 10 to 12):
  - Linux installs get a console login token (see above);
  - with Tailscale, a Tor hidden service could not reach the peer port;
  - a node on a slow disk caused "RPC timeout" while it connected a block:
    the timeout is now 30 seconds, and polls no longer pile up;
  - a 1.2 from-source install's history was not copied to
    `/var/lib/nodesignal`;
  - `nodesignal status` run without sudo now says why it cannot read the
    config.

### Known limits

- No outside review of the daemon yet. The test vectors prove `noise.js` only.
- Run on one real Linux node (amd64, beside several other programs that use
  the node's RPC). Not yet on real Windows, arm64 hardware or a real
  router; CI runs mocks for those.
- Metadata (who talks to whom, when) is not hidden. Running NodeSignal links a
  social identity to a node IP; Tor is the mitigation.

## Earlier versions

1.2 and before were developed without release notes. The git history has the
details.
