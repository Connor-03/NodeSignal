# Changelog

Every release lists what changed for an operator, then what changed under the
hood. Security changes are tracked in more depth in `SECURITY-CRITIQUE.md`.

## 1.3.0 (not yet released)

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
  `rpc-access show|add|remove`, `open`, `logs`.

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

### Known limits

- No outside review of the daemon yet. The test vectors prove `noise.js` only.
- Not yet run by a person on real Windows, real arm64 hardware, a real router
  or a real bitcoind; CI runs mocks for all of them.
- Metadata (who talks to whom, when) is not hidden. Running NodeSignal links a
  social identity to a node IP; Tor is the mitigation.

## Earlier versions

1.2 and before were developed without release notes. The git history has the
details.
