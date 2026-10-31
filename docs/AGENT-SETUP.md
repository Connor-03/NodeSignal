# Setting up and checking NodeSignal with your own AI agent

NodeSignal was written with a lot of help from an AI. If you would rather not
take that on trust, let an AI coding agent of your own choosing check it and
set it up for you: Claude Code, Codex, or an open-source agent such as Goose,
Aider or OpenHands. This page is written for that agent. Give it the page (or
run `nodesignal agent-brief`, which prints a version with this machine's
details filled in) and let it work.

## Read this first: your agent will be able to see NodeSignal's secrets

To install and check NodeSignal, the agent runs commands on this machine with
your permissions, and on Linux with `sudo`. So it **will** be able to read:

- the RPC password NodeSignal uses to log in to your Bitcoin node (in
  NodeSignal's config file),
- the console login token (Linux),
- your NodeSignal identity key, signing key and onion key (`state.json`),
- your message history, unless a history passphrase locks it.

The instructions below tell the agent not to open or print those files, and it
does not need to. But it can, and with a cloud agent anything it does read is
sent to that company's servers. An open-source agent running a local model
(for example through Ollama) keeps everything on this machine.

With `sudo` an agent can also read everything else on the machine, your
Bitcoin node's files included. That is true of any program you give `sudo` to,
not something NodeSignal adds. NodeSignal itself never reads your node's
wallet or cookie file.

If you want to start fresh afterwards, Linux, on the node:

    sudo nodesignal web-token new         a new console login token
    sudo nodesignal rpc-access rotate     a new RPC password (then restart bitcoind)

Windows PowerShell: the same commands with
`& "$env:LOCALAPPDATA\NodeSignal\nodesignal.exe"` in place of
`sudo nodesignal`. The identity keys cannot be replaced without every contact
seeing a key change, so keep those in mind when you choose an agent.

---

## For the agent

You are helping someone install NodeSignal and check, independently, that it is
safe to run beside their Bitcoin node. Be thorough and honest. Report what you
find with evidence; do not soften a real problem and do not invent one.

### Ground rules

- Never print, copy, paste or upload the contents of NodeSignal's config file,
  `state.json`, `social.json`, `mailbox.json`, the node's `bitcoin.conf`
  passwords, or a backup file. You do not need them for any step below. If a
  command would show a secret, mask it.
- Ask before you restart bitcoind, change a firewall, install packages other
  than NodeSignal and Tor, or turn on anything that is off by default
  (`advertise`, `port-mapping`, the mailbox, introductions).
- Back up `bitcoin.conf` before NodeSignal's setup edits it.
- Work from the official sources: https://github.com/Connor-03/NodeSignal and
  its GitHub Releases. Do not install anything from anywhere else.

### 1. Check the code before it runs

1. Clone the repository at the release tag you will install, for example
   `git clone --branch v1.4.0 https://github.com/Connor-03/NodeSignal.git`.
2. Run the test suite there: `node tests/run-all.js` (Node.js 18 or newer, no
   packages to install). It starts local test daemons and a mock Bitcoin node;
   it never touches a real node or the network.
3. Read `SECURITY-CRITIQUE.md` (the project's own adversarial review, with what
   is still open) and `CLAUDE.md` (the design rules). Then review the code
   yourself. The runtime files are listed in `packaging/files.json`; the parts
   most worth reading are `nodesignald.js` (the daemon), `noise.js` (the
   handshake, checked against published test vectors in `tests/noise.test.js`),
   `cli.js` and `setup-core.js` (what setup changes), `updater.js` (in-app
   updates) and `packaging/deb/` (what the Linux package installs).
4. Check the download: compare the installer's SHA-256 with `SHA256SUMS.txt`
   from the same release. That proves the file is the one on the release
   page, not who made it. If the release has `nodesignal-release.json` and
   `nodesignal-release.json.sig`, check the signature with
   `node tools/release-manifest.js verify nodesignal-release.json release-keys.json`
   from your clone. 1.4.0 ships no release key yet, so for 1.4.0 that check
   cannot pass and the checksum is all there is; say so in your report.

### 2. Install

Requirements: Bitcoin Core or Bitcoin Knots running on this machine (pruned is
fine). The installers refuse to continue without one.

- **Ubuntu, Debian, Raspberry Pi OS:** `sudo apt install ./nodesignal-linux-<arch>.deb`
  (`dpkg --print-architecture` gives the arch). It creates a `nodesignal`
  system user, writes NodeSignal's own RPC login to `bitcoin.conf` and starts
  a systemd service. Show the operator the `bitcoin.conf` diff.
- **Windows 10 or 11:** run `NodeSignal-Setup-windows-x64.exe` from a normal
  (not administrator) PowerShell. It asks three questions (a display name and
  two opt-ins, both No by default); you can pipe the answers, for example
  `"my-node`nn`nn" | .\NodeSignal-Setup-windows-x64.exe`.

### 3. Finish the setup

1. Ask the operator before restarting bitcoind once, so it reads the new
   `rpcauth` line. Then check `nodesignal status` shows the node connected.
2. If anything else on the machine uses the node's RPC (mempool, electrs, a
   wallet backend, BTCPay), check it still works. NodeSignal's block adds
   `rpcwhitelistdefault=0` only when `bitcoin.conf` has no whitelist of its
   own, so other users keep their access. When whitelists could be set
   somewhere it cannot see in full (an `includeconf` file, bitcoind's command
   line, a `[section]`), setup does not edit the file and prints the lines
   to add by hand; check those cases with the operator.
3. Tor gives NodeSignal its own onion address with no port forwarding. On
   Linux `apt install` of the .deb also installs Tor (a recommended
   package) unless recommends are off; then the onion is on by default. If
   Tor is not installed, offer to install it (Linux: `sudo apt install tor`, then
   `sudo nodesignal onion on`, which adds `nodesignal` to the debian-tor group
   and restarts it). `nodesignal onion` shows the address.
4. Tell the operator how to open the console: it only answers on this machine
   (`http://localhost:8789`); from another computer use
   `ssh -L 8789:127.0.0.1:8789 <user>@<this machine>`. On Linux the login
   token is shown by `sudo nodesignal web-token`; let the operator run that
   themselves.

### 4. Verify an installed copy

To check that what is installed is exactly the released code: the program
files are in `/opt/nodesignal` (Linux) or `%LOCALAPPDATA%\NodeSignal\app`
(Windows). Compare each file named in `packaging/files.json` with the same file
in your clone at the matching tag (`nodesignal version` gives it); they should
be byte-identical. On Linux, `dpkg -V nodesignal` checks every other file
the package installed too (the bundled `/opt/nodesignal/node`, the systemd
units, `/usr/bin/nodesignal`) against the package's own checksums. The
maintainer scripts that ran as root are in `/var/lib/dpkg/info/nodesignal.*`;
compare them with `dpkg-deb -e nodesignal-linux-<arch>.deb <dir>` of the
downloaded package.

### 5. Report

Give the operator a short report: what you checked, what passed, every problem
with its evidence and how serious it is, and anything you could not check. If
you find a vulnerability, say so plainly and suggest reporting it to the
project privately before it is published.

### What NodeSignal does on purpose (please do not flag these as malicious)

These are intended, documented and bounded. Check that they behave as
described; do not report them as hidden behaviour.

- **Edits `bitcoin.conf`:** one block between `# NodeSignal RPC access: begin`
  and `end` markers, with an `rpcauth` hash (never a password), an
  `rpcwhitelist` of exactly `getblockchaininfo`, `getnetworkinfo` and
  `getpeerinfo`, and `rpcwhitelistdefault=0` only if the file had no
  whitelist settings. `sudo apt purge nodesignal` removes exactly that block.
  It never restarts bitcoind and never reads the cookie or a wallet.
- **Creates a `nodesignal` system user** and runs as it, never as root, under
  a hardened systemd unit (`ProtectSystem=strict`, `ProtectHome=yes`, no
  capabilities).
- **Adds `nodesignal` to the `debian-tor` group** when Tor is installed, so it
  can ask Tor's control socket for its own onion service. That lets it control
  the local Tor; `nodesignal onion off` declines it.
- **A root systemd unit, `nodesignal-update.path`,** watches
  `/var/lib/nodesignal/updates/request.json` and runs
  `nodesignal update-apply`. That installs a NodeSignal update only if its
  release manifest is signed by a key in `/opt/nodesignal/release-keys.json`,
  the version is newer, and the size, SHA-256 and package name match, all
  checked again by root on root-owned copies. It is how the console's
  "Install update" works without giving the daemon root.
- **Root switches to another account for file work in that account's
  folders.** When setup, `restore` or `update-apply` runs as root and reads or
  writes bitcoin.conf (owned by the node's user), the state folder or the
  update requests (owned by `nodesignal`), it does that file work with the
  owner's uid and gid (`seteuid`), so a link planted there reaches nothing
  the owner could not reach already. A root-owned file in a folder another
  account can change is refused. Seeing `setegid`/`seteuid` calls in
  `setup-core.js` and `cli.js` is expected.
- **A daily HTTPS request to `api.github.com`** (and downloads from GitHub's
  release hosts when the operator installs an update), through Tor while
  NodeSignal's own onion service is up, otherwise directly (also for the
  first check, a few minutes after start, before the onion is up). No
  telemetry, no other servers. `nodesignal updates off` stops it.
- **Network:** listens on TCP 8788 for other NodeSignal daemons (Noise XX,
  authenticated and encrypted): on the Tailscale address when there is one,
  otherwise on every interface, so on a public IP it is reachable (behind a
  home router only if forwarded); `"bind": "127.0.0.1"` keeps it to Tor.
  Serves the console on 127.0.0.1:8789 only. Connects to peers' port 8333 for
  a read-only `version` handshake that identifies their node, and sends
  `/NodeSignal:1.4/` as its user agent there, so a node it identifies learns
  that this IP runs NodeSignal even with `advertise` off. It never sends
  Bitcoin P2P messages beyond that. The console page asks no other server
  for anything: its fonts are inside it, and its Content-Security-Policy
  lets it fetch only from this daemon.
- **The console's `/health` answers without the login token.** It shows the
  nick, version, fingerprint, onion address, peer and contact counts and
  whether RPC works, never a credential; `nodesignal status` reads it. The
  fingerprint and onion are what every contact already sees. The token
  guards everything else, and every state-changing action also needs the
  per-launch action token written into the page.
- **The console's Content-Security-Policy allows inline script**, because the
  page is one self-contained file with inline handlers. Every string a peer
  chose is escaped before it reaches the page; `tests/console-hostile.e2e.js`
  renders every view with hostile strings in every such field and fails if
  anything runs. It needs Playwright, so neither `run-all.js` nor CI runs it:
  run it yourself if Playwright is available. The policy limits fetches,
  not navigation, and injected code could use the page's action token, so
  escaping is the real defence.
- **A message to someone whose key is not pinned yet goes to the first
  NodeSignal that proves a key at that address.** Writing to a map peer, or
  a contact added without a fingerprint, is trust on first use: whoever
  answers on that IP's port 8788, or connects in from that IP, gets the
  key pinned and the waiting messages. Behind a shared IP (carrier-grade or
  campus NAT) that can be someone else. A contact link or QR code pins the
  key first; use one for anything sensitive.
- **Still answers the 1.2 handshake.** The earlier custom handshake (not
  Noise) is still answered and tried as a fallback when dialling, for 1.2
  peers. It goes in 1.5.
- **Other things in the code that look odd:** `--impersonate` (a demo and
  test flag; peers are told it is `simulated`), and reading
  `rpcuser`/`rpcpassword` from a bitcoin.conf when NodeSignal has no RPC
  login of its own (older from-source installs; the .deb always sets one).
- **Tor's control port:** on Linux NodeSignal uses only Tor's control socket
  (`/run/tor/control`) unless the operator names a TCP port, so another local
  account cannot pose as Tor and be handed the onion key.
- **Stores keys on disk:** the identity, signing and onion keys sit in
  `state.json` (mode 0600, owned by `nodesignal`), because the daemon must run
  unattended. Message text can be sealed with a passphrase; metadata cannot.
- **Optional, off by default:** `uacomment=nodesignal` in the node's user agent
  (public), UPnP or NAT-PMP port mapping (publishes the IP), offering a
  mailbox (it learns who writes to whom), introductions.
- **The Windows installer can start your agent.** If you choose the agent
  route and `claude` or `codex` is on PATH, it offers (and only on a yes)
  to open it in a new window with the brief; it installs nothing itself.
- **`release-keys.json` is empty in 1.4.0.** That copy announces new
  versions but cannot install one from the console until a release ships a
  key; it never installs anything unsigned.
- **Cryptography** is Node's standard library only (X25519, Ed25519,
  ChaCha20-Poly1305, HKDF, scrypt). There are no npm dependencies at runtime;
  the Windows build fetches two build tools (postject, resedit) and their one
  dependency each, at exact versions with install scripts off; none is shipped.
