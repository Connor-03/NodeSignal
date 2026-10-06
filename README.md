# NodeSignal

Encrypted chat between Bitcoin node operators. It runs beside Bitcoin
Core or Knots, uses your node to discover and identify peers, and serves
its own web interface.

**Messages are not sent over the Bitcoin P2P network.** They cannot be:
the protocol has no message type that can carry chat, and nodes drop
peers that send unknown data. NodeSignal is honest about the split:

| Layer | Source |
|---|---|
| **Discovery** | `getpeerinfo`: your map is your node's real peer list |
| **Identity** | a real `version`/`verack` handshake on port 8333 |
| **Transport** | a separate encrypted channel on port 8788 |

## Features

- No central server, no accounts
- End-to-end encrypted with standard **Noise_XX_25519_ChaChaPoly_SHA256**
  (checked against published test vectors), forward secrecy and key pinning
- A changed key is rejected until you review both fingerprints and accept it
- Optional history passphrase: message text sealed at rest, still received
  while locked
- Messages wait and retry until delivered; only one of two operators needs
  to be reachable
- Find other operators: peers that advertise NodeSignal in their user agent
  are marked on the map (opt-in for your own node)
- Bitcoin Core and Bitcoin Knots, including pruned nodes
- Tor, Tailscale, IPv4 and IPv6; opt-in router port mapping (UPnP / NAT-PMP)
- **Zero runtime dependencies**: Node.js standard library only
- Self-hosted web interface, one-download installers for Windows and Linux

## How it works

```
Your Bitcoin node
   └─ RPC (read-only, 3 methods)
        └─ NodeSignal daemon ──── encrypted TCP :8788 ────┐
             └─ web interface :8789                       │
                                                          ▼
                                          Remote NodeSignal daemon
                                               └─ their Bitcoin node
```

## Install

NodeSignal runs beside a Bitcoin node and **requires Bitcoin Core or Bitcoin
Knots on the same machine** (pruned is fine). The installers check for one
and stop, with directions, if there is none. Each download includes its own
Node.js, so nothing else needs installing.

| Platform | Download |
|---|---|
| Windows 10 / 11 (64-bit) | [NodeSignal-Setup-windows-x64.exe](https://github.com/Connor-03/NodeSignal/releases/latest/download/NodeSignal-Setup-windows-x64.exe) |
| Ubuntu, Debian (amd64) | [nodesignal-linux-amd64.deb](https://github.com/Connor-03/NodeSignal/releases/latest/download/nodesignal-linux-amd64.deb) |
| Raspberry Pi OS 64-bit, other arm64 | [nodesignal-linux-arm64.deb](https://github.com/Connor-03/NodeSignal/releases/latest/download/nodesignal-linux-arm64.deb) |
| Checksums | [SHA256SUMS.txt](https://github.com/Connor-03/NodeSignal/releases/latest/download/SHA256SUMS.txt) |

**Windows:** double-click the .exe. No admin rights needed. It asks for a
display name and two optional extras (both default to No), installs to
`%LOCALAPPDATA%\NodeSignal`, starts hidden at sign-in, and opens in its own
window (Edge's app mode: no tabs, its own taskbar icon) from a Desktop and
Start menu shortcut. Closing the window does not stop it receiving. The file is not code-signed, so SmartScreen will warn;
compare its SHA-256 with `SHA256SUMS.txt` first.

**Linux** (on the node):

```
sudo apt install ./nodesignal-linux-amd64.deb
```

It runs as a systemd service under its own `nodesignal` system user (never
root), gives itself an RPC login of its own (an `rpcauth` line plus an
`rpcwhitelist` of the three read-only methods it calls, written to
bitcoin.conf; the cookie file is never used), and prints the web address when
done. Restart bitcoind once afterwards so it reads the new login; the installer
says so and does not do it for you. On Windows the same login is set up, and
NodeSignal runs as your account without admin rights.

Optional, both off by default (Linux: `sudo nodesignal ...` on the node;
Windows: `%LOCALAPPDATA%\NodeSignal\nodesignal.exe ...` in Command Prompt):

- **Advertise:** `nodesignal advertise on` adds `uacomment=nodesignal` to
  bitcoin.conf so peers can see you run NodeSignal. Public to every peer;
  takes effect when you restart your node.
- **Port mapping:** `nodesignal port-mapping on` asks your router (UPnP /
  NAT-PMP) to forward the peer port. Exposes your node's IP on clearnet; Tor
  or Tailscale need no port mapping.

Details, troubleshooting and installing from source: `WindowsInstallGuide.txt`,
`LinuxInstallGuide.txt`, `TorSetupGuide.txt`.

Tor (recommended for privacy): `TorSetupGuide.txt`.

## Files

| File | Purpose |
|---|---|
| `nodesignald.js` | the daemon |
| `noise.js` | Noise XX handshake (X25519 / ChaCha20-Poly1305 / SHA-256) |
| `store.js` | history at rest: passphrase vault and sealed messages |
| `portmap.js` | opt-in router port mapping (UPnP / NAT-PMP) |
| `nodeps.js` | http + websocket layer, replaces express/ws |
| `nodesignal.html` | the operator console |
| `cli.js` + `setup-core.js` | the `nodesignal` command and shared setup logic |
| `packaging/` | builds the Windows .exe and the Linux .debs |
| `install.js` + `install-windows.bat`, `install-node.sh` | from-source installers |
| `tests/`, `tools/screenshots/` | tests (`npm test`) and publishable screenshots |

The daemon needs the files listed in `packaging/files.json` side by side.

## Repository contents

Program files (all required together, listed in `packaging/files.json`):

    nodesignald.js  noise.js  nodeps.js  store.js  portmap.js
    nodesignal.html          the operator console

From-source installers (most people should use the downloads above):

    install-windows.bat + install.js     Windows
    install-node.sh                      Linux (systemd)
    start-node.bat                       Windows manual launcher

Everything else is documentation, plus `LICENSE` (MIT) and `.gitignore`.

### Do not commit these

The `.gitignore` already excludes them, but they are worth knowing about,
because two of them are genuinely sensitive:

| File | Why |
|---|---|
| `nodesignal-config.json` | NodeSignal's RPC **password** and web login token, in plain text (installed copies live in `/etc/nodesignal/` or `%LOCALAPPDATA%\NodeSignal\`, outside the repo) |
| `state.json` / `~/.nodesignal/` | your **private identity key** and full message history |
| `run-nodesignal.*` | generated per machine by the installer |
| `node_modules/` | not used: NodeSignal has no dependencies |

If you ever commit `state.json` by accident, treat that identity as burned:
delete it, restart the daemon to generate a new keypair, and tell your
contacts, who will see a fingerprint mismatch.

## Documentation

| Document | Contents |
|---|---|
| `FAQ.txt` | common questions |
| `Security.txt` | practical security guidance |
| `SECURITY-CRITIQUE.md` | full adversarial threat model, including what is still weak |
| `CHANGELOG.md` | what changed in each release |
| `RELEASING.md` | how a release is built, dry-run and published |
| `Troubleshooting.txt` | when something does not work |

## Honest limitations

Worth knowing before you run it:

- Without a history passphrase, messages are stored **in the clear** on
  disk. With one, message text is sealed, but metadata and the identity key
  stay readable by the daemon's user.
- The Noise handshake is checked against the specification's test vectors;
  the daemon around it has **not had an outside review**.
- The installers are **not code-signed**; check `SHA256SUMS.txt`.
- Running it **links a social identity to a node IP**. That is inherent
  to the design, and the reason to prefer Tor.
- Content is encrypted; **metadata is not**: who talks to whom, and
  when, is visible to anyone positioned to watch.
- Every claim a peer makes about its node is **self-declared**.

`SECURITY-CRITIQUE.md` covers these properly, with what has been fixed
and what has not.

## Ports

| Port | Purpose | Direction |
|---|---|---|
| 8789 | web interface, API, `/health` | this machine only (127.0.0.1); use an SSH tunnel from elsewhere |
| 8788 | daemon-to-daemon messaging | inbound |
| 8333 | peer identification | outbound only |
| 8332 | bitcoind RPC | localhost only |

Tor and Tailscale need no port forwarding. On clearnet only one of two
operators needs TCP 8788 reachable; `nodesignal port-mapping on` can ask
the router to forward it (opt-in, exposes your IP). Router port mapping
also sends UDP to the router (SSDP 1900, NAT-PMP 5351) on the LAN only.

## License

MIT: see `LICENSE`.
