# NodeSignal

Encrypted chat between Bitcoin node operators. It runs beside Bitcoin
Core or Knots, uses your node to discover and identify peers, and serves
its own web interface.

**Messages are not sent over the Bitcoin P2P network.** They cannot be —
the protocol has no message type that can carry chat, and nodes drop
peers that send unknown data. NodeSignal is honest about the split:

| Layer | Source |
|---|---|
| **Discovery** | `getpeerinfo` — your map is your node's real peer list |
| **Identity** | a real `version`/`verack` handshake on port 8333 |
| **Transport** | a separate encrypted channel on port 8788 |

## Features

- No central server, no accounts
- End-to-end encrypted, with forward secrecy and key pinning
- Bitcoin Core and Bitcoin Knots, including pruned nodes
- Tor, Tailscale, IPv4 and IPv6
- **Zero dependencies** — Node.js and nothing else
- Self-hosted web interface

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

| Platform | Guide |
|---|---|
| Ubuntu / Linux | `LinuxInstallGuide.txt` |
| Windows | `WindowsInstallGuide.txt` — run `install-windows.bat` |
| Tor (recommended) | `TorSetupGuide.txt` |

On Windows the installer asks a short series of questions and verifies
each answer against your actual system: it finds your RPC credentials,
really connects to bitcoind and reports your node's height and peer
count, checks ports are free, and starts the daemon once to prove the
configuration works.

On Linux, `install-node.sh` installs a systemd service.

## Files

| File | Purpose |
|---|---|
| `nodesignald.js` | the daemon |
| `noise.js` | encryption (X25519 / ChaCha20-Poly1305) |
| `nodeps.js` | http + websocket layer, replaces express/ws |
| `nodesignal.html` | operator console — for a machine with a node |
| `nodesignal-demo.html` | demo build — for a machine without one |
| `install.js` + `install-windows.bat` | Windows installer |
| `install-node.sh` | Linux installer |

The daemon needs `noise.js` and `nodeps.js` beside it, plus one
interface file.

## Repository contents

Program files (all required together):

    nodesignald.js  noise.js  nodeps.js
    nodesignal.html          operator console, for a machine with a node
    nodesignal-demo.html     demo build, for a machine without one

Installers:

    install-windows.bat + install.js     Windows
    install-node.sh                      Linux (systemd)
    start-node.bat / start-daemon.bat    Windows manual launchers

Everything else is documentation, plus `LICENSE` (MIT) and `.gitignore`.

### Do not commit these

The `.gitignore` already excludes them, but they are worth knowing about,
because two of them are genuinely sensitive:

| File | Why |
|---|---|
| `nodesignal-config.json` | your RPC **password** and web login token, in plain text |
| `state.json` / `~/.nodesignal/` | your **private identity key** and full message history |
| `run-nodesignal.*` | generated per machine by the installer |
| `node_modules/` | not used — NodeSignal has no dependencies |

If you ever commit `state.json` by accident, treat that identity as burned:
delete it, restart the daemon to generate a new keypair, and tell your
contacts, who will see a fingerprint mismatch.

## Documentation

| Document | Contents |
|---|---|
| `FAQ.txt` | common questions |
| `Security.txt` | practical security guidance |
| `SECURITY-CRITIQUE.md` | full adversarial threat model, including what is still weak |
| `Troubleshooting.txt` | when something does not work |

## Honest limitations

Worth knowing before you run it:

- Messages are stored **decrypted at rest**.
- Running it **links a social identity to a node IP**. That is inherent
  to the design, and the reason to prefer Tor.
- Content is encrypted; **metadata is not** — who talks to whom, and
  when, is visible to anyone positioned to watch.
- Every claim a peer makes about its node is **self-declared**.

`SECURITY-CRITIQUE.md` covers these properly, with what has been fixed
and what has not.

## Ports

| Port | Purpose | Direction |
|---|---|---|
| 8789 | web interface, API, `/health` | inbound |
| 8788 | daemon-to-daemon messaging | inbound |
| 8333 | peer identification | outbound only |
| 8332 | bitcoind RPC | localhost only |

Tor and Tailscale need no port forwarding. Clearnet needs TCP 8788
reachable.

## License

MIT — see `LICENSE`.
