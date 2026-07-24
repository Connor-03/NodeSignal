NodeSignal — two programs, one protocol
=======================================================================
There are now TWO interfaces, because they do different jobs:

  nodesignal.html        the OPERATOR CONSOLE  -> goes on the node
                         real peers only, no demo, no dev tools
  nodesignal-demo.html   the DEMO PROGRAM      -> stays on Windows
                         fake constellation + dev tools, for showing
                         the concept without a node

Both are served by the same daemon (nodesignald.js).

  ON THE UBUNTU NODE            ON WINDOWS (demo peer)
    nodesignald.js                nodesignald.js
    nodesignal.html               nodesignal-demo.html
    install-node.sh               start-daemon.bat

Do NOT put nodesignal-demo.html on the node. It uses the browser Web
Crypto API for its fake encrypted chats, and that API does not exist on
a plain http:// page served to an IP address — which is exactly why the
node's page came up blank before. The console has no browser crypto at
all: the daemon does the encryption.


=======================================================================
UBUNTU NODE
=======================================================================
Put nodesignald.js, nodesignal.html and install-node.sh in one folder:

    chmod +x install-node.sh
    ./install-node.sh Bama-Knots-Node

Then open  http://100.99.115.114:8789

What you get, all of it real:
  · your node's identity, height and network in the header
  · every peer from getpeerinfo on the constellation map, coloured and
    classified by implementation, placed by ping time
  · each peer's version and declared BIPs, parsed from the user agent
    your node already received
  · click ANY peer to open a chat with its operator
  · contacts (operators running nodesignald) draw with a solid line and
    a live pip; ordinary node peers stay dashed

Upgrading over an older install keeps ~/.nodesignal/state.json — your
contacts and message history are untouched.

Controls:
    sudo systemctl status nodesignal
    sudo systemctl restart nodesignal
    journalctl -u nodesignal -f
    curl http://127.0.0.1:8789/health

If ufw is on:
    sudo ufw allow in on tailscale0 to any port 8789 proto tcp
    sudo ufw allow in on tailscale0 to any port 8788 proto tcp


=======================================================================
WINDOWS DEMO PROGRAM
=======================================================================
Put nodesignald.js, nodesignal-demo.html and start-daemon.bat in one
folder, install Node.js LTS, then double-click start-daemon.bat.
Leave the window open — that window is the peer.

If Windows Firewall prompts, ALLOW it, or replies cannot get back in.
To do it manually, once, in an ADMIN PowerShell:

    netsh advfirewall firewall add rule name="NodeSignal 8788" dir=in action=allow protocol=TCP localport=8788

Open the demo interface by double-clicking nodesignal-demo.html
(file:// is a secure context, so its demo encryption works there).

The launcher starts the daemon with --impersonate, so this machine
advertises a Knots identity signalling BIP-110 + UASF. It has no Bitcoin
node, so that identity is SIMULATED and is flagged as such to the peers
that receive it — the node's console shows it like any other classified
peer, which is what makes the demo read clearly.

Do NOT double-click nodesignald.js. Windows hands .js files to Windows
Script Host, which fails with "800A03EA JScript compilation error".
That is the wrong interpreter, not a broken file. Use the .bat.


=======================================================================
DEMO RUNBOOK
=======================================================================
Before the audience:
  [ ] tailscale status        both machines, on both machines
  [ ] http://100.99.115.114:8789 loads and shows your real peers
  [ ] start-daemon.bat window open on Windows
  [ ] know the Windows Tailscale IP   (tailscale ip -4)
  [ ] pick a shared PIN, e.g. 2013

Prep:
  On WINDOWS (nodesignal-demo.html): add 100.99.115.114 with PIN 2013.
    It identifies over :8333 within seconds — Knots, version, height,
    BIP-110 + UASF.
  On the NODE (:8789): add the Windows Tailscale IP with PIN 2013.

The demo:
  1. Windows: open the node's chat, send a message -> "delivered".
  2. Node console: the message is already there. It arrived at the NODE,
     not at a browser — the laptop could have been closed.
  3. Reply from the node. It appears on Windows immediately.
  4. Point at the map: the Windows machine now sits among your real
     peers, classified like any of them, with a solid line and live pip
     because it speaks NodeSignal.

Honest talking points:
  · Bitcoin's P2P protocol has no message type for chat, so messages
    ride a separate channel between the two operators' daemons on 8788.
  · Discovery and identity DO come from Bitcoin: getpeerinfo for the
    map, and a real version/verack handshake on 8333 per peer.
  · Encryption is PBKDF2 -> AES-256-GCM in the daemon. To prove it:
    clear the PIN on the node side and the message shows as LOCKED;
    set it again and the text returns.
  · The Windows machine's node identity is simulated — it is a demo
    stand-in, and the daemon marks it as such.


=======================================================================
IF SOMETHING BREAKS
=======================================================================
Node page loads but is empty / header shows a placeholder
    You are serving the DEMO html on the node. Install nodesignal.html
    (the console) instead — see the note at the top.

"timeout — is nodesignald running and reachable"
    The other side is not listening on 8788. On Windows that is almost
    always the firewall rule above, or a closed .bat window.

Map shows no peers / banner says "Bitcoin RPC not connected"
    Your node's peers cannot be read yet. The daemon now searches, in
    order: --rpc-user/--rpc-pass, --rpc-cookie, rpcuser/rpcpassword or
    rpccookiefile or datadir in bitcoin.conf (~/.bitcoin, /etc/bitcoin,
    /var/lib/bitcoind), then the usual .cookie locations.

    Run  journalctl -u nodesignal -n 40  and it prints every path it
    tried and why each failed. The two usual answers:

      "permission denied"  the service user cannot read bitcoind's
          cookie. Either run the service as that user, or add to
          bitcoin.conf:   rpcuser=someone
                          rpcpassword=something-long
          then restart bitcoind and nodesignal.

      "not found"  your datadir is elsewhere. Point at it directly by
          editing ExecStart in /etc/systemd/system/nodesignal.service:
              --rpc-cookie /path/to/datadir/.cookie
          or --rpc-conf /path/to/bitcoin.conf
          then: sudo systemctl daemon-reload
                sudo systemctl restart nodesignal

    Once connected, every peer of your node appears on the map
    automatically, coloured and classified by implementation.

A peer shows "not identified"
    Nothing answered on its :8333. Normal for machines with no Bitcoin
    node. Messaging is unaffected.

Message arrives but says LOCKED
    The two sides have different PINs. Use "set PIN" in that chat.
