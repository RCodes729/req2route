# Architecture

```
┌──────────────────────────── Chrome ────────────────────────────┐
│  Inspected tab (any website)                                    │
│        │ page load                                              │
│        ▼                                                        │
│  chrome.devtools.network  ──HAR entries──►  Req2Route panel     │
│   (getHAR, onRequestFinished)               (panel/panel.js)    │
│                                              │    │     │       │
│                       ┌──────────────────────┘    │     │       │
│                       ▼                           ▼     │       │
│               lib/layers.js               lib/tcpsim.js │       │
│               HAR → layers  [Observed]    lib/subnet.js │       │
│                                           lib/acl.js    │       │
│                                           [Simulated]   │       │
└─────────────────────────────────────────────────────────┼───────┘
                                                          │ fetch (only http://127.0.0.1:8765)
                                                          ▼
                                   helper/server.py  (localhost only)  [Tested]
                                   /dns  → dnspython or getaddrinfo
                                   /tcp  → socket.create_connection timing ─┐
                                   /udp  → datagram echo, loss + RTT ───────┤ approved targets only
                                   /arp  → `arp -a` or /proc/net/arp        │
                                                                            ▼
                                                     helper/echo_server.py (team-controlled)
                                                     optional --loss / --delay injection
```

## Why a DevTools panel?
`chrome.devtools.network` gives the full HAR for the inspected page, including per-phase timings (`blocked`, `dns`, `connect`, `ssl`, `send`, `wait`, `receive`), `serverIPAddress`, the `connection` ID and `httpVersion`. That is enough to explain DNS caching, TCP/TLS handshakes, connection reuse, HTTP/2 multiplexing and HTTP/3 over QUIC **without** any packet-capture permissions.

What the browser cannot see (MAC addresses, ARP, raw DNS records, raw sockets) is handled by the helper, and only when the user explicitly runs a test.

## Labelling contract
Every object returned by `lib/` carries a `label` field: `Observed`, `Tested` or `Simulated`. The UI must render that badge next to any result. **Do not** merge simulated values into observed views.

## HAR interpretation notes
- Timings of `-1` mean *not applicable*: DNS was cached or the connection was reused.
- Per the HAR spec, `connect` **includes** `ssl`. TCP handshake = `connect − ssl`.
- `httpVersion` values seen in Chrome: `http/1.1`, `http/2.0`, `h3`. HTTP/3 means UDP (QUIC) at the transport layer.
- Requests served from memory cache or a service worker may have no `serverIPAddress`.

## Helper security model
| Threat | Mitigation |
|---|---|
| A random website calls the helper with `fetch()` | Requests with a non-`chrome-extension://` `Origin` get 403 |
| A website calls it with no `Origin` (`<img>`, `<script>`, `<iframe>`, a link) | Browsers label these `Sec-Fetch-Mode: no-cors` / `navigate`; the helper returns 403. The extension's own `fetch()` is `cors` mode and always sends its `chrome-extension://` Origin. Tools like curl send neither header and are allowed (they already run on your machine). |
| DNS rebinding | `Host` header must be `127.0.0.1`, `localhost` or `::1` |
| Using the tool to scan other people's hosts | TCP/UDP tests only run against `allowed_test_targets` + `allowed_ports` |
| Command injection via hostnames | Strict hostname regex; `arp` is called with fixed arguments, never a shell |
| Exposure on the LAN | Binds `127.0.0.1` only |

## Extending
- **New simulator:** add a pure module in `extension/lib/` that returns `{ label: 'Simulated', ... }`, write a `tests/*.test.js`, then add a card to the Experiment tab.
- **New live test:** add a function + route in `helper/server.py`, a method in `helper-client.js`, and a test in `helper/tests/`.
