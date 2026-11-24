# Req2Route

**A cross-layer browser network explorer and what-if lab.**
Computer Networks semester project: a Chrome extension (Manifest V3) plus an optional Python helper.

Open any website, press **Analyze**, and Req2Route shows how each request got to you, layer by layer:
DNS and HTTP at the application layer, TCP/QUIC handshakes and connection reuse at the transport layer, server IPs and address types at the network layer, and your local ARP cache at the data link layer. Then change the conditions (loss, delay, window size, subnet or ACL rules) and see what would happen.

> **Observe → Explain → Experiment.** Every result is labelled so a model is never mistaken for a real capture:
>
> | Label | Meaning | Source |
> |---|---|---|
> | 🟢 **Observed** | Seen by the browser on this page load | `chrome.devtools.network` HAR |
> | 🟡 **Tested** | Measured by a real diagnostic you triggered | Python helper (DNS, TCP, UDP, ARP) |
> | 🟣 **Simulated** | Output of a model in the sandbox | `extension/lib/*.js` |
> | 🔵 **Calculated** | Exact arithmetic, no model or measurement | subnet calculator, VLSM planner |

---

## Quick start

### 1. Load the extension
1. Open `chrome://extensions`, then turn on **Developer mode**.
2. Click **Load unpacked** and select the `extension/` folder.
3. Open any site, press **F12**, and open the **Req2Route** tab in DevTools.
4. Click **Analyze**. The page reloads and every request is listed and explained.

### 2. (Optional) Start the helper for live tests
On Windows, double-click `helper\start-helper.bat`. Full walkthrough: [`docs/SETUP.md`](docs/SETUP.md).
```bash
python helper/server.py                 # localhost:8765, standard library only
python helper/echo_server.py --port 9000 --loss 10 --delay 40   # team-controlled test endpoint
pip install dnspython                   # optional: TTL / CNAME / MX / NS records
```
Copy `helper/config.example.json` to `helper/config.json` to approve more test targets. Only add machines your team controls.

### 3. Develop the panel without Chrome DevTools
```bash
cd extension && python -m http.server 8811
# open http://127.0.0.1:8811/panel/panel.html  → runs in demo mode with sample data
```

### 4. Run the tests
```bash
npm test          # JS: subnet, VLSM, TCP sim, sliding window, ACL/NAT, HAR → layers   (Node 20+)
npm run test:py   # Python helper: DNS wire format, ARP parsing, allowlist, live TCP/UDP echo, HTTP API
```
On Windows PowerShell, if `npm` says *running scripts is disabled*, use `npm.cmd test` (see [`docs/SETUP.md`](docs/SETUP.md#troubleshooting)).

---

## What's in the repo

```
extension/
  manifest.json          MV3 manifest (DevTools page, localhost helper permission)
  devtools/              registers the "Req2Route" DevTools tab
  panel/                 the UI: Observe | Experiment | Live
  lib/
    layers.js            HAR entry → application / transport / network / link explanation   [Observed]
    tcpsim.js            TCP Reno/Tahoe congestion + flow control model, Mathis, BDP        [Simulated]
    ledger.js            RTT ledger: handshake → RTT, TTFB split, slow-start vs observed    [Simulated]
    window.js            Go-Back-N vs Selective Repeat discrete-event simulator             [Simulated]
    subnet.js            IPv4, CIDR, masks, private/public classification, subnet splitting
    vlsm.js              VLSM planner (largest subnet first, aligned blocks)
    acl.js               ACL parser + first-match evaluation, NAT/PAT translation           [Simulated]
    helper-client.js     calls the Python helper                                            [Tested]
    sample-har.js        sample data for demo mode and tests
helper/
  server.py              localhost API: /health /dns /resolvers /tcp /udp /arp
  echo_server.py         TCP+UDP echo endpoint with optional loss/delay injection
  start-helper.bat       Windows: double-click to start helper + echo server
  tests/                 Python unit + integration tests
tests/                   Node unit tests for extension/lib
docs/                    architecture, roadmap, report notes
```

## Course coverage

| Layer | Observed | Tested | Simulated |
|---|---|---|---|
| Application: DNS, HTTP | methods, status codes, headers, HTTP version, timing waterfall | DNS records; Observed-vs-Tested IP comparison; resolver comparison with hand-built DNS packets | — |
| Transport: TCP, UDP, QUIC | new vs reused connections, handshake/TLS time, ports, requests per connection (HTTP/2 multiplexing) | TCP handshake timing, UDP echo loss/RTT (with injected loss/delay) | cwnd/ssthresh (Reno/Tahoe), rwnd flow control; Go-Back-N vs Selective Repeat; RTT/loss/bandwidth what-if (Mathis, BDP) |
| Network: IP, CIDR, NAT, ACL | server IP, IPv4/IPv6, address type | — | subnet calculator, VLSM planner, ACL first-match, NAT/PAT table |
| Data link: ARP, VLAN, STP | — (browsers can't see it) | ARP cache (with permission) | VLAN isolation and STP *(stretch goal)* |

### What is new beyond a packet viewer

- **RTT ledger (Observe tab).** A new connection's TCP handshake is exactly one round trip, so the handshake time Chrome already reports is a free RTT measurement. Req2Route then writes everything else in RTTs: the TLS handshake (about 1 RTT = TLS 1.3, about 2 = TLS 1.2), and the wait for the first byte, split into one RTT of network time and the server's own think time. Finally it feeds each download to a slow-start model (initial window 10 segments, doubling per RTT) and says whether the *Simulated* time agrees with the *Observed* one; when it does not, the limit is bandwidth or loss, not latency. It also totals the handshake time that connection reuse avoided.
- **Handshake packet sizes (Live tab).** The TCP handshake test reports the size of the SYN, SYN-ACK and ACK from the IP/TCP header layout and the options the OS sends (*Calculated*, not captured), the negotiated MSS, and a measured data round trip so the 0-byte handshake can be compared with a real data segment.

HTTPS/TLS is covered only at the basic level here. Deeper security analysis belongs to the separate Information Security project.

## Team

| # | Name | CMS |
|---|---|---|
| 01 | Abdullah Cheema | 551210 |
| 02 | Huzaifa Maqbool | 556377 |
| 03 | Rehan Ahmed | 553327 |
| 04 | M Hassan | 540896 |
| 05 | Pirzada Ali Shah Mardan | 553466 |

See [`docs/ROADMAP.md`](docs/ROADMAP.md) for who owns what and [`CONTRIBUTING.md`](CONTRIBUTING.md) for the Git workflow.
