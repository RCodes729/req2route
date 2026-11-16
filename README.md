# Req2Route

**A cross-layer browser network explorer and what-if lab.**
Computer Networks semester project: a Chrome extension (Manifest V3) plus an optional Python helper.

Open any website, press **Analyze this page**, and Req2Route shows how each request got to you, layer by layer:
DNS and HTTP at the application layer, TCP/QUIC handshakes and connection reuse at the transport layer, server IPs and address types at the network layer, and your local ARP cache at the data link layer. Then change the conditions (loss, delay, window size, subnet or ACL rules) and see what would happen.

> **Observe → Explain → Experiment.** Every result is labelled so a model is never mistaken for a real capture:
>
> | Label | Meaning | Source |
> |---|---|---|
> | 🟢 **Observed** | Seen by the browser on this page load | `chrome.devtools.network` HAR |
> | 🟡 **Tested** | Measured by a real diagnostic you triggered | Python helper (DNS, TCP, UDP, ARP) |
> | 🟣 **Simulated** | Output of a model in the sandbox | `extension/lib/*.js` |

---

## Quick start

### 1. Load the extension
1. Open `chrome://extensions`, then turn on **Developer mode**.
2. Click **Load unpacked** and select the `extension/` folder.
3. Open any site, press **F12**, and open the **Req2Route** tab in DevTools.
4. Click **Analyze this page**. The page reloads and every request is listed and explained.

### 2. (Optional) Start the helper for live tests
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
npm test          # JS: subnet, TCP sim, ACL/NAT, HAR → layers   (Node 20+)
npm run test:py   # Python helper: ARP parsing, allowlist, live TCP/UDP echo, HTTP API
```

---

## What's in the repo

```
extension/
  manifest.json          MV3 manifest (DevTools page, localhost helper permission)
  devtools/              registers the "Req2Route" DevTools tab
  panel/                 the UI: Observe & Explain | Experiment | Live tests
  lib/
    layers.js            HAR entry → application / transport / network / link explanation   [Observed]
    tcpsim.js            TCP Reno/Tahoe congestion + flow control model, Mathis, BDP        [Simulated]
    subnet.js            IPv4, CIDR, masks, private/public classification, subnet splitting
    acl.js               ACL parser + first-match evaluation, NAT/PAT translation           [Simulated]
    helper-client.js     calls the Python helper                                            [Tested]
    sample-har.js        sample data for demo mode and tests
helper/
  server.py              localhost API: /health /dns /tcp /udp /arp
  echo_server.py         TCP+UDP echo endpoint with optional loss/delay injection
  tests/                 Python unit + integration tests
tests/                   Node unit tests for extension/lib
docs/                    architecture, roadmap, report notes
```

## Course coverage

| Layer | Observed | Tested | Simulated |
|---|---|---|---|
| Application: DNS, HTTP | methods, status codes, headers, HTTP version, timing waterfall | DNS records + resolver time | — |
| Transport: TCP, UDP, QUIC | new vs reused connections, handshake/TLS time, ports | TCP handshake timing, UDP echo loss/RTT | cwnd/ssthresh (Reno/Tahoe), rwnd flow control, random/scripted loss |
| Network: IP, CIDR, NAT, ACL | server IP, IPv4/IPv6, address type | — | subnet calculator, ACL first-match, PAT table |
| Data link: ARP, VLAN, STP | — (browsers can't see it) | ARP cache (with permission) | VLAN isolation and STP *(stretch goal)* |

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
