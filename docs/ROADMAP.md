# Roadmap and work split

Status key: ✅ done in the starter repo · ⬜ to do · ⭐ stretch goal

## Suggested ownership

| Area | Owner | Branch prefix |
|---|---|---|
| Extension shell, Observe & Explain (HAR → layers), integration lead | Abdullah Cheema | `feat/observe-` |
| Transport sandbox (TCP congestion/flow control, sliding window, loss/delay) | Huzaifa Maqbool | `feat/transport-` |
| Network tools (subnet/CIDR, NAT/PAT, ACL, routing) | Rehan Ahmed | `feat/network-` |
| Python helper (DNS, TCP/UDP tests, ARP, echo endpoint) + helper security | M Hassan | `feat/helper-` |
| Data link sandbox (VLAN, STP), UI polish, report, demo video | Pirzada Ali Shah Mardan | `feat/link-` / `docs/` |

Everyone writes tests for their own module and reviews one other member's PRs.

---

## Milestone 1: Working core (weeks 1–2)
- ✅ MV3 extension with DevTools panel, three tabs
- ✅ HAR → layer explanation, timing waterfall, page summary
- ✅ TCP Reno/Tahoe model with rwnd, scripted + random loss, baseline comparison
- ✅ Subnet calculator, ACL first-match tester
- ✅ Helper: `/health /dns /tcp /udp /arp`, echo server with loss/delay
- ✅ Unit tests (21 JS, 15 Python) and CI
- ⬜ Everyone loads the extension and runs the helper on their own machine (Windows)
- ⬜ Add extension icons (16/48/128) and a name/logo

## Milestone 2: Depth (weeks 3–4)
**Observe & Explain** (Abdullah)
- ⬜ "Explain" step-through mode: animate DNS → TCP → TLS → HTTP for the selected request
- ⬜ Group requests by connection ID to show HTTP/2 multiplexing (many requests, one TCP connection)
- ⬜ Highlight redirects (3xx chains) and the `Location` hops
- ⬜ One-click "test this" button: send the host to the helper DNS test, then show Observed vs Tested side by side

**Transport** (Huzaifa)
- ⬜ Sliding-window animation: Go-Back-N vs Selective Repeat with a lost segment
- ⬜ Delay slider → throughput curve (Mathis formula is already in `tcpsim.js`)
- ⬜ Bandwidth-delay product card: "how big must the window be to fill this link?"
- ⬜ Compare a Tested UDP loss % (echo server `--loss`) with the Simulated result at the same loss

**Network** (Rehan)
- ⬜ NAT/PAT card in the UI (`natTranslate` already exists in `acl.js`)
- ⬜ VLSM planner: given host counts per department, allocate subnets
- ⬜ Longest-prefix-match routing table simulator
- ⬜ Show the user's own private IP vs the public server IP on the Observe tab (with the helper)

**Helper** (M Hassan)
- ⬜ `/traceroute` against approved targets (hop list → network-layer view)
- ⬜ Resolver comparison: system vs 1.1.1.1 vs 8.8.8.8 timings
- ⬜ Windows packaging: a `start-helper.bat` script and one-page setup guide

**Data link + UI** (Pirzada)
- ⭐ VLAN sandbox: drag hosts onto VLANs, send a broadcast, see who receives it
- ⭐ STP sandbox: switches with a loop, elect the root bridge, show blocked ports
- ⬜ Consistent visual style, dark mode check, empty/error states

## Milestone 3: Finish (weeks 5–6)
- ⬜ Freeze features; fix bugs; every module ≥ 1 test file
- ⬜ Report: problem, design, layer mapping, labelling contract, evaluation, limitations
- ⬜ Demo script (5–7 min): analyze a real site → explain one request → change loss → compare
- ⬜ Screenshots / GIFs for the README
- ⬜ Tag `v1.0.0` release

## Out of scope
- Raw packet capture (would need Npcap/Wireshark-level access)
- Vulnerability scanning and TLS security analysis (separate IS project)
