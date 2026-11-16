# Roadmap: one-week plan (16–23 Nov 2026)

**Goal:** submit-ready by **Sun 22 Nov**, with **Mon 23 Nov** as buffer.

**Status (Mon 16 Nov, evening):** all build features below are done and tested (v0.2.0). What remains is testing on Windows with real sites, the report, and the demo.
**Rule:** the starter repo is the core. Each person adds 1–2 features, nothing more. Feature freeze is **Fri 20 Nov, 11 pm**.

Status key: ✅ already done · ⬜ to do · ✂️ cut (only if everything else is finished)

## Already done (starter repo)
- ✅ MV3 extension, DevTools panel, three tabs
- ✅ Observe & Explain: HAR → layers, timing waterfall, page summary
- ✅ TCP Reno/Tahoe simulator with rwnd, scripted/random loss, baseline comparison
- ✅ Subnet/CIDR calculator, ACL tester, NAT/PAT logic (`acl.js`)
- ✅ Helper: `/health /dns /tcp /udp /arp`; echo server with loss/delay
- ✅ JS + Python test suites + CI (CI is paused while the repo account has a billing lock; run both suites locally before every PR)

---

## Day-by-day

| Day | Date | Everyone |
|---|---|---|
| 0 | Mon 16 (tonight) | Repo pushed to GitHub, all 5 added as collaborators |
| 1 | Tue 17 | Everyone loads the extension + runs the helper on their own laptop. Each person opens their branch and starts their feature. Pirzada starts the report outline. |
| 2 | Wed 18 | Build. **First PR from each person by 11 pm.** Abdullah merges. |
| 3 | Thu 19 | Build + tests. **Second PR by 11 pm.** |
| 4 | Fri 20 | Integration day: everyone pulls `main`, tests the whole extension, fixes bugs. **Feature freeze 11 pm.** |
| 5 | Sat 21 | Bug fixes only. Test on Windows with 3+ real sites. Screenshots. Each person sends Pirzada 1 paragraph on their module. |
| 6 | Sun 22 | Report finished, demo video recorded, tag `v1.0.0`, **submit** |
| 7 | Mon 23 | Buffer |

Daily check-in (10 min, WhatsApp is fine): what I merged yesterday, what I'm merging today, what's blocking me.

---

## Work per person

### Abdullah Cheema: Observe & Explain + integration
- ✅ Group requests by connection ID → shows HTTP/2 multiplexing (many requests, one TCP connection)
- ✅ "Test this host" button: runs helper DNS on the selected request's host and shows **Observed vs Tested** side by side
- ✅ Extension icons (16/48/128)
- ⬜ Merge PRs every evening; keep `main` working

### Huzaifa Maqbool: Transport
- ✅ Sliding-window simulator: **Go-Back-N vs Selective Repeat** with a lost segment (new `lib/window.js` + card + tests)
- ✅ "What-if" card: RTT and loss sliders → throughput (Mathis) + bandwidth-delay product (both already in `tcpsim.js`)

### Rehan Ahmed: Network
- ✅ NAT/PAT card in the Experiment tab (logic exists: `natTranslate` in `acl.js`)
- ✅ VLSM planner: department host counts → allocated subnets (new `lib/vlsm.js` + tests)

### M Hassan: Helper
- ⬜ Test every endpoint on **Windows** (especially `arp -a` parsing); fix what breaks
- ✅ `start-helper.bat` + one-page setup guide in `docs/SETUP.md`
- ✅ `/resolvers` endpoint: same name via system vs 1.1.1.1 vs 8.8.8.8 timing (hand-built DNS packets over UDP/53, no dependencies)

### Pirzada Ali Shah Mardan: Report, demo, UI
- ⬜ Report from day 1 (structure below), filled in as features land
- ⬜ UI polish: empty/error states, dark mode check, consistent badges
- ⬜ Demo script + 5–7 min recording on Sun
- ✂️ VLAN broadcast sandbox (only if report and UI are done by Thu)

## Cut from scope (documented as future work)
- ✂️ STP sandbox
- ✂️ Traceroute
- ✂️ Step-through animation of a request

The proposal already lists VLAN/STP as extensions, so cutting them stays within the proposal.

---

## Report outline (Pirzada owns, everyone contributes)
1. Introduction and objective
2. Related tools (Wireshark, Chrome DevTools, packet tracers) and what Req2Route adds
3. Design: architecture diagram, Observed/Tested/Simulated labelling
4. Layer-by-layer features (one section per module, written by its owner)
5. Helper security model
6. Testing: unit tests, CI, manual test on real sites
7. Results: screenshots, one Observed vs Tested vs Simulated comparison
8. Limitations and future work (cut items above)
9. Team contributions

## Demo script (5–7 min)
1. Open a real site → Analyze → explain one new HTTPS request (DNS, TCP, TLS, HTTP)
2. Show a reused connection and an HTTP/3 (QUIC/UDP) request
3. Run UDP echo test with `--loss 10` → compare with the TCP simulator at 10% loss
4. Subnet + VLSM + ACL in 60 seconds
5. ARP table → explain the data link layer
