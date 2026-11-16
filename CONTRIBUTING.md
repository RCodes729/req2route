# Contributing

## Git workflow
1. `main` is always working. Never push directly to it.
2. Create a branch from `main` for each task: `feat/transport-sliding-window`, `fix/helper-arp-windows`, `docs/report-intro`.
3. Commit small and often. Message style: `area: what changed` (for example `transport: add Go-Back-N animation`).
4. Open a pull request, link the roadmap item, and ask one teammate to review.
5. CI must be green (JS + Python tests) before merging. Use **Squash and merge**.

```bash
git checkout main && git pull
git checkout -b feat/network-vlsm
# ...work...
npm test && npm run test:py
git add -A && git commit -m "network: add VLSM planner"
git push -u origin feat/network-vlsm
```

## Rules for code
- `extension/lib/` modules are **pure** (no `chrome.*`, no DOM) so they can be unit-tested in Node.
- Every result object carries a `label`: `Observed`, `Tested` or `Simulated`.
- Never insert page data with `innerHTML`; use the `el()` helper in `panel.js` (it uses `textContent`).
- The helper must stay localhost-only and allowlist-gated. See `docs/ARCHITECTURE.md`.
- Add or update a test with every feature.
