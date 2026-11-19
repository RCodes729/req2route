import { explainEntry, summarizePage, detectHttpVersion, groupByConnection, compareDns } from '../lib/layers.js';
import { simulateCongestion, mathisThroughput, bandwidthDelayProduct } from '../lib/tcpsim.js';
import { simulateWindow } from '../lib/window.js';
import { parseCidr, splitSubnet } from '../lib/subnet.js';
import { planVlsm, parseRequirements } from '../lib/vlsm.js';
import { parseAcl, evaluateAcl, natTranslate } from '../lib/acl.js';
import { helper } from '../lib/helper-client.js';
import { SAMPLE_ENTRIES } from '../lib/sample-har.js';

// ---------- tiny DOM helper (always textContent, never innerHTML with page data) ----------
function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') node.className = v;
    else if (k === 'style') Object.assign(node.style, v);
    else if (k.startsWith('on')) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return node;
}
const $ = sel => document.querySelector(sel);
const badge = label => el('span', { class: `badge ${label.toLowerCase()}` }, label);
const kv = pairs => el('dl', { class: 'kv' }, pairs.filter(([, v]) => v !== null && v !== undefined && v !== '').flatMap(([k, v]) => [el('dt', {}, k), el('dd', {}, v instanceof Node ? v : String(v))]));

// data-label lets narrow panels show each cell as "label  value" (see table.data in panel.css)
// (tables with 3 or fewer columns fit a 360px panel as-is, so only wider ones stack).
const table = (headers, rows) => el('table', { class: headers.length <= 3 ? 'data tight' : 'data' },
  el('thead', {}, el('tr', {}, headers.map(h => el('th', {}, h)))),
  el('tbody', {}, rows.map(r => el('tr', {}, r.map((v, i) => el('td', { 'data-label': headers[i] ?? '', title: v instanceof Node ? '' : String(v ?? '') }, v ?? ''))))));

// ---------- tabs ----------
document.querySelectorAll('.tab-btn').forEach(btn => btn.addEventListener('click', () => {
  document.querySelectorAll('.tab-btn').forEach(b => { b.classList.toggle('active', b === btn); b.setAttribute('aria-pressed', String(b === btn)); });
  document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.id === `tab-${btn.dataset.tab}`));
}));

// =====================================================================
// OBSERVE + EXPLAIN
// =====================================================================
const inDevtools = typeof chrome !== 'undefined' && chrome.devtools?.network;
// Match the DevTools theme rather than the OS one (outside DevTools, CSS falls back to prefers-color-scheme).
if (inDevtools && chrome.devtools.panels?.themeName) {
  document.documentElement.dataset.theme = chrome.devtools.panels.themeName === 'dark' ? 'dark' : 'light';
}
let entries = [];

function addEntry(entry) {
  entries.push(entry);
  renderRow(entry, entries.length - 1);
  renderSummary();
}

function renderRow(entry, idx) {
  let host = '';
  try {
    const u = new URL(entry.request.url);
    // data:/blob: URLs are built inside the page: no DNS, no connection, no server.
    host = u.hostname || `${u.protocol} (inline, no network)`;
  } catch { host = entry.request.url.slice(0, 40); }
  const row = el('tr', { 'data-idx': idx, title: entry.request.url },
    el('td', {}, entry.request.method),
    el('td', {}, entry.response?.status || '—'),
    el('td', {}, host),
    el('td', {}, detectHttpVersion(entry)),
    el('td', {}, entry.serverIPAddress || '—'),
    el('td', {}, `${Math.round(entry.time || 0)} ms`),
  );
  row.addEventListener('click', () => {
    document.querySelectorAll('#requests tr.selected').forEach(r => r.classList.remove('selected'));
    row.classList.add('selected');
    renderExplain(entry);
  });
  $('#requests tbody').append(row);
}

function renderSummary() {
  const s = summarizePage(entries);
  const stat = (label, value, cls = 'stat') => el('div', { class: cls }, el('b', {}, value), label);
  $('#summary').replaceChildren(
    stat('Requests', s.requests),
    stat('Hosts', s.uniqueHosts),
    stat('Server IPs', s.uniqueServerIps),
    stat('DNS lookups', s.dnsLookups),
    stat('Connections', s.newConnections),
    stat('KB', Math.round(s.bytesTransferred / 1024)),
    stat('Protocols', Object.entries(s.protocols).map(([k, v]) => `${k} ×${v}`).join('   ') || '—', 'stat wide'),
  );
  renderConnections();
}

function renderConnections() {
  const groups = groupByConnection(entries);
  $('#connections').replaceChildren(groups.length ? table(
    ['Connection', 'Transport', 'HTTP', 'Server IP', 'Hosts', 'Requests', 'Handshake', 'Meaning'],
    groups.map(g => [g.connectionId, g.transport, g.httpVersion, g.serverIp || '—', g.hosts.join(', '), g.requests, g.opened ? `${g.handshakeMs} ms` : 'reused', g.meaning]),
  ) : el('p', { class: 'empty' }, 'No requests yet.'));
}

const PHASE_COLORS = { browser: 'var(--browser)', application: 'var(--app)', transport: 'var(--transport)' };

function renderExplain(entry) {
  const x = explainEntry(entry);
  const total = x.timeline.reduce((s, p) => s + p.ms, 0) || 1;
  const waterfall = el('div', { class: 'waterfall' }, x.timeline.map(p =>
    el('span', { title: `${p.phase}: ${p.ms} ms`, style: { width: `${(p.ms / total) * 100}%`, background: PHASE_COLORS[p.layer] } })));
  const legend = el('div', { class: 'legend' }, x.timeline.map(p => el('span', {}, el('i', { style: { background: PHASE_COLORS[p.layer] } }), `${p.phase} ${p.ms} ms`)));

  $('#explain').replaceChildren(
    el('h2', {}, 'Request journey', badge(x.label)),
    el('p', { class: 'url' }, x.url),
    waterfall, legend,
    el('div', { class: 'layer application' },
      el('h3', {}, `Application layer: ${x.application.protocol} (${x.application.httpVersion}) + DNS`),
      kv([
        ['Request', `${x.application.method} → ${x.application.status} ${x.application.statusText}`],
        ['Status class', x.application.statusClass],
        ['Content type', x.application.mimeType],
        ['DNS', x.application.dns.note],
        ...Object.entries(x.application.headers).map(([k, v]) => [k, v]),
      ])),
    el('div', { class: 'layer transport' },
      el('h3', {}, `Transport layer: ${x.transport.protocol}`),
      kv([
        ['Server port', x.transport.serverPort],
        ['Connection ID', x.transport.connectionId],
        ['Handshake', x.transport.handshakeMs !== null ? `${x.transport.handshakeMs} ms` : 'none (reused)'],
        ['TLS', x.transport.tls ? (x.transport.tlsMs ? `${x.transport.tlsMs} ms` : 'yes (combined or reused)') : 'no — plaintext HTTP'],
        ['What happened', x.transport.note],
      ])),
    el('div', { class: 'layer network' },
      el('h3', {}, `Network layer: ${x.network.ipVersion || 'IP'}`),
      kv([
        ['Server IP', x.network.serverIp],
        ['Address type', x.network.classification ? `${x.network.classification.category}${x.network.classification.rfc ? ` (${x.network.classification.rfc})` : ''}` : null],
        ['What happened', x.network.note],
      ])),
    el('div', { class: 'layer' },
      el('h3', {}, 'Data link layer'),
      el('p', { class: 'muted' }, x.link.note)),
    el('div', { class: 'layer compare' },
      el('h3', {}, 'Observed vs Tested'),
      el('p', { class: 'muted' }, 'Resolve this host now and compare with what the browser used.'),
      el('button', { onclick: () => runCompare(x) }, `Resolve ${x.host}`),
      el('div', { id: 'compare-out' })),
  );
}

async function runCompare(x) {
  const out = $('#compare-out');
  out.replaceChildren(el('p', { class: 'muted' }, 'Resolving…'));
  try {
    const c = compareDns(x, await helper.dns(x.host));
    out.replaceChildren(
      table(['', 'Server IP / answers', 'DNS time'], [
        [badge('Observed'), c.observed.serverIp || '—', c.observed.dnsMs !== null ? `${c.observed.dnsMs} ms` : 'cached / reused'],
        [badge('Tested'), c.tested.addresses.join(', ') || '—', `${c.tested.resolverMs} ms (${c.tested.method.split(' ')[0]})`],
      ]),
      el('p', { class: c.ipMatch === false ? 'verdict deny' : 'verdict permit' }, c.verdict),
      c.tested.records.some(r => r.ttl !== null) ? table(['Type', 'Value', 'TTL (s)'], c.tested.records.map(r => [r.type, r.value, r.ttl])) : null,
    );
  } catch (e) {
    out.replaceChildren(el('p', { class: 'error' }, e.message));
  }
}

function resetObserve() {
  entries = [];
  $('#requests tbody').replaceChildren();
  $('#explain').replaceChildren(el('p', { class: 'empty' }, 'Select a request to trace it through each layer.'));
  renderSummary();
}

if (inDevtools) {
  chrome.devtools.network.getHAR(har => (har?.entries || []).forEach(addEntry));
  chrome.devtools.network.onRequestFinished.addListener(addEntry);
  chrome.devtools.network.onNavigated.addListener(resetObserve);
  $('#analyze').addEventListener('click', () => {
    resetObserve();
    chrome.devtools.inspectedWindow.reload({ ignoreCache: true });
  });
} else {
  const note = $('#mode-note');
  note.textContent = 'Sample data. Open Req2Route in DevTools (F12) to inspect a real page.';
  note.classList.remove('hidden');
  $('#analyze').addEventListener('click', () => { resetObserve(); SAMPLE_ENTRIES.forEach(addEntry); });
  SAMPLE_ENTRIES.forEach(addEntry);
}

// =====================================================================
// EXPERIMENT: TCP
// =====================================================================
let tcpBaseline = null;
let tcpLast = null;

function parseLossRounds(text) {
  const out = {};
  for (const part of text.split(',').map(s => s.trim()).filter(Boolean)) {
    const [r, kind] = part.split(':');
    out[Number(r)] = kind === 'timeout' ? 'timeout' : 'dupack';
  }
  return out;
}

// Colours come from CSS custom properties so the charts follow the light/dark theme.
const cssVar = name => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
let tcpRunsDrawn = null;

function drawTcpChart(svg, runs) {
  tcpRunsDrawn = runs;
  // Draw at the element's real pixel width so 10px text stays 10px in a 360px panel and in a wide dock.
  const W = Math.max(280, Math.round(svg.getBoundingClientRect().width) || 700);
  const H = W < 480 ? 200 : 240, PL = 32, PR = 12, PT = 20, PB = 24;
  const all = runs.flatMap(r => r.series);
  const maxRound = Math.max(...all.map(p => p.round));
  const maxY = Math.max(4, ...all.map(p => Math.max(p.cwnd, p.ssthresh)));
  const x = r => PL + ((r - 1) / Math.max(1, maxRound - 1)) * (W - PL - PR);
  const y = v => H - PB - (v / maxY) * (H - PT - PB);
  const ns = 'http://www.w3.org/2000/svg';
  const mk = (tag, attrs, text) => { const n = document.createElementNS(ns, tag); for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v); if (text !== undefined) n.textContent = text; return n; };
  svg.setAttribute('viewBox', `0 0 ${W} ${H}`);
  svg.replaceChildren();
  // quiet horizontal guides instead of a boxed frame
  for (const v of [0, Math.round(maxY / 2), maxY]) {
    svg.append(mk('line', { x1: PL, y1: y(v), x2: W - PR, y2: y(v), stroke: 'currentColor', 'stroke-opacity': v === 0 ? 0.25 : 0.08 }));
    svg.append(mk('text', { x: PL - 6, y: y(v) + 3, 'font-size': 10, fill: 'currentColor', 'fill-opacity': 0.6, 'text-anchor': 'end' }, v));
  }
  svg.append(mk('text', { x: PL, y: 12, 'font-size': 10, fill: 'currentColor', 'fill-opacity': 0.6 }, 'cwnd (segments)'));
  svg.append(mk('text', { x: W - PR, y: H - 6, 'font-size': 10, fill: 'currentColor', 'fill-opacity': 0.6, 'text-anchor': 'end' }, `RTT round 1–${maxRound}`));

  runs.forEach(run => {
    const isBaseline = run === tcpBaseline && runs.length > 1;
    svg.append(mk('polyline', {
      points: run.series.map(p => `${x(p.round)},${y(p.cwnd)}`).join(' '), fill: 'none', stroke: 'currentColor',
      'stroke-width': isBaseline ? 1.25 : 1.75, 'stroke-opacity': isBaseline ? 0.35 : 1, 'stroke-dasharray': isBaseline ? '4 4' : '', 'stroke-linejoin': 'round',
    }));
    if (!isBaseline) {
      svg.append(mk('polyline', { points: run.series.map(p => `${x(p.round)},${y(p.ssthresh)}`).join(' '), fill: 'none', stroke: 'currentColor', 'stroke-opacity': 0.4, 'stroke-width': 1, 'stroke-dasharray': '3 3' }));
      run.series.filter(p => p.event).forEach(p => svg.append(mk('circle', { cx: x(p.round), cy: y(p.cwnd), r: 3.5, fill: cssVar(p.event === 'timeout' ? '--chart-loss' : '--chart-warn') })));
    }
  });
}
// Redraw at the new width when the panel is resized or the tab first becomes visible.
new ResizeObserver(() => { if (tcpRunsDrawn) drawTcpChart($('#tcp-chart'), tcpRunsDrawn); }).observe($('#tcp-chart'));

$('#tcp-form').addEventListener('submit', ev => {
  ev.preventDefault();
  const f = new FormData(ev.target);
  try {
    tcpLast = simulateCongestion({
      variant: f.get('variant'),
      rounds: Number(f.get('rounds')),
      ssthresh: Number(f.get('ssthresh')),
      rwnd: Number(f.get('rwnd')),
      lossRate: Number(f.get('lossPct')) / 100,
      lossEvents: parseLossRounds(f.get('lossRounds') || ''),
      rttMs: Number(f.get('rttMs')),
    });
    drawTcpChart($('#tcp-chart'), tcpBaseline ? [tcpBaseline, tcpLast] : [tcpLast]);
    const s = tcpLast.summary;
    const cmp = tcpBaseline ? `  (baseline ${tcpBaseline.summary.avgThroughputKbps})` : '';
    $('#tcp-summary').replaceChildren(...kv([
      ['Segments', s.totalSegments],
      ['Loss events', s.lossEvents],
      ['Throughput', `${s.avgThroughputKbps} kbps avg${cmp}`],
    ]).children);
  } catch (e) {
    $('#tcp-summary').replaceChildren(el('span', { class: 'error' }, e.message));
  }
});
$('#tcp-baseline').addEventListener('click', () => {
  if (!tcpLast) return;
  tcpBaseline = tcpLast;
  drawTcpChart($('#tcp-chart'), [tcpBaseline]);
});
$('#tcp-form').requestSubmit();

// =====================================================================
// EXPERIMENT: SUBNET
// =====================================================================
$('#subnet-form').addEventListener('submit', ev => {
  ev.preventDefault();
  const f = new FormData(ev.target);
  const out = $('#subnet-out');
  try {
    const s = parseCidr(f.get('cidr'));
    const items = [
      ['Network', `${s.network}/${s.prefix}`], ['Mask', s.mask], ['Wildcard', s.wildcard],
      ['Broadcast', s.broadcast], ['Host range', `${s.firstHost} – ${s.lastHost}`], ['Usable hosts', s.hostCount],
      ['Address type', `${s.classification.category}${s.classification.rfc ? ` (${s.classification.rfc})` : ''}`],
      ['Legacy class', s.legacyClass], ['IP (binary)', s.binary.ip], ['Mask (binary)', s.binary.mask],
    ];
    const split = f.get('split');
    if (split) {
      const r = splitSubnet(f.get('cidr'), Number(split));
      items.push([`Split into /${split}`, `${r.count} subnets${r.truncated ? ' (first 1024 shown)' : ''}`]);
      r.subnets.slice(0, 16).forEach((n, i) => items.push([`  #${i + 1}`, `${n.network}/${n.prefix}  hosts ${n.firstHost}–${n.lastHost}`]));
    }
    out.replaceChildren(...kv(items).children);
  } catch (e) {
    out.replaceChildren(el('span', { class: 'error' }, e.message));
  }
});
$('#subnet-form').requestSubmit();

// =====================================================================
// EXPERIMENT: ACL
// =====================================================================
$('#acl-form').addEventListener('submit', ev => {
  ev.preventDefault();
  const f = new FormData(ev.target);
  const out = $('#acl-out');
  try {
    const rules = parseAcl($('#acl-rules').value);
    const r = evaluateAcl(rules, { proto: f.get('proto'), src: f.get('src'), dst: f.get('dst'), dstPort: Number(f.get('dstPort')) });
    out.replaceChildren(
      el('div', { class: `verdict ${r.action}` }, r.action === 'permit' ? 'Permit' : 'Deny',
        el('span', { class: 'muted' }, r.implicit ? 'no rule matched (implicit deny)' : `rule ${r.matchedIndex + 1}`)),
      ...r.trace.map(t => el('div', { class: `trace-row${t.matched ? ' hit' : ''}` },
        `${t.index + 1}  ${t.rule}  ${t.matched ? '→ match' : `· ${Object.entries(t.checks).filter(([, ok]) => !ok).map(([k]) => k).join(', ')} differs`}`)),
    );
  } catch (e) {
    out.replaceChildren(el('span', { class: 'error' }, e.message));
  }
});

// =====================================================================
// LIVE TESTS
// =====================================================================
// Run a helper call into an output slot: a quiet "running" line, then a rendered result or the error.
async function run(target, call, render, busy = 'Running…') {
  const out = $(target);
  out.replaceChildren(el('p', { class: 'muted' }, busy));
  try { out.replaceChildren(...[].concat(render(await call()))); }
  catch (e) { out.replaceChildren(el('p', { class: 'error' }, e.message)); }
}

$('#helper-health').addEventListener('click', () => run('#helper-health-out', helper.health, h => kv([
  ['Status', el('span', { class: 'status' }, 'Running')],
  ['Version', `${h.version} on ${h.os}`],
  ['dnspython', h.dnspython ? 'installed (TTL, CNAME, MX, NS)' : 'not installed (A/AAAA only)'],
  ['Test targets', `${h.allowedTargets.join(', ')} : ${h.allowedPorts.length ? h.allowedPorts.join(', ') : 'none'}`],
]), 'Checking…'));

$('#dns-form').addEventListener('submit', ev => {
  ev.preventDefault();
  run('#dns-out', () => helper.dns(new FormData(ev.target).get('name')), d => [
    kv([['Lookup', `${d.timeMs} ms`], ['Resolver', d.method.split(';')[0]]]),
    table(['Type', 'Value', 'TTL'], d.records.map(r => [r.type, r.value, r.ttl ?? '—'])),
  ], 'Resolving…');
});

$('#sock-form').addEventListener('submit', ev => {
  ev.preventDefault();
  const f = new FormData(ev.target);
  if ((ev.submitter?.value || 'tcp') === 'udp') {
    run('#sock-out', () => helper.udp(f.get('host'), f.get('port'), 10), u => kv([
      ['Target', u.target],
      ['Echoed', `${u.received} of ${u.sent}`],
      ['Loss', `${u.lossPct}%`],
      ['Avg RTT', u.avgRttMs !== null ? `${u.avgRttMs} ms` : '—'],
      ['Note', u.note],
    ]), 'Sending 10 datagrams…');
  } else {
    run('#sock-out', () => helper.tcp(f.get('host'), f.get('port')), t => [
      kv([['Target', t.target], ['Handshakes', `${t.succeeded} of ${t.attempts}`], ['Average', t.avgHandshakeMs !== null ? `${t.avgHandshakeMs} ms` : '—']]),
      table(['Local port', 'Handshake'], t.samples.map(s => s.ok ? [s.local, `${s.handshakeMs} ms`] : ['—', s.error])),
    ], 'Connecting…');
  }
});

$('#arp-btn').addEventListener('click', () => run('#arp-out', helper.arp, r => [
  el('p', { class: 'hint' }, `${r.count} entries from ${r.source}`),
  table(['IP', 'MAC', 'Type', 'Note'], r.entries.map(e => [e.ip, e.mac, e.type, e.note || ''])),
], 'Reading…'));

// =====================================================================
// EXPERIMENT: SLIDING WINDOW (GBN vs SR)
// =====================================================================
const numList = text => String(text || '').split(/[\s,]+/).filter(Boolean).map(Number).filter(Number.isFinite);

// sharedMaxT: draw several runs on the same time scale so they can be compared by eye.
function drawSequence(svg, run, prefix, sharedMaxT) {
  const ns = 'http://www.w3.org/2000/svg';
  const mk = (tag, attrs, text) => {
    const n = document.createElementNS(ns, tag);
    for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
    if (text !== undefined) n.textContent = text;
    return n;
  };
  const maxT = sharedMaxT ?? Math.max(...run.segments.map(s => s.t1), 1);
  const W = 340, TOP = 34, SX = 60, RX = 280;
  const scale = Math.min(9, 620 / maxT);
  const H = TOP + maxT * scale + 20;
  const y = t => TOP + t * scale;
  svg.setAttribute('viewBox', `0 0 ${W} ${H}`);
  svg.replaceChildren();
  const dataColor = 'currentColor';
  const ackColor = cssVar('--chart-ack');
  const lossColor = cssVar('--chart-loss');
  const defs = mk('defs', {});
  for (const [id, color] of [['data', dataColor], ['ack', ackColor]]) {
    const m = mk('marker', { id: `${prefix}-${id}`, viewBox: '0 0 10 10', refX: 9, refY: 5, markerWidth: 6, markerHeight: 6, orient: 'auto-start-reverse' });
    m.append(mk('path', { d: 'M0,0 L10,5 L0,10 z', fill: color }));
    defs.append(m);
  }
  svg.append(defs);
  svg.append(mk('text', { x: SX, y: 14, 'text-anchor': 'middle', 'font-size': 11, 'font-weight': 600, fill: 'currentColor' }, 'Sender'));
  svg.append(mk('text', { x: RX, y: 14, 'text-anchor': 'middle', 'font-size': 11, 'font-weight': 600, fill: 'currentColor' }, 'Receiver'));
  for (const x of [SX, RX]) svg.append(mk('line', { x1: x, y1: TOP - 10, x2: x, y2: H - 5, stroke: 'currentColor', 'stroke-opacity': 0.2 }));

  for (const s of run.segments) {
    const fromX = s.kind === 'data' ? SX : RX;
    const toX = s.kind === 'data' ? RX : SX;
    const color = s.kind === 'data' ? dataColor : ackColor;
    const y0 = y(s.t0);
    const y1 = y(s.t1);
    if (s.lost) {
      const mx = (fromX + toX) / 2;
      const my = (y0 + y1) / 2;
      svg.append(mk('line', { x1: fromX, y1: y0, x2: mx, y2: my, stroke: color, 'stroke-width': 1.25, 'stroke-dasharray': s.retransmission ? '4 3' : '' }));
      // crisp drawn cross instead of a text glyph
      svg.append(mk('path', { d: `M${mx - 4},${my - 4}L${mx + 4},${my + 4}M${mx + 4},${my - 4}L${mx - 4},${my + 4}`, stroke: lossColor, 'stroke-width': 1.75, 'stroke-linecap': 'round' }));
    } else {
      svg.append(mk('line', { x1: fromX, y1: y0, x2: toX, y2: y1, stroke: color, 'stroke-width': 1.25, 'stroke-dasharray': s.retransmission ? '4 3' : '', 'marker-end': `url(#${prefix}-${s.kind})` }));
    }
    const lx = s.kind === 'data' ? SX - 6 : RX + 6;
    svg.append(mk('text', { x: lx, y: y0 + 3, 'text-anchor': s.kind === 'data' ? 'end' : 'start', 'font-size': 9, fill: color }, s.kind === 'data' ? `P${s.seq}` : `A${s.seq}`));
  }
  for (const l of run.log.filter(l => l.text.startsWith('Timeout'))) {
    svg.append(mk('text', { x: SX + 4, y: y(l.time) - 3, 'font-size': 9, fill: cssVar('--chart-warn') }, 'timeout'));
  }
}

$('#win-form').addEventListener('submit', ev => {
  ev.preventDefault();
  const f = new FormData(ev.target);
  const opts = {
    packets: Number(f.get('packets')),
    window: Number(f.get('window')),
    delay: Number(f.get('delay')),
    timeout: Number(f.get('timeout')),
    lostPackets: numList(f.get('lostPackets')),
    lostAcks: numList(f.get('lostAcks')),
  };
  // Run both first, then draw them on one shared time axis so the faster protocol visibly finishes higher up.
  const runs = {};
  for (const protocol of ['gbn', 'sr']) {
    try { runs[protocol] = simulateWindow({ ...opts, protocol }); } catch (e) { runs[protocol] = e; }
  }
  const ok = Object.values(runs).filter(r => !(r instanceof Error));
  const sharedMaxT = ok.length ? Math.max(1, ...ok.flatMap(r => r.segments.map(s => s.t1))) : undefined;
  for (const protocol of ['gbn', 'sr']) {
    const out = $(`#${protocol}-summary`);
    try {
      const run = runs[protocol];
      if (run instanceof Error) throw run;
      drawSequence($(`#${protocol}-chart`), run, protocol, sharedMaxT);
      out.replaceChildren(kv([
        ['Sent', `${run.summary.transmissions} (${run.summary.retransmissions} resent)`],
        ['Done at', run.summary.completionTime !== null ? `tick ${run.summary.completionTime}` : 'did not finish'],
        ['Useful', `${run.summary.efficiencyPct}%`],
      ]));
    } catch (e) {
      out.replaceChildren(el('span', { class: 'error' }, e.message));
    }
  }
  const timeoutTicks = opts.timeout;
  if (timeoutTicks <= 2 * opts.delay) {
    $('#sr-summary').append(el('p', { class: 'error' }, `Timeout ${timeoutTicks} ≤ RTT ${2 * opts.delay}: packets resend before their ACK arrives.`));
  }
});
$('#win-form').requestSubmit();

// =====================================================================
// EXPERIMENT: WHAT-IF THROUGHPUT
// =====================================================================
function fmtBps(bps) {
  if (!Number.isFinite(bps)) return '∞';
  if (bps >= 1e9) return `${(bps / 1e9).toFixed(2)} Gbps`;
  if (bps >= 1e6) return `${(bps / 1e6).toFixed(2)} Mbps`;
  return `${Math.round(bps / 1e3)} kbps`;
}

function renderWhatIf() {
  const form = $('#whatif-form');
  const f = new FormData(form);
  const rtt = Number(f.get('rtt'));
  const loss = Number(f.get('loss')) / 100;
  const bw = Number(f.get('bw'));
  const mss = Number(f.get('mss'));
  form.rttOut.value = rtt; form.lossOut.value = (loss * 100).toFixed(2); form.bwOut.value = bw;

  const tput = (r, p) => Math.min(mathisThroughput({ mss, rttMs: r, lossRate: p }), bw * 1e6);
  const now = tput(rtt, loss);
  const limitedBy = mathisThroughput({ mss, rttMs: rtt, lossRate: loss }) >= bw * 1e6 ? 'link capacity' : 'loss and RTT (TCP backs off)';
  const bdp = bandwidthDelayProduct({ bandwidthMbps: bw, rttMs: rtt });
  const util = Math.round((now / (bw * 1e6)) * 100);

  $('#whatif-out').replaceChildren(
    el('div', { class: 'meter' }, el('span', { style: { width: `${util}%` } })),
    kv([
      ['Throughput', `${fmtBps(now)} · ${util}% of link`],
      ['Limited by', limitedBy],
      ['BDP', `${Math.round(bdp.bytes / 1024)} KB · ${bdp.segments1460} segments in flight to fill the link`],
      ['RTT ×2', fmtBps(tput(rtt * 2, loss))],
      ['Loss ×2', fmtBps(tput(rtt, Math.min(loss * 2, 0.99)))],
      ['Loss ÷2', fmtBps(tput(rtt, loss / 2))],
      ['Model', 'Mathis: (MSS / RTT) × 1.22 / √loss, capped at link speed'],
    ]),
  );
}
$('#whatif-form').addEventListener('input', renderWhatIf);
renderWhatIf();

// =====================================================================
// EXPERIMENT: VLSM
// =====================================================================
$('#vlsm-form').addEventListener('submit', ev => {
  ev.preventDefault();
  const out = $('#vlsm-out');
  try {
    const plan = planVlsm(new FormData(ev.target).get('base'), parseRequirements($('#vlsm-reqs').value));
    out.replaceChildren(
      table(['Subnet', 'Hosts', 'Network', 'Mask', 'Usable range', 'Broadcast', 'Usable', 'Unused'],
        plan.allocations.map(a => [a.name, a.requestedHosts, `${a.network}/${a.prefix}`, a.mask, `${a.firstHost} – ${a.lastHost}`, a.broadcast, a.hostCount, a.wasted])),
      el('p', { class: 'hint' }, `Largest first. ${plan.usedAddresses} of ${plan.usedAddresses + plan.freeAddresses} used${plan.nextFree ? ` · next free ${plan.nextFree}` : ' · block full'}`),
    );
  } catch (e) {
    out.replaceChildren(el('p', { class: 'error' }, e.message));
  }
});
$('#vlsm-form').requestSubmit();

// =====================================================================
// EXPERIMENT: NAT / PAT
// =====================================================================
function parseFlows(text) {
  return text.split('\n').map(l => l.trim()).filter(Boolean).map(line => {
    const m = line.match(/^([\d.]+):(\d+)\s*-+>\s*([\d.]+):(\d+)$/);
    if (!m) throw new Error(`Write each flow as "10.0.0.5:51000 -> 93.184.215.14:443", got: "${line}"`);
    return { src: m[1], srcPort: Number(m[2]), dst: m[3], dstPort: Number(m[4]) };
  });
}

$('#nat-form').addEventListener('submit', ev => {
  ev.preventDefault();
  const f = new FormData(ev.target);
  const out = $('#nat-out');
  try {
    const r = natTranslate(parseFlows($('#nat-flows').value), { publicIp: f.get('publicIp'), startPort: Number(f.get('startPort')) });
    out.replaceChildren(
      table(['Inside local', 'Inside global', 'Outside', 'NAT'],
        r.table.map(t => [t.insideLocal || `${t.src}:${t.srcPort}`, t.insideGlobal || '—', t.outside || `${t.dst}:${t.dstPort}`, t.translated ? 'yes' : t.note])),
      el('p', { class: 'hint' }, `Each private socket gets one public port on ${r.publicIp}; replies to that port are forwarded back inside.`),
    );
  } catch (e) {
    out.replaceChildren(el('p', { class: 'error' }, e.message));
  }
});
$('#nat-form').requestSubmit();
$('#acl-form').requestSubmit(); // show a verdict on load, like every other card

// =====================================================================
// LIVE TESTS: RESOLVERS
// =====================================================================
$('#resolvers-form').addEventListener('submit', async ev => {
  ev.preventDefault();
  const out = $('#resolvers-out');
  out.replaceChildren(el('p', { class: 'muted' }, 'Querying…'));
  try {
    const r = await helper.resolvers(new FormData(ev.target).get('name'));
    out.replaceChildren(
      table(['Resolver', 'Time', 'Answers', 'Bytes'],
        r.results.map(x => [
          el('span', {}, x.resolver.replace(' (your OS / router)', ''), x.resolver === r.fastest ? el('span', { class: 'tag' }, 'Fastest') : null),
          x.ok ? `${x.timeMs} ms` : 'failed',
          !x.ok ? x.error
            : (x.answers || []).map(a => `${a.type} ${a.value} · TTL ${a.ttl}`).join('\n') || x.addresses.join(', ') || `no answers${x.rcode ? ` (${x.rcode})` : ''}`,
          x.bytesSent ? `${x.bytesSent} → ${x.bytesReceived}` : '—',
        ])),
    );
  } catch (e) {
    out.replaceChildren(el('p', { class: 'error' }, e.message));
  }
});
