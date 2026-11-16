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
const kv = pairs => el('dl', { class: 'kv' }, pairs.filter(([, v]) => v !== null && v !== undefined && v !== '').flatMap(([k, v]) => [el('dt', {}, k), el('dd', {}, String(v))]));

const table = (headers, rows) => el('table', { class: 'data' },
  el('thead', {}, el('tr', {}, headers.map(h => el('th', {}, h)))),
  el('tbody', {}, rows.map(r => el('tr', {}, r.map(v => el('td', { title: String(v ?? '') }, v ?? ''))))));

// ---------- tabs ----------
document.querySelectorAll('.tab-btn').forEach(btn => btn.addEventListener('click', () => {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.toggle('active', b === btn));
  document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.id === `tab-${btn.dataset.tab}`));
}));

// =====================================================================
// OBSERVE + EXPLAIN
// =====================================================================
const inDevtools = typeof chrome !== 'undefined' && chrome.devtools?.network;
let entries = [];

function addEntry(entry) {
  entries.push(entry);
  renderRow(entry, entries.length - 1);
  renderSummary();
}

function renderRow(entry, idx) {
  let host = '';
  try { host = new URL(entry.request.url).hostname; } catch { host = entry.request.url.slice(0, 40); }
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
  const stat = (label, value) => el('div', { class: 'stat' }, el('b', {}, value), label);
  $('#summary').replaceChildren(
    stat('requests', s.requests),
    stat('hosts', s.uniqueHosts),
    stat('server IPs', s.uniqueServerIps),
    stat('DNS lookups', s.dnsLookups),
    stat('new connections', s.newConnections),
    stat('KB transferred', Math.round(s.bytesTransferred / 1024)),
    stat('protocols', Object.entries(s.protocols).map(([k, v]) => `${k}×${v}`).join(' ') || '—'),
    badge(s.label),
  );
  renderConnections();
}

function renderConnections() {
  const groups = groupByConnection(entries);
  $('#connections').replaceChildren(groups.length ? table(
    ['Connection', 'Transport', 'HTTP', 'Server IP', 'Hosts', 'Requests', 'Connect (TCP+TLS)', 'What it means'],
    groups.map(g => [g.connectionId, g.transport, g.httpVersion, g.serverIp || '—', g.hosts.join(', '), g.requests, g.opened ? `${g.handshakeMs} ms` : 'reused / none', g.meaning]),
  ) : el('p', { class: 'muted' }, 'No requests yet.'));
}

const PHASE_COLORS = { browser: 'var(--browser)', application: 'var(--app)', transport: 'var(--transport)' };

function renderExplain(entry) {
  const x = explainEntry(entry);
  const total = x.timeline.reduce((s, p) => s + p.ms, 0) || 1;
  const waterfall = el('div', { class: 'waterfall' }, x.timeline.map((p, i) =>
    el('span', { title: `${p.phase}: ${p.ms} ms`, style: { width: `${(p.ms / total) * 100}%`, background: PHASE_COLORS[p.layer], opacity: 0.55 + (i % 3) * 0.15 } })));
  const legend = el('div', { class: 'legend' }, x.timeline.map(p => el('span', {}, el('i', { style: { background: PHASE_COLORS[p.layer] } }), `${p.phase} ${p.ms} ms`)));

  $('#explain').replaceChildren(
    el('h2', {}, 'Journey of this request ', badge(x.label)),
    el('p', { class: 'muted' }, x.url),
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
      el('p', { class: 'muted' }, `Ask the helper to resolve ${x.host} now and compare with what the browser used.`),
      el('button', { class: 'primary', onclick: () => runCompare(x) }, `Test ${x.host}`),
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
  $('#explain').replaceChildren(el('p', { class: 'muted' }, 'Select a request to see its journey through each layer.'));
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
  note.textContent = 'Demo mode: not running inside DevTools, so sample data is shown. Load the extension in Chrome to observe real pages.';
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

function drawTcpChart(svg, runs) {
  const W = 700, H = 260, P = 30;
  const all = runs.flatMap(r => r.series);
  const maxRound = Math.max(...all.map(p => p.round));
  const maxY = Math.max(4, ...all.map(p => Math.max(p.cwnd, p.ssthresh)));
  const x = r => P + ((r - 1) / Math.max(1, maxRound - 1)) * (W - 2 * P);
  const y = v => H - P - (v / maxY) * (H - 2 * P);
  const ns = 'http://www.w3.org/2000/svg';
  const mk = (tag, attrs) => { const n = document.createElementNS(ns, tag); for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v); return n; };
  svg.replaceChildren();
  svg.append(mk('line', { x1: P, y1: H - P, x2: W - P, y2: H - P, stroke: 'currentColor', 'stroke-opacity': 0.3 }));
  svg.append(mk('line', { x1: P, y1: P, x2: P, y2: H - P, stroke: 'currentColor', 'stroke-opacity': 0.3 }));
  const label = (tx, ty, text, anchor = 'start') => { const t = mk('text', { x: tx, y: ty, 'font-size': 10, fill: 'currentColor', 'text-anchor': anchor }); t.textContent = text; svg.append(t); };
  label(P, P - 8, `cwnd (segments), max ${maxY}`);
  label(W - P, H - 8, `RTT round (1–${maxRound})`, 'end');

  runs.forEach((run, i) => {
    const dashed = run === tcpBaseline;
    const color = dashed ? '#8c959f' : '#8250df';
    svg.append(mk('polyline', { points: run.series.map(p => `${x(p.round)},${y(p.cwnd)}`).join(' '), fill: 'none', stroke: color, 'stroke-width': 2, 'stroke-dasharray': dashed ? '5 4' : '' }));
    if (!dashed) {
      svg.append(mk('polyline', { points: run.series.map(p => `${x(p.round)},${y(p.ssthresh)}`).join(' '), fill: 'none', stroke: '#bf3989', 'stroke-width': 1, 'stroke-dasharray': '2 3' }));
      run.series.filter(p => p.event).forEach(p => svg.append(mk('circle', { cx: x(p.round), cy: y(p.cwnd), r: 4, fill: p.event === 'timeout' ? '#cf222e' : '#9a6700' })));
    }
  });
  label(W - P, P - 8, `${tcpBaseline ? 'grey dashed = baseline · ' : ''}pink dotted = ssthresh · dots = loss`, 'end');
}

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
    const cmp = tcpBaseline ? ` (baseline ${tcpBaseline.summary.avgThroughputKbps} kbps)` : '';
    $('#tcp-summary').replaceChildren(...kv([
      ['Variant', tcpLast.variant.toUpperCase()],
      ['Segments delivered', s.totalSegments],
      ['Loss events', s.lossEvents],
      ['Avg throughput', `${s.avgThroughputKbps} kbps${cmp}`],
      ['Label', tcpLast.label],
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
      el('div', { class: `verdict ${r.action}` }, `${r.action.toUpperCase()} — ${r.implicit ? 'no rule matched, implicit deny' : `matched rule ${r.matchedIndex + 1}`} `, badge(r.label)),
      ...r.trace.map(t => el('div', { class: `trace-row${t.matched ? ' hit' : ''}` },
        `${t.index + 1}. ${t.rule}  →  ${t.matched ? 'MATCH' : 'no match: ' + Object.entries(t.checks).filter(([, ok]) => !ok).map(([k]) => k).join(', ')}`)),
    );
  } catch (e) {
    out.replaceChildren(el('span', { class: 'error' }, e.message));
  }
});

// =====================================================================
// LIVE TESTS
// =====================================================================
async function show(target, fn) {
  const out = $(target);
  out.textContent = 'Running…';
  try { out.textContent = JSON.stringify(await fn(), null, 2); }
  catch (e) { out.textContent = e.message; }
}
$('#helper-health').addEventListener('click', () => show('#helper-health-out', helper.health));
$('#dns-form').addEventListener('submit', ev => { ev.preventDefault(); show('#dns-out', () => helper.dns(new FormData(ev.target).get('name'))); });
$('#sock-form').addEventListener('submit', ev => {
  ev.preventDefault();
  const f = new FormData(ev.target);
  const kind = ev.submitter?.value || 'tcp';
  show('#sock-out', () => kind === 'udp' ? helper.udp(f.get('host'), f.get('port'), 10) : helper.tcp(f.get('host'), f.get('port')));
});
$('#arp-btn').addEventListener('click', async () => {
  const out = $('#arp-out');
  out.textContent = 'Reading…';
  try {
    const r = await helper.arp();
    out.replaceChildren(el('table', {},
      el('thead', {}, el('tr', {}, ['Interface', 'IP address', 'MAC address', 'Type', 'Note'].map(h => el('th', {}, h)))),
      el('tbody', {}, r.entries.map(e => el('tr', {}, [e.interface, e.ip, e.mac, e.type, e.note || ''].map(v => el('td', {}, v ?? '')))))));
  } catch (e) {
    out.textContent = e.message;
  }
});

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
  const defs = mk('defs', {});
  for (const [id, color] of [['data', '#0969da'], ['ack', '#1a7f37']]) {
    const m = mk('marker', { id: `${prefix}-${id}`, viewBox: '0 0 10 10', refX: 9, refY: 5, markerWidth: 6, markerHeight: 6, orient: 'auto-start-reverse' });
    m.append(mk('path', { d: 'M0,0 L10,5 L0,10 z', fill: color }));
    defs.append(m);
  }
  svg.append(defs);
  svg.append(mk('text', { x: SX, y: 14, 'text-anchor': 'middle', 'font-size': 11, 'font-weight': 600, fill: 'currentColor' }, 'Sender'));
  svg.append(mk('text', { x: RX, y: 14, 'text-anchor': 'middle', 'font-size': 11, 'font-weight': 600, fill: 'currentColor' }, 'Receiver'));
  for (const x of [SX, RX]) svg.append(mk('line', { x1: x, y1: TOP - 10, x2: x, y2: H - 5, stroke: 'currentColor', 'stroke-opacity': 0.35 }));

  for (const s of run.segments) {
    const fromX = s.kind === 'data' ? SX : RX;
    const toX = s.kind === 'data' ? RX : SX;
    const color = s.kind === 'data' ? '#0969da' : '#1a7f37';
    const y0 = y(s.t0);
    const y1 = y(s.t1);
    if (s.lost) {
      const mx = (fromX + toX) / 2;
      const my = (y0 + y1) / 2;
      svg.append(mk('line', { x1: fromX, y1: y0, x2: mx, y2: my, stroke: color, 'stroke-width': 1.4, 'stroke-dasharray': s.retransmission ? '4 3' : '' }));
      svg.append(mk('text', { x: mx, y: my + 4, 'text-anchor': 'middle', 'font-size': 13, fill: '#cf222e', 'font-weight': 700 }, '✕'));
    } else {
      svg.append(mk('line', { x1: fromX, y1: y0, x2: toX, y2: y1, stroke: color, 'stroke-width': 1.4, 'stroke-dasharray': s.retransmission ? '4 3' : '', 'marker-end': `url(#${prefix}-${s.kind})` }));
    }
    const lx = s.kind === 'data' ? SX - 6 : RX + 6;
    svg.append(mk('text', { x: lx, y: y0 + 3, 'text-anchor': s.kind === 'data' ? 'end' : 'start', 'font-size': 9, fill: color }, s.kind === 'data' ? `P${s.seq}` : `A${s.seq}`));
  }
  for (const l of run.log.filter(l => l.text.startsWith('Timeout'))) {
    svg.append(mk('text', { x: SX + 4, y: y(l.time) - 2, 'font-size': 9, fill: '#9a6700' }, '⏱ timeout'));
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
        ['Transmissions', run.summary.transmissions],
        ['Retransmissions', run.summary.retransmissions],
        ['Finished at tick', run.summary.completionTime ?? 'did not finish'],
        ['Efficiency', `${run.summary.efficiencyPct}% of sends were useful`],
      ]));
    } catch (e) {
      out.replaceChildren(el('span', { class: 'error' }, e.message));
    }
  }
  const timeoutTicks = opts.timeout;
  if (timeoutTicks <= 2 * opts.delay) {
    $('#sr-summary').append(el('p', { class: 'error' }, `Timeout (${timeoutTicks}) ≤ RTT (${2 * opts.delay}): packets will be resent before their ACK can arrive.`));
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
      ['Estimated TCP throughput', `${fmtBps(now)} (${util}% of the link)`],
      ['Limited by', limitedBy],
      ['Bandwidth-delay product', `${Math.round(bdp.bytes / 1024)} KB ≈ ${bdp.segments1460} segments must be in flight to fill the link`],
      ['If RTT doubles', fmtBps(tput(rtt * 2, loss))],
      ['If loss doubles', fmtBps(tput(rtt, Math.min(loss * 2, 0.99)))],
      ['If loss halves', fmtBps(tput(rtt, loss / 2))],
      ['Model', 'Mathis et al.: throughput ≈ (MSS / RTT) × 1.22 / √loss, capped at link speed'],
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
      table(['Subnet', 'Hosts needed', 'Network', 'Mask', 'Usable range', 'Broadcast', 'Usable', 'Unused'],
        plan.allocations.map(a => [a.name, a.requestedHosts, `${a.network}/${a.prefix}`, a.mask, `${a.firstHost} – ${a.lastHost}`, a.broadcast, a.hostCount, a.wasted])),
      el('p', { class: 'muted' }, `Allocated largest first. ${plan.usedAddresses} of ${plan.usedAddresses + plan.freeAddresses} addresses used${plan.nextFree ? `; next free address ${plan.nextFree}` : '; block is full'}.`),
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
      table(['Inside local (private)', 'Inside global (after NAT)', 'Outside (server)', 'Translated?'],
        r.table.map(t => [t.insideLocal || `${t.src}:${t.srcPort}`, t.insideGlobal || '—', t.outside || `${t.dst}:${t.dstPort}`, t.translated ? 'yes' : t.note])),
      el('p', { class: 'muted' }, `Every private socket gets its own public port on ${r.publicIp}. Replies come back to that port and the router uses this table to forward them inside. The same inside socket reuses its mapping.`),
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
      table(['Resolver', 'Server', 'Time', 'Answers', 'Packet sizes'],
        r.results.map(x => [
          x.resolver + (x.resolver === r.fastest ? ' ⚡' : ''),
          x.server,
          x.ok ? `${x.timeMs} ms` : 'failed',
          !x.ok ? x.error
            : (x.answers || []).map(a => `${a.type} ${a.value} (TTL ${a.ttl})`).join('; ') || x.addresses.join(', ') || `no answers${x.rcode ? ` (${x.rcode})` : ''}`,
          x.bytesSent ? `${x.bytesSent} B query / ${x.bytesReceived} B reply` : '',
        ])),
      el('p', { class: 'muted' }, r.note),
    );
  } catch (e) {
    out.replaceChildren(el('p', { class: 'error' }, e.message));
  }
});
