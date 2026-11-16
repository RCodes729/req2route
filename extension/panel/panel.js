import { explainEntry, summarizePage, detectHttpVersion } from '../lib/layers.js';
import { simulateCongestion } from '../lib/tcpsim.js';
import { parseCidr, splitSubnet } from '../lib/subnet.js';
import { parseAcl, evaluateAcl } from '../lib/acl.js';
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
  );
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
