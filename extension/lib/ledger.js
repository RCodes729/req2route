// RTT ledger: a cross-layer calculation that links what the browser OBSERVED to what the
// transport model would PREDICT.
//
//  1. The TCP handshake takes exactly one round trip, so a new connection's handshake time
//     is a free measurement of the path RTT to that server (no ping needed).
//  2. With the RTT known, every other phase can be written in RTTs: the TLS handshake (1 RTT
//     for TLS 1.3, 2 for TLS 1.2) and the wait for the first byte, which splits into one RTT of
//     network time plus the server's own think time.
//  3. The body download is then fed to a slow-start model (initial window 10 segments, doubling
//     each RTT) and compared with the download time the browser actually recorded.
//
// The RTT is derived from Observed timings; the transfer prediction is Simulated, so the
// result is labelled Simulated and every field says which side it came from.
import { detectHttpVersion } from './layers.js';

export const LABEL = 'Simulated';
export const INITIAL_CWND = 10; // segments, RFC 6928
export const MSS = 1460;
const MIN_RTT_MS = 1; // below this the timer resolution swamps the signal (loopback, cached sockets)

// Chrome can reuse one "connection" value for sockets to different servers, so the server IP is part of the key.
const connKey = e => `${e.connection}|${e.serverIPAddress || ''}`;
const ms = v => (typeof v === 'number' && v >= 0 ? v : null);
const round1 = v => Math.round(v * 10) / 10;

/** Rounds (RTTs) slow start needs to deliver `bytes`; the first flight counts as round 1. */
export function transferRounds(bytes, { mss = MSS, initialCwnd = INITIAL_CWND } = {}) {
  if (!(bytes > 0)) return { segments: 0, rounds: 0 };
  const segments = Math.ceil(bytes / mss);
  let sent = 0;
  let cwnd = initialCwnd;
  let rounds = 0;
  while (sent < segments) {
    sent += cwnd;
    cwnd *= 2;
    rounds++;
  }
  return { segments, rounds };
}

/** Compressed bytes the response body occupied on the wire. */
export function bodyBytes(entry) {
  const r = entry.response || {};
  if (r.bodySize > 0) return r.bodySize;
  if (r._transferSize > 0) return Math.max(0, r._transferSize - (r.headersSize > 0 ? r.headersSize : 0));
  return r.content?.size > 0 ? r.content.size : 0;
}

/** Read a TLS handshake time as a number of round trips. A heuristic, so the wording says "looks like". */
export function classifyTls(tlsRtts) {
  if (tlsRtts === null) return null;
  if (tlsRtts < 0.5) return 'resumed or combined with the TCP handshake';
  if (tlsRtts < 1.7) return 'looks like TLS 1.3 (1 round trip)';
  if (tlsRtts < 2.7) return 'looks like TLS 1.2 (2 round trips)';
  return 'more than 2 round trips: certificate checks, a slow server or retransmissions';
}

function compareTransfer(observedMs, predictedMs, rtt) {
  const slack = Math.max(rtt * 0.5, predictedMs * 0.3);
  if (Math.abs(observedMs - predictedMs) <= slack) return 'agrees';
  return observedMs > predictedMs
    ? 'slower than the model: bandwidth, loss or server pacing is the limit, not RTT'
    : 'faster than the model: a larger initial window or a warm path';
}

function rowFor(entry, connection) {
  const t = entry.timings || {};
  const ttfb = ms(t.wait);
  const receive = ms(t.receive);
  const wait = ttfb ?? 0;
  const think = Math.max(0, wait - connection.rttMs);
  const bytes = bodyBytes(entry);
  const row = {
    label: LABEL,
    url: entry.request.url,
    connection: entry.connection ?? null,
    connectionKey: connKey(entry),
    newConnection: connection.isOpener,
    rttMs: round1(connection.rttMs),
    rttSource: 'Observed: TCP handshake time of this connection',
    ttfbMs: round1(wait),
    networkMs: round1(Math.min(wait, connection.rttMs)),
    serverThinkMs: round1(think),
    bodyBytes: bytes,
    transfer: null,
    savedIfReusedMs: connection.isOpener ? round1(connection.tcpMs + connection.sslMs) : 0,
  };
  if (connection.isOpener) {
    row.tlsRtts = connection.sslMs > 0 ? round1(connection.sslMs / connection.rttMs) : null;
    row.tlsKind = classifyTls(row.tlsRtts);
  } else {
    row.tlsRtts = null;
    row.tlsKind = null;
  }
  if (!connection.isOpener) {
    row.transferNote = 'Connection already warm (its window has grown), so the slow-start model does not apply.';
  } else if (bytes > 0 && receive !== null) {
    const { segments, rounds } = transferRounds(bytes);
    // The first flight is already arriving when "receive" starts, so each further round costs one RTT.
    const predictedMs = (rounds - 1) * connection.rttMs;
    row.transfer = {
      segments,
      rounds,
      predictedReceiveMs: round1(predictedMs),
      observedReceiveMs: round1(receive),
      observedExtraRtts: round1(receive / connection.rttMs),
      goodputKbps: receive > 0 ? Math.round((bytes * 8) / receive) : null,
      verdict: compareTransfer(receive, predictedMs, connection.rttMs),
    };
  }
  return row;
}

/**
 * Build the ledger for a page load.
 * Only new TCP connections give an RTT; later requests on the same connection inherit it.
 */
export function pageLedger(entries) {
  const connections = new Map();
  const skipped = [];

  for (const e of entries) {
    if (e.connection === undefined || e.connection === null || connections.has(connKey(e))) continue;
    const connect = ms(e.timings?.connect);
    if (!connect) continue; // reused connection: not the opener
    if (detectHttpVersion(e) === 'HTTP/3') continue; // QUIC: no separate TCP handshake to measure
    const ssl = ms(e.timings?.ssl) ?? 0;
    const tcp = Math.max(0, connect - ssl);
    if (tcp < MIN_RTT_MS) continue;
    connections.set(connKey(e), { rttMs: tcp, tcpMs: tcp, sslMs: ssl, opener: e });
  }

  const rows = [];
  for (const e of entries) {
    const known = connections.get(connKey(e));
    if (!known) {
      const why = detectHttpVersion(e) === 'HTTP/3'
        ? 'HTTP/3 runs over QUIC: no TCP handshake to read the RTT from'
        : 'no measurable TCP handshake for this connection (reused earlier, cached, or under 1 ms)';
      skipped.push({ url: e.request.url, reason: why });
      continue;
    }
    rows.push(rowFor(e, { ...known, isOpener: known.opener === e }));
  }

  const opened = rows.filter(r => r.newConnection);
  const checked = opened.filter(r => r.transfer);
  const totalWait = rows.reduce((s, r) => s + r.ttfbMs, 0);
  const summary = {
    label: LABEL,
    requestsAnalysed: rows.length,
    requestsSkipped: skipped.length,
    connectionsMeasured: connections.size,
    avgRttMs: opened.length ? round1(opened.reduce((s, r) => s + r.rttMs, 0) / opened.length) : null,
    handshakeMsPaid: round1(opened.reduce((s, r) => s + r.savedIfReusedMs, 0)),
    handshakeMsSavedByReuse: round1(rows.filter(r => !r.newConnection)
      .reduce((s, r) => s + (connections.get(r.connectionKey)?.tcpMs ?? 0) + (connections.get(r.connectionKey)?.sslMs ?? 0), 0)),
    waitNetworkPct: totalWait > 0 ? Math.round(100 * rows.reduce((s, r) => s + r.networkMs, 0) / totalWait) : null,
    waitServerPct: totalWait > 0 ? Math.round(100 * rows.reduce((s, r) => s + r.serverThinkMs, 0) / totalWait) : null,
    modelChecked: checked.length,
    modelAgrees: checked.filter(r => r.transfer.verdict === 'agrees').length,
  };
  return { label: LABEL, rows, skipped, summary };
}
