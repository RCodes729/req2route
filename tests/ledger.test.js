import { test } from 'node:test';
import assert from 'node:assert/strict';
import { transferRounds, bodyBytes, classifyTls, pageLedger } from '../extension/lib/ledger.js';
import { SAMPLE_ENTRIES } from '../extension/lib/sample-har.js';

const entry = (over = {}) => ({
  request: { method: 'GET', url: 'https://big.example/file', httpVersion: 'http/2.0' },
  response: { status: 200, httpVersion: 'http/2.0', _transferSize: 1_000_000 },
  serverIPAddress: '203.0.113.9',
  connection: 'c1',
  timings: { connect: 100, ssl: 50, wait: 80, receive: 300 },
  ...over,
});

test('slow start delivers 10, 30, 70, 150 ... segments per cumulative round', () => {
  assert.deepEqual(transferRounds(0), { segments: 0, rounds: 0 });
  assert.equal(transferRounds(10 * 1460).rounds, 1);      // fits the initial window
  assert.equal(transferRounds(10 * 1460 + 1).rounds, 2);  // one byte over
  assert.equal(transferRounds(70 * 1460).rounds, 3);      // 10 + 20 + 40
  assert.equal(transferRounds(1_000_000).rounds, 7);      // 685 segments
  assert.equal(transferRounds(1_000_000, { initialCwnd: 1 }).rounds, 10); // old initial window needs more
});

test('body size prefers bodySize, then transfer size minus headers, then content size', () => {
  assert.equal(bodyBytes({ response: { bodySize: 500, _transferSize: 900 } }), 500);
  assert.equal(bodyBytes({ response: { bodySize: -1, _transferSize: 900, headersSize: 300 } }), 600);
  assert.equal(bodyBytes({ response: { content: { size: 42 } } }), 42);
  assert.equal(bodyBytes({}), 0);
});

test('TLS handshake time is read as round trips', () => {
  assert.equal(classifyTls(null), null);
  assert.match(classifyTls(0.2), /resumed/);
  assert.match(classifyTls(1.1), /TLS 1\.3/);
  assert.match(classifyTls(2.1), /TLS 1\.2/);
  assert.match(classifyTls(4), /more than 2/);
});

test('sample page: handshake gives the RTT, first-byte wait splits into network and server', () => {
  const { label, rows, skipped, summary } = pageLedger(SAMPLE_ENTRIES);
  assert.equal(label, 'Simulated');
  const first = rows[0];
  assert.equal(first.newConnection, true);
  assert.equal(first.rttMs, 37.1);              // connect 88.3 - ssl 51.2
  assert.equal(first.networkMs, 37.1);          // one RTT of the 61.8 ms wait is the network
  assert.equal(first.serverThinkMs, 24.7);      // the rest is the server thinking
  assert.equal(first.tlsRtts, 1.4);
  assert.match(first.tlsKind, /TLS 1\.3/);
  assert.equal(first.savedIfReusedMs, 88.3);    // handshake + TLS a reused connection avoids
  // the HTTP/3 request has no TCP handshake, so it is skipped with a reason
  assert.equal(skipped.length, 1);
  assert.match(skipped[0].reason, /QUIC/);
  assert.equal(summary.requestsAnalysed, 3);
  assert.equal(summary.connectionsMeasured, 2);
});

test('a reused connection inherits the RTT but gets no slow-start prediction', () => {
  const reused = pageLedger(SAMPLE_ENTRIES).rows[1];
  assert.equal(reused.newConnection, false);
  assert.equal(reused.rttMs, 37.1);
  assert.equal(reused.serverThinkMs, 0);        // wait 36.4 < RTT 37.1: clamped, never negative
  assert.equal(reused.transfer, null);
  assert.match(reused.transferNote, /warm/);
  assert.equal(pageLedger(SAMPLE_ENTRIES).summary.handshakeMsSavedByReuse, 88.3);
});

test('plain HTTP has no TLS round trips', () => {
  const http = pageLedger(SAMPLE_ENTRIES).rows.find(r => r.url.startsWith('http://'));
  assert.equal(http.rttMs, 2.1);
  assert.equal(http.tlsRtts, null);
});

test('model check: observed download time vs predicted slow start', () => {
  // RTT 50 ms, 1 MB needs 7 rounds -> 6 extra RTTs -> 300 ms predicted
  const agree = pageLedger([entry()]).rows[0].transfer;
  assert.equal(agree.rounds, 7);
  assert.equal(agree.predictedReceiveMs, 300);
  assert.equal(agree.verdict, 'agrees');
  assert.equal(agree.goodputKbps, Math.round((1_000_000 * 8) / 300));

  const slow = pageLedger([entry({ timings: { connect: 100, ssl: 50, wait: 80, receive: 2000 } })]).rows[0].transfer;
  assert.match(slow.verdict, /^slower than the model/);

  const fast = pageLedger([entry({ timings: { connect: 100, ssl: 50, wait: 80, receive: 20 } })]).rows[0].transfer;
  assert.match(fast.verdict, /^faster than the model/);
});

test('sub-millisecond handshakes (loopback) are skipped, not divided by', () => {
  const r = pageLedger([entry({ timings: { connect: 0.4, ssl: -1, wait: 3, receive: 1 } })]);
  assert.equal(r.rows.length, 0);
  assert.equal(r.skipped.length, 1);
  assert.equal(r.summary.avgRttMs, null);
});

test('empty page does not throw', () => {
  const r = pageLedger([]);
  assert.deepEqual(r.rows, []);
  assert.equal(r.summary.waitNetworkPct, null);
});

test('same connection value but different server IPs are different connections (Chrome reports "443")', () => {
  // Real Wikipedia capture: every request had connection "443", yet the servers differed.
  const wiki = entry({ connection: '443', serverIPAddress: '103.102.166.224', timings: { connect: -1, ssl: -1, wait: 50, receive: 5 } });
  const cdn = entry({ connection: '443', serverIPAddress: '142.250.1.1', timings: { connect: 100, ssl: 50, wait: 80, receive: 30 } });
  const r = pageLedger([wiki, cdn]);
  assert.equal(r.summary.connectionsMeasured, 1);
  assert.equal(r.rows.length, 1);                     // the wiki request is NOT given the CDN's RTT
  assert.equal(r.summary.handshakeMsSavedByReuse, 0); // and no phantom "saved" time
  assert.equal(r.skipped.length, 1);
});

test('a download far faster than the model is not called "agrees"', () => {
  // Real capture: model +174.5 ms (1 extra RTT), observed 13.4 ms
  const r = pageLedger([entry({ response: { status: 200, httpVersion: 'http/2.0', _transferSize: 24314 },
    timings: { connect: 174.5, ssl: 0, wait: 314.5, receive: 13.4 } })]).rows[0].transfer;
  assert.equal(r.predictedReceiveMs, 174.5);
  assert.match(r.verdict, /^faster than the model/);
});
