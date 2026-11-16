import { test } from 'node:test';
import assert from 'node:assert/strict';
import { explainEntry, summarizePage } from '../extension/lib/layers.js';
import { SAMPLE_ENTRIES } from '../extension/lib/sample-har.js';

test('new HTTPS/2 connection is explained across layers', () => {
  const x = explainEntry(SAMPLE_ENTRIES[0]);
  assert.equal(x.label, 'Observed');
  assert.equal(x.application.protocol, 'HTTPS');
  assert.equal(x.application.httpVersion, 'HTTP/2');
  assert.equal(x.transport.protocol, 'TCP');
  assert.equal(x.transport.reused, false);
  assert.equal(x.transport.handshakeMs, 37.1); // connect 88.3 includes ssl 51.2
  assert.equal(x.network.ipVersion, 'IPv4');
  assert.equal(x.network.classification.category, 'Public');
  assert.deepEqual(x.timeline.map(p => p.phase).slice(0, 4), ['Queued / blocked', 'DNS lookup', 'TCP handshake', 'TLS handshake']);
});

test('reused connection has no handshake and no DNS', () => {
  const x = explainEntry(SAMPLE_ENTRIES[1]);
  assert.equal(x.transport.reused, true);
  assert.equal(x.application.dns.timeMs, null);
  assert.ok(!x.timeline.some(p => p.phase.includes('handshake')));
});

test('HTTP/3 is shown as QUIC over UDP', () => {
  const x = explainEntry(SAMPLE_ENTRIES[2]);
  assert.equal(x.application.httpVersion, 'HTTP/3');
  assert.equal(x.transport.protocol, 'UDP (QUIC)');
});

test('plain HTTP to a private IP', () => {
  const x = explainEntry(SAMPLE_ENTRIES[3]);
  assert.equal(x.transport.tls, false);
  assert.equal(x.transport.serverPort, 80);
  assert.equal(x.network.classification.isPrivate, true);
  assert.equal(x.application.statusClass, '4xx Client error');
});

test('page summary counts', () => {
  const s = summarizePage(SAMPLE_ENTRIES);
  assert.equal(s.requests, 4);
  assert.equal(s.uniqueHosts, 3);
  assert.equal(s.connectionsSeen, 3);
  assert.equal(s.dnsLookups, 2);
  assert.equal(s.newConnections, 3);
  assert.equal(s.statuses['2xx'], 3);
});

import { groupByConnection, compareDns } from '../extension/lib/layers.js';

test('group requests by connection', () => {
  const g = groupByConnection(SAMPLE_ENTRIES);
  assert.equal(g.length, 3);
  assert.equal(g[0].connectionId, '1021');
  assert.equal(g[0].requests, 2);
  assert.equal(g[0].opened, true);
  assert.match(g[0].meaning, /multiplexed over one TCP connection/);
  const quic = g.find(x => x.connectionId === '1188');
  assert.equal(quic.transport, 'QUIC/UDP');
});

test('compare observed IP with tested DNS answer', () => {
  const x = explainEntry(SAMPLE_ENTRIES[0]);
  const same = compareDns(x, { timeMs: 12, method: 'dnspython', records: [{ type: 'A', value: '93.184.215.14' }] });
  assert.equal(same.ipMatch, true);
  const diff = compareDns(x, { timeMs: 12, records: [{ type: 'A', value: '1.2.3.4' }] });
  assert.equal(diff.ipMatch, false);
  assert.match(diff.verdict, /CDN/);
  assert.equal(same.observed.label, 'Observed');
  assert.equal(same.tested.label, 'Tested');
});

test('IPv6 server addresses are classified too', () => {
  const x = explainEntry({
    request: { method: 'GET', url: 'https://cloudflare.com/' },
    response: { status: 200, httpVersion: 'h3' },
    serverIPAddress: '[2606:4700::6810:84e5]',
    timings: { dns: 5, connect: 30, ssl: 20, wait: 40 },
    time: 80,
  });
  assert.equal(x.network.ipVersion, 'IPv6');
  assert.equal(x.network.classification.category, 'Public');
});

test('an unparseable server IP does not break the explanation', () => {
  const x = explainEntry({
    request: { method: 'GET', url: 'https://example.com/' },
    response: { status: 200 },
    serverIPAddress: 'not-an-ip',
    timings: {},
    time: 1,
  });
  assert.equal(x.network.classification, null);
});
