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
