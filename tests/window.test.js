import { test } from 'node:test';
import assert from 'node:assert/strict';
import { simulateWindow } from '../extension/lib/window.js';

const base = { packets: 8, window: 4, delay: 5, timeout: 12 };

test('no loss: every packet sent once, delivered in order', () => {
  for (const protocol of ['gbn', 'sr']) {
    const r = simulateWindow({ ...base, protocol });
    assert.equal(r.summary.transmissions, 8, protocol);
    assert.equal(r.summary.retransmissions, 0, protocol);
    assert.ok(r.summary.inOrder, protocol);
    assert.equal(r.label, 'Simulated');
  }
});

test('one lost packet: GBN resends the whole window, SR resends one', () => {
  const gbn = simulateWindow({ ...base, protocol: 'gbn', lostPackets: [2] });
  const sr = simulateWindow({ ...base, protocol: 'sr', lostPackets: [2] });
  assert.equal(gbn.summary.retransmissions, 4); // 2,3,4,5 resent
  assert.equal(sr.summary.retransmissions, 1);  // only 2 resent
  assert.ok(gbn.summary.inOrder && sr.summary.inOrder);
  assert.ok(sr.summary.efficiencyPct > gbn.summary.efficiencyPct);
  assert.ok(gbn.log.some(l => l.text.includes('out of order → discard')));
  assert.ok(sr.log.some(l => l.text.includes('→ buffer')));
});

test('GBN tolerates a lost ACK thanks to cumulative ACKs', () => {
  const r = simulateWindow({ ...base, protocol: 'gbn', lostAcks: [1] });
  assert.equal(r.summary.retransmissions, 0);
  assert.ok(r.summary.inOrder);
});

test('SR lost ACK causes exactly one retransmission and a re-ACK', () => {
  const r = simulateWindow({ ...base, protocol: 'sr', lostAcks: [1] });
  assert.equal(r.summary.retransmissions, 1);
  assert.ok(r.log.some(l => l.text.includes('re-ACK') || l.text.includes('duplicate')));
  assert.ok(r.summary.inOrder);
});

test('window of 1 behaves like stop-and-wait', () => {
  const r = simulateWindow({ packets: 3, window: 1, delay: 5, timeout: 12, protocol: 'gbn' });
  // each packet needs a full RTT (10 ticks) before the next one
  assert.equal(r.summary.completionTime, 30);
});

test('all segments are drawn with valid times', () => {
  const r = simulateWindow({ ...base, protocol: 'sr', lostPackets: [1, 5], lostAcks: [3] });
  assert.ok(r.segments.every(s => s.t1 > s.t0));
  assert.ok(r.segments.filter(s => s.lost).length === 3);
});
