import { test } from 'node:test';
import assert from 'node:assert/strict';
import { simulateCongestion, mathisThroughput, bandwidthDelayProduct } from '../extension/lib/tcpsim.js';

test('slow start doubles until ssthresh, then grows by one', () => {
  const r = simulateCongestion({ rounds: 8, ssthresh: 8, rwnd: 100 });
  assert.deepEqual(r.series.map(p => p.cwnd), [1, 2, 4, 8, 9, 10, 11, 12]);
  assert.equal(r.series[0].phase, 'slow-start');
  assert.equal(r.series[4].phase, 'congestion-avoidance');
  assert.equal(r.label, 'Simulated');
});

test('Reno halves on triple duplicate ACK, Tahoe resets to 1', () => {
  const opts = { rounds: 8, ssthresh: 8, rwnd: 100, lossEvents: { 6: 'dupack' } };
  const reno = simulateCongestion({ ...opts, variant: 'reno' });
  const tahoe = simulateCongestion({ ...opts, variant: 'tahoe' });
  // round 6 window = 10 -> ssthresh 5
  assert.equal(reno.series[6].cwnd, 5);
  assert.equal(reno.series[6].ssthresh, 5);
  assert.equal(tahoe.series[6].cwnd, 1);
  assert.equal(tahoe.series[6].ssthresh, 5);
});

test('timeout resets cwnd to 1 for both variants', () => {
  const r = simulateCongestion({ rounds: 6, ssthresh: 64, rwnd: 100, lossEvents: { 5: 'timeout' } });
  assert.equal(r.series[5].cwnd, 1);
  assert.equal(r.series[5].ssthresh, 8);
});

test('receiver window caps the sending window (flow control)', () => {
  const r = simulateCongestion({ rounds: 12, ssthresh: 64, rwnd: 10 });
  assert.ok(r.series.every(p => p.window <= 10));
  assert.equal(r.series.at(-1).phase, 'flow-control-limited');
});

test('random loss is reproducible with the same seed', () => {
  const a = simulateCongestion({ rounds: 40, lossRate: 0.02, seed: 7 });
  const b = simulateCongestion({ rounds: 40, lossRate: 0.02, seed: 7 });
  assert.deepEqual(a.series, b.series);
  assert.ok(a.summary.lossEvents > 0);
});

test('Mathis: 4x loss halves throughput; BDP math', () => {
  const t1 = mathisThroughput({ lossRate: 0.01 });
  const t4 = mathisThroughput({ lossRate: 0.04 });
  assert.ok(Math.abs(t1 / t4 - 2) < 0.01);
  assert.equal(bandwidthDelayProduct({ bandwidthMbps: 100, rttMs: 50 }).bytes, 625000);
});
