// Transport-layer sandbox: a per-RTT model of TCP congestion control and flow control.
// Everything returned here is a SIMULATION and must be labelled as such in the UI.

export const LABEL = 'Simulated';

/** Small deterministic PRNG so a "what-if" run can be repeated exactly. */
export function mulberry32(seed) {
  let a = seed >>> 0;
  return function () {
    a = (a + 0x6D2B79F5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/**
 * Simulate cwnd evolution round by round (1 round = 1 RTT).
 *
 * options:
 *   variant      'reno' | 'tahoe'
 *   rounds       number of RTTs to simulate
 *   initialCwnd  segments (default 1)
 *   ssthresh     initial slow-start threshold, segments
 *   rwnd         receiver advertised window, segments (flow control)
 *   lossEvents   { [round]: 'dupack' | 'timeout' }  scripted losses
 *   lossRate     per-segment random loss probability (0..1)
 *   seed         PRNG seed for random loss
 *   rttMs, mss   used for throughput estimates
 */
export function simulateCongestion(options = {}) {
  const {
    variant = 'reno',
    rounds = 30,
    initialCwnd = 1,
    ssthresh: initialSsthresh = 16,
    rwnd = 64,
    lossEvents = {},
    lossRate = 0,
    seed = 42,
    rttMs = 100,
    mss = 1460,
  } = options;

  if (!['reno', 'tahoe'].includes(variant)) throw new Error(`Unknown variant: ${variant}`);
  if (lossRate < 0 || lossRate >= 1) throw new Error('lossRate must be in [0, 1)');

  const rand = mulberry32(seed);
  let cwnd = initialCwnd;
  let ssthresh = initialSsthresh;
  const series = [];

  for (let round = 1; round <= rounds; round++) {
    const window = Math.max(1, Math.min(Math.floor(cwnd), rwnd));
    let phase;
    if (cwnd >= rwnd) phase = 'flow-control-limited';
    else if (cwnd < ssthresh) phase = 'slow-start';
    else phase = 'congestion-avoidance';

    let event = lossEvents[round] ?? null;
    if (!event && lossRate > 0) {
      const pAnyLoss = 1 - (1 - lossRate) ** window;
      if (rand() < pAnyLoss) event = 'dupack';
    }

    series.push({
      round,
      cwnd: Math.round(cwnd * 100) / 100,
      ssthresh,
      window,
      phase,
      event,
      throughputKbps: Math.round((window * mss * 8) / rttMs),
    });

    // State update for the next RTT
    if (event === 'timeout') {
      ssthresh = Math.max(Math.floor(window / 2), 2);
      cwnd = 1;
    } else if (event === 'dupack') {
      ssthresh = Math.max(Math.floor(window / 2), 2);
      cwnd = variant === 'tahoe' ? 1 : ssthresh; // Reno: fast recovery
    } else if (cwnd < ssthresh) {
      cwnd = Math.min(cwnd * 2, ssthresh); // exponential growth, capped at ssthresh
    } else {
      cwnd += 1; // additive increase
    }
    cwnd = Math.min(cwnd, rwnd); // cannot usefully exceed the receiver window
  }

  const totalSegments = series.reduce((s, r) => s + r.window, 0);
  return {
    label: LABEL,
    variant,
    params: { rounds, initialCwnd, ssthresh: initialSsthresh, rwnd, lossRate, seed, rttMs, mss },
    series,
    summary: {
      totalSegments,
      lossEvents: series.filter(r => r.event).length,
      avgThroughputKbps: Math.round(series.reduce((s, r) => s + r.throughputKbps, 0) / series.length),
      transferTimeMs: rounds * rttMs,
    },
  };
}

/**
 * Mathis et al. steady-state TCP throughput approximation:
 *   throughput ≈ (MSS / RTT) * (C / sqrt(p)),  C ≈ 1.22
 * Returns bits per second. Useful for "what if loss doubles?" comparisons.
 */
export function mathisThroughput({ mss = 1460, rttMs = 100, lossRate = 0.01 } = {}) {
  if (lossRate <= 0) return Infinity;
  return Math.round(((mss * 8) / (rttMs / 1000)) * (1.22 / Math.sqrt(lossRate)));
}

/** Bandwidth-delay product: how many bytes must be "in flight" to fill a link. */
export function bandwidthDelayProduct({ bandwidthMbps = 100, rttMs = 50 } = {}) {
  const bytes = (bandwidthMbps * 1e6 / 8) * (rttMs / 1000);
  return { bytes: Math.round(bytes), segments1460: Math.ceil(bytes / 1460) };
}
