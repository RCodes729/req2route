// Transport-layer sandbox: reliable data transfer with a sliding window.
// Discrete-event simulation of Go-Back-N and Selective Repeat over a channel
// with a fixed one-way delay and scripted packet / ACK loss.  [Simulated]

export const LABEL = 'Simulated';

/**
 * options:
 *   protocol     'gbn' | 'sr'
 *   packets      number of packets to deliver (seq 0..packets-1)
 *   window       sender window size (SR also uses it as receiver window)
 *   delay        one-way propagation delay in ticks (RTT = 2 * delay)
 *   timeout      retransmission timeout in ticks
 *   lostPackets  seq numbers whose FIRST transmission is dropped
 *   lostAcks     ACK numbers whose FIRST transmission is dropped
 *
 * Sender transmits at most one packet per tick.
 */
export function simulateWindow(options = {}) {
  const {
    protocol = 'gbn',
    packets = 10,
    window = 4,
    delay = 5,
    timeout = 14,
    lostPackets = [],
    lostAcks = [],
  } = options;
  if (!['gbn', 'sr'].includes(protocol)) throw new Error(`Unknown protocol: ${protocol}`);
  if (packets < 1 || packets > 200) throw new Error('packets must be 1–200');
  if (window < 1) throw new Error('window must be ≥ 1');
  if (protocol === 'sr' && window > 64) throw new Error('window too large');

  const pendingPacketLoss = new Set(lostPackets.map(Number));
  const pendingAckLoss = new Set(lostAcks.map(Number));

  // ---- event queue (time-ordered, FIFO for ties)
  const queue = [];
  let order = 0;
  const schedule = (time, kind, data) => {
    queue.push({ time, order: order++, kind, ...data });
    queue.sort((a, b) => a.time - b.time || a.order - b.order);
  };

  const segments = []; // drawn as arrows: {kind:'data'|'ack', seq, t0, t1, lost, retransmission}
  const log = [];      // human-readable timeline
  const sentCount = new Map();
  const delivered = [];
  let freeAt = 0;      // sender transmits one packet per tick
  let transmissions = 0;
  let retransmissions = 0;
  let finishedAt = null;

  // ---- sender state
  let base = 0;
  let next = 0;
  let gbnTimerToken = 0;
  const srTimerToken = new Map();
  const acked = new Set();

  // ---- receiver state
  let expected = 0;           // GBN
  let rcvBase = 0;            // SR
  const rcvBuffer = new Set(); // SR

  function transmit(now, seq) {
    const t = Math.max(now, freeAt);
    freeAt = t + 1;
    const count = (sentCount.get(seq) || 0) + 1;
    sentCount.set(seq, count);
    transmissions++;
    const retransmission = count > 1;
    if (retransmission) retransmissions++;
    const lost = pendingPacketLoss.has(seq) && count === 1;
    segments.push({ kind: 'data', seq, t0: t, t1: t + delay, lost, retransmission });
    log.push({ time: t, who: 'sender', text: `${retransmission ? 'Retransmit' : 'Send'} pkt ${seq}${lost ? ' (lost in channel)' : ''}` });
    if (!lost) schedule(t + delay, 'data-arrive', { seq });
    return t;
  }

  function sendAck(now, ackNum) {
    const lost = pendingAckLoss.has(ackNum);
    if (lost) pendingAckLoss.delete(ackNum);
    segments.push({ kind: 'ack', seq: ackNum, t0: now, t1: now + delay, lost });
    log.push({ time: now, who: 'receiver', text: `Send ACK ${ackNum}${lost ? ' (lost in channel)' : ''}` });
    if (!lost) schedule(now + delay, 'ack-arrive', { seq: ackNum });
  }

  function startGbnTimer(at) {
    gbnTimerToken++;
    schedule(at + timeout, 'timeout', { token: gbnTimerToken });
  }

  function startSrTimer(seq, at) {
    const token = (srTimerToken.get(seq) || 0) + 1;
    srTimerToken.set(seq, token);
    schedule(at + timeout, 'timeout', { seq, token });
  }

  function fillWindow(now) {
    while (next < base + window && next < packets) {
      const t = transmit(now, next);
      if (protocol === 'gbn') { if (base === next) startGbnTimer(t); }
      else startSrTimer(next, t);
      next++;
    }
  }

  fillWindow(0);

  let guard = 0;
  while (queue.length && guard++ < 20000) {
    const ev = queue.shift();
    const now = ev.time;

    if (ev.kind === 'data-arrive') {
      if (protocol === 'gbn') {
        if (ev.seq === expected) {
          delivered.push(ev.seq);
          log.push({ time: now, who: 'receiver', text: `Receive pkt ${ev.seq} in order → deliver` });
          expected++;
          sendAck(now, expected - 1);
        } else {
          log.push({ time: now, who: 'receiver', text: `Receive pkt ${ev.seq} out of order → discard (expecting ${expected})` });
          if (expected > 0) sendAck(now, expected - 1);
        }
      } else {
        if (ev.seq >= rcvBase && ev.seq < rcvBase + window) {
          const dup = rcvBuffer.has(ev.seq);
          rcvBuffer.add(ev.seq);
          log.push({ time: now, who: 'receiver', text: dup ? `Receive duplicate pkt ${ev.seq}` : `Receive pkt ${ev.seq} → buffer` });
          sendAck(now, ev.seq);
          while (rcvBuffer.has(rcvBase)) {
            rcvBuffer.delete(rcvBase);
            delivered.push(rcvBase);
            log.push({ time: now, who: 'receiver', text: `Deliver pkt ${rcvBase}` });
            rcvBase++;
          }
        } else if (ev.seq < rcvBase) {
          log.push({ time: now, who: 'receiver', text: `Receive old pkt ${ev.seq} → re-ACK` });
          sendAck(now, ev.seq);
        }
      }
    } else if (ev.kind === 'ack-arrive') {
      if (protocol === 'gbn') {
        if (ev.seq >= base) {
          log.push({ time: now, who: 'sender', text: `ACK ${ev.seq} (cumulative) → window slides to ${ev.seq + 1}` });
          base = ev.seq + 1;
          if (base === next) gbnTimerToken++; // stop timer
          else startGbnTimer(now);
        } else {
          log.push({ time: now, who: 'sender', text: `Duplicate ACK ${ev.seq} ignored` });
        }
      } else if (!acked.has(ev.seq) && ev.seq >= base) {
        acked.add(ev.seq);
        srTimerToken.set(ev.seq, (srTimerToken.get(ev.seq) || 0) + 1); // stop its timer
        log.push({ time: now, who: 'sender', text: `ACK ${ev.seq} → mark acknowledged` });
        while (acked.has(base)) base++;
      }
      fillWindow(now);
    } else if (ev.kind === 'timeout') {
      if (protocol === 'gbn') {
        if (ev.token !== gbnTimerToken || base >= next) continue;
        log.push({ time: now, who: 'sender', text: `Timeout → resend pkts ${base}…${next - 1}` });
        let first = null;
        for (let s = base; s < next; s++) {
          const t = transmit(now, s);
          if (first === null) first = t;
        }
        startGbnTimer(first);
      } else {
        if (ev.token !== srTimerToken.get(ev.seq) || acked.has(ev.seq)) continue;
        log.push({ time: now, who: 'sender', text: `Timeout for pkt ${ev.seq} → resend only pkt ${ev.seq}` });
        const t = transmit(now, ev.seq);
        startSrTimer(ev.seq, t);
      }
    }

    if (base >= packets && finishedAt === null) finishedAt = now;
  }

  log.sort((a, b) => a.time - b.time);
  return {
    label: LABEL,
    protocol,
    params: { packets, window, delay, timeout, lostPackets, lostAcks },
    segments,
    log,
    delivered,
    summary: {
      transmissions,
      retransmissions,
      completionTime: finishedAt,
      efficiencyPct: Math.round((packets / transmissions) * 100),
      inOrder: delivered.every((s, i) => s === i) && delivered.length === packets,
    },
  };
}
