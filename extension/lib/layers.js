// Observe → Explain: turn one HAR entry (from chrome.devtools.network) into a layer-by-layer view.
// Every value produced here comes from the browser, so it is labelled "Observed".
import { classify, isIPv4 } from './subnet.js';

export const LABEL = 'Observed';

const KEY_HEADERS = ['content-type', 'content-encoding', 'cache-control', 'server', 'alt-svc', 'strict-transport-security', 'location'];

// HAR uses -1 for "not applicable / reused".
const ms = v => (typeof v === 'number' && v >= 0 ? Math.round(v * 10) / 10 : null);

function pickHeaders(headers = []) {
  const out = {};
  for (const h of headers) {
    const n = h.name.toLowerCase();
    if (KEY_HEADERS.includes(n)) out[n] = h.value;
  }
  return out;
}

function statusClass(code) {
  if (!code) return 'No response (blocked, failed or cached in memory)';
  if (code < 200) return '1xx Informational';
  if (code < 300) return '2xx Success';
  if (code < 400) return '3xx Redirection';
  if (code < 500) return '4xx Client error';
  return '5xx Server error';
}

export function detectHttpVersion(entry) {
  const v = (entry.response?.httpVersion || entry.request?.httpVersion || '').toLowerCase();
  if (v.includes('h3') || v.includes('http/3')) return 'HTTP/3';
  if (v.includes('h2') || v.includes('http/2')) return 'HTTP/2';
  if (v.includes('1.0')) return 'HTTP/1.0';
  if (v.includes('1.1')) return 'HTTP/1.1';
  return v || 'unknown';
}

export function explainEntry(entry) {
  const url = new URL(entry.request.url);
  const t = entry.timings || {};
  const secure = url.protocol === 'https:' || url.protocol === 'wss:';
  const port = url.port ? Number(url.port) : (secure ? 443 : 80);
  const httpVersion = detectHttpVersion(entry);
  const isQuic = httpVersion === 'HTTP/3';
  const ip = (entry.serverIPAddress || '').replace(/^\[|\]$/g, '');
  const ipVersion = !ip ? null : (ip.includes(':') ? 'IPv6' : 'IPv4');

  const dnsMs = ms(t.dns);
  const connectMs = ms(t.connect); // per HAR spec, includes ssl
  const sslMs = ms(t.ssl);
  const tcpOnlyMs = connectMs !== null ? ms(Math.max(0, connectMs - (sslMs ?? 0))) : null;
  const reused = connectMs === null || connectMs === 0;

  const timeline = [
    { phase: 'Queued / blocked', ms: ms(t.blocked), layer: 'browser' },
    { phase: 'DNS lookup', ms: dnsMs, layer: 'application' },
    { phase: isQuic ? 'QUIC handshake' : 'TCP handshake', ms: tcpOnlyMs, layer: 'transport' },
    { phase: 'TLS handshake', ms: sslMs, layer: 'transport' },
    { phase: 'Request sent', ms: ms(t.send), layer: 'application' },
    { phase: 'Waiting (TTFB)', ms: ms(t.wait), layer: 'application' },
    { phase: 'Content download', ms: ms(t.receive), layer: 'application' },
  ].filter(p => p.ms !== null && p.ms > 0);

  return {
    label: LABEL,
    url: entry.request.url,
    host: url.hostname,
    totalMs: ms(entry.time),
    application: {
      protocol: secure ? 'HTTPS' : 'HTTP',
      httpVersion,
      method: entry.request.method,
      status: entry.response?.status ?? 0,
      statusText: entry.response?.statusText ?? '',
      statusClass: statusClass(entry.response?.status),
      mimeType: entry.response?.content?.mimeType ?? '',
      headers: pickHeaders(entry.response?.headers),
      dns: {
        host: url.hostname,
        timeMs: dnsMs,
        note: dnsMs === null
          ? 'No DNS time: the answer was cached, or the connection was reused.'
          : `Resolver answered in ${dnsMs} ms. Full records (A/AAAA/CNAME, TTL) need the helper's DNS test.`,
      },
    },
    transport: {
      protocol: isQuic ? 'UDP (QUIC)' : 'TCP',
      serverPort: port,
      connectionId: entry.connection ?? null,
      reused,
      handshakeMs: tcpOnlyMs,
      tlsMs: sslMs,
      tls: secure,
      note: reused
        ? 'Existing connection reused: no new handshake was needed (keep-alive / HTTP/2 multiplexing).'
        : isQuic
          ? 'New QUIC connection over UDP: transport and TLS 1.3 handshakes are combined.'
          : `New TCP connection (SYN, SYN-ACK, ACK) to port ${port}${secure ? ', followed by a TLS handshake' : ''}.`,
    },
    network: {
      serverIp: ip || null,
      ipVersion,
      classification: ip && isIPv4(ip) ? classify(ip) : null,
      note: ip
        ? `Packets were routed to ${ip}. Your machine's private address is usually translated by NAT on the router.`
        : 'Server IP not reported (served from cache or a service worker).',
    },
    link: {
      visible: false,
      note: 'The browser cannot see MAC addresses or ARP. Run the helper ARP test to see your local gateway mapping.',
    },
    timeline,
  };
}

export function summarizePage(entries) {
  const hosts = new Set();
  const ips = new Set();
  const connections = new Set();
  const protocols = {};
  const statuses = {};
  let dnsLookups = 0;
  let newConnections = 0;
  let bytes = 0;

  for (const e of entries) {
    try { hosts.add(new URL(e.request.url).hostname); } catch { /* data: urls etc. */ }
    if (e.serverIPAddress) ips.add(e.serverIPAddress);
    if (e.connection) connections.add(e.connection);
    const v = detectHttpVersion(e);
    protocols[v] = (protocols[v] || 0) + 1;
    const s = e.response?.status ?? 0;
    const bucket = s ? `${Math.floor(s / 100)}xx` : 'failed';
    statuses[bucket] = (statuses[bucket] || 0) + 1;
    if (ms(e.timings?.dns)) dnsLookups++;
    if (ms(e.timings?.connect)) newConnections++;
    const size = e.response?._transferSize ?? e.response?.bodySize ?? 0;
    if (size > 0) bytes += size;
  }

  return {
    label: LABEL,
    requests: entries.length,
    uniqueHosts: hosts.size,
    uniqueServerIps: ips.size,
    connectionsSeen: connections.size,
    newConnections,
    dnsLookups,
    bytesTransferred: bytes,
    protocols,
    statuses,
  };
}
