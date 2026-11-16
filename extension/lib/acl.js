// Network-layer sandbox: ACL first-match evaluation and NAT/PAT translation.
import { contains, isIPv4, parseIPv4, classify, maskToPrefix, toIPv4 } from './subnet.js';

export const LABEL = 'Simulated';
const PORT_NAMES = { ftp: 21, ssh: 22, telnet: 23, smtp: 25, domain: 53, www: 80, http: 80, pop3: 110, https: 443 };
// Cisco wildcard mask -> prefix length (0.0.0.255 -> 24). Returns null if tok is not a valid wildcard.
function wildcardToPrefix(tok) {
  if (!tok || !isIPv4(tok)) return null;
  try { return maskToPrefix(toIPv4(~parseIPv4(tok) >>> 0)); } catch { return null; }
}
function matchAddr(spec, ip) {
  if (!spec || spec === 'any') return true;
  if (spec.startsWith('host ')) return parseIPv4(spec.slice(5)) === parseIPv4(ip);
  if (spec.includes('/')) return contains(spec, ip);
  return parseIPv4(spec) === parseIPv4(ip);
}

function matchPort(spec, port) {
  if (spec === undefined || spec === null || spec === 'any') return true;
  if (port === undefined || port === null) return false;
  if (Array.isArray(spec)) return port >= spec[0] && port <= spec[1];
  return Number(spec) === Number(port);
}

function matchProto(spec, proto) {
  if (!spec || spec === 'ip' || spec === 'any') return true;
  return spec === proto;
}

/**
 * Parse one rule line, e.g.
 *   permit tcp 10.0.0.0/8 any eq 443
 *   deny udp any 192.168.1.0/24 range 1000 2000
 *   deny ip host 10.0.0.5 any
 */
export function parseAclLine(line) {
  const tokens = line.trim().split(/\s+/);
  const rule = { raw: line.trim() };
  let i = 0;
  rule.action = tokens[i++];
  if (!['permit', 'deny'].includes(rule.action)) throw new Error(`Rule must start with permit/deny: "${line}"`);
  rule.proto = tokens[i++];
  if (!['ip', 'tcp', 'udp', 'icmp'].includes(rule.proto)) throw new Error(`Unknown protocol in: "${line}"`);
  const readAddr = () => {
    const t = tokens[i++];
    if (t === 'host') return `host ${tokens[i++]}`;
    if (t === 'any') return 'any';
      if (t && t.includes('/')) return t;
    if (t && isIPv4(t)) {
      const prefix = wildcardToPrefix(tokens[i]);
      if (prefix !== null) { i++; return `${t}/${prefix}`; }
      return t;
    }
    throw new Error(`Bad address "${t}" in: "${line}"`);
  };

  const readPort = t => {
    if (t in PORT_NAMES) return PORT_NAMES[t];
    if (/^\d+$/.test(t) && Number(t) <= 65535) return Number(t);
    throw new Error(`Bad port "${t}" in: "${line}"`);
  };

  rule.src = readAddr();
  rule.dst = readAddr();
   if (tokens[i] === 'eq') { rule.dstPort = readPort(tokens[i + 1]); i += 2; }
  else if (tokens[i] === 'range') { rule.dstPort = [readPort(tokens[i + 1]), readPort(tokens[i + 2])]; i += 3; }
  if (i < tokens.length) throw new Error(`Unexpected "${tokens.slice(i).join(' ')}" in: "${line}"`);
  return rule;
}

export function parseAcl(text) {
  return text.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('!') && !l.startsWith('#')).map(parseAclLine);
}

/** First-match evaluation with an implicit "deny any" at the end, like Cisco ACLs. */
export function evaluateAcl(rules, packet) {
  const trace = [];
  for (let idx = 0; idx < rules.length; idx++) {
    const r = rules[idx];
    const checks = {
      proto: matchProto(r.proto, packet.proto),
      src: matchAddr(r.src, packet.src),
      dst: matchAddr(r.dst, packet.dst),
      port: matchPort(r.dstPort, packet.dstPort),
    };
    const matched = Object.values(checks).every(Boolean);
    trace.push({ index: idx, rule: r.raw ?? r, matched, checks });
    if (matched) return { label: LABEL, action: r.action, matchedIndex: idx, implicit: false, trace };
  }
  return { label: LABEL, action: 'deny', matchedIndex: -1, implicit: true, trace };
}

/**
 * PAT (NAT overload): translate outbound private flows to one public IP.
 * Returns a new table so the UI can show before/after.
 */
export function natTranslate(flows, { publicIp = '203.0.113.10', startPort = 50000 } = {}) {
  let nextPort = startPort;
  const table = [];
  const seen = new Map();
  for (const f of flows) {
    const key = `${f.src}:${f.srcPort}`;
    const needsNat = classify(f.src).isPrivate;
    if (!needsNat) {
      table.push({ ...f, translated: false, note: 'Source already public — no translation' });
      continue;
    }
     if (!seen.has(key)) {
      if (nextPort > 65535) throw new Error(`Out of public ports: PAT pool exhausted at ${publicIp}:65535`);
      seen.set(key, nextPort++);
    }
    table.push({
      ...f,
      translated: true,
      insideLocal: key,
      insideGlobal: `${publicIp}:${seen.get(key)}`,
      outside: `${f.dst}:${f.dstPort}`,
    });
  }
  return { label: LABEL, publicIp, table };
}