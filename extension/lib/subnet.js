// IPv4 / CIDR utilities used by the Network-layer tools and the ACL / NAT sandboxes.
// Pure functions, no browser APIs, so they run in both the extension and Node tests.

export function parseIPv4(str) {
  const parts = String(str).trim().split('.');
  if (parts.length !== 4) throw new Error(`Invalid IPv4 address: ${str}`);
  let n = 0;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) throw new Error(`Invalid IPv4 address: ${str}`);
    const v = Number(p);
    if (v > 255) throw new Error(`Invalid IPv4 address: ${str}`);
    n = n * 256 + v;
  }
  return n >>> 0;
}

export function toIPv4(n) {
  n >>>= 0;
  return [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}

export function isIPv4(str) {
  try { parseIPv4(str); return true; } catch { return false; }
}

export function prefixToMask(prefix) {
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) {
    throw new Error(`Invalid prefix length: ${prefix}`);
  }
  return prefix === 0 ? 0 : (0xFFFFFFFF << (32 - prefix)) >>> 0;
}

export function maskToPrefix(maskStr) {
  const mask = parseIPv4(maskStr);
  const inverted = (~mask) >>> 0;
  // A valid mask is a run of 1s followed by a run of 0s, so ~mask + 1 is a power of two.
  if (((inverted + 1) & inverted) !== 0) throw new Error(`Non-contiguous subnet mask: ${maskStr}`);
  let prefix = 0;
  for (let m = mask; m & 0x80000000; m = (m << 1) >>> 0) prefix++;
  return prefix;
}

/** Accepts "192.168.1.10/24" or "192.168.1.10 255.255.255.0". */
export function parseCidr(input) {
  const s = String(input).trim();
  let ipStr, prefix;
  if (s.includes('/')) {
    const [a, b] = s.split('/');
    ipStr = a;
    prefix = Number(b);
    if (!/^\d{1,2}$/.test(b)) throw new Error(`Invalid prefix length: ${b}`);
  } else if (/\s+/.test(s)) {
    const [a, b] = s.split(/\s+/);
    ipStr = a;
    prefix = maskToPrefix(b);
  } else {
    ipStr = s;
    prefix = 32;
  }
  const ip = parseIPv4(ipStr);
  const mask = prefixToMask(prefix);
  const network = (ip & mask) >>> 0;
  const broadcast = (network | (~mask >>> 0)) >>> 0;
  let firstHost, lastHost, hostCount;
  if (prefix === 32) { firstHost = lastHost = network; hostCount = 1; }
  else if (prefix === 31) { firstHost = network; lastHost = broadcast; hostCount = 2; } // RFC 3021 point-to-point
  else { firstHost = network + 1; lastHost = broadcast - 1; hostCount = 2 ** (32 - prefix) - 2; }

  return {
    input: s,
    ip: toIPv4(ip),
    prefix,
    mask: toIPv4(mask),
    wildcard: toIPv4(~mask >>> 0),
    network: toIPv4(network),
    broadcast: toIPv4(broadcast),
    firstHost: toIPv4(firstHost),
    lastHost: toIPv4(lastHost),
    hostCount,
    totalAddresses: 2 ** (32 - prefix),
    legacyClass: legacyClass(ip),
    classification: classify(toIPv4(ip)),
    binary: {
      ip: toBinary(ip),
      mask: toBinary(mask),
    },
  };
}

export function toBinary(n) {
  return toIPv4(n).split('.').map(o => Number(o).toString(2).padStart(8, '0')).join('.');
}

export function contains(cidr, ipStr) {
  const [netStr, p] = cidr.split('/');
  const prefix = p === undefined ? 32 : Number(p);
  const mask = prefixToMask(prefix);
  return ((parseIPv4(ipStr) & mask) >>> 0) === ((parseIPv4(netStr) & mask) >>> 0);
}

const SPECIAL_RANGES = [
  ['0.0.0.0/8', 'This network', 'RFC 791'],
  ['10.0.0.0/8', 'Private', 'RFC 1918'],
  ['100.64.0.0/10', 'Carrier-grade NAT (shared)', 'RFC 6598'],
  ['127.0.0.0/8', 'Loopback', 'RFC 1122'],
  ['169.254.0.0/16', 'Link-local (APIPA)', 'RFC 3927'],
  ['172.16.0.0/12', 'Private', 'RFC 1918'],
  ['192.0.2.0/24', 'Documentation (TEST-NET)', 'RFC 5737'],
  ['192.168.0.0/16', 'Private', 'RFC 1918'],
  ['198.51.100.0/24', 'Documentation (TEST-NET)', 'RFC 5737'],
  ['203.0.113.0/24', 'Documentation (TEST-NET)', 'RFC 5737'],
  ['224.0.0.0/4', 'Multicast', 'RFC 5771'],
  ['240.0.0.0/4', 'Reserved', 'RFC 1112'],
];

/**
 * Parse an IPv6 address into its eight 16-bit groups.
 * Handles "::" compression, [brackets], a %zone suffix and an embedded IPv4 tail (::ffff:1.2.3.4).
 */
export function parseIPv6(str) {
  const bad = () => new Error(`Invalid IPv6 address: ${str}`);
  let s = String(str).trim().toLowerCase().replace(/^\[|\]$/g, '');
  if (s.includes('%')) s = s.slice(0, s.indexOf('%'));
  if (s.includes('.')) { // embedded IPv4 in the last 32 bits
    const cut = s.lastIndexOf(':');
    let v4;
    try { v4 = parseIPv4(s.slice(cut + 1)); } catch { throw bad(); }
    s = `${s.slice(0, cut + 1)}${(v4 >>> 16).toString(16)}:${(v4 & 0xffff).toString(16)}`;
  }
  const halves = s.split('::');
  if (halves.length > 2) throw bad();
  const groups = part => (part === '' ? [] : part.split(':').map(h => {
    if (!/^[0-9a-f]{1,4}$/.test(h)) throw bad();
    return parseInt(h, 16);
  }));
  const head = groups(halves[0]);
  if (halves.length === 1) {
    if (head.length !== 8) throw bad();
    return head;
  }
  const tail = groups(halves[1]);
  if (head.length + tail.length > 7) throw bad(); // "::" must stand for at least one zero group
  return [...head, ...new Array(8 - head.length - tail.length).fill(0), ...tail];
}

export function isIPv6(str) {
  try { parseIPv6(str); return true; } catch { return false; }
}

function classifyIPv6(ipStr) {
  const g = parseIPv6(ipStr);
  const result = (category, rfc, range, { isPrivate = false, routable = false } = {}) => ({ category, rfc, range, isPrivate, routable });
  if (g.every(x => x === 0)) return result('Unspecified', 'RFC 4291', '::/128');
  if (g.slice(0, 7).every(x => x === 0) && g[7] === 1) return result('Loopback', 'RFC 4291', '::1/128');
  if (g.slice(0, 5).every(x => x === 0) && g[5] === 0xffff) {
    const inner = classify(toIPv4(((g[6] << 16) | g[7]) >>> 0));
    return { ...inner, category: `IPv4-mapped (${inner.category})`, range: '::ffff:0:0/96' };
  }
  if ((g[0] & 0xffc0) === 0xfe80) return result('Link-local', 'RFC 4291', 'fe80::/10');
  if ((g[0] & 0xfe00) === 0xfc00) return result('Unique local (ULA)', 'RFC 4193', 'fc00::/7', { isPrivate: true });
  if ((g[0] & 0xff00) === 0xff00) return result('Multicast', 'RFC 4291', 'ff00::/8');
  if (g[0] === 0x2001 && g[1] === 0x0db8) return result('Documentation', 'RFC 3849', '2001:db8::/32');
  if ((g[0] & 0xe000) === 0x2000) return { category: 'Public', rfc: null, isPrivate: false, routable: true };
  return result('Reserved', 'RFC 4291', null);
}

/** Classify an IPv4 or IPv6 address (anything containing ":" is treated as IPv6). */
export function classify(ipStr) {
  if (String(ipStr).includes(':')) return classifyIPv6(ipStr);
  if (ipStr === '255.255.255.255') {
    return { category: 'Limited broadcast', rfc: 'RFC 919', isPrivate: false, routable: false };
  }
  for (const [range, category, rfc] of SPECIAL_RANGES) {
    if (contains(range, ipStr)) {
      return {
        category, rfc, range,
        isPrivate: category === 'Private' || category.startsWith('Carrier'),
        routable: false,
      };
    }
  }
  return { category: 'Public', rfc: null, isPrivate: false, routable: true };
}

export function legacyClass(ipNum) {
  const first = ipNum >>> 24;
  if (first < 128) return 'A';
  if (first < 192) return 'B';
  if (first < 224) return 'C';
  if (first < 240) return 'D (multicast)';
  return 'E (reserved)';
}

/** Split a network into equal subnets of newPrefix (capped to 1024 results). */
export function splitSubnet(cidr, newPrefix) {
  const info = parseCidr(cidr);
  if (newPrefix < info.prefix || newPrefix > 32) {
    throw new Error(`New prefix must be between /${info.prefix} and /32`);
  }
  const count = 2 ** (newPrefix - info.prefix);
  const size = 2 ** (32 - newPrefix);
  const base = parseIPv4(info.network);
  const limit = Math.min(count, 1024);
  const subnets = [];
  for (let i = 0; i < limit; i++) {
    subnets.push(parseCidr(`${toIPv4(base + i * size)}/${newPrefix}`));
  }
  return { count, truncated: count > limit, subnets };
}
