// Network-layer tool: VLSM (variable-length subnet mask) planner.
// Allocates the largest subnets first so every block stays aligned.
import { parseCidr, parseIPv4, toIPv4 } from './subnet.js';

export const LABEL = 'Calculated';

/** Smallest prefix whose block fits `hosts` usable addresses (+ network + broadcast). */
export function prefixForHosts(hosts) {
  if (!Number.isInteger(hosts) || hosts < 1) throw new Error('Host count must be a whole number ≥ 1');
  const needed = hosts + 2;
  const bits = Math.ceil(Math.log2(needed));
  if (bits > 32) throw new Error(`Too many hosts: ${hosts}`);
  return 32 - bits;
}

/**
 * plan('192.168.1.0/24', [{ name: 'Sales', hosts: 50 }, ...])
 */
export function planVlsm(baseCidr, requirements) {
  const block = parseCidr(baseCidr);
  if (!requirements.length) throw new Error('Add at least one subnet requirement');
  const start = parseIPv4(block.network);
  const end = start + block.totalAddresses; // exclusive

  const sorted = requirements
    .map((r, i) => ({ ...r, hosts: Number(r.hosts), order: i }))
    .sort((a, b) => b.hosts - a.hosts || a.order - b.order);

  let cursor = start;
  const allocations = [];
  for (const req of sorted) {
    const prefix = prefixForHosts(req.hosts);
    if (prefix < block.prefix) {
      throw new Error(`"${req.name}" needs a /${prefix}, larger than the whole ${block.network}/${block.prefix}`);
    }
    const size = 2 ** (32 - prefix);
    if (cursor + size > end) {
      throw new Error(`Out of space: "${req.name}" (${req.hosts} hosts, /${prefix}) does not fit in ${block.network}/${block.prefix}`);
    }
    const info = parseCidr(`${toIPv4(cursor)}/${prefix}`);
    allocations.push({
      name: req.name,
      requestedHosts: req.hosts,
      ...info,
      wasted: info.hostCount - req.hosts,
    });
    cursor += size;
  }

  const used = cursor - start;
  return {
    label: LABEL,
    base: `${block.network}/${block.prefix}`,
    allocations,
    usedAddresses: used,
    freeAddresses: block.totalAddresses - used,
    nextFree: cursor < end ? toIPv4(cursor) : null,
    utilisationPct: Math.round((allocations.reduce((s, a) => s + a.requestedHosts, 0) / block.totalAddresses) * 100),
  };
}

/** Parse lines like "Sales 50" or "Sales: 50" into requirements. */
export function parseRequirements(text) {
  return text.split('\n').map(l => l.trim()).filter(Boolean).map(line => {
    const m = line.match(/^(.*?)[\s:=,]+(\d+)$/);
    if (!m) throw new Error(`Write each line as "Name hosts", got: "${line}"`);
    return { name: m[1].trim() || 'Subnet', hosts: Number(m[2]) };
  });
}
