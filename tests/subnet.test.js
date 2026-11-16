import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseIPv4, toIPv4, parseCidr, maskToPrefix, contains, classify, splitSubnet, parseIPv6 } from '../extension/lib/subnet.js';

test('parse and format IPv4 round-trip', () => {
  assert.equal(toIPv4(parseIPv4('192.168.1.10')), '192.168.1.10');
  assert.equal(parseIPv4('255.255.255.255'), 4294967295);
  assert.throws(() => parseIPv4('256.1.1.1'));
  assert.throws(() => parseIPv4('1.2.3'));
});

test('/26 network facts', () => {
  const s = parseCidr('192.168.10.77/26');
  assert.equal(s.network, '192.168.10.64');
  assert.equal(s.broadcast, '192.168.10.127');
  assert.equal(s.mask, '255.255.255.192');
  assert.equal(s.wildcard, '0.0.0.63');
  assert.equal(s.firstHost, '192.168.10.65');
  assert.equal(s.lastHost, '192.168.10.126');
  assert.equal(s.hostCount, 62);
  assert.equal(s.classification.category, 'Private');
});

test('dotted mask input and edge prefixes', () => {
  assert.equal(parseCidr('10.0.0.1 255.255.0.0').prefix, 16);
  assert.equal(parseCidr('10.0.0.1/32').hostCount, 1);
  assert.equal(parseCidr('10.0.0.0/31').hostCount, 2);
  assert.equal(parseCidr('0.0.0.0/0').totalAddresses, 2 ** 32);
  assert.throws(() => maskToPrefix('255.0.255.0'));
});

test('contains and classify', () => {
  assert.ok(contains('172.16.0.0/12', '172.31.255.1'));
  assert.ok(!contains('172.16.0.0/12', '172.32.0.1'));
  assert.equal(classify('100.64.3.4').category, 'Carrier-grade NAT (shared)');
  assert.equal(classify('8.8.8.8').category, 'Public');
  assert.equal(classify('169.254.1.1').category, 'Link-local (APIPA)');
});

test('split /24 into /26', () => {
  const r = splitSubnet('192.168.1.0/24', 26);
  assert.equal(r.count, 4);
  assert.deepEqual(r.subnets.map(s => s.network), ['192.168.1.0', '192.168.1.64', '192.168.1.128', '192.168.1.192']);
});

test('documentation ranges (RFC 5737) are not "Public"', () => {
  for (const ip of ['192.0.2.5', '198.51.100.7', '203.0.113.10']) {
    const c = classify(ip);
    assert.equal(c.category, 'Documentation (TEST-NET)', ip);
    assert.equal(c.routable, false, ip);
    assert.equal(c.isPrivate, false, ip);
  }
  // neighbours just outside the ranges are still public
  assert.equal(classify('192.0.3.1').category, 'Public');
  assert.equal(classify('203.0.114.1').category, 'Public');
});

test('parse IPv6 with :: compression and embedded IPv4', () => {
  assert.deepEqual(parseIPv6('::'), [0, 0, 0, 0, 0, 0, 0, 0]);
  assert.deepEqual(parseIPv6('::1'), [0, 0, 0, 0, 0, 0, 0, 1]);
  assert.deepEqual(parseIPv6('2001:db8::8:800:200c:417a'), [0x2001, 0xdb8, 0, 0, 0x8, 0x800, 0x200c, 0x417a]);
  assert.deepEqual(parseIPv6('[fe80::1%eth0]'), [0xfe80, 0, 0, 0, 0, 0, 0, 1]); // brackets + zone id
  assert.deepEqual(parseIPv6('::ffff:192.168.1.1'), [0, 0, 0, 0, 0, 0xffff, 0xc0a8, 0x0101]);
});

test('IPv6 address types', () => {
  assert.equal(classify('::1').category, 'Loopback');
  assert.equal(classify('::').category, 'Unspecified');
  assert.equal(classify('fe80::1').category, 'Link-local');
  assert.equal(classify('FE80::abcd').category, 'Link-local'); // case does not matter
  assert.equal(classify('fd00::1').category, 'Unique local (ULA)');
  assert.equal(classify('fc12:3456::1').category, 'Unique local (ULA)');
  assert.equal(classify('ff02::1').category, 'Multicast');
  assert.equal(classify('2001:db8::1').category, 'Documentation');
  assert.equal(classify('2606:4700::1111').category, 'Public');
  assert.equal(classify('::ffff:192.168.1.1').category, 'IPv4-mapped (Private)');
});

test('IPv6 private / routable flags', () => {
  assert.equal(classify('fd00::1').isPrivate, true); // ULA is the IPv6 "private" range
  assert.equal(classify('2606:4700::1111').routable, true);
  assert.equal(classify('fe80::1').routable, false);
  assert.equal(classify('2606:4700::1111').rfc, null);
  assert.equal(classify('fd00::1').rfc, 'RFC 4193');
});

test('invalid IPv6 is rejected', () => {
  assert.throws(() => classify('fe80::zz'));
  assert.throws(() => classify('1:2:3:4:5:6:7:8:9'));
  assert.throws(() => classify('1::2::3'));
  assert.throws(() => classify('12345::1'));
});
