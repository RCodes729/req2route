import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseIPv4, toIPv4, parseCidr, maskToPrefix, contains, classify, splitSubnet } from '../extension/lib/subnet.js';

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
