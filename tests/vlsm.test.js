import { test } from 'node:test';
import assert from 'node:assert/strict';
import { planVlsm, prefixForHosts, parseRequirements } from '../extension/lib/vlsm.js';

test('prefix sizing includes network and broadcast', () => {
  assert.equal(prefixForHosts(2), 30);
  assert.equal(prefixForHosts(30), 27);
  assert.equal(prefixForHosts(31), 26);
  assert.equal(prefixForHosts(62), 26);
  assert.equal(prefixForHosts(254), 24);
});

test('classic textbook plan, largest first, aligned', () => {
  const r = planVlsm('192.168.1.0/24', [
    { name: 'WAN', hosts: 2 },
    { name: 'Sales', hosts: 50 },
    { name: 'HR', hosts: 10 },
    { name: 'IT', hosts: 25 },
  ]);
  assert.deepEqual(r.allocations.map(a => `${a.name} ${a.network}/${a.prefix}`), [
    'Sales 192.168.1.0/26',
    'IT 192.168.1.64/27',
    'HR 192.168.1.96/28',
    'WAN 192.168.1.112/30',
  ]);
  assert.equal(r.allocations[0].wasted, 12);
  assert.equal(r.nextFree, '192.168.1.116');
  assert.equal(r.freeAddresses, 256 - 116);
});

test('out of space is reported clearly', () => {
  assert.throws(() => planVlsm('10.0.0.0/26', [{ name: 'A', hosts: 30 }, { name: 'B', hosts: 30 }, { name: 'C', hosts: 30 }]), /Out of space: "C"/);
  assert.throws(() => planVlsm('10.0.0.0/28', [{ name: 'Big', hosts: 100 }]), /larger than the whole/);
});

test('parse requirement lines', () => {
  assert.deepEqual(parseRequirements('Sales 50\nHR: 10\n\nGuest Wi-Fi = 100'), [
    { name: 'Sales', hosts: 50 }, { name: 'HR', hosts: 10 }, { name: 'Guest Wi-Fi', hosts: 100 },
  ]);
  assert.throws(() => parseRequirements('Sales lots'));
});
