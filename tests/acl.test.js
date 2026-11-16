import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseAcl, parseAclLine, evaluateAcl, natTranslate } from '../extension/lib/acl.js';

const RULES = parseAcl(`
! sample ACL
permit tcp 10.0.0.0/8 any eq 443
deny tcp any any eq 23
permit udp any host 8.8.8.8 eq 53
deny ip 192.168.50.0/24 any
permit tcp any any range 8000 8100
`);

test('first match wins', () => {
  const r = evaluateAcl(RULES, { proto: 'tcp', src: '10.1.2.3', dst: '1.1.1.1', dstPort: 443 });
  assert.equal(r.action, 'permit');
  assert.equal(r.matchedIndex, 0);
});

test('host keyword and port ranges', () => {
  assert.equal(evaluateAcl(RULES, { proto: 'udp', src: '172.16.0.9', dst: '8.8.8.8', dstPort: 53 }).action, 'permit');
  assert.equal(evaluateAcl(RULES, { proto: 'udp', src: '172.16.0.9', dst: '8.8.4.4', dstPort: 53 }).implicit, true);
  assert.equal(evaluateAcl(RULES, { proto: 'tcp', src: '1.2.3.4', dst: '5.6.7.8', dstPort: 8050 }).matchedIndex, 4);
});

test('implicit deny when nothing matches', () => {
  const r = evaluateAcl(RULES, { proto: 'tcp', src: '1.2.3.4', dst: '5.6.7.8', dstPort: 80 });
  assert.equal(r.action, 'deny');
  assert.equal(r.implicit, true);
  assert.equal(r.trace.length, RULES.length);
});

test('bad rules are rejected with a message', () => {
  assert.throws(() => parseAclLine('allow tcp any any'), /permit\/deny/);
  assert.throws(() => parseAclLine('permit tcp nowhere any'), /Bad address/);
});

test('PAT maps each private socket to a unique public port', () => {
  const r = natTranslate([
    { src: '192.168.1.10', srcPort: 51000, dst: '93.184.215.14', dstPort: 443 },
    { src: '192.168.1.11', srcPort: 51000, dst: '93.184.215.14', dstPort: 443 },
    { src: '192.168.1.10', srcPort: 51000, dst: '8.8.8.8', dstPort: 53 },
    { src: '8.8.8.8', srcPort: 53, dst: '1.1.1.1', dstPort: 53 },
  ]);
  assert.equal(r.table[0].insideGlobal, '203.0.113.10:50000');
  assert.equal(r.table[1].insideGlobal, '203.0.113.10:50001');
  assert.equal(r.table[2].insideGlobal, '203.0.113.10:50000'); // same inside socket reuses mapping
  assert.equal(r.table[3].translated, false);
});
