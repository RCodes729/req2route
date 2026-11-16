import { test, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { helper } from '../extension/lib/helper-client.js';

const realFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = realFetch; });

test('results from the helper are labelled Tested', async () => {
  globalThis.fetch = async () => new Response(JSON.stringify({ ok: true }), { status: 200 });
  const r = await helper.health();
  assert.equal(r.ok, true);
  assert.equal(r.label, 'Tested');
});

test('helper not running → "not reachable" message', async () => {
  globalThis.fetch = async () => { throw new TypeError('Failed to fetch'); };
  await assert.rejects(helper.health(), /not reachable/);
});

test('slow test → timeout message, not "not reachable"', async () => {
  globalThis.fetch = async () => { throw new DOMException('signal timed out', 'TimeoutError'); };
  await assert.rejects(helper.dns('example.com'), err => {
    assert.match(err.message, /took longer than 15 s/);
    assert.doesNotMatch(err.message, /not reachable/);
    return true;
  });
});

test('helper errors are passed through', async () => {
  globalThis.fetch = async () => new Response(JSON.stringify({ error: 'Invalid hostname' }), { status: 400 });
  await assert.rejects(helper.dns('bad host'), /Invalid hostname/);
});
