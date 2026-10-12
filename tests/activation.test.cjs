const { test } = require('node:test');
const assert = require('node:assert/strict');
const { webcrypto } = require('node:crypto');
const activation = require('../activation-core.js');

async function fixture() {
  const keys = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const publicKey = await webcrypto.subtle.exportKey('jwk', keys.publicKey);
  const request = activation.newRequest();
  async function issue(id = request, payload = activation.payload(id)) {
    const signature = await webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, keys.privateKey, payload);
    return activation.token(id, signature);
  }
  return { request, publicKey, issue };
}

test('request IDs are random 128-bit values and the displayed form round-trips', () => {
  const ids = new Set(Array.from({ length: 100 }, () => activation.newRequest()));
  assert.equal(ids.size, 100);
  for (const id of ids) {
    assert.match(id, /^[0-9A-F]{32}$/);
    assert.equal(activation.normalizeRequest(activation.formatRequest(id)), id);
    assert.equal(activation.normalizeRequest(activation.formatRequest(id).toLowerCase()), id);
  }
  for (const invalid of ['', 'A3-1234', 'G'.repeat(32), '<script>', null, 'A3-' + 'A'.repeat(31)]) {
    assert.equal(activation.normalizeRequest(invalid), null);
  }
});

test('a genuine code activates only its matching request', async () => {
  const { request, publicKey, issue } = await fixture();
  const code = await issue();
  assert.equal(await activation.verify(code, request, publicKey), true);
  assert.equal(await activation.verify('  ' + code.slice(0, 50) + '\n' + code.slice(50) + ' ', request, publicKey), true);
  assert.equal(await activation.verify(code, activation.newRequest(), publicKey), false);
});

test('changing either a request ID or a signature invalidates the code', async () => {
  const { request, publicKey, issue } = await fixture();
  const code = await issue();
  const other = activation.newRequest();
  assert.equal(await activation.verify(code.replace(request, other), other, publicKey), false);
  const parts = code.split('.');
  parts[2] = (parts[2][0] === 'A' ? 'B' : 'A') + parts[2].slice(1);
  assert.equal(await activation.verify(parts.join('.'), request, publicKey), false);
});

test('tokens signed for another application or issuer are rejected', async () => {
  const { request, publicKey, issue } = await fixture();
  const wrongScope = await issue(request, new TextEncoder().encode('other-app:' + request));
  assert.equal(await activation.verify(wrongScope, request, publicKey), false);
  const other = await fixture();
  const wrongIssuer = await other.issue(request);
  assert.equal(await activation.verify(wrongIssuer, request, publicKey), false);
});

test('malformed tokens and requests never activate', async () => {
  const { request, publicKey } = await fixture();
  for (const code of ['', 'yes', 'AT3.' + request, 'AT3.' + request + '.' + 'A'.repeat(85), 'AT3.' + request + '.' + 'A'.repeat(10000), null, {}, '<script>']) {
    assert.equal(await activation.verify(code, request, publicKey), false);
  }
  assert.equal(activation.parseToken('AT3.' + request + '.' + 'A'.repeat(85) + 'B'), null, 'noncanonical signature encoding rejected');
  assert.equal(await activation.verify('yes', 'invalid-request', publicKey), false);
});
