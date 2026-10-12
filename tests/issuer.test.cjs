const { test } = require('node:test');
const assert = require('node:assert/strict');
const { webcrypto } = require('node:crypto');
const issuer = require('../issuer-crypto.js');
const activation = require('../activation-core.js');
const password = 'disposable-test-password-not-a-production-secret';

async function fixture() {
  const keys = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const privateJwk = await webcrypto.subtle.exportKey('jwk', keys.privateKey);
  const publicJwk = await webcrypto.subtle.exportKey('jwk', keys.publicKey);
  const vault = await issuer.seal(privateJwk, password);
  return { privateJwk, publicJwk, vault };
}

test('encrypted issuer unwraps a nonextractable key and produces compatible activation codes', async () => {
  const { privateJwk, publicJwk, vault } = await fixture();
  const serialized = JSON.stringify(vault);
  assert.ok(!serialized.includes(password));
  assert.ok(!serialized.includes(privateJwk.d));
  const key = await issuer.unlock(vault, password);
  assert.equal(key.extractable, false);
  assert.deepEqual(key.usages, ['sign']);
  await assert.rejects(webcrypto.subtle.exportKey('jwk', key));
  const request = activation.newRequest();
  const signature = await webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, activation.payload(request));
  assert.equal(await activation.verify(activation.token(request, signature), request, publicJwk), true);
});

test('a wrong password does not recover the signing key', async () => {
  const { vault } = await fixture();
  await assert.rejects(issuer.unlock(vault, 'a-completely-different-password'));
});

test('tampering with ciphertext, salt or IV is rejected', async () => {
  const { vault } = await fixture();
  for (const name of ['ciphertext', 'salt', 'iv']) {
    const changed = { ...vault, [name]: (vault[name][0] === 'A' ? 'B' : 'A') + vault[name].slice(1) };
    await assert.rejects(issuer.unlock(changed, password));
  }
});

test('invalid vault parameters and weak passwords cannot create or unlock a vault', async () => {
  const { vault, privateJwk } = await fixture();
  for (const changed of [{ ...vault, version: 2 }, { ...vault, iterations: 1 }, { ...vault, kdf: 'plain' }, { ...vault, ciphertext: '<script>' }, { ...vault, iv: '' }, null]) {
    await assert.rejects(issuer.unlock(changed, password));
  }
  await assert.rejects(issuer.seal(privateJwk, 'short'));
});

test('sealing the same key and password uses fresh encryption randomness', async () => {
  const { vault, privateJwk } = await fixture();
  const other = await issuer.seal(privateJwk, password);
  assert.notEqual(vault.salt, other.salt);
  assert.notEqual(vault.iv, other.iv);
  assert.notEqual(vault.ciphertext, other.ciphertext);
});
