/* Password-encrypted owner key. No plaintext password or signing key belongs here. */
(function (root, factory) {
  'use strict';
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.AtomicIssuerCrypto = api;
})(globalThis, function () {
  'use strict';
  const ITERATIONS = 600000;
  const CONTEXT = new TextEncoder().encode('atomic-english-3a:password-encrypted-issuer:v1');
  const algorithm = { name: 'ECDSA', namedCurve: 'P-256' };

  function encode(value) {
    return btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function decode(value) {
    if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{1,2048}$/.test(value)) throw new Error('Invalid encrypted key');
    const padded = value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4);
    const bytes = Uint8Array.from(atob(padded), char => char.charCodeAt(0));
    if (encode(bytes) !== value) throw new Error('Invalid encrypted key encoding');
    return bytes;
  }

  async function wrappingKey(password, salt) {
    if (typeof password !== 'string' || password.length < 16 || password.length > 256) throw new Error('A strong password is required');
    const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: ITERATIONS, hash: 'SHA-256' },
      base, { name: 'AES-GCM', length: 256 }, false, ['wrapKey', 'unwrapKey']
    );
  }

  async function seal(privateJwk, password) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const wrapping = await wrappingKey(password, salt);
    const signing = await crypto.subtle.importKey('jwk', privateJwk, algorithm, true, ['sign']);
    const ciphertext = await crypto.subtle.wrapKey('pkcs8', signing, wrapping, { name: 'AES-GCM', iv, additionalData: CONTEXT, tagLength: 128 });
    return { version: 1, kdf: 'PBKDF2-SHA256', iterations: ITERATIONS, salt: encode(salt), iv: encode(iv), ciphertext: encode(ciphertext) };
  }

  async function unlock(vault, password) {
    if (!vault || vault.version !== 1 || vault.kdf !== 'PBKDF2-SHA256' || vault.iterations !== ITERATIONS) throw new Error('Unsupported encrypted key');
    const salt = decode(vault.salt);
    const iv = decode(vault.iv);
    const ciphertext = decode(vault.ciphertext);
    if (salt.length !== 16 || iv.length !== 12 || ciphertext.length < 32 || ciphertext.length > 1024) throw new Error('Invalid encrypted key');
    const wrapping = await wrappingKey(password, salt);
    return crypto.subtle.unwrapKey('pkcs8', ciphertext, wrapping, { name: 'AES-GCM', iv, additionalData: CONTEXT, tagLength: 128 }, algorithm, false, ['sign']);
  }

  return Object.freeze({ seal, unlock });
});
