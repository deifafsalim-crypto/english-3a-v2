/* Public verification primitives. The signing key never belongs in this file. */
(function (root, factory) {
  'use strict';
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.AtomicActivation = api;
})(globalThis, function () {
  'use strict';
  const scope = 'atomic-english-3a:browser-activation:v1:';

  function normalizeRequest(value) {
    if (typeof value !== 'string' || value.length > 100) return null;
    const text = value.trim().toUpperCase().replace(/\s/g, '');
    if (/^[0-9A-F]{32}$/.test(text)) return text;
    if (/^A3-(?:[0-9A-F]{8}-){3}[0-9A-F]{8}$/.test(text)) return text.slice(3).replace(/-/g, '');
    return null;
  }

  function formatRequest(value) {
    const id = normalizeRequest(value);
    if (!id) throw new Error('Invalid request ID');
    return 'A3-' + id.match(/.{8}/g).join('-');
  }

  function newRequest() {
    return Array.from(crypto.getRandomValues(new Uint8Array(16)), byte => byte.toString(16).padStart(2, '0')).join('').toUpperCase();
  }

  function payload(value) {
    const id = normalizeRequest(value);
    if (!id) throw new Error('Invalid request ID');
    return new TextEncoder().encode(scope + id);
  }

  function encode(bytes) {
    return btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function token(value, signature) {
    const id = normalizeRequest(value);
    if (!id || signature.byteLength !== 64) throw new Error('Invalid activation signature');
    return 'AT3.' + id + '.' + encode(signature);
  }

  function parseToken(value) {
    if (typeof value !== 'string' || value.length > 512) return null;
    const text = value.replace(/\s/g, '');
    const match = /^AT3\.([0-9A-F]{32})\.([A-Za-z0-9_-]{86})$/.exec(text);
    if (!match) return null;
    try {
      const signature = Uint8Array.from(atob(match[2].replace(/-/g, '+').replace(/_/g, '/') + '=='), char => char.charCodeAt(0));
      if (signature.length !== 64 || encode(signature) !== match[2]) return null;
      return { request: match[1], signature, text };
    } catch (_) { return null; }
  }

  async function verify(value, request, publicJwk) {
    const parsed = parseToken(value);
    const id = normalizeRequest(request);
    if (!parsed || !id || parsed.request !== id) return false;
    const key = await crypto.subtle.importKey('jwk', publicJwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    return crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, parsed.signature, payload(id));
  }

  return Object.freeze({ normalizeRequest, formatRequest, newRequest, payload, token, parseToken, verify });
});
