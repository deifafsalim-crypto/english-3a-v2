# Offline browser activation

The main `index.html` entry point starts locked. `activation.js` creates a random 128-bit request identifier in `atomic3a-browser-activation-v1`, sends it to the owner's WhatsApp number, and checks an app-scoped ECDSA P-256 signature before rendering the course. Saved tokens are verified again on every load. Different origins, profiles, private sessions, or cleared site data produce separate requests.

The public verifier is `activation-public-key.js`. Never publish a plaintext signing key or an owner password. The owner retains a self-contained offline HTML issuer outside the publication checkout. Keep its private signing key and backups private. Retain that same key when updating either issuer; replacing it invalidates previous codes.

## Hosted owner tool

`owner.html` provides the password-protected code issuer. `issuer-vault.js` contains only an encrypted PKCS#8 signing key: AES-256-GCM with a random 96-bit IV, PBKDF2-SHA-256 with a random 128-bit salt and 600,000 iterations, and a fixed authenticated application context. The generated password has 192 bits of randomness and is retained only in the owner's private files. Encryption and unwrapping follow the [Web Crypto key-wrapping API](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/wrapKey).

`owner.js` unwraps a nonextractable signing CryptoKey in browser memory and checks it against the existing verifier. It does not send passwords to a server or persist passwords/keys in localStorage or sessionStorage. Explicit logout, page exit, refresh, or ten minutes of inactivity lock the issuer. Operation counters prevent an in-progress unlock or signing operation from displaying output after logout. The owner page has a restrictive CSP and uses no third-party scripts.

The ciphertext is publicly downloadable; security depends on retaining a strong private password. Do not replace this with a frontend password comparison or publish plaintext owner files. The original offline issuer and the encrypted recovery tool remain compatible with the same platform verifier.

This is a static-site deterrent. It does not provide server-enforced authorization, prevent source downloads, prevent deliberate transplantation of localStorage, maintain a global spent-code ledger, or support remote revocation. A code is scoped to its request and is checked again on subsequent visits to that browser. Do not describe this as complete content protection or strict one-time redemption.

## Checks

- `node --test tests/activation.test.cjs` checks real signatures, browser request matching, malformed input, tampering, and application scope using disposable test keys.
- `python tests/activation_browser.py` exercises the actual browser and the local offline issuer. It expects Chrome and Python `websocket-client` on Windows, plus the owner's issuer at `../private-activation/إصدار-أكواد-الدخول.html`. The integration test does not read or log signing secrets.
- `node --test tests/issuer.test.cjs` checks encrypted-key recovery, wrong passwords, tampering, nonextractability, and compatibility with activation signatures using disposable keys.
- Set `ACTIVATION_HOSTED_ISSUER=1` when running `tests/activation_browser.py` to exercise the hosted tool and its encrypted offline recovery file. The integration test reads the locally generated password without logging it, checks logout/refresh/idle locking and pending-operation cancellation, and verifies issuance into the actual platform.

The original copyright dialog appears after successful activation. Locked content stays hidden for direct hash routes and printing.
