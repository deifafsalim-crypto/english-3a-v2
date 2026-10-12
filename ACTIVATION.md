# Offline browser activation

The main `index.html` entry point starts locked. `activation.js` creates a random 128-bit request identifier in `atomic3a-browser-activation-v1`, sends it to the owner's WhatsApp number, and checks an app-scoped ECDSA P-256 signature before rendering the course. Saved tokens are verified again on every load. Different origins, profiles, private sessions, or cleared site data produce separate requests.

The public verifier is `activation-public-key.js`. Only a public key belongs in this repository. The owner has a self-contained offline HTML issuer outside the publication checkout. Keep its private signing key and backups private. Retain that same key when updating the issuer; replacing it invalidates previous codes.

This is a static-site deterrent. It does not provide server-enforced authorization, prevent source downloads, prevent deliberate transplantation of localStorage, maintain a global spent-code ledger, or support remote revocation. A code is scoped to its request and is checked again on subsequent visits to that browser. Do not describe this as complete content protection or strict one-time redemption.

## Checks

- `node --test tests/activation.test.cjs` checks real signatures, browser request matching, malformed input, tampering, and application scope using disposable test keys.
- `python tests/activation_browser.py` exercises the actual browser and the local offline issuer. It expects Chrome and Python `websocket-client` on Windows, plus the owner's issuer at `../private-activation/إصدار-أكواد-الدخول.html`. The integration test does not read or log signing secrets.

The original copyright dialog appears after successful activation. Locked content stays hidden for direct hash routes and printing.
