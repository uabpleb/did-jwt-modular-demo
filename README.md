# did-jwt multi-algorithm demo (POC)

Two pages served by one Vite app:

- **`/` (index.html) — the unified composite demo.** ONE `CompositeSigner` and ONE
  `CompositeVerifier` serve three algorithm modules at once: **EdDSA** (did-jwt's
  built-in `SoftwareSigner`/`SoftwareVerifier`, `did:jwk`), **EIP712**
  ([`did-jwt-eip712-signer`](../did-jwt-eip712-signer), in-page Ethereum wallet,
  `did:ethr` via a network-free local resolver), and **WebAuthn**
  ([`did-jwt-webauthn-signer`](../did-jwt-webauthn-signer), passkey, `did:jwk`).
  Every `createJWT`/`verifyJWT` call uses the same two instances — only `alg`
  changes. Includes a software-only negative control (drop the modules and the
  external algs stop verifying), an `expectedDomain` policy rejection for EIP-712,
  and a tamper check per algorithm.
- **`/passkey.html` — the WebAuthn deep dive.** The original passkey walkthrough
  (register → sign → verify → present → replay → tamper), unchanged.

## Run

```bash
npm install
npm run dev      # open the printed http://localhost:5173
npm test         # headless smoke test of the composite wiring (no browser needed)
```

WebAuthn requires a secure context — `localhost` counts, so dev works without HTTPS.
Use a browser with a platform authenticator (Touch ID / Windows Hello) or a security key.

Then click through the steps: **Register → Sign → Verify → Present → Replay → Tamper**.
Each step card shows the actual API call it makes and its inline result; later steps
unlock as their prerequisites complete. Two live panels make the internals visible:

- **JWT inspector** — decodes the current credential's three segments and, for
  `alg: WebAuthn`, unpacks the `{ s, a, c }` signature blob: the parsed
  `clientDataJSON`, the `authenticatorData` flags (UP/UV/**BE**/BS/AT/ED), and a
  check that the WebAuthn `challenge` equals `SHA-256(signing input)` — the
  load-bearing claim that the passkey signs a hash of `header.payload`, not the JWT.
  A **Copy JWT** button puts the token on the clipboard (e.g. for jwt.io).
- **Resolved DID document** — what the `did:jwk` resolver hands `verifyJWT`.

A **Reset** button clears the stored passkey identity and **Clear** empties the log.

## What it demonstrates

1. **Register** — `registerPasskey()` (from the module) creates an ES256 (P-256) passkey,
   reads the public key with `getPublicKey()`, and derives a `did:jwk` (the issuer DID).
   The passkey is the DID controller; no key material is exported.
2. **Sign** — `createJWT(payload, { issuer: didJwk, signer: new WebAuthnSigner(identity),
   alg: 'WebAuthn' })`. did-jwt assembles the JWT; the passkey prompts for touch/biometric
   inside `signer.sign()`.
3. **Verify** — `verifyJWT(jwt, { resolver }, new WebAuthnVerifier(rpId, { requireDeviceBound }))`.
   The resolver is the real `did-resolver` `Resolver` registry with a `did:jwk`
   method resolver registered (`new Resolver(jwkResolver())`); it returns the
   `publicKeyJwk` and did-jwt's async seam awaits the WebCrypto-based verifier. The
   step echoes the verifier's challenge-binding check (`clientData.challenge ===
   SHA-256(header.payload)`). A second **Verify requiring device-bound** button forces
   `requireDeviceBound: true` so you can watch a syncable (BE=1) passkey get rejected.
4. **Present** — the holder wraps the signed VC in a W3C **Verifiable Presentation**
   (`vp` claim + a fresh `nonce`), signs the VP with the passkey via `createJWT`,
   then `verifyJWT()`s it, checks the nonce, and walks the chain to verify the embedded
   VC. The VP is the holder signature — exactly where a device-bound passkey proves the
   holder key never left the device.
5. **Replay** — re-submits the step-4 VP against a freshly issued challenge nonce.
   `verifyJWT()` still accepts the passkey signature, but the stale nonce no longer
   matches — demonstrating that signature validity ≠ freshness, and that the nonce
   binding is what defeats replay. (Freshness is an app-level check; `verifyJWT`
   verifies signatures, not nonces.)
6. **Tamper** — flips a payload byte (the changed bytes are highlighted) and confirms
   `verifyJWT()` rejects it.

The **Require device-bound passkey** checkbox toggles `requireDeviceBound` on both
registration and verification: when checked, only a non-syncable passkey (Backup
Eligibility flag = 0, e.g. a hardware security key) is accepted; synced platform
passkeys (iCloud Keychain, Google Password Manager) are rejected. The identity
panel shows each passkey's `device-bound` status.

## Why a dedicated `alg` (not plain ES256)

WebAuthn never signs your message directly — it signs
`authenticatorData ‖ SHA-256(clientDataJSON)`, with your data carried in the
`challenge`. So a stock ES256 verifier can't validate a passkey assertion. Same shape
as the `did-jwt-eip712-signer` module: the verifier rebuilds the signed structure
rather than verifying a bare signature over the JWT. The crypto/encoding all lives in
the module now; this app is just the UI + a `did:jwk` resolver.

## Architecture

```
 registerPasskey() ─┐                            did-jwt-webauthn-signer
                    ▼                            ┌───────────────────────┐
 navigator.credentials  ──►  WebAuthnSigner ─────┤ AbstractSigner        │
                                  │              └───────────────────────┘
                    did-jwt createJWT(alg:WebAuthn)
                                  ▼
                          VC-JWT (did:jwk issuer)
                                  ▼
                    did-jwt verifyJWT(resolver, verifier)
                                  │              ┌───────────────────────┐
                                  └──────────────┤ WebAuthnVerifier(async)│
                          did:jwk-resolver       └───────────────────────┘
```

## Files

- `index.html` + `src/unified.ts` — the unified composite demo (one
  `CompositeSigner`/`CompositeVerifier` pair, three algorithms).
- `passkey.html` + `src/main.ts` — the passkey deep dive: `registerPasskey` /
  `WebAuthnSigner` / `WebAuthnVerifier` from the module, `createJWT` / `verifyJWT`
  from `did-jwt`.
- `src/did-jwk-resolver.ts` — spec-complete `did:jwk` method resolver in the
  `did-resolver` `getResolver()` shape (no network), wired into a real `Resolver`.
- `src/did-ethr-local-resolver.ts` — network-free `did:ethr` resolver synthesizing
  the default ERC-1056 DID document (`blockchainAccountId`, CAIP-10) for the
  EIP-712 verifier to match against.
- `test/smoke.mjs` — headless Node check of the composite wiring (sign + verify
  EdDSA and EIP712 through the shared pair, software-only negative control,
  `expectedDomain` rejection, tamper rejection).

All WebAuthn crypto, encoding, and DID derivation live in `did-jwt-webauthn-signer`;
all EIP-712 typed-data construction lives in `did-jwt-eip712-signer`.
