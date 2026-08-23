/**
 * cnf.ts
 *
 * Minimal support for the `cnf` (confirmation) claim, RFC 7800 / SD-JWT VC -
 * the standard mechanism for binding a credential to a specific
 * proof-of-possession key. This is the "quick" (Option A) alignment item:
 * it replaces this demo's prior DID-string holder-binding check
 * (comparing vpResult.issuer against the VC's own `sub`) with an explicit,
 * spec-shaped cnf.jwk check.
 *
 * Scope note: this thesis's WebAuthnSigner/AuthenticatorBackend design ties
 * every signature to a specific registered passkey, so cnf.jwk here is
 * always set to the SAME key already encoded in the credential's `sub`
 * (did:jwk). This does not close a security gap specific to this thesis's
 * did:jwk choice - a did:jwk-based `sub` comparison was already,
 * functionally, a key check, since did:jwk IS the encoded key. The value of
 * this change is standards conformance and portability: any SD-JWT VC
 * verifier knows to look for cnf.jwk; none of them know to decode a
 * did:jwk string as a confirmation key. A fully general implementation that
 * let cnf name a DIFFERENT key than sub - e.g. a holder-chosen, ephemeral
 * binding key not tied to any passkey - was considered and left out of
 * scope, since it would require a second, non-WebAuthn-backed signing
 * mechanism this thesis's architecture does not otherwise have.
 */

import { base64urlEncode, base64urlDecode } from 'did-jwt-webauthn-signer'

export interface ConfirmationJwk {
    kty: 'EC'
    crv: 'P-256'
    x: string
    y: string
}

/** Builds a `cnf: { jwk }` claim value from a raw uncompressed P-256 public key (0x04 || x || y). */
export function toConfirmationClaim(publicKeyBytes: Uint8Array): { jwk: ConfirmationJwk } {
    if (publicKeyBytes.length !== 65 || publicKeyBytes[0] !== 0x04) {
        throw new Error('toConfirmationClaim: expected an uncompressed P-256 public key (65 bytes, 0x04 prefix)')
    }
    return {
        jwk: {
            kty: 'EC',
            crv: 'P-256',
            x: base64urlEncode(publicKeyBytes.slice(1, 33)),
            y: base64urlEncode(publicKeyBytes.slice(33, 65)),
        },
    }
}

/** Recovers the raw uncompressed P-256 public key (0x04 || x || y) from a `cnf.jwk` value. */
export function fromConfirmationJwk(jwk: ConfirmationJwk): Uint8Array {
    const x = base64urlDecode(jwk.x)
    const y = base64urlDecode(jwk.y)
    const bytes = new Uint8Array(65)
    bytes[0] = 0x04
    bytes.set(x, 1)
    bytes.set(y, 33)
    return bytes
}