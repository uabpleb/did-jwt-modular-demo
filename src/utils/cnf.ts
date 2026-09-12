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
 *
 * Curve-generic since the algorithm/curve chosen at registration is not
 * fixed to P-256 (see registerPasskey() and the algorithm registry in
 * did-jwt-webauthn-signer) - cnf.jwk.crv reflects whatever the authenticator
 * actually produced, and fromConfirmationJwk() returns the matching
 * EcAlgorithm alongside the recovered bytes so callers don't have to
 * re-derive it themselves.
 */

import { base64urlEncode, base64urlDecode, ecAlgorithmByJwkCrv } from 'did-jwt-webauthn-signer'
import type { EcAlgorithm } from 'did-jwt-webauthn-signer'

export interface ConfirmationJwk {
    kty: 'EC'
    crv: string
    x: string
    y: string
}

/** Builds a `cnf: { jwk }` claim value from a raw uncompressed EC public key (0x04 || x || y), for the given algorithm/curve. */
export function toConfirmationClaim(publicKeyBytes: Uint8Array, algorithm: EcAlgorithm): { jwk: ConfirmationJwk } {
    const expectedLength = 1 + 2 * algorithm.coordinateLength
    if (publicKeyBytes.length !== expectedLength || publicKeyBytes[0] !== 0x04) {
        throw new Error(
            `toConfirmationClaim: expected an uncompressed ${algorithm.jwkCrv} public key (${expectedLength} bytes, 0x04 prefix)`
        )
    }
    return {
        jwk: {
            kty: 'EC',
            crv: algorithm.jwkCrv,
            x: base64urlEncode(publicKeyBytes.slice(1, algorithm.coordinateLength + 1)),
            y: base64urlEncode(publicKeyBytes.slice(algorithm.coordinateLength + 1, expectedLength)),
        },
    }
}

/** Recovers the raw uncompressed EC public key (0x04 || x || y) and its algorithm from a `cnf.jwk` value. */
export function fromConfirmationJwk(jwk: ConfirmationJwk): { publicKeyBytes: Uint8Array; algorithm: EcAlgorithm } {
    const algorithm = ecAlgorithmByJwkCrv(jwk.crv)
    if (!algorithm) {
        throw new Error(`fromConfirmationJwk: unsupported curve "${jwk.crv}" in cnf.jwk`)
    }
    const x = base64urlDecode(jwk.x)
    const y = base64urlDecode(jwk.y)
    const bytes = new Uint8Array(1 + 2 * algorithm.coordinateLength)
    bytes[0] = 0x04
    bytes.set(x, 1)
    bytes.set(y, algorithm.coordinateLength + 1)
    return { publicKeyBytes: bytes, algorithm }
}