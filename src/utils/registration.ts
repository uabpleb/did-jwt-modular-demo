/**
 * registration.ts
 *
 * Thin demo-side wrapper around the library's registration ceremony
 * (registerPasskey, resolveDiscoverableCredential, formatAaguid), which now
 * lives in did-jwt-webauthn-signer itself - nothing about the ceremony was
 * actually demo-specific. What genuinely IS demo-specific, and stays here:
 *   - did:key derivation, kept purely for this demo's did:jwk-vs-did:key
 *     comparison view (the library standardized on did:jwk; see thesis
 *     section on DID method comparison for why)
 *   - always requesting attestation at registration, so this demo's later
 *     steps have something to embed/verify (the library itself defaults to
 *     'none', to avoid silently changing the registration prompt for
 *     callers who don't ask for it)
 */

import {
    registerPasskey as libraryRegisterPasskey,
    resolveDiscoverableCredential,
    formatAaguid,
    base64urlDecode,
    verifyAttestation,
} from 'did-jwt-webauthn-signer'
import type {
    PasskeyIdentity as LibraryPasskeyIdentity,
    RegisterPasskeyOptions,
    AttestationResult,
} from 'did-jwt-webauthn-signer'
import { p256 } from '@noble/curves/nist.js'
import { base58 } from '@scure/base'

export type { RegisterPasskeyOptions }
export { resolveDiscoverableCredential, formatAaguid }

/** The library's PasskeyIdentity, plus this demo's own did:key comparison field. */
export interface PasskeyIdentity extends LibraryPasskeyIdentity {
    didKey: string
}


export async function registerPasskey(options: RegisterPasskeyOptions): Promise<PasskeyIdentity> {
    const identity = await libraryRegisterPasskey({
        ...options,
        attestation: options.attestation ?? 'direct',
    })
    const publicKeyBytes = base64urlDecode(identity.publicKey)
    return { ...identity, didKey: p256PublicKeyToDidKey(publicKeyBytes) }
}

const P256_MULTICODEC_PREFIX = new Uint8Array([0x80, 0x24])

/**
 * Derives a did:key DID from a P-256 public key - kept only for UI comparison
 * against did:jwk in this demo. Never moved into the library, unlike
 * registerPasskey/resolveDiscoverableCredential/formatAaguid above.
 */
export function p256PublicKeyToDidKey(publicKey: Uint8Array): string {
    let compressed: Uint8Array

    if (publicKey.length === 65 && publicKey[0] === 0x04) {
        compressed = p256.Point.fromBytes(publicKey).toBytes(true)
    } else if (publicKey.length === 33 && (publicKey[0] === 0x02 || publicKey[0] === 0x03)) {
        compressed = publicKey
    } else {
        throw new Error(
            `p256PublicKeyToDidKey: unexpected public key format (length ${publicKey.length}, prefix 0x${publicKey[0].toString(16)})`
        )
    }

    const multicodecKey = new Uint8Array(P256_MULTICODEC_PREFIX.length + compressed.length)
    multicodecKey.set(P256_MULTICODEC_PREFIX, 0)
    multicodecKey.set(compressed, P256_MULTICODEC_PREFIX.length)

    return `did:key:z${base58.encode(multicodecKey)}`
}

/**
 * Convenience wrapper around verifyAttestation() for a stored PasskeyIdentity.
 * Returns null if this identity was registered without attestation (e.g. an
 * older identity from local storage), or an AttestationResult otherwise.
 */
export async function checkAttestation(identity: PasskeyIdentity, trustedRoots: Uint8Array[]): Promise<AttestationResult | null> {
    if (!identity.attestationObject || !identity.attestationClientDataHash) return null
    const attestationObject = base64urlDecode(identity.attestationObject)
    const clientDataHash = base64urlDecode(identity.attestationClientDataHash)
    return verifyAttestation(attestationObject, clientDataHash, trustedRoots)
}