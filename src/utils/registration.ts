import {
    registerPasskey as libraryRegisterPasskey,
    resolveDiscoverableCredential,
    formatAaguid,
    base64urlDecode,
    verifyAttestation,
    ecAlgorithmByCoseAlg,
} from 'did-jwt-webauthn-signer'
import type {
    PasskeyIdentity as LibraryPasskeyIdentity,
    RegisterPasskeyOptions,
    AttestationResult,
    EcAlgorithm,
} from 'did-jwt-webauthn-signer'
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
    const algorithm = ecAlgorithmByCoseAlg(identity.coseAlgorithm)
    if (!algorithm) {
        throw new Error(`registerPasskey: unsupported COSE algorithm ${identity.coseAlgorithm}`)
    }
    return { ...identity, didKey: ecPublicKeyToDidKey(publicKeyBytes, algorithm) }
}

// Multicodec codes for compressed EC public keys (https://github.com/multiformats/multicodec/blob/master/table.csv)
const MULTICODEC_PREFIX_BY_CRV: Record<string, Uint8Array> = {
    'P-256': new Uint8Array([0x80, 0x24]),
    'P-384': new Uint8Array([0x81, 0x24]),
}

/**
 * Derives a did:key DID from an EC public key - kept only for UI comparison
 * against did:jwk in this demo. Never moved into the library, unlike
 * registerPasskey/resolveDiscoverableCredential/formatAaguid above.
 */
export function ecPublicKeyToDidKey(publicKey: Uint8Array, algorithm: EcAlgorithm): string {
    const uncompressedLength = 1 + 2 * algorithm.coordinateLength
    const compressedLength = 1 + algorithm.coordinateLength

    let compressed: Uint8Array

    if (publicKey.length === uncompressedLength && publicKey[0] === 0x04) {
        compressed = algorithm.curve.Point.fromBytes(publicKey).toBytes(true)
    } else if (publicKey.length === compressedLength && (publicKey[0] === 0x02 || publicKey[0] === 0x03)) {
        compressed = publicKey
    } else {
        throw new Error(
            `ecPublicKeyToDidKey: unexpected public key format for ${algorithm.jwkCrv} (length ${publicKey.length}, prefix 0x${publicKey[0].toString(16)})`
        )
    }

    const multicodecPrefix = MULTICODEC_PREFIX_BY_CRV[algorithm.jwkCrv]
    if (!multicodecPrefix) {
        throw new Error(`ecPublicKeyToDidKey: no multicodec prefix registered for curve ${algorithm.jwkCrv}`)
    }

    const multicodecKey = new Uint8Array(multicodecPrefix.length + compressed.length)
    multicodecKey.set(multicodecPrefix, 0)
    multicodecKey.set(compressed, multicodecPrefix.length)

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