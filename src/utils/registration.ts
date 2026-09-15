import {
    registerPasskey as libraryRegisterPasskey,
    resolveDiscoverableCredential,
    formatAaguid,
    base64urlDecode,
    verifyAttestation,
    ecAlgorithmByCoseAlg,
} from 'did-jwt-webauthn-signer'
import type {
    PasskeyIdentity,
    RegisterPasskeyOptions,
    AttestationResult,
    EcAlgorithm,
} from 'did-jwt-webauthn-signer'

export type { RegisterPasskeyOptions }
export { resolveDiscoverableCredential, formatAaguid }


export async function registerPasskey(options: RegisterPasskeyOptions): Promise<PasskeyIdentity> {
    const identity = await libraryRegisterPasskey({
        ...options,
    })
    const algorithm = ecAlgorithmByCoseAlg(identity.coseAlgorithm)
    if (!algorithm) {
        throw new Error(`registerPasskey: unsupported COSE algorithm ${identity.coseAlgorithm}`)
    }
    return identity
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