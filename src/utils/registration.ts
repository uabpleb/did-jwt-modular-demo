/**
 * registration.ts
 *
 * Browser-side WebAuthn registration helper.
 *
 * WebAuthn does not expose an API to query which algorithms an authenticator
 * supports before attempting registration (unlike CTAP2, which does support
 * such queries between the browser/OS and hardware). This is a deliberate
 * privacy design choice — exposing detailed capability information would be
 * a fingerprinting vector. As a consequence, this function must attempt
 * registration with a list of acceptable algorithms and read back which one
 * was actually used, rather than proactively selecting one.
 */

import {
    spkiToP256PublicKey,
    p256PublicKeyToDidJwk,
    parseAuthenticatorData,
    base64urlEncode,
} from 'did-jwt-webauthn-signer'

import { p256 } from '@noble/curves/nist.js'
import { base58 } from '@scure/base'

export const WEBAUTHN_ALG = 'WebAuthn'

const SUPPORTED_COSE_ALGS = [
    { alg: -7, type: 'public-key' as const },
    { alg: -257, type: 'public-key' as const },
]

export interface RegisterPasskeyOptions {
    rpId: string
    rpName: string
    userName: string
    requireDeviceBound?: boolean
}

export interface PasskeyIdentity {
    // TODO: review if all these are necessary
    credentialId: string   // base64url — JSON-safe
    publicKey: string       // base64url — JSON-safe
    didJwk: string
    didKey: string
    rpId: string
    coseAlgorithm: number
    deviceBound?: boolean
    aaguid?: string //self-reported by the authenticator at registration, not cryptographically verified.
}

export async function registerPasskey(options: RegisterPasskeyOptions): Promise<PasskeyIdentity> {
    if (typeof navigator === 'undefined' || !navigator.credentials) {
        throw new Error('registerPasskey: navigator.credentials is not available in this environment')
    }

    const credential = (await navigator.credentials.create({
        publicKey: {
            rp: { id: options.rpId, name: options.rpName },
            user: {
                id: crypto.getRandomValues(new Uint8Array(16)),
                name: options.userName,
                displayName: options.userName,
            },
            challenge: crypto.getRandomValues(new Uint8Array(32)),
            pubKeyCredParams: SUPPORTED_COSE_ALGS,
            authenticatorSelection: { userVerification: 'required', residentKey: 'required' },
        },
    })) as PublicKeyCredential

    const response = credential.response as AuthenticatorAttestationResponse
    const coseAlgorithm = response.getPublicKeyAlgorithm()

    if (coseAlgorithm !== -7) {
        throw new Error(
            `registerPasskey: unsupported COSE algorithm ${coseAlgorithm} — only ES256 (P-256) is currently implemented`
        )
    }

    const spki = response.getPublicKey()
    if (!spki) throw new Error('registerPasskey: authenticator did not return a public key')

    const publicKeyBytes = await spkiToP256PublicKey(spki)
    const didJwk = p256PublicKeyToDidJwk(publicKeyBytes)
    const didKey = p256PublicKeyToDidKey(publicKeyBytes)

    let deviceBound: boolean | undefined
    let aaguid: string|undefined
    if (typeof response.getAuthenticatorData === 'function') {
        const authData = new Uint8Array(response.getAuthenticatorData())
        const parsed = parseAuthenticatorData(authData)
        if (parsed.attestedCredentialData) {
            aaguid = formatAaguid(parsed.attestedCredentialData.aaguid)
        }
        deviceBound = !parsed.flags.backupEligible
    }

    if (options.requireDeviceBound && deviceBound === false) {
        throw new Error('registerPasskey: a device-bound passkey was required, but this one is syncable (BE=1)')
    }

    return {
        credentialId: base64urlEncode(new Uint8Array(credential.rawId)),
        publicKey: base64urlEncode(publicKeyBytes),
        didJwk,
        didKey,
        rpId: options.rpId,
        coseAlgorithm,
        deviceBound,
        aaguid
    }
}


const P256_MULTICODEC_PREFIX = new Uint8Array([0x80, 0x24])

/**
 * Derives a did:key DID from a P-256 public key — kept only for UI comparison
 * against did:jwk in this demo. The library itself standardized on did:jwk;
 * see thesis section on DID method comparison for why.
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
 * Formats a 16-byte AAGUID as a canonical UUID string (8-4-4-4-12 hex groups).
 * Self-reported by the authenticator — see thesis note on the attestation gap:
 * this value carries no cryptographic guarantee of authenticity.
 */
function formatAaguid(bytes: Uint8Array): string {
    const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`
}

/**
 * Resolves which resident credential the user selects via the browser's native
 * passkey picker — WITHOUT performing any JWT-binding ceremony.
 *
 * Exists to solve an ordering conflict: WebAuthnSigner's challenge binding
 * requires `iss` (the signer's DID) to already be in the JWT payload before
 * the signing ceremony starts, but discoverable credentials don't reveal
 * *which* credential (and therefore which DID) until the OS picker resolves.
 * So identity must be established in a prior, separate ceremony using a
 * throwaway local challenge — nothing meaningful is bound to it.
 *
 * Note: this demo resolves identity via local storage only (see App.tsx). A
 * real deployment would resolve identity server-side (e.g. from the
 * assertion's userHandle), not from the browser's own storage.
 */
export async function resolveDiscoverableCredential(rpId: string): Promise<{ credentialId: string }> {
    if (typeof navigator === 'undefined' || !navigator.credentials) {
        throw new Error('resolveDiscoverableCredential: navigator.credentials is not available in this environment')
    }
    const assertion = (await navigator.credentials.get({
        publicKey: {
            challenge: crypto.getRandomValues(new Uint8Array(32)),
            rpId,
            userVerification: 'required',
            // No allowCredentials — the browser enumerates resident credentials and shows the picker.
        },
    })) as PublicKeyCredential
    return { credentialId: base64urlEncode(new Uint8Array(assertion.rawId)) }
}