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
    credentialId: string   // base64url — JSON-safe
    publicKey: string       // base64url — JSON-safe
    didJwk: string
    didKey: string
    rpId: string
    coseAlgorithm: number
    deviceBound?: boolean
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
    if (typeof response.getAuthenticatorData === 'function') {
        const authData = new Uint8Array(response.getAuthenticatorData())
        deviceBound = !parseAuthenticatorData(authData).flags.backupEligible
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
        compressed = p256.Point.fromHex(publicKey).toBytes(true)
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