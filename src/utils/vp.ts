import { decodeJWT } from 'did-jwt'

/**
 * Summarizes what a VP-JWT adds on top of the VC(s) it wraps, redacting the
 * embedded VC-JWT strings themselves (already shown in full elsewhere, e.g.
 * JwtPanel for Step 2's VC) rather than duplicating them here.
 *
 * Deliberately excludes `iat` and `iss` - both claim NAMES already exist on
 * the VC too, so they aren't "new" fields, even though `iss` here means
 * "holder" rather than "issuer" (same field name, different role - see
 * Step4Present.tsx's own note on self-issued VCs / holder binding).
 */
export function summarizeVpAdditions(vpJwt: string): Record<string, unknown> {
    const { payload } = decodeJWT(vpJwt)
    const vp = payload.vp as {
        '@context': string[]
        type: string[]
        verifiableCredential: string[]
    }

    return {
        nonce: payload.nonce,
        vp: {
            '@context': vp['@context'],
            type: vp.type,
            verifiableCredential: vp.verifiableCredential.map(
                (vcJwt) => `<VC JWT redacted, ${vcJwt.length} chars>`
            ),
        },
    }
}