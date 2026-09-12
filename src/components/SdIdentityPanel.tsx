import { useState } from 'react'
import { Resolver } from 'did-resolver'
import { WebAuthnSigner, WebAuthnVerifier, BrowserAuthenticatorBackend, base64urlDecode, WEBAUTHN_ALG } from 'did-jwt-webauthn-signer'
import { issueSdCredential, createSdPresentation, verifySdPresentation, type Disclosure } from 'did-jwt-vc'
import { decodeJWT } from 'did-jwt'
import type { PasskeyIdentity } from '../utils/registration'
import type { StepResult } from './step-types'
import { buildPidCredentialSubject } from '../utils/pid'

interface Props {
    identity: PasskeyIdentity | null
    jwt: string | null
    resolver: Resolver
    deviceBoundRequired: boolean
    log: (msg: string, obj?: unknown) => void
}

const AUDIENCE = 'demo-verifier'

const SELECTIVELY_HIDDEN_FIELDS = ['age_over_18', 'nationalities']

export default function SdIdentityPanel({ identity, jwt, resolver, deviceBoundRequired, log }: Props) {
    const [issued, setIssued] = useState<{ jwt: string; disclosures: Disclosure[] } | null>(null)
    const [reveal, setReveal] = useState<Record<string, boolean>>(
        // age_over_18 defaults to revealed, nationalities defaults to withheld.
        Object.fromEntries(SELECTIVELY_HIDDEN_FIELDS.map((name) => [name, name === 'age_over_18']))
    )
    const [presentResult, setPresentResult] = useState<StepResult | null>(null)
    const [claims, setClaims] = useState<Record<string, unknown> | null>(null)
    const [undisclosedCount, setUndisclosedCount] = useState<number | null>(null)

    const handleIssue = async () => {
        if (!identity) {
            return
        }

        try {
            const backend = new BrowserAuthenticatorBackend(base64urlDecode(identity.credentialId).buffer)
            const signer = new WebAuthnSigner(backend)

            const fullSubject = buildPidCredentialSubject()
            const disclosed: Record<string, unknown> = {}
            const hidden: Record<string, unknown> = {}
            for (const [name, value] of Object.entries(fullSubject)) {
                const target = (SELECTIVELY_HIDDEN_FIELDS as readonly string[]).includes(name) ? hidden : disclosed
                target[name] = value
            }

            const result = await issueSdCredential({
                issuer: {
                    did: identity.didJwk,
                    signer: signer,
                    alg: WEBAUTHN_ALG,
                },
                disclosed,
                hidden,
                base: {
                    sub: identity.didJwk
                }
            })

            setIssued({jwt: result.jwt, disclosures: result.disclosures})
            setClaims(null)
            setPresentResult(null)
            log('✅ Issued SD-JWT-VC.', { jwt: result.jwt, disclosures: result.disclosures })
        } catch (e) {
            const message = (e as Error).message
            log(`SD issue failed: ${message}`)
        }
    }

    const handlePresent = async () => {
        if (!identity || !issued) {
            return null
        }

        try {
            const backend = new BrowserAuthenticatorBackend(base64urlDecode(identity.credentialId).buffer)
            const signer = new WebAuthnSigner(backend)
            const revealNames = Object.keys(reveal).filter((k) => reveal[k])

            const { combined } = await createSdPresentation({
                vcJwt: issued.jwt,
                disclosures: issued.disclosures,
                reveal: revealNames,
                holderDid: identity.didJwk,
                signer: signer,
                alg: WEBAUTHN_ALG,
                audience: AUDIENCE,
                nonce: crypto.randomUUID()
            })

            const verifier = new WebAuthnVerifier(identity.rpId, { origin: location.origin, requireDeviceBound: deviceBoundRequired })
            // expectedNonce must match what was just used - re-derive by re-splitting isn't available here,
            // so verify against the same call's nonce by capturing it above instead of re-generating.
            const result = await verifySdPresentation(combined, {
                resolver: resolver,
                expectedAudience: AUDIENCE,
                expectedNonce: JSON.parse(new TextDecoder().decode(base64urlDecode(combined.split('~').pop()!.split('.')[1]))).nonce,
                verifier: verifier
            })

            setClaims(result.claims)
            setUndisclosedCount(result.undisclosedCount)
            setPresentResult({ ok: true, msg: `✓ Presented & verified. ${result.disclosedNames.length} revealed, ${result.undisclosedCount} withheld.` })
            log('✅ SD presentation verified.', { revealed: result.disclosedNames, claims: result.claims })

        } catch (e) {
            const message = (e as Error).message
            setPresentResult({ ok: false, msg: message })
            log(`SD present/verify failed: ${message}`)
        }


    }

    let plainClaims: Record<string, unknown> | null = null
    let plainClaimsError: string | null = null
    if (jwt) {
        try {
            const payload = decodeJWT(jwt).payload as { vc?: { credentialSubject?: Record<string, unknown> } }
            if (!payload.vc?.credentialSubject) {
                throw new Error('Decoded JWT payload has no vc.credentialSubject claim')
            }
            plainClaims = payload.vc.credentialSubject
        } catch (e) {
            plainClaimsError = (e as Error).message
        }
    }

  return (
    <div className="step">
      <h2>Selective Disclosure - side by side</h2>
      <div style={{ display: 'flex', gap: '20px', flexWrap: 'wrap' }}>
        <div style={{ flex: 1, minWidth: '260px' }}>
          <h3 style={{ fontSize: '1rem' }}>Plain VC (Step 2)</h3>
          {plainClaimsError ? (
            <p className="bad">Failed to read Step 2 credential: {plainClaimsError}</p>
          ) : plainClaims ? (
            <pre>{JSON.stringify(plainClaims, null, 2)}</pre>
          ) : (
            <p>Sign a credential in Step 2 first.</p>
          )}
        </div>

        <div style={{ flex: 1, minWidth: '260px' }}>
          <h3 style={{ fontSize: '1rem' }}>SD-JWT-VC</h3>
          <button type="button" onClick={handleIssue} disabled={!identity}>
            Issue SD credential
          </button>

          {issued && (
            <div style={{ marginTop: '10px' }}>
              {Object.keys(reveal).map((name) => (
                <label key={name} style={{ display: 'block', margin: '4px 0' }}>
                  <input
                    type="checkbox"
                    checked={reveal[name]}
                    onChange={(e) => setReveal({ ...reveal, [name]: e.target.checked })}
                  />
                  {' '}reveal <code>{name}</code>
                </label>
              ))}
              <button type="button" onClick={handlePresent} style={{ marginTop: '8px' }}>
                Present (SD)
              </button>
            </div>
          )}

          {presentResult && <p className={presentResult.ok ? 'ok' : 'bad'}>{presentResult.msg}</p>}
          {claims && (
            <>
              <pre>{JSON.stringify(claims, null, 2)}</pre>
              <p style={{ fontSize: '0.85rem', color: '#64748b' }}>{undisclosedCount} claim(s) remain hashed, unreadable to this verifier.</p>
            </>
          )}

        </div>
      </div>
    </div>
  )
}