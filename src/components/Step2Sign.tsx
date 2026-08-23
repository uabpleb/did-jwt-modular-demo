import { useState } from 'react'
import { createJWT } from 'did-jwt'
import { WebAuthnSigner, WEBAUTHN_ALG, BrowserAuthenticatorBackend, base64urlDecode, withAttestation } from 'did-jwt-webauthn-signer'
import type { PasskeyIdentity } from '../utils/registration'
import { resolveDiscoverableCredential } from '../utils/registration'
import type { StepResult } from './step-types'

interface Props {
  identity: PasskeyIdentity | null
  identities: PasskeyIdentity[]
  onIdentityResolved: (identity: PasskeyIdentity) => void
  onSigned: (jwt: string) => void
  log: (msg: string, obj?: unknown) => void
}

// Short-lived, per ARF alignment: PID/EAA validity should not exceed ~24h (res:alignment-strengthening).
const VC_VALIDITY_SECONDS = 3600

function buildVcPayload(identity: PasskeyIdentity) {
  const now = Math.floor(Date.now() / 1000)
  const basePayload = {
    sub: identity.didJwk,
    // iat, not nbf: per the "Securing Verifiable Credentials using JOSE and COSE" spec, nbf is
    // explicitly NOT RECOMMENDED for VC-JWTs ("makes little sense to assign a future date to a
    // signature") - iat is the intended claim for when the signature itself was created.
    iat: now,
    exp: now + VC_VALIDITY_SECONDS, // JWT-level claims - this is what verifyJWT()'s own time-window check enforces
    vc: {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiableCredential'],
      // VCDM v2.0's own data-model fields - NOT the same axis as iat/exp above. iat/exp describe
      // the SIGNATURE's validity (and are the only ones did-jwt's verifyJWT() actually enforces);
      // validFrom/validUntil describe the underlying DATA's validity, and nothing in this demo
      // currently checks them - they're included here for VCDM conformance, not as an active gate.
      validFrom: new Date(now * 1000).toISOString(),
      validUntil: new Date((now + VC_VALIDITY_SECONDS) * 1000).toISOString(),
      credentialSubject: {
        passkey: true,
        demo: 'did-jwt WebAuthn signer',
        memberSince: '2024-01-15',
        verificationLevel: 'gold'
      },
    },
  }

  // Embed the registration-time attestation, if this identity has one (see
  // utils/registration.ts - attestation is requested by default for every
  // identity registered in this demo). Older identities from local storage,
  // registered before this change, simply won't have one - nothing to embed.
  return identity.attestationObject
    ? withAttestation(basePayload, base64urlDecode(identity.attestationObject))
    : basePayload
}

export default function Step2Sign({ identity, identities, onIdentityResolved, onSigned, log }: Props) {
  const [result, setResult] = useState<StepResult | null>(null)
  const [discoverableResult, setDiscoverableResult] = useState<StepResult | null>(null)

  const handleClick = async () => {
    if (!identity) return
    try {
      const payload = buildVcPayload(identity)
      const backend = new BrowserAuthenticatorBackend(base64urlDecode(identity.credentialId).buffer)
      const signer = new WebAuthnSigner(backend)
      const jwt = await createJWT(payload, { issuer: identity.didJwk, signer, alg: WEBAUTHN_ALG })

      onSigned(jwt)
      setResult({ ok: true, msg: '✓ Signed. See the JWT below.' })
      log('✅ Signed VC-JWT via createJWT().', { jwt })
    } catch (e) {
      const message = (e as Error).message
      setResult({ ok: false, msg: message })
      log(`Signing failed: ${message}`)
    }
  }

  const handleDiscoverableClick = async () => {
    try {
      // Phase 1 - resolve identity (no JWT binding, no allowlist: OS picker runs)
      const { credentialId: pickedId } = await resolveDiscoverableCredential(location.hostname)
      const matched = identities.find((i) => i.credentialId === pickedId)

      if (!matched) {
        setDiscoverableResult({
          ok: false,
          msg: `Picker resolved credential ${pickedId.slice(0, 12)}… - not in this demo's known identities (registered elsewhere, or before a Reset).`,
        })
        log('⚠️ Discoverable resolve: no matching stored identity.', { pickedId })
        return
      }

      onIdentityResolved(matched)

      // Phase 2 - real signing ceremony, now correctly scoped to the resolved credential
      const payload = buildVcPayload(matched)
      const backend = new BrowserAuthenticatorBackend(base64urlDecode(matched.credentialId).buffer)
      const signer = new WebAuthnSigner(backend)
      const jwt = await createJWT(payload, { issuer: matched.didJwk, signer, alg: WEBAUTHN_ALG })

      onSigned(jwt)
      setDiscoverableResult({
        ok: true,
        msg: `✓ Resolved passkey → signed as ${matched.didJwk.slice(0, 28)}…`,
      })
      log('✅ Discoverable resolve-then-sign succeeded.', { jwt, resolvedDid: matched.didJwk })
    } catch (e) {
      const message = (e as Error).message
      setDiscoverableResult({ ok: false, msg: message })
      log(`Discoverable sign failed: ${message}`)
    }
  }

  return (
    <div className="step">
      <h2>2. Sign a VC-JWT</h2>
      <button type="button" onClick={handleClick} disabled={!identity}>Sign credential</button>
      {result && <p className={result.ok ? 'ok' : 'bad'}>{result.msg}</p>}

      <button type="button" onClick={handleDiscoverableClick} disabled={identities.length === 0}>
        Sign (discoverable - choose passkey)
      </button>
      {discoverableResult && <p className={discoverableResult.ok ? 'ok' : 'bad'}>{discoverableResult.msg}</p>}
    </div>
  )
}