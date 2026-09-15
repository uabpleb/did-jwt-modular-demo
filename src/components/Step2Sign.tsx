import { useState } from 'react'
import { createJWT } from 'did-jwt'
import { WebAuthnSigner, WEBAUTHN_ALG, BrowserAuthenticatorBackend, base64urlDecode, withAttestation, ecAlgorithmByCoseAlg } from 'did-jwt-webauthn-signer'
import type { PasskeyIdentity } from 'did-jwt-webauthn-signer'
import type { StepResult } from './step-types'
import { toConfirmationClaim } from '../utils/cnf'
import { buildPidCredentialSubject } from '../utils/pid'

interface Props {
  identity: PasskeyIdentity | null
  onSigned: (jwt: string) => void
  log: (msg: string, obj?: unknown) => void
}

// Short-lived, per ARF alignment: PID/EAA validity should not exceed ~24h.
const VC_VALIDITY_SECONDS = 3600

function buildVcPayload(identity: PasskeyIdentity) {
  const now = Math.floor(Date.now() / 1000)
  const ecAlgorithm = ecAlgorithmByCoseAlg(identity.coseAlgorithm)
  if (!ecAlgorithm) {
    throw new Error(`buildVcPayload: identity has unsupported COSE algorithm ${identity.coseAlgorithm}`)
  }

  const basePayload = {
    sub: identity.didJwk,
    // RFC 7800 confirmation claim
    cnf: toConfirmationClaim(base64urlDecode(identity.publicKey), ecAlgorithm),
    // iat, not nbf: per the "Securing Verifiable Credentials using JOSE and COSE" spec, nbf is
    // explicitly NOT RECOMMENDED for VC-JWTs ("makes little sense to assign a future date to a
    // signature") - iat is the intended claim for when the signature itself was created.
    iat: now,
    exp: now + VC_VALIDITY_SECONDS, // JWT-level claims - this is what verifyJWT()'s own time-window check enforces
    vct: 'urn:eudi:pid:de:1',
    vc: {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiableCredential'],
      validFrom: new Date(now * 1000).toISOString(),
      validUntil: new Date((now + VC_VALIDITY_SECONDS) * 1000).toISOString(),
      credentialSubject: buildPidCredentialSubject(),
    },
  }

  return identity.attestationObject ? withAttestation(basePayload, base64urlDecode(identity.attestationObject)) : basePayload
}

export default function Step2Sign({ identity, onSigned, log }: Props) {
  const [result, setResult] = useState<StepResult | null>(null)

  const handleClick = async () => {
    if (!identity) return
    try {
      const payload = buildVcPayload(identity)
      const backend = new BrowserAuthenticatorBackend(base64urlDecode(identity.credentialId).buffer)
      const signer = new WebAuthnSigner(backend)
      const jwt = await createJWT(payload, { issuer: identity.didJwk, signer, alg: WEBAUTHN_ALG })

      onSigned(jwt)
      setResult({ ok: true, msg: 'Signed successfully. See the JWT below.' })
      log('✅ Signed VC-JWT via createJWT().', { jwt })
    } catch (e) {
      const message = (e as Error).message
      setResult({ ok: false, msg: message })
      log(`Signing failed: ${message}`)
    }
  }

  return (
    <div className="step">
      <h2>2. Sign a VC-JWT</h2>
      <button type="button" onClick={handleClick} disabled={!identity}>Sign credential</button>
      {result && <p className={result.ok ? 'ok' : 'bad'}>{result.msg}</p>}
    </div>
  )
}