import { useState } from 'react'
import { createJWT } from 'did-jwt'
import { WebAuthnSigner, WEBAUTHN_ALG, BrowserAuthenticatorBackend, base64urlDecode } from 'did-jwt-webauthn-signer'
import type { PasskeyIdentity } from '../utils/registration'
import type { StepResult } from './step-types'

interface Props {
  identity: PasskeyIdentity | null
  onSigned: (jwt: string) => void
  log: (msg: string, obj?: unknown) => void
}

export default function Step2Sign({ identity, onSigned, log }: Props) {
  const [result, setResult] = useState<StepResult | null>(null)

  const handleClick = async () => {
    if (!identity) return
    try {
      const now = Math.floor(Date.now() / 1000)
      const payload = {
        sub: identity.didJwk,
        nbf: now,
        vc: {
          '@context': ['https://www.w3.org/2018/credentials/v1'],
          type: ['VerifiableCredential'],
          credentialSubject: { passkey: true, demo: 'did-jwt WebAuthn signer' },
        },
      }
      const backend = new BrowserAuthenticatorBackend(base64urlDecode(identity.credentialId).buffer)
      const signer = new WebAuthnSigner(backend)
      const jwt = await createJWT(payload, { issuer: identity.didJwk, signer, alg: WEBAUTHN_ALG })

      onSigned(jwt)
      setResult({ ok: true, msg: '✓ Signed. See the JWT below.' })
      log('✅ Signed VC-JWT via createJWT().', { jwt })
    } catch (e) {
      const message = (e as Error).message
      setResult({ ok: false, msg: `${message}` })
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