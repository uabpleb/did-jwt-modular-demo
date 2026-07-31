/*import { useState } from 'react'
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
}*/

import { useState } from 'react'
import { createJWT } from 'did-jwt'
import { WebAuthnSigner, WEBAUTHN_ALG, BrowserAuthenticatorBackend, base64urlDecode, base64urlEncode } from 'did-jwt-webauthn-signer'
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

function buildVcPayload(didJwk: string) {
  const now = Math.floor(Date.now() / 1000)
  return {
    sub: didJwk,
    nbf: now,
    vc: {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      type: ['VerifiableCredential'],
      credentialSubject: { passkey: true, demo: 'did-jwt WebAuthn signer' },
    },
  }
}

export default function Step2Sign({ identity, identities, onIdentityResolved, onSigned, log }: Props) {
  const [result, setResult] = useState<StepResult | null>(null)
  const [discoverableResult, setDiscoverableResult] = useState<StepResult | null>(null)

  const handleClick = async () => {
    if (!identity) return
    try {
      const payload = buildVcPayload(identity.didJwk)
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
      // Phase 1 — resolve identity (no JWT binding, no allowlist: OS picker runs)
      const { credentialId: pickedId } = await resolveDiscoverableCredential(location.hostname)
      const matched = identities.find((i) => i.credentialId === pickedId)

      if (!matched) {
        setDiscoverableResult({
          ok: false,
          msg: `Picker resolved credential ${pickedId.slice(0, 12)}… — not in this demo's known identities (registered elsewhere, or before a Reset).`,
        })
        log('⚠️ Discoverable resolve: no matching stored identity.', { pickedId })
        return
      }

      onIdentityResolved(matched)

      // Phase 2 — real signing ceremony, now correctly scoped to the resolved credential
      const payload = buildVcPayload(matched.didJwk)
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
        Sign (discoverable — choose passkey)
      </button>
      {discoverableResult && <p className={discoverableResult.ok ? 'ok' : 'bad'}>{discoverableResult.msg}</p>}
    </div>
  )
}