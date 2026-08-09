import { useState } from 'react'
import { createJWT, verifyJWT } from 'did-jwt'
import { Resolver } from 'did-resolver'
import { WebAuthnSigner, WebAuthnVerifier, WEBAUTHN_ALG, BrowserAuthenticatorBackend, base64urlDecode } from 'did-jwt-webauthn-signer'
import type { PasskeyIdentity } from '../utils/registration'
import type { StepResult } from './step-types'
import type { PresentedVp } from '../App'

interface Props {
  holderIdentity: PasskeyIdentity | null
  jwt: string | null
  resolver: Resolver
  deviceBoundRequired: boolean
  onPresented: (vp: PresentedVp) => void
  log: (msg: string, obj?: unknown) => void
}

export default function Step4Present({ holderIdentity, jwt, resolver, deviceBoundRequired, onPresented, log }: Props) {
  const [status, setStatus] = useState<StepResult | null>(null)

  // DEBUG
  const [busy, setBusy] = useState(false)

  const handleClick = async () => {
    if (busy || !jwt || !holderIdentity) return
    setBusy(true)

    try {
      const nonce = crypto.randomUUID()
      const now = Math.floor(Date.now() / 1000)
      const vpPayload = {
        nbf: now,
        nonce,
        vp: {
          '@context': ['https://www.w3.org/2018/credentials/v1'],
          type: ['VerifiablePresentation'],
          verifiableCredential: [jwt],
        },
      }
      const backend = new BrowserAuthenticatorBackend(base64urlDecode(holderIdentity.credentialId).buffer)
      const signer = new WebAuthnSigner(backend)
      const vpJwt = await createJWT(vpPayload, { issuer: holderIdentity.didJwk, signer, alg: WEBAUTHN_ALG })
      log('✅ Holder signed a Verifiable Presentation (passkey-bound).', { nonce, vp: vpJwt })

      const verifierOpts = { origin: location.origin, requireDeviceBound: deviceBoundRequired }
      const vpResult = await verifyJWT(vpJwt, { resolver }, new WebAuthnVerifier(holderIdentity.rpId, verifierOpts))

      const gotNonce = (vpResult.payload as { nonce?: string }).nonce
      const nonceOk = gotNonce === nonce
      const vp = (vpResult.payload as { vp?: { verifiableCredential?: string[] } }).vp
      const vc = vp?.verifiableCredential?.[0]

      let vcLine = ''
      if (typeof vc === 'string') {
        const vcResult = await verifyJWT(vc, { resolver }, new WebAuthnVerifier(holderIdentity.rpId, verifierOpts))
        const vcSubject = (vcResult.payload as { sub?: string }).sub
        

        if (vpResult.issuer !== vcSubject) {
          throw new Error(`Holder binding failed: VP signed by ${vpResult.issuer}, but VC names subject ${vcSubject}`)
        }

        vcLine = ` ↳ embedded VC also verified (issuer = ${vcResult.issuer}) — holder matches VC subject ✓`

        log('✅ Embedded VC also verified (issuer signature, holder binding OK).', {
          issuer: vcResult.issuer,
          vcSubject,
        })
      }

      onPresented({ jwt: vpJwt, nonce })
      setStatus({
        ok: true,
        msg: `✓ VP verified. holder = ${vpResult.issuer} — nonce match: ${nonceOk ? '✓' : '✗'}.${vcLine}`,
      })
      log('✅ verifyJWT() accepted the VP — holder key verified.', {
        verified: vpResult.verified,
        holder: vpResult.issuer,
        nonce: nonce,
        embeddedCredentials: vp?.verifiableCredential?.length ?? 0,
      })
    } catch (e) {
      const message = (e as Error).message
      setStatus({ ok: false, msg: `✗ ${message}` })
      log(`❌ Presentation failed: ${message}`)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="step">
      <h2>4. Present (Verifiable Presentation)</h2>
      <button type="button" onClick={handleClick} disabled={!jwt || !holderIdentity}>Present & verify</button>
      {status && <p className={status.ok ? 'ok' : 'bad'}>{status.msg}</p>}
    </div>
  )
}