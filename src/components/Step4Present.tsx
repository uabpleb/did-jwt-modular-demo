import { useState } from 'react'
import { createJWT, verifyJWT } from 'did-jwt'
import { Resolver } from 'did-resolver'
import { WebAuthnSigner, WebAuthnVerifier, WEBAUTHN_ALG, BrowserAuthenticatorBackend, base64urlDecode, ecPublicKeyToDidJwk } from 'did-jwt-webauthn-signer'
import type { PasskeyIdentity } from '../utils/registration'
import type { StepResult } from './step-types'
import type { PresentedVp } from '../App'
import { fromConfirmationJwk } from '../utils/cnf'
import type { ConfirmationJwk } from '../utils/cnf'

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
        // iat, not nbf - same spec reasoning as the VC payload in Step2Sign: nbf is NOT
        // RECOMMENDED for a JWS's own claims. No exp here: the presentation is single-use,
        // immediate, and already replay-guarded by `nonce`, unlike the VC's longer-lived exp.
        iat: now,
        nonce,
        vp: {
          '@context': ['https://www.w3.org/ns/credentials/v2'],
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
        const vcPayload = vcResult.payload as { sub?: string; cnf?: { jwk: ConfirmationJwk } }

        // Holder binding is now checked against the standard cnf.jwk claim (RFC 7800 / SD-JWT VC),
        // not against `sub`. did:jwk resolution is a pure, local, deterministic decode of the DID
        // string (Section soa:ssi:did-methods) - so deriving the did:jwk that cnf.jwk WOULD produce,
        // and comparing it against the VP's already-verified signer, is exactly equivalent to
        // checking that the VP was signed by the key cnf actually names.
        if (!vcPayload.cnf?.jwk) {
          throw new Error('Holder binding failed: VC does not carry a cnf claim to bind against')
        }
        const {publicKeyBytes, algorithm} = fromConfirmationJwk(vcPayload.cnf.jwk)
        const expectedHolderDid = ecPublicKeyToDidJwk(publicKeyBytes, algorithm)

        if (vpResult.issuer !== expectedHolderDid) {
          throw new Error(
            `Holder binding failed: VP signed by ${vpResult.issuer}, but VC's cnf names the key for ${expectedHolderDid}`
          )
        }

        const cnfMatchesSub = vcPayload.sub === expectedHolderDid
        vcLine = ` ↳ embedded VC also verified (issuer = ${vcResult.issuer}) - holder matches VC cnf ✓${
          cnfMatchesSub ? '' : ' (note: cnf differs from sub - see utils/cnf.ts)'
        }`

        log('✅ Embedded VC also verified (issuer signature, holder binding via cnf OK).', {
          issuer: vcResult.issuer,
          sub: vcPayload.sub,
          expectedHolderDidFromCnf: expectedHolderDid,
        })
      }

      onPresented({ jwt: vpJwt, nonce })
      setStatus({
        ok: true,
        msg: `✓ VP verified. holder = ${vpResult.issuer} - nonce match: ${nonceOk ? '✓' : '✗'}.${vcLine}`,
      })
      log('✅ verifyJWT() accepted the VP - holder key verified.', {
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