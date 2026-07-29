import { useState } from 'react'
import { verifyJWT } from 'did-jwt'
import { Resolver } from 'did-resolver'
import { WebAuthnVerifier } from 'did-jwt-webauthn-signer'
import type { PasskeyIdentity } from '../utils/registration'
import type { StepResult } from './step-types'

interface Props {
  identity: PasskeyIdentity | null
  jwt: string | null
  resolver: Resolver
  deviceBoundRequired: boolean
  log: (msg: string, obj?: unknown) => void
}

export default function Step3Verify({ identity, jwt, resolver, deviceBoundRequired, log }: Props) {
  const [status, setStatus] = useState<StepResult | null>(null)

  const handleVerify = async () => {
    if (!jwt || !identity) return

    // debug
    console.log('identity.didJwk', identity.didJwk)
    console.log('identity.rpId', identity.rpId, 'vs location.hostname', location.hostname)


    try {
      const result = await verifyJWT(
        jwt,
        { resolver },
        new WebAuthnVerifier(identity.rpId, { origin: location.origin, requireDeviceBound: deviceBoundRequired }),
      )
      setStatus({ ok: true, msg: `✓ verifyJWT() succeeded. signer = ${result.signer.id}` })
      log('✅ verifyJWT() succeeded.', { verified: result.verified, signer: result.signer.id, issuer: result.issuer })
    } catch (e) {
      const message = (e as Error).message
      setStatus({ ok: false, msg: `✗ ${message}` })
      log(`❌ Verification failed: ${message}`)
    }
  }

  const handleVerifyDeviceBound = async () => {
    if (!jwt || !identity) return
    try {
      // DEBUG
      console.log('identity.didJwk', identity.didJwk)
      console.log('identity.rpId', identity.rpId, 'vs location.hostname', location.hostname)


      // Always forces requireDeviceBound: true, regardless of the checkbox —
      // demonstrates rejection of syncable (BE=1) credentials under a strict policy.
      await verifyJWT(
        jwt,
        { resolver },
        new WebAuthnVerifier(identity.rpId, { origin: location.origin, requireDeviceBound: true }),
      )
      setStatus({ ok: true, msg: '✓ Accepted under requireDeviceBound: true.' })
      log('✅ verifyJWT() accepted under requireDeviceBound: true.')
    } catch (e) {
      const message = (e as Error).message
      setStatus({
        ok: false,
        msg: `⛔ Rejected under requireDeviceBound: true. ${message}`,
      })
      log(`⛔ requireDeviceBound rejected the credential: ${message}`)
    }
  }

  return (
    <div className="step">
      <h2>3. Verify</h2>
      <button type="button" onClick={handleVerify} disabled={!jwt}>Verify credential</button>
      <button type="button" onClick={handleVerifyDeviceBound} disabled={!jwt}>Verify requiring device-bound</button>
      {status && <p className={status.ok ? 'ok' : 'bad'}>{status.msg}</p>}
    </div>
  )
}