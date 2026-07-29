import { useState } from 'react'
import { verifyJWT } from 'did-jwt'
import { Resolver } from 'did-resolver'
import { WebAuthnVerifier } from 'did-jwt-webauthn-signer'
import type { PasskeyIdentity } from '../utils/registration'
import type { StepResult } from './step-types'
import type { PresentedVp } from '../App'

interface Props {
  identity: PasskeyIdentity | null
  presentedVp: PresentedVp | null
  resolver: Resolver
  log: (msg: string, obj?: unknown) => void
}

export default function Step5Replay({ identity, presentedVp, resolver, log }: Props) {
    const [result, setResult] = useState<StepResult | null>(null)

    const handleClick = async () => {
        if (!presentedVp || !identity) return

        try {
            const freshChallenge = crypto.randomUUID()
            const vpResult = await verifyJWT(
                presentedVp.jwt,
                { resolver: resolver },
                new WebAuthnVerifier(identity.rpId, { origin: location.origin }),
            )
            const presentedNonce = (vpResult.payload as {nonce?: string}).nonce

            if (presentedNonce === freshChallenge) {
                setResult({ok: false, msg: 'Stale nonce matched a fresh challenge: astronomically unlikely; treat as a bug'})
                return
            }

            setResult({ok: true, msg: `Replay rejected. Signature still verifies, but nonce is stale. Expected ${freshChallenge}, got ${presentedNonce ?? '∅'}. Signature validity ≠ freshness.`})
        } catch (e) {
            const message = (e as Error).message
            setResult({ok: false, msg: `fail: ${message}`})
            log(`Replay step failed: ${message}`)
        }
    }

    return (
        <div className='step'>
            <h2>5. Replay (stale VP rejection)</h2>
            <button type="button" onClick={handleClick} disabled={!presentedVp}>Replay old presentation</button>
            {result && <p className={result.ok ? 'ok': 'bad'}>{result.msg}</p>}
        </div>
    )
}