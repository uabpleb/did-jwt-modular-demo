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

interface BeforeAfter {
    before: string,
    after: string
}

export default function Step6Tamper({ identity, jwt, resolver, deviceBoundRequired, log }: Props) {
    const [result, setResult] = useState<StepResult | null>(null)
    const [diff, setDiff] = useState<BeforeAfter| null >(null)

    const handleClick = async () => {
        if (!jwt || !identity) return

        // flip the last 2 characters of the payload segment, but maintain the signature
        const [header, payload, signature] = jwt.split('.')
        const lastChars = payload.slice(-2).split('')
        const flippedPayload = payload.slice(0, -2) + lastChars.reverse().join()
        const tamperedJwt = `${header}.${flippedPayload}.${signature}`
        setDiff({before: payload.slice(-10), after: flippedPayload.slice(-10)})

        try {
            await verifyJWT(tamperedJwt, {resolver}, new WebAuthnVerifier(identity.rpId, { origin: location.origin, requireDeviceBound: deviceBoundRequired}))
            setResult({ok: false, msg: 'Tampered JWT unexpectedly verified, incorrect behavior'})
            log('Tampered JWT unexpectedly verified, incorrect behavior')
        } catch (e) {
            const message = (e as Error).message
            setResult({ok: true, msg: `Correctly rejected: ${message}`})
            log(`Tampered JWT correctly rejected by verifyJWT(): ${message}`)
        }
        
    }

    return (
        <div className='step'>
            <h2>6. Tamper (payload mutation)</h2>
            <button type='button' onClick={handleClick} disabled={!jwt}>Tamper & re-verify</button>
            {result && <p className={result.ok ? 'ok' : 'bad'}>{result.msg}</p>}
            {diff && (
                <pre className="mono" style={{ fontSize: '0.78rem' }}>
                before: …{diff.before.slice(0, -2)}
                <span className="hl">{diff.before.slice(-2)}</span>
                {'\n'}after:  …{diff.after.slice(0, -2)}
                <span className="hl">{diff.after.slice(-2)}</span>
                </pre>
            )}
        </div>
    )
}