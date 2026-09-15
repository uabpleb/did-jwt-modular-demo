import { useState } from 'react'
import { verifyJWT } from 'did-jwt'
import { Resolver } from 'did-resolver'
import { WebAuthnVerifier, base64urlDecode, base64urlEncode } from 'did-jwt-webauthn-signer'
import type { PasskeyIdentity } from 'did-jwt-webauthn-signer'
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
    const [diff, setDiff] = useState<BeforeAfter | null>(null)

    const handleClick = async () => {
        if (!jwt || !identity) return

        const [header, payload, signature] = jwt.split('.')

        // Decode -> mutate the actual claim -> re-encode, so the tampered JWT
        // stays a well-formed JWS (valid base64url, valid JSON). Flipping raw
        // characters in the encoded string risks breaking the base64url
        // alphabet/padding itself, which fails at JWS PARSING - a different,
        // less interesting failure than the one this step means to demonstrate
        // (signature mismatch due to changed content).
        const decoded = JSON.parse(new TextDecoder().decode(base64urlDecode(payload))) as Record<string, unknown>
        const before = JSON.stringify(decoded.sub)
        decoded.sub = typeof decoded.sub === 'string' ? `${decoded.sub}TAMPERED` : 'TAMPERED'
        const after = JSON.stringify(decoded.sub)

        const tamperedPayload = base64urlEncode(new TextEncoder().encode(JSON.stringify(decoded)))
        const tamperedJwt = `${header}.${tamperedPayload}.${signature}`
        setDiff({ before, after })

        try {
            await verifyJWT(tamperedJwt, { resolver }, new WebAuthnVerifier(identity.rpId, { origin: location.origin, requireDeviceBound: deviceBoundRequired }))
            setResult({ ok: false, msg: 'Tampered JWT unexpectedly verified, incorrect behavior' })
            log('Tampered JWT unexpectedly verified, incorrect behavior')
        } catch (e) {
            const message = (e as Error).message
            setResult({ ok: true, msg: `Correctly rejected: ${message}` })
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
                before sub: {diff.before}
                {'\n'}after sub:  {diff.after}
                </pre>
            )}
        </div>
    )
}