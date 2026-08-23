import { useState } from 'react'
import { checkAttestation } from '../utils/registration'
import type { PasskeyIdentity } from '../utils/registration'
import type { AttestationResult } from 'did-jwt-webauthn-signer'
import { parsePemRoots } from '../utils/pem'

interface Props {
  identity: PasskeyIdentity | null
  trustedRootsPem: string
}

export default function IdentityPanel({ identity, trustedRootsPem }: Props) {
  const [result, setResult] = useState<AttestationResult | null>(null)
  const [checked, setChecked] = useState(false)

  const handleCheck = async () => {
    if (!identity) return
    
    const  trustedRoots = parsePemRoots(trustedRootsPem) 
    const res = await checkAttestation(identity, trustedRoots)
    setResult(res)
    setChecked(true)
  }

  return (
    <div className="step">
      <h2>Identity</h2>
      {identity ? (
        <>
          <pre>{JSON.stringify(identity, null, 2)}</pre>
          <button type="button" onClick={handleCheck} disabled={!identity.attestationObject}>
            Check attestation
          </button>
          {!identity.attestationObject && (
            <p style={{ fontSize: '0.8rem', color: '#94a3b8' }}>
              No attestation captured for this identity (registered before this feature, or authenticator returned none).
            </p>
          )}
          {checked && result && (
            <p className={result.verified ? 'ok' : 'bad'}>
              fmt: {result.fmt} - trustLevel: {result.trustLevel} - aaguid: {result.aaguid ?? 'n/a'}
            </p>
          )}
          {checked && !result && (
            <p className="bad">No attestation available to check.</p>
          )}
        </>
      ) : (
        <p>No passkey yet. Register one below.</p>
      )}
    </div>
  )
}