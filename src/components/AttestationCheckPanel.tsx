import { useState } from 'react'
import { checkAttestation } from '../utils/registration'
import type { PasskeyIdentity } from 'did-jwt-webauthn-signer'
import type { AttestationResult } from 'did-jwt-webauthn-signer'
import { parsePemRoots } from '../utils/pem'
import DecodedAttestationObject from './DecodedAttestationObject'

interface Props {
  identity: PasskeyIdentity | null
  trustedRootsPem: string
}

export default function AttestationCheckPanel({ identity, trustedRootsPem }: Props) {
  const [result, setResult] = useState<AttestationResult | null>(null)
  const [checked, setChecked] = useState(false)

  const handleCheck = async () => {
    if (!identity) return
    const trustedRoots = parsePemRoots(trustedRootsPem)
    const res = await checkAttestation(identity, trustedRoots)
    setResult(res)
    setChecked(true)
  }

  if (!identity) return null

  return (
    <div className="step">
      <h2>Attestation</h2>
      {identity.attestationObject ? (
        <>
          <DecodedAttestationObject attestationObject={identity.attestationObject} />

          <button type="button" onClick={handleCheck} style={{ marginTop: 10 }}>
            Check attestation
          </button>
          {checked && result && (
            <p className={result.verified ? 'ok' : 'bad'}>
              fmt: {result.fmt} - trustLevel: {result.trustLevel} - aaguid: {result.aaguid ?? 'n/a'}
            </p>
          )}
          {checked && !result && <p className="bad">No attestation available to check.</p>}
        </>
      ) : (
        <p style={{ fontSize: '0.8rem', color: '#94a3b8' }}>
          No attestation captured for this identity (registered before this feature, or authenticator returned none).
        </p>
      )}
    </div>
  )
}