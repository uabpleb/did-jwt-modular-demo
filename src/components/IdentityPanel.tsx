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

export default function IdentityPanel({ identity, trustedRootsPem }: Props) {
  const [showRaw, setShowRaw] = useState(false)
  const [showAttestation, setShowAttestation] = useState(false)
  const [result, setResult] = useState<AttestationResult | null>(null)
  const [checked, setChecked] = useState(false)

  const handleCheck = async () => {
    if (!identity) return
    const trustedRoots = parsePemRoots(trustedRootsPem)
    const res = await checkAttestation(identity, trustedRoots)
    setResult(res)
    setChecked(true)
  }

  return (
    <div className="step">
      <h2>Identity</h2>
      {identity ? (
        <>
          <dl style={{ fontSize: '0.9rem' }}>
            <dt style={{ fontWeight: 600 }}>did:jwk</dt>
            <dd><code>{identity.didJwk}</code></dd>
            <dt style={{ fontWeight: 600, marginTop: 8 }}>Algorithm</dt>
            <dd>{identity.coseAlgorithm === -7 ? 'ES256 (P-256)' : identity.coseAlgorithm === -35 ? 'ES384 (P-384)' : identity.coseAlgorithm}</dd>
            <dt style={{ fontWeight: 600, marginTop: 8 }}>Device-bound</dt>
            <dd>{identity.deviceBound ? 'yes (BE=0)' : 'no — syncable passkey (BE=1)'}</dd>
            <dt style={{ fontWeight: 600, marginTop: 8 }}>AAGUID</dt>
            <dd><code>{identity.aaguid ?? 'n/a'}</code></dd>
          </dl>

          <button type="button" onClick={() => setShowRaw(!showRaw)} style={{ marginTop: 10 }}>
            {showRaw ? 'Hide' : 'Show'} raw identity
          </button>
          {showRaw && <pre>{JSON.stringify(identity, null, 2)}</pre>}

          <button type="button" onClick={() => setShowAttestation(!showAttestation)} style={{ marginTop: 10, marginLeft: 8 }}>
            {showAttestation ? 'Hide' : 'Show'} attestation
          </button>

          {showAttestation && (
            <div style={{ marginTop: 10, paddingTop: 10, borderTop: '1px solid #e2e8f0' }}>
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
          )}
        </>
      ) : (
        <p>No passkey yet. Register one below.</p>
      )}
    </div>
  )
}