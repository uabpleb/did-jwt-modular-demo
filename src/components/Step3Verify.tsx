import { useState } from 'react'
import { verifyJWT } from 'did-jwt'
import { Resolver } from 'did-resolver'
import { WebAuthnVerifier, extractAttestation, base64urlDecode } from 'did-jwt-webauthn-signer'
import type { PasskeyIdentity } from '../utils/registration'
import type { StepResult } from './step-types'
import { parsePemRoots } from '../utils/pem'

interface Props {
  identity: PasskeyIdentity | null
  jwt: string | null
  resolver: Resolver
  deviceBoundRequired: boolean
  trustedRootsPem: string
  onTrustedRootsPemChange: (pem: string) => void
  log: (msg: string, obj?: unknown) => void
}

export default function Step3Verify({ identity, jwt, resolver, deviceBoundRequired, trustedRootsPem, onTrustedRootsPemChange, log }: Props) {
  const [status, setStatus] = useState<StepResult | null>(null)
  const [attestationStatus, setAttestationStatus] = useState<StepResult | null>(null)
  //const [trustedRootsPem, setTrustedRootsPem] = useState('')


  const checkAttestation = async (payload: Record<string, unknown>) => {
    if (!identity?.attestationClientDataHash) {
      // If identity wasn't registered with attestation status, ignore it
      setAttestationStatus(null)
      return
    }

    try {
      const trustedRoots = parsePemRoots(trustedRootsPem)
      const clientDataHash = base64urlDecode(identity.attestationClientDataHash)
      const attestationResult = await extractAttestation(payload, clientDataHash, trustedRoots)

      if (!attestationResult) {
        setAttestationStatus({ ok: false, msg: 'No attestation claim embedded in this credential.' })
        return
      }

      const aaguidPart = attestationResult.aaguid
        ? `, aaguid=${attestationResult.aaguid} (${attestationResult.aaguidCorroborated ? 'certificate-corroborated' : 'self-reported only'})`
        : ''
      const noRootsNote = trustedRoots.length === 0 && attestationResult.trustLevel === 'unverified'
        ? ' - no trusted roots configured below, so "chain-verified" is not reachable yet'
        : ''

      setAttestationStatus({
        ok: attestationResult.verified,
        msg: `Attestation: fmt=${attestationResult.fmt}, trustLevel=${attestationResult.trustLevel}${aaguidPart}${noRootsNote}`,
      })
      log('Attestation check result.', attestationResult)
    } catch (e) {
      const message = (e as Error).message
      setAttestationStatus({ ok: false, msg: `Attestation check errored: ${message}` })
      log(`Attestation check errored: ${message}`)
    }
  }

  const handleVerify = async () => {
    if (!jwt || !identity) return

    try {
      const result = await verifyJWT(
        jwt,
        { resolver },
        new WebAuthnVerifier(identity.rpId, { origin: location.origin, requireDeviceBound: deviceBoundRequired }),
      )
      setStatus({ ok: true, msg: `✓ verifyJWT() succeeded. signer = ${result.signer.id}` })
      log('✅ verifyJWT() succeeded.', { verified: result.verified, signer: result.signer.id, issuer: result.issuer })

      await checkAttestation(result.payload as Record<string, unknown>)
    } catch (e) {
      const message = (e as Error).message
      setStatus({ ok: false, msg: `✗ ${message}` })
      log(`❌ Verification failed: ${message}`)
    }
  }

  const handleVerifyDeviceBound = async () => {
    if (!jwt || !identity) return
    try {
      // Always forces requireDeviceBound: true, regardless of the checkbox -
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

      <details style={{ marginTop: 8 }}>
        <summary>Trusted attestation roots (optional, PEM, paste one or more certificates). Shared with IdentityPanel.</summary>
        <textarea
          rows={4}
          style={{ width: '100%' }}
          placeholder="-----BEGIN CERTIFICATE-----..."
          value={trustedRootsPem}
          onChange={(e) => onTrustedRootsPemChange(e.target.value)}
        />
        <p style={{ fontSize: 12, opacity: 0.7 }}>
          Paste a manufacturer's published root certificate (e.g. Yubico's) here, then re-run
          "Verify credential" to see attestation trustLevel reach "chain-verified". Defaults to
          Chromium built-in DevTools virtual authenticator.
        </p>
      </details>
      {attestationStatus && <p className={attestationStatus.ok ? 'ok' : 'bad'}>{attestationStatus.msg}</p>}
    </div>
  )
}