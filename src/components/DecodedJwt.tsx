import { base64urlDecode, base64urlEncode, decodeAssertion, hash, parseAuthenticatorData } from 'did-jwt-webauthn-signer'

interface Props {
  jwt: string
  label?: string
}

function decodeSegment(b64: string): unknown {
  try {
    return JSON.parse(new TextDecoder().decode(base64urlDecode(b64)))
  } catch {
    return null
  }
}

function truncate(s: string, n = 24): string {
  return s.length > n ? `${s.slice(0, n)}…` : s
}

export default function DecodedJwt({ jwt, label }: Props) {
  const parts = jwt.split('.')
  if (parts.length !== 3) {
    // Not a plain JWT (e.g. an SD combined string) - fall back to raw display.
    return <pre>{jwt}</pre>
  }

  const header = decodeSegment(parts[0])
  const payload = decodeSegment(parts[1])

  let signatureView: Record<string, unknown> | null = null
  let challengeMatches = false

  try {
    const assertion = decodeAssertion(parts[2])
    const clientData = JSON.parse(new TextDecoder().decode(base64urlDecode(assertion.clientDataJSON))) as {
      type: string
      challenge: string
      origin: string
    }
    const authData = parseAuthenticatorData(base64urlDecode(assertion.authenticatorData))

    // The binding proof: challenge must equal sha256(header.payload) - see webauthn-verifier.ts.
    const expectedChallenge = base64urlEncode(hash(`${parts[0]}.${parts[1]}`))
    challengeMatches = clientData.challenge === expectedChallenge

    signatureView = {
      authenticatorData: {
        rpIdHash: truncate(base64urlEncode(authData.rpIdHash)),
        flags: {
          userPresent: authData.flags.userPresent,
          userVerified: authData.flags.userVerified,
          backupEligible: authData.flags.backupEligible,
          backupState: authData.flags.backupState,
        },
        signCount: authData.signCount,
      },
      clientDataJSON: {
        type: clientData.type,
        origin: clientData.origin,
        challenge: truncate(clientData.challenge),
      },
      signature: `${truncate(assertion.signature)} (ECDSA, DER, over authenticatorData || SHA256(clientDataJSON))`,
    }
  } catch {
    // Not a WebAuthn-signed JWT (different alg), or malformed - signatureView stays null
  }

  return (
    <div>
      {label && <p style={{ fontWeight: 600, marginBottom: 4 }}>{label}</p>}

      <p style={{ fontSize: '0.8rem', color: '#64748b', marginBottom: 4 }}>header</p>
      <pre>{JSON.stringify(header, null, 2)}</pre>

      <p style={{ fontSize: '0.8rem', color: '#64748b', marginBottom: 4 }}>payload</p>
      <pre>{JSON.stringify(payload, null, 2)}</pre>

      <p style={{ fontSize: '0.8rem', color: '#64748b', marginBottom: 4 }}>signature (WebAuthn assertion)</p>
      {signatureView ? (
        <>
          <pre>{JSON.stringify(signatureView, null, 2)}</pre>
          <p style={{ fontSize: '0.85rem' }} className={challengeMatches ? 'ok' : 'bad'}>
            {challengeMatches ? '✓' : '✗'} challenge === sha256(header.payload) — the binding proof
          </p>
        </>
      ) : (
        <pre style={{ fontSize: '0.75rem', color: '#94a3b8' }}>{truncate(parts[2])}</pre>
      )}
    </div>
  )
}