import { base64urlDecode, base64urlEncode, parseAttestationObject, parseAuthenticatorData } from 'did-jwt-webauthn-signer'

interface Props {
  attestationObject: string // base64url, as stored on PasskeyIdentity
  label?: string
}

export default function DecodedAttestationObject({ attestationObject, label }: Props) {
  let parsed
  try {
    parsed = parseAttestationObject(base64urlDecode(attestationObject))
  } catch (e) {
    return <p className="bad">Failed to decode attestationObject: {(e as Error).message}</p>
  }

  const { fmt, attStmt, authData } = parsed
  const sig = attStmt.sig as Uint8Array | undefined
  const x5c = attStmt.x5c as Uint8Array[] | undefined

  let authInfo: ReturnType<typeof parseAuthenticatorData> | null = null
  try {
    authInfo = parseAuthenticatorData(authData)
  } catch {
    // fmt/attStmt below still render even if authData itself is malformed
  }

  return (
    <div>
      {label && <p style={{ fontWeight: 600, marginBottom: 4 }}>{label}</p>}

      <p style={{ fontSize: '0.8rem', color: '#64748b' }}>fmt</p>
      <pre>{fmt}</pre>

      {authInfo && (
        <>
          <p style={{ fontSize: '0.8rem', color: '#64748b' }}>authData (parsed)</p>
          <pre>{JSON.stringify({ flags: authInfo.flags, signCount: authInfo.signCount }, null, 2)}</pre>
        </>
      )}

      <p style={{ fontSize: '0.8rem', color: '#64748b' }}>attStmt</p>
      <pre>{JSON.stringify(
        {
          alg: attStmt.alg,
          sig: sig ? `${base64urlEncode(sig).slice(0, 24)}… (${sig.length} bytes, DER)` : undefined,
          x5c: x5c ? `${x5c.length} certificate(s) — see attestation check below for chain verification` : undefined,
        },
        null,
        2
      )}</pre>
    </div>
  )
}