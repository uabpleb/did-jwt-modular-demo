import { base64urlDecode } from 'did-jwt-webauthn-signer'

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

export default function DecodedJwt({ jwt, label }: Props) {
  const parts = jwt.split('.')
  if (parts.length !== 3) {
    // Not a plain JWT (e.g. an SD combined string) — fall back to raw display.
    return <pre>{jwt}</pre>
  }

  const header = decodeSegment(parts[0])
  const payload = decodeSegment(parts[1])
  const sigPreview = parts[2].length > 24 ? `${parts[2].slice(0, 24)}…` : parts[2]

  return (
    <div>
      {label && <p style={{ fontWeight: 600, marginBottom: 4 }}>{label}</p>}
      <p style={{ fontSize: '0.8rem', color: '#64748b', marginBottom: 4 }}>header</p>
      <pre>{JSON.stringify(header, null, 2)}</pre>
      <p style={{ fontSize: '0.8rem', color: '#64748b', marginBottom: 4 }}>payload</p>
      <pre>{JSON.stringify(payload, null, 2)}</pre>
      <p style={{ fontSize: '0.75rem', color: '#94a3b8' }}>
        signature (base64url, not human-meaningful): <code>{sigPreview}</code>
      </p>
    </div>
  )
}