import type { PasskeyIdentity } from 'did-jwt-webauthn-signer'
import { base64urlDecode } from 'did-jwt-webauthn-signer'

interface Props {
  label: string
  identities: PasskeyIdentity[]
  value: PasskeyIdentity | null
  onChange: (id: PasskeyIdentity) => void
}

function decodeDidJwk(did: string): Record<string, string> | null {
  try {
    const raw = did.replace('did:jwk:', '').split('#')[0] // strip prefix, drop any #key-id fragment
    return JSON.parse(new TextDecoder().decode(base64urlDecode(raw)))
  } catch {
    return null
  }
}

export default function IdentitySelect({ label, identities, value, onChange }: Props) {
  const decoded = value ? decodeDidJwk(value.didJwk) : null

  return (
    <label style={{ display: 'flex', alignItems: 'flex-start', gap: 10, margin: '6px 0' }}>
      <span style={{ whiteSpace: 'nowrap' }}>
        {label}{' '}
        <select
          value={value?.credentialId ?? ''}
          onChange={(e) => {
            const found = identities.find((i) => i.credentialId === e.target.value)
            if (found) onChange(found)
          }}
        >
          {identities.map((i) => (
            <option key={i.credentialId} value={i.credentialId}>
              {i.didJwk.slice(0, 28)}…
            </option>
          ))}
        </select>
      </span>
      {decoded && (
        <pre style={{ margin: 0, fontSize: '0.75rem' }}>{JSON.stringify(decoded, null, 2)}</pre>
      )}
    </label>
  )
}