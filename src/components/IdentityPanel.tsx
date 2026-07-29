import type { PasskeyIdentity } from '../utils/registration'

interface Props {
  identity: PasskeyIdentity | null
}

export default function IdentityPanel({ identity }: Props) {
  return (
    <div className="step">
      <h2>Identity</h2>
      {identity ? (
        <pre>{JSON.stringify(identity, null, 2)}</pre>
      ) : (
        <p>No passkey yet. Register one below.</p>
      )}
    </div>
  )
}