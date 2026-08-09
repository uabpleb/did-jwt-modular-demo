import type { PresentedVp } from '../App'
import DecodedJwt from './DecodedJwt'

interface Props {
  presentedVp: PresentedVp | null
}

export default function PresentedVpPanel({ presentedVp }: Props) {
  if (!presentedVp) return null
  return (
    <div className="step">
      <h2>Presented VP</h2>
      <p style={{ fontSize: '0.85rem', color: '#64748b' }}>nonce: <code>{presentedVp.nonce}</code></p>
      <DecodedJwt jwt={presentedVp.jwt} />
    </div>
  )
}