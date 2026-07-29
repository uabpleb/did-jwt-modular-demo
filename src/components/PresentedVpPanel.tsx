import type { PresentedVp } from '../App'

interface Props {
  presentedVp: PresentedVp | null
}

export default function PresentedVpPanel({ presentedVp }: Props) {
  if (!presentedVp) return null
  return (
    <div className="step">
      <h2>Presented VP</h2>
      <pre>{JSON.stringify(presentedVp, null, 2)}</pre>
    </div>
  )
}