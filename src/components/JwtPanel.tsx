import DecodedJwt from "./DecodedJwt"

interface Props {
  jwt: string | null
}

export default function SignedVcPanel({ jwt }: Props) {
  if (!jwt) return null
  return (
    <div className="step">
      <h2>Signed VC</h2>
      <DecodedJwt jwt={jwt} />
    </div>
  )
}