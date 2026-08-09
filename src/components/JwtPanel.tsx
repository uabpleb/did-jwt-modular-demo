import DecodedJwt from "./DecodedJwt"

interface Props {
  jwt: string | null
}

export default function JwtPanel({ jwt }: Props) {
  if (!jwt) return null
  return (
    <div className="step">
      <h2>Last signed JWT</h2>
      <DecodedJwt jwt={jwt} />
    </div>
  )
}