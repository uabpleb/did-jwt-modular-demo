// Decoders that make a WebAuthn-signed JWT transparent in the UI.
//
// The whole point of the `alg: WebAuthn` module is that the JWS signature segment
// is NOT a bare ES256 signature over the signing input. It is a base64url JSON blob
// `{ s, a, c }` (signature, authenticatorData, clientDataJSON), and the authenticator
// actually signs `authenticatorData ‖ SHA-256(clientDataJSON)` with the JWT signing
// input carried inside the WebAuthn `challenge`. These helpers crack that open so the
// demo can show it rather than assert it.

function b64urlToBytes(s: string): Uint8Array {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4)
  const bin = atob(b64)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

function b64urlToString(s: string): string {
  return new TextDecoder().decode(b64urlToBytes(s))
}

function bytesToB64url(bytes: Uint8Array): string {
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function hex(bytes: Uint8Array, max = 16): string {
  const head = Array.from(bytes.slice(0, max), (b) => b.toString(16).padStart(2, '0')).join(' ')
  return bytes.length > max ? `${head} … (${bytes.length} bytes)` : head
}

export interface WebAuthnFlags {
  byte: string // hex of the flags byte
  UP: boolean // user present
  UV: boolean // user verified
  BE: boolean // backup eligible  (BE=0 ⟹ device-bound)
  BS: boolean // backup state (currently backed up)
  AT: boolean // attested credential data included
  ED: boolean // extension data included
}

export interface JwtInspection {
  header: unknown
  payload: unknown
  /** Decoded WebAuthn signature container, present only for `alg: WebAuthn`. */
  webauthn?: {
    clientData: unknown // parsed clientDataJSON
    rpIdHash: string // hex (first 32 bytes of authenticatorData)
    flags: WebAuthnFlags
    signCount: number
    signatureDerHex: string
    /** Does the challenge inside clientDataJSON equal SHA-256(signing input)? */
    challengeBindsSigningInput: boolean
    expectedChallenge: string
    actualChallenge: string
  }
  raw: { header: string; payload: string; signature: string }
}

function parseFlags(flagsByte: number): WebAuthnFlags {
  return {
    byte: '0x' + flagsByte.toString(16).padStart(2, '0'),
    UP: (flagsByte & 0x01) !== 0,
    UV: (flagsByte & 0x04) !== 0,
    BE: (flagsByte & 0x08) !== 0,
    BS: (flagsByte & 0x10) !== 0,
    AT: (flagsByte & 0x40) !== 0,
    ED: (flagsByte & 0x80) !== 0,
  }
}

/**
 * Decode a JWT into its parts. For `alg: WebAuthn` it additionally unpacks the
 * `{ s, a, c }` blob and verifies that the WebAuthn `challenge` is the SHA-256 of
 * the JWT signing input — the load-bearing claim of the whole design.
 */
export async function inspectJwt(jwt: string): Promise<JwtInspection> {
  const [h, p, s] = jwt.split('.')
  const header = JSON.parse(b64urlToString(h))
  const payload = JSON.parse(b64urlToString(p))

  const inspection: JwtInspection = {
    header,
    payload,
    raw: { header: h, payload: p, signature: s },
  }

  if ((header as { alg?: string }).alg === 'WebAuthn') {
    const blob = JSON.parse(b64urlToString(s)) as { s: string; a: string; c: string }
    const clientData = JSON.parse(b64urlToString(blob.c))
    const authData = b64urlToBytes(blob.a)

    // The signer hashes the signing input (`header.payload`) into the challenge.
    const signingInput = new TextEncoder().encode(`${h}.${p}`)
    const expectedChallenge = bytesToB64url(new Uint8Array(await crypto.subtle.digest('SHA-256', signingInput)))
    const actualChallenge = (clientData as { challenge?: string }).challenge ?? ''

    inspection.webauthn = {
      clientData,
      rpIdHash: hex(authData.slice(0, 32), 32),
      flags: parseFlags(authData[32]),
      signCount: new DataView(authData.buffer, authData.byteOffset).getUint32(33, false),
      signatureDerHex: hex(b64urlToBytes(blob.s), 12),
      challengeBindsSigningInput: actualChallenge === expectedChallenge,
      expectedChallenge,
      actualChallenge,
    }
  }

  return inspection
}
