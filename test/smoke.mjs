// Headless smoke test for the unified demo's composite wiring (everything the
// page does except the WebAuthn flow, which needs a real authenticator — that
// path is covered by did-jwt-webauthn-signer's own integration test).
//
//   node test/smoke.mjs

import {
  bytesToBase64url,
  CompositeSigner,
  CompositeVerifier,
  createJWT,
  SoftwareSigner,
  SoftwareVerifier,
  verifyJWT,
} from 'did-jwt'
import { Resolver } from 'did-resolver'
import { Eip712Signer, Eip712Verifier } from 'did-jwt-eip712-signer'
import { WebAuthnVerifier } from 'did-jwt-webauthn-signer'
import { Wallet } from 'ethers'
import { ed25519 } from '@noble/curves/ed25519'

const ok = (name) => console.log(`✅ ${name}`)
const fail = (name, e) => {
  console.error(`❌ ${name}: ${e?.message ?? e}`)
  process.exitCode = 1
}

// ---- resolvers (same documents the demo's local resolvers synthesize) ------
const jwkResolve = async (did, parsed) => {
  const jwk = JSON.parse(Buffer.from(parsed.id, 'base64url').toString('utf8'))
  const vmId = `${did}#0`
  return {
    didResolutionMetadata: { contentType: 'application/did+ld+json' },
    didDocument: {
      id: did,
      verificationMethod: [{ id: vmId, type: 'JsonWebKey2020', controller: did, publicKeyJwk: jwk }],
      assertionMethod: [vmId],
      authentication: [vmId],
    },
    didDocumentMetadata: {},
  }
}
const ethrResolve = async (did, parsed) => {
  const vmId = `${did}#controller`
  return {
    didResolutionMetadata: { contentType: 'application/did+ld+json' },
    didDocument: {
      id: did,
      verificationMethod: [
        {
          id: vmId,
          type: 'EcdsaSecp256k1RecoveryMethod2020',
          controller: did,
          blockchainAccountId: `eip155:1:${parsed.id}`,
        },
      ],
      authentication: [vmId],
      assertionMethod: [vmId],
    },
    didDocumentMetadata: {},
  }
}
const resolver = new Resolver({ jwk: jwkResolve, ethr: ethrResolve })

// ---- identities -------------------------------------------------------------
const edPrivateKey = ed25519.utils.randomPrivateKey()
const edJwk = { kty: 'OKP', crv: 'Ed25519', x: bytesToBase64url(ed25519.getPublicKey(edPrivateKey)) }
const edDid = `did:jwk:${bytesToBase64url(new TextEncoder().encode(JSON.stringify(edJwk)))}`
const wallet = Wallet.createRandom()
const ethrDid = `did:ethr:${wallet.address.toLowerCase()}`
const EIP712_DOMAIN = { name: 'did-jwt unified demo', version: '1', chainId: 1 }

// ---- the composite pair (same construction as src/unified.ts) ---------------
const compositeSigner = new CompositeSigner()
  .register(new SoftwareSigner(edPrivateKey, 'EdDSA'), ['EdDSA'])
  .register(new Eip712Signer(wallet.privateKey))

const compositeVerifier = new CompositeVerifier([
  new SoftwareVerifier(),
  new Eip712Verifier(),
  new WebAuthnVerifier('localhost'),
])

const payloadFor = (issuer, alg) => ({
  sub: issuer,
  nbf: Math.floor(Date.now() / 1000),
  vc: {
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    type: ['VerifiableCredential'],
    credentialSubject: { demo: 'composite signer/verifier', alg },
  },
  ...(alg === 'EIP712' ? { domain: EIP712_DOMAIN } : {}),
})

// 1. both algs sign through the one CompositeSigner
const edJwt = await createJWT(payloadFor(edDid, 'EdDSA'), { issuer: edDid, signer: compositeSigner, alg: 'EdDSA' })
const eipJwt = await createJWT(payloadFor(ethrDid, 'EIP712'), {
  issuer: ethrDid,
  signer: compositeSigner,
  alg: 'EIP712',
})
ok('CompositeSigner signed EdDSA and EIP712 JWTs')

// 2. both verify through the one CompositeVerifier
for (const [alg, jwt] of [['EdDSA', edJwt], ['EIP712', eipJwt]]) {
  const { verified, signer } = await verifyJWT(jwt, { resolver }, compositeVerifier)
  if (!verified) throw new Error(`${alg} not verified`)
  ok(`CompositeVerifier verified ${alg} (signer = ${signer.id})`)
}

// 3. negative control: bare SoftwareVerifier handles EdDSA but not EIP712
await verifyJWT(edJwt, { resolver }, new SoftwareVerifier())
ok('SoftwareVerifier alone still verifies EdDSA')
try {
  await verifyJWT(eipJwt, { resolver }, new SoftwareVerifier())
  fail('SoftwareVerifier alone should reject EIP712', 'unexpectedly verified')
} catch {
  ok('SoftwareVerifier alone rejects EIP712 (module removed → alg gone)')
}

// 4. domain policy: pinning a different application domain rejects the EIP712 JWT
const pinned = new CompositeVerifier([
  new SoftwareVerifier(),
  new Eip712Verifier({ expectedDomain: { name: 'SomeOtherApp' } }),
])
try {
  await verifyJWT(eipJwt, { resolver }, pinned)
  fail('expectedDomain policy should reject', 'unexpectedly verified')
} catch (e) {
  if (!/Domain policy violation/.test(e.message)) throw e
  ok('expectedDomain policy rejects a foreign-domain EIP712 JWT')
}

// 5. tamper: one payload byte flipped → both algs reject
for (const [alg, jwt] of [['EdDSA', edJwt], ['EIP712', eipJwt]]) {
  const [h, p, s] = jwt.split('.')
  const tampered = `${h}.${p.slice(0, -2)}${p.slice(-2) === 'AA' ? 'AB' : 'AA'}.${s}`
  try {
    await verifyJWT(tampered, { resolver }, compositeVerifier)
    fail(`tampered ${alg} JWT should be rejected`, 'unexpectedly verified')
  } catch {
    ok(`tampered ${alg} JWT rejected`)
  }
}

console.log(process.exitCode ? '\nSmoke test FAILED.' : '\nAll smoke checks passed.')
