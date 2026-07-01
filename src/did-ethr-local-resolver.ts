// A network-free `did:ethr` resolver in the `did-resolver` `getResolver()` shape.
//
// The real `ethr-did-resolver` reads the ERC-1056 registry over JSON-RPC; this
// demo never touches a chain, so we synthesize the *default* DID document the
// registry would return for an address with no on-chain modifications: a single
// `EcdsaSecp256k1RecoveryMethod2020` controller key carrying the address as a
// CAIP-10 `blockchainAccountId` — exactly what `Eip712Verifier` matches against.

import type { DIDDocument, DIDResolutionResult, DIDResolver, ParsedDID, ResolverRegistry } from 'did-resolver'

const CHAIN_ID = 1 // must agree with the `domain.chainId` the demo signs under

const resolve: DIDResolver = async (did: string, parsed: ParsedDID): Promise<DIDResolutionResult> => {
  const address = parsed.id
  if (!/^0x[0-9a-fA-F]{40}$/.test(address)) {
    return {
      didResolutionMetadata: { error: 'invalidDid', message: 'did:ethr identifier is not a 0x address' },
      didDocument: null,
      didDocumentMetadata: {},
    }
  }

  const vmId = `${did}#controller`
  const didDocument: DIDDocument = {
    '@context': [
      'https://www.w3.org/ns/did/v1',
      'https://w3id.org/security/suites/secp256k1recovery-2020/v2',
    ],
    id: did,
    verificationMethod: [
      {
        id: vmId,
        type: 'EcdsaSecp256k1RecoveryMethod2020',
        controller: did,
        blockchainAccountId: `eip155:${CHAIN_ID}:${address}`,
      },
    ],
    authentication: [vmId],
    assertionMethod: [vmId],
  }

  return {
    didResolutionMetadata: { contentType: 'application/did+ld+json' },
    didDocument,
    didDocumentMetadata: {},
  }
}

/** `getResolver()` registry entry for a local `did:ethr` method — pass to `new Resolver(...)`. */
export function getResolver(): ResolverRegistry {
  return { ethr: resolve }
}
