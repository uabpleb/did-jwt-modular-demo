// A spec-complete `did:jwk` method resolver in the `did-resolver` `getResolver()`
// shape, so the demo drives the real `Resolver` registry (method dispatch,
// caching, error metadata) instead of an ad-hoc `{ resolve }` object.
//
// did:jwk is self-contained: `did:jwk:<base64url(utf8(JSON(jwk)))>` — resolution
// is a local decode (no network), but it goes through the genuine resolver
// machinery you'd also register `ethr-did-resolver` / `web-did-resolver` against.
// Method spec: https://github.com/quartzjer/did-jwk/blob/main/spec.md

import type {
  DIDDocument,
  DIDResolutionResult,
  DIDResolver,
  JsonWebKey,
  ParsedDID,
  ResolverRegistry,
} from 'did-resolver'

function b64urlToString(s: string): string {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4)
  const bin = atob(b64)
  const bytes = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
  return new TextDecoder().decode(bytes)
}

function fail(error: string, message?: string): DIDResolutionResult {
  return {
    didResolutionMetadata: message ? { error, message } : { error },
    didDocument: null,
    didDocumentMetadata: {},
  }
}

const resolve: DIDResolver = async (did: string, parsed: ParsedDID): Promise<DIDResolutionResult> => {
  let jwk: Record<string, unknown>
  try {
    jwk = JSON.parse(b64urlToString(parsed.id))
  } catch {
    return fail('invalidDid', 'did:jwk identifier is not base64url(JSON(jwk))')
  }
  if (typeof jwk !== 'object' || jwk == null || typeof jwk.kty !== 'string') {
    return fail('invalidDid', 'decoded JWK is missing "kty"')
  }

  const vmId = `${did}#0`
  // Per the did:jwk spec: an encryption key (use:"enc") is only for keyAgreement;
  // any other key gets the signing/invocation relationships.
  const isEnc = jwk.use === 'enc'
  const didDocument: DIDDocument = {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/jws-2020/v1'],
    id: did,
    verificationMethod: [
      { id: vmId, type: 'JsonWebKey2020', controller: did, publicKeyJwk: jwk as JsonWebKey },
    ],
    ...(isEnc
      ? { keyAgreement: [vmId] }
      : {
          assertionMethod: [vmId],
          authentication: [vmId],
          capabilityInvocation: [vmId],
          capabilityDelegation: [vmId],
        }),
  }

  return {
    didResolutionMetadata: { contentType: 'application/did+ld+json' },
    didDocument,
    didDocumentMetadata: {},
  }
}

/** `getResolver()` registry entry for the `did:jwk` method — pass to `new Resolver(...)`. */
export function getResolver(): ResolverRegistry {
  return { jwk: resolve }
}
