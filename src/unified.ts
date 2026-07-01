// Unified multi-algorithm demo: ONE CompositeSigner and ONE CompositeVerifier
// serving three algorithm modules at once —
//   EdDSA    → SoftwareSigner / SoftwareVerifier   (did-jwt built-ins, did:jwk)
//   EIP712   → Eip712Signer / Eip712Verifier       (external module, did:ethr)
//   WebAuthn → WebAuthnSigner / WebAuthnVerifier   (external module, did:jwk, passkey)
//
// Every `createJWT` call goes through the same CompositeSigner instance and every
// `verifyJWT` call through the same CompositeVerifier instance; only the `alg`
// differs. That dispatch seam is the whole point of the fork.

import {
  bytesToBase64url,
  CompositeSigner,
  CompositeVerifier,
  createJWT,
  decodeJWT,
  SoftwareSigner,
  SoftwareVerifier,
  verifyJWT,
} from 'did-jwt'
import { Resolver } from 'did-resolver'
import { Eip712Signer, Eip712Verifier } from 'did-jwt-eip712-signer'
import {
  registerPasskey,
  WebAuthnSigner,
  WebAuthnVerifier,
  WEBAUTHN_ALG,
  type PasskeyIdentity,
} from 'did-jwt-webauthn-signer'
import { BrowserProvider, type Eip1193Provider, type JsonRpcSigner, type TypedDataDomain } from 'ethers'
import { getResolver as ethrDidResolver } from 'ethr-did-resolver'
import { ed25519 } from '@noble/curves/ed25519'
import { getResolver as jwkResolver } from './did-jwk-resolver'

const RP_NAME = 'did-jwt unified demo'
const STORAGE_KEY = 'passkey-identity' // shared with the passkey deep-dive page
const rpId = location.hostname

const EIP712_DOMAIN_NAME = 'did-jwt unified demo'

type Alg = 'EdDSA' | 'EIP712' | typeof WEBAUTHN_ALG
const ALGS: Alg[] = ['EdDSA', 'EIP712', WEBAUTHN_ALG]

// ---- DOM helpers ---------------------------------------------------------
const $ = (id: string) => document.getElementById(id) as HTMLElement
const esc = (s: string) => s.replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]!))
const enable = (id: string, on: boolean) => (($(id) as HTMLButtonElement).disabled = !on)

const log = (msg: string, obj?: unknown) => {
  const out = $('log')
  if (out.querySelector('.empty')) out.textContent = ''
  const time = new Date().toLocaleTimeString()
  const body = obj !== undefined ? `\n${JSON.stringify(obj, null, 2)}` : ''
  const entry = document.createElement('div')
  entry.style.marginBottom = '0.6rem'
  entry.innerHTML = `<span style="color:var(--muted)">${time}</span>  ${esc(msg)}<span class="mono">${esc(body)}</span>`
  out.prepend(entry)
}

// ---- The resolver registry: did:jwk (EdDSA + passkey) and did:ethr (EIP-712)
// The did:ethr method is added once MetaMask connects — its network + provider
// are needed to build the real ethr-did-resolver (reads the ERC-1056 registry).
let resolver = new Resolver({ ...jwkResolver() })

// ---- Identities -----------------------------------------------------------
// 1. Software Ed25519 key → did:jwk
const edPrivateKey = ed25519.utils.randomPrivateKey()
const edJwk = { kty: 'OKP', crv: 'Ed25519', x: bytesToBase64url(ed25519.getPublicKey(edPrivateKey)) }
const edDid = `did:jwk:${bytesToBase64url(new TextEncoder().encode(JSON.stringify(edJwk)))}`

// 2. MetaMask account → did:ethr (populated on connect; null until then)
interface Eip712Identity {
  address: string
  chainId: number
  did: string
  domain: TypedDataDomain
}
let eip712: Eip712Identity | null = null

// 3. Passkey → did:jwk (registered on demand, persisted in localStorage)
let passkey: PasskeyIdentity | null = (() => {
  const raw = localStorage.getItem(STORAGE_KEY)
  return raw ? (JSON.parse(raw) as PasskeyIdentity) : null
})()

// ---- THE composite pair ----------------------------------------------------
// SoftwareSigner's static lists every built-in alg but this instance only holds
// an Ed25519 key, so we register it explicitly for EdDSA. The other two modules
// declare accurate statics and are auto-discovered.
// The Eip712Signer is registered on demand once MetaMask connects (it wraps the
// MetaMask JsonRpcSigner, so the wallet performs the typed-data signature).
const compositeSigner = new CompositeSigner()
  .register(new SoftwareSigner(edPrivateKey, 'EdDSA'), ['EdDSA'])

const compositeVerifier = new CompositeVerifier([
  new SoftwareVerifier(),
  new Eip712Verifier(),
  new WebAuthnVerifier(rpId),
])

function registerPasskeySigner() {
  if (passkey) compositeSigner.register(new WebAuthnSigner(passkey))
}
registerPasskeySigner()

// ---- Rendering -------------------------------------------------------------
const issuerFor: Record<Alg, () => string | null> = {
  EdDSA: () => edDid,
  EIP712: () => eip712?.did ?? null,
  [WEBAUTHN_ALG]: () => passkey?.didJwk ?? null,
}

const jwts: Partial<Record<Alg, string>> = {}

function renderChips() {
  const signerAlgs = compositeSigner.supportedAlgorithms()
  const verifierAlgs = compositeVerifier.supportedAlgorithms()
  $('signer-algs').innerHTML = signerAlgs.map((a) => `<span class="flag on">${esc(a)}</span>`).join(' ')
  $('verifier-algs').innerHTML = verifierAlgs.map((a) => `<span class="flag on">${esc(a)}</span>`).join(' ')
}

function renderIdentities() {
  $('id-eddsa').innerHTML = `<div class="kv mono">
    <span class="k">DID</span><span>${esc(edDid)}</span>
    <span class="k">key</span><span>Ed25519 (in-page, ephemeral)</span>
  </div>`
  $('id-eip712').innerHTML = eip712
    ? `<div class="kv mono">
        <span class="k">DID</span><span>${esc(eip712.did)}</span>
        <span class="k">address</span><span>${esc(eip712.address)}</span>
        <span class="k">chainId</span><span>${esc(String(eip712.chainId))}</span>
        <span class="k">domain</span><span>${esc(JSON.stringify(eip712.domain))}</span>
      </div>`
    : '<span class="empty">MetaMask not connected — connect a wallet.</span>'
  $('id-webauthn').innerHTML = passkey
    ? `<div class="kv mono">
        <span class="k">DID</span><span>${esc(passkey.didJwk)}</span>
        <span class="k">rpId</span><span>${esc(passkey.rpId)}</span>
      </div>`
    : '<span class="empty">No passkey yet — register one.</span>'
}

function renderRow(alg: Alg) {
  const el = $(`row-${alg}`)
  const jwt = jwts[alg]
  if (!jwt) {
    el.innerHTML = '<span class="empty">not signed yet</span>'
    return
  }
  const [h, p, s] = jwt.split('.')
  el.innerHTML = `<div class="jwt-raw mono">
      <span class="seg seg-h">${esc(h.slice(0, 18))}…</span>.<span class="seg seg-p">${esc(p.slice(0, 24))}…</span>.<span class="seg seg-s">${esc(s.slice(0, 18))}…</span>
    </div>
    <details><summary>decoded</summary><pre>${esc(JSON.stringify({ header: decodeJWT(jwt).header, payload: decodeJWT(jwt).payload }, null, 2))}</pre></details>`
}

function refreshGates() {
  enable('btn-register', true)
  enable('btn-sign-EIP712', eip712 != null)
  enable(`btn-sign-${WEBAUTHN_ALG}`, passkey != null)
  const any = ALGS.some((a) => jwts[a])
  enable('btn-verify-all', any)
  enable('btn-verify-software-only', any)
  enable('btn-tamper-all', any)
  enable('btn-domain-policy', jwts['EIP712'] != null)
}

// ---- Signing ----------------------------------------------------------------
async function sign(alg: Alg) {
  const issuer = issuerFor[alg]()
  if (!issuer) return
  const payload: Record<string, unknown> = {
    sub: issuer,
    nbf: Math.floor(Date.now() / 1000),
    vc: {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      type: ['VerifiableCredential'],
      credentialSubject: { demo: 'composite signer/verifier', alg },
    },
  }
  // Eip712Signer requires the EIP-712 domain inside the payload
  if (alg === 'EIP712') payload.domain = eip712!.domain

  // Same CompositeSigner instance for every algorithm — only `alg` changes.
  const jwt = await createJWT(payload, { issuer, signer: compositeSigner, alg })
  jwts[alg] = jwt
  renderRow(alg)
  refreshGates()
  log(`✅ Signed with alg ${alg} through the shared CompositeSigner.`, { issuer, jwt })
}

for (const alg of ALGS) {
  $(`btn-sign-${alg}`).addEventListener('click', () =>
    sign(alg).catch((e) => log(`❌ ${alg} signing failed: ${(e as Error).message}`))
  )
}

// ---- MetaMask connection (EIP-712 identity + did:ethr resolver) ----------------
// Connecting does three things: derives the EIP712 issuer DID from the selected
// account, wires an Eip712Signer to MetaMask's JsonRpcSigner (so the wallet — not
// an in-page key — produces the typed-data signature), and rebuilds the resolver
// with the real ethr-did-resolver reading the ERC-1056 registry via MetaMask.
type InjectedProvider = Eip1193Provider & { on?: (event: string, handler: () => void) => void }
const injected = (window as unknown as { ethereum?: InjectedProvider }).ethereum

async function connectMetaMask() {
  if (!injected) throw new Error('MetaMask not found — install the extension')

  const provider = new BrowserProvider(injected)
  await provider.send('eth_requestAccounts', [])
  const signer: JsonRpcSigner = await provider.getSigner()
  const address = await signer.getAddress()
  const chainId = Number((await provider.getNetwork()).chainId)
  const chainHex = '0x' + chainId.toString(16)
  const did = `did:ethr:${chainHex}:${address.toLowerCase()}`
  const domain: TypedDataDomain = { name: EIP712_DOMAIN_NAME, version: '1', chainId }
  eip712 = { address, chainId, did, domain }

  // MetaMask signs the typed data; register (overriding any prior) the EIP712 signer.
  // The `as never` casts bridge two structurally-identical but distinct `ethers`
  // copies on disk (the demo's vs the eip712-signer fork's own node_modules) — a
  // compile-time-only mismatch of ethers' branded #private fields; see CLAUDE.md.
  compositeSigner.register(new Eip712Signer(signer as never))

  // Rebuild the resolver: did:jwk (local) + did:ethr (ethr-did-resolver via MetaMask).
  resolver = new Resolver({
    ...jwkResolver(),
    ...ethrDidResolver({ networks: [{ chainId, provider: provider as never }] }),
  })

  delete jwts['EIP712'] // a new account/chain invalidates the previous EIP712 JWT
  renderIdentities()
  renderRow('EIP712')
  renderChips()
  refreshGates()
  log('✅ MetaMask connected: Eip712Signer wired to the wallet, did:ethr resolver configured.', {
    did,
    chainId,
    signerAlgs: compositeSigner.supportedAlgorithms(),
  })
}

$('btn-connect-eip712').addEventListener('click', () =>
  connectMetaMask().catch((e) => log(`❌ MetaMask connection failed: ${(e as Error).message}`))
)

// Re-sync when the user switches account or network inside MetaMask.
injected?.on?.('accountsChanged', () => { if (eip712) void connectMetaMask().catch(() => {}) })
injected?.on?.('chainChanged', () => { if (eip712) void connectMetaMask().catch(() => {}) })

// ---- Passkey registration -----------------------------------------------------
$('btn-register').addEventListener('click', async () => {
  try {
    passkey = await registerPasskey({ rpId, rpName: RP_NAME, userName: `user-${Date.now()}` })
    localStorage.setItem(STORAGE_KEY, JSON.stringify(passkey))
    delete jwts[WEBAUTHN_ALG]
    registerPasskeySigner()
    renderIdentities()
    renderRow(WEBAUTHN_ALG)
    renderChips()
    refreshGates()
    log('✅ Passkey registered and its WebAuthnSigner added to the CompositeSigner.', {
      did: passkey.didJwk,
      signerAlgs: compositeSigner.supportedAlgorithms(),
    })
  } catch (e) {
    log(`❌ Passkey registration failed: ${(e as Error).message}`)
  }
})

// ---- Verification ---------------------------------------------------------------
async function verifyAll(verifier: CompositeVerifier | SoftwareVerifier, label: string, expectFailure = false) {
  const lines: string[] = []
  for (const alg of ALGS) {
    const jwt = jwts[alg]
    if (!jwt) continue
    try {
      const result = await verifyJWT(jwt, { resolver }, verifier)
      lines.push(
        `<span class="${expectFailure && alg !== 'EdDSA' ? 'warn' : 'ok'}">✓ ${esc(alg)}</span> signer = <span class="mono">${esc(result.signer.id)}</span>`
      )
      log(`✅ [${label}] verified ${alg} JWT.`, { signer: result.signer.id })
    } catch (e) {
      lines.push(`<span class="bad">✗ ${esc(alg)}</span> <span class="mono">${esc((e as Error).message)}</span>`)
      log(`⛔ [${label}] rejected ${alg} JWT: ${(e as Error).message}`)
    }
  }
  return lines.join('<br>')
}

$('btn-verify-all').addEventListener('click', async () => {
  const out = $('verify-out')
  out.classList.add('show')
  out.innerHTML = await verifyAll(compositeVerifier, 'CompositeVerifier')
})

$('btn-verify-software-only').addEventListener('click', async () => {
  // The negative control: a bare SoftwareVerifier knows the built-in algs only.
  // EdDSA still verifies; EIP712 and WebAuthn fail because no module handles them.
  const out = $('verify-out')
  out.classList.add('show')
  out.innerHTML =
    `<div style="color:var(--muted);margin-bottom:0.3rem;">verifier = <span class="mono">new SoftwareVerifier()</span> — the external algs should fail:</div>` +
    (await verifyAll(new SoftwareVerifier(), 'SoftwareVerifier only'))
})

$('btn-domain-policy').addEventListener('click', async () => {
  // Same composite, but the EIP-712 module is pinned to a different application
  // domain — structurally valid signature, rejected by policy.
  const pinned = new CompositeVerifier([
    new SoftwareVerifier(),
    new Eip712Verifier({ expectedDomain: { name: 'SomeOtherApp' } }),
    new WebAuthnVerifier(rpId),
  ])
  const out = $('verify-out')
  out.classList.add('show')
  const jwt = jwts['EIP712']!
  try {
    await verifyJWT(jwt, { resolver }, pinned)
    out.innerHTML = '<span class="warn">⚠️ Unexpectedly verified — that would be a bug.</span>'
  } catch (e) {
    out.innerHTML = `<span class="ok">✓ Domain policy rejected the EIP-712 JWT as intended.</span><br><span class="mono">${esc((e as Error).message)}</span>`
    log(`✅ Eip712Verifier expectedDomain policy rejected a foreign-domain token: ${(e as Error).message}`)
  }
})

$('btn-tamper-all').addEventListener('click', async () => {
  const out = $('verify-out')
  out.classList.add('show')
  const lines: string[] = []
  for (const alg of ALGS) {
    const jwt = jwts[alg]
    if (!jwt) continue
    const [h, p, s] = jwt.split('.')
    const flipped = p.slice(-2) === 'AA' ? 'AB' : 'AA'
    const tampered = `${h}.${p.slice(0, -2)}${flipped}.${s}`
    try {
      await verifyJWT(tampered, { resolver }, compositeVerifier)
      lines.push(`<span class="warn">⚠️ ${esc(alg)} tampered JWT unexpectedly verified</span>`)
      log(`⚠️ Tampered ${alg} JWT unexpectedly verified — that would be a bug.`)
    } catch (e) {
      lines.push(`<span class="ok">✓ ${esc(alg)} tamper rejected</span> <span class="mono">${esc((e as Error).message.slice(0, 90))}…</span>`)
      log(`✅ Tampered ${alg} JWT correctly rejected.`)
    }
  }
  out.innerHTML = lines.join('<br>')
})

$('btn-clear-log').addEventListener('click', () => {
  $('log').innerHTML = '<span class="empty">Events appear here, newest first.</span>'
})

// ---- Init ---------------------------------------------------------------------
if (!window.PublicKeyCredential) {
  log('❌ WebAuthn is unavailable in this context (needs HTTPS or localhost) — the EdDSA and EIP-712 flows still work.')
}
renderIdentities()
renderChips()
for (const alg of ALGS) renderRow(alg)
refreshGates()
