import { createJWT, verifyJWT } from 'did-jwt'
import { Resolver } from 'did-resolver'
import {
  registerPasskey,
  WebAuthnSigner,
  WebAuthnVerifier,
  WEBAUTHN_ALG,
  type PasskeyIdentity,
} from 'did-jwt-webauthn-signer'
import { getResolver as jwkResolver } from './did-jwk-resolver'
import { inspectJwt, type JwtInspection } from './inspect'

const RP_NAME = 'did-jwt passkey demo'
const STORAGE_KEY = 'passkey-identity'

const rpId = location.hostname // 'localhost' in dev

// The real did-resolver registry: dispatches by DID method, caches, and returns
// spec DIDResolutionResults. Register more methods (ethr/web/key) here as needed.
const resolver = new Resolver(jwkResolver())

const $ = (id: string) => document.getElementById(id) as HTMLElement
const deviceBoundRequired = () => ($('chk-device-bound') as HTMLInputElement).checked
const esc = (s: string) => s.replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]!))

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

// Per-step inline output (success/failure right under the button).
const stepOut = (n: number, html: string) => {
  const el = $(`out-${n}`)
  el.innerHTML = html
  el.classList.add('show')
}

let identity: PasskeyIdentity | null = loadIdentity()
let lastJwt: string | null = null
// The VP from step 4 + the nonce it was bound to — kept so the replay step can
// re-submit a stale presentation against a fresh verifier challenge.
let presentedVp: { jwt: string; nonce: string } | null = null

function loadIdentity(): PasskeyIdentity | null {
  const raw = localStorage.getItem(STORAGE_KEY)
  return raw ? (JSON.parse(raw) as PasskeyIdentity) : null
}

// ---- Step state machine -------------------------------------------------
// 1 register → unlocks 2 sign → unlocks 3 verify, 4 present, 5 tamper.
type StepState = 'locked' | 'ready' | 'done'
const setStep = (n: number, state: StepState) => $(`step-${n}`).setAttribute('data-state', state)
const enable = (id: string, on: boolean) => (($(id) as HTMLButtonElement).disabled = !on)

function refreshGates() {
  const hasId = identity != null
  const hasJwt = lastJwt != null
  const hasVp = presentedVp != null
  enable('btn-register', true)
  enable('btn-reset', hasId)
  enable('btn-sign', hasId)
  enable('btn-verify', hasJwt)
  enable('btn-verify-db', hasJwt)
  enable('btn-present', hasJwt)
  enable('btn-replay', hasVp)
  enable('btn-tamper', hasJwt)
  enable('btn-copy-jwt', hasJwt)
  setStep(1, hasId ? 'done' : 'ready')
  setStep(2, !hasId ? 'locked' : hasJwt ? 'done' : 'ready')
  for (const n of [3, 4]) setStep(n, hasJwt ? 'ready' : 'locked')
  setStep(5, hasVp ? 'ready' : 'locked')
  setStep(6, hasJwt ? 'ready' : 'locked')
}

// ---- Renderers ----------------------------------------------------------
function renderIdentity() {
  const el = $('identity')
  if (!identity) {
    el.innerHTML = '<span class="empty">No passkey yet — register one in step 1.</span>'
    return
  }
  const bound =
    identity.deviceBound === undefined
      ? '<span class="warn">unknown</span>'
      : identity.deviceBound
        ? '<span class="ok">device-bound (BE=0)</span>'
        : '<span class="warn">syncable (BE=1)</span>'
  el.innerHTML = `<div class="kv mono">
    <span class="k">did:jwk (issuer)</span><span>${esc(identity.didJwk)}</span>
    <span class="k">did:key</span><span>${esc(identity.didKey)}</span>
    <span class="k">rpId</span><span>${esc(identity.rpId)}</span>
    <span class="k">device-bound</span><span>${bound}</span>
  </div>`
}

async function renderDidDoc() {
  if (!identity) {
    $('diddoc').innerHTML = '<span class="empty">Register a passkey (step 1) to populate.</span>'
    return
  }
  const res = await resolver.resolve(identity.didJwk)
  $('diddoc').innerHTML = `<pre>${esc(JSON.stringify(res.didDocument, null, 2))}</pre>`
}

function flagChip(label: string, on: boolean, title: string) {
  return `<span class="flag ${on ? 'on' : ''}" title="${esc(title)}">${label} ${on ? '1' : '0'}</span>`
}

async function renderInspector(jwt: string) {
  let info: JwtInspection
  try {
    info = await inspectJwt(jwt)
  } catch (e) {
    $('inspector').innerHTML = `<span class="bad">Could not decode: ${esc((e as Error).message)}</span>`
    return
  }
  const wa = info.webauthn
  const segs = `<div class="jwt-raw mono">
    <span class="seg seg-h">${esc(info.raw.header)}</span>.<span class="seg seg-p">${esc(info.raw.payload)}</span>.<span class="seg seg-s">${esc(info.raw.signature.slice(0, 24))}…</span>
  </div>`

  let waHtml = ''
  if (wa) {
    const f = wa.flags
    const bind = wa.challengeBindsSigningInput
    waHtml = `
    <h2 style="font-size:0.9rem;margin-top:0.9rem;">WebAuthn signature blob <span style="color:var(--muted);font-weight:400;">(decoded from the <span class="seg seg-s">signature</span> segment)</span></h2>
    <div class="${bind ? 'ok' : 'bad'}" style="margin:0.4rem 0;">
      ${bind ? '✓' : '✗'} WebAuthn <code>challenge</code> ${bind ? 'equals' : 'does NOT equal'} <code>SHA-256(signing input)</code>
      — i.e. the passkey signed a hash of <span class="seg seg-h">header</span>.<span class="seg seg-p">payload</span>, not the JWT itself.
    </div>
    <div class="flags">
      ${flagChip('UP', f.UP, 'User present')}
      ${flagChip('UV', f.UV, 'User verified (biometric/PIN)')}
      ${flagChip('BE', f.BE, 'Backup eligible — BE=0 means device-bound')}
      ${flagChip('BS', f.BS, 'Backup state — currently synced')}
      ${flagChip('AT', f.AT, 'Attested credential data present')}
      ${flagChip('ED', f.ED, 'Extension data present')}
    </div>
    <div class="kv mono" style="margin-top:0.4rem;">
      <span class="k">flags byte</span><span>${f.byte}</span>
      <span class="k">rpIdHash</span><span>${esc(wa.rpIdHash)}</span>
      <span class="k">signCount</span><span>${wa.signCount}</span>
      <span class="k">signature (DER)</span><span>${esc(wa.signatureDerHex)}</span>
    </div>
    <details><summary>clientDataJSON (what the authenticator hashed)</summary><pre>${esc(JSON.stringify(wa.clientData, null, 2))}</pre></details>`
  }

  $('inspector').innerHTML = `
    ${segs}
    <details open><summary>header</summary><pre>${esc(JSON.stringify(info.header, null, 2))}</pre></details>
    <details><summary>payload</summary><pre>${esc(JSON.stringify(info.payload, null, 2))}</pre></details>
    ${waHtml}`
}

// ---- Step handlers ------------------------------------------------------
$('btn-register').addEventListener('click', async () => {
  try {
    identity = await registerPasskey({
      rpId,
      rpName: RP_NAME,
      userName: `user-${Date.now()}`,
      requireDeviceBound: deviceBoundRequired(),
    })
    localStorage.setItem(STORAGE_KEY, JSON.stringify(identity))
    lastJwt = null
    presentedVp = null
    renderIdentity()
    await renderDidDoc()
    refreshGates()
    stepOut(1, `<span class="ok">✓ Registered.</span> The passkey is now the DID controller.`)
    log('✅ Registered passkey.', { did: identity.didJwk, deviceBound: identity.deviceBound })
  } catch (e) {
    stepOut(1, `<span class="bad">✗ ${esc((e as Error).message)}</span>`)
    log(`❌ Registration failed: ${(e as Error).message}`)
  }
})

$('btn-sign').addEventListener('click', async () => {
  if (!identity) return
  try {
    const now = Math.floor(Date.now() / 1000)
    const payload = {
      sub: identity.didJwk,
      nbf: now,
      vc: {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiableCredential'],
        credentialSubject: { passkey: true, demo: 'did-jwt WebAuthn signer' },
      },
    }
    const signer = new WebAuthnSigner(identity)
    lastJwt = await createJWT(payload, { issuer: identity.didJwk, signer, alg: WEBAUTHN_ALG })
    presentedVp = null
    await renderInspector(lastJwt)
    refreshGates()
    stepOut(2, `<span class="ok">✓ Signed.</span> See the JWT inspector below for the decoded WebAuthn signature.`)
    log('✅ Signed VC-JWT via createJWT().', { jwt: lastJwt })
  } catch (e) {
    stepOut(2, `<span class="bad">✗ ${esc((e as Error).message)}</span>`)
    log(`❌ Signing failed: ${(e as Error).message}`)
  }
})

$('btn-verify').addEventListener('click', async () => {
  if (!lastJwt || !identity) return
  try {
    const result = await verifyJWT(
      lastJwt,
      { resolver },
      new WebAuthnVerifier(identity.rpId, { requireDeviceBound: deviceBoundRequired() }),
    )
    setStep(3, 'done')
    // Echo the verifier's own challenge-binding step: clientData.challenge must
    // equal SHA-256(signing input). This is what proves the assertion is over
    // *this* JWT and not some other message.
    const info = await inspectJwt(lastJwt)
    const wa = info.webauthn
    const chal = wa
      ? `<br>challenge binding: <span class="mono">clientData.challenge === SHA-256(header.payload)</span> ${
          wa.challengeBindsSigningInput ? '<span class="ok">✓</span>' : '<span class="bad">✗</span>'
        }<br><span class="mono" style="font-size:0.75rem;color:var(--muted)">${esc(wa.actualChallenge)}</span>`
      : ''
    stepOut(3, `<span class="ok">✓ verifyJWT() succeeded.</span> signer = <span class="mono">${esc(result.signer.id)}</span>${chal}`)
    log('✅ verifyJWT() succeeded.', {
      verified: result.verified,
      signer: result.signer.id,
      issuer: result.issuer,
    })
  } catch (e) {
    stepOut(3, `<span class="bad">✗ ${esc((e as Error).message)}</span>`)
    log(`❌ Verification failed: ${(e as Error).message}`)
  }
})

$('btn-verify-db').addEventListener('click', async () => {
  if (!lastJwt || !identity) return
  try {
    // Force device-bound regardless of the checkbox: every assertion must carry
    // Backup Eligibility = 0. A syncable (BE=1) passkey is refused here.
    await verifyJWT(lastJwt, { resolver }, new WebAuthnVerifier(identity.rpId, { requireDeviceBound: true }))
    stepOut(
      3,
      `<span class="ok">✓ Accepted under requireDeviceBound: true.</span> This passkey is device-bound (BE=0)${
        identity.deviceBound === false ? ' <span class="warn">(unexpected — identity says syncable)</span>' : ''
      }.`,
    )
    log('✅ verifyJWT() accepted under requireDeviceBound: true.')
  } catch (e) {
    stepOut(
      3,
      `<span class="warn">⛔ Rejected under requireDeviceBound: true.</span> <span class="mono">${esc((e as Error).message)}</span><br>The security property in action: a syncable (BE=1) passkey is refused when a device-bound key is demanded.`,
    )
    log(`⛔ requireDeviceBound rejected the credential: ${(e as Error).message}`)
  }
})

$('btn-present').addEventListener('click', async () => {
  if (!lastJwt || !identity) return
  try {
    const nonce = crypto.randomUUID()
    const now = Math.floor(Date.now() / 1000)
    const vpPayload = {
      nbf: now,
      nonce,
      vp: {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiablePresentation'],
        verifiableCredential: [lastJwt],
      },
    }
    const signer = new WebAuthnSigner(identity)
    const vpJwt = await createJWT(vpPayload, { issuer: identity.didJwk, signer, alg: WEBAUTHN_ALG })
    log('✅ Holder signed a Verifiable Presentation (passkey-bound).', { nonce, vp: vpJwt })

    const vpResult = await verifyJWT(
      vpJwt,
      { resolver },
      new WebAuthnVerifier(identity.rpId, { requireDeviceBound: deviceBoundRequired() }),
    )
    // App-level freshness check: verifyJWT proves the signature; the verifier must
    // separately confirm the presentation carries the nonce it challenged with.
    const gotNonce = (vpResult.payload as { nonce?: string }).nonce
    const nonceOk = gotNonce === nonce
    const vp = (vpResult.payload as { vp?: { verifiableCredential?: string[] } }).vp

    const vc = vp?.verifiableCredential?.[0]
    let vcLine = ''
    if (typeof vc === 'string') {
      const vcResult = await verifyJWT(
        vc,
        { resolver },
        new WebAuthnVerifier(identity.rpId, { requireDeviceBound: deviceBoundRequired() }),
      )
      vcLine = `<br>↳ embedded VC also verified (issuer = <span class="mono">${esc(String(vcResult.issuer))}</span>)`
      log('✅ Embedded VC also verified (issuer signature).', { issuer: vcResult.issuer })
    }
    presentedVp = { jwt: vpJwt, nonce }
    setStep(4, 'done')
    refreshGates()
    stepOut(
      4,
      `<span class="ok">✓ VP verified.</span> holder = <span class="mono">${esc(String(vpResult.issuer))}</span><br>nonce match: <span class="mono">${esc(nonce)}</span> ${
        nonceOk ? '<span class="ok">✓</span>' : '<span class="bad">✗</span>'
      }${vcLine}<br><span style="color:var(--muted)">Now try step 5 to see this same VP rejected as a replay.</span>`,
    )
    log('✅ verifyJWT() accepted the VP — holder key verified.', {
      verified: vpResult.verified,
      holder: vpResult.issuer,
      nonce,
      embeddedCredentials: vp?.verifiableCredential?.length ?? 0,
    })
  } catch (e) {
    stepOut(4, `<span class="bad">✗ ${esc((e as Error).message)}</span>`)
    log(`❌ Presentation failed: ${(e as Error).message}`)
  }
})

$('btn-replay').addEventListener('click', async () => {
  if (!presentedVp || !identity) return
  try {
    // The verifier starts a fresh interaction and issues a new challenge nonce.
    const freshChallenge = crypto.randomUUID()
    // The attacker replays the OLD presentation — still validly signed by the passkey.
    const result = await verifyJWT(presentedVp.jwt, { resolver }, new WebAuthnVerifier(identity.rpId))
    const presentedNonce = (result.payload as { nonce?: string }).nonce
    // verifyJWT confirmed the signature; freshness is a separate, app-level check.
    if (presentedNonce === freshChallenge) {
      stepOut(5, `<span class="warn">⚠️ Stale nonce matched a fresh challenge — astronomically unlikely; treat as a bug.</span>`)
      return
    }
    setStep(5, 'done')
    stepOut(
      5,
      `<span class="ok">✓ Replay rejected.</span> The passkey signature still verifies, but the nonce is stale:<br><span class="mono" style="font-size:0.78rem">expected ${esc(freshChallenge)}</span><br><span class="mono" style="font-size:0.78rem">got&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;${esc(presentedNonce ?? '∅')}</span><br>Signature validity ≠ freshness — the nonce binding is what stops replay.`,
    )
    log('✅ Replay correctly rejected: VP signature valid but nonce stale.', {
      expected: freshChallenge,
      got: presentedNonce,
    })
  } catch (e) {
    stepOut(5, `<span class="bad">✗ ${esc((e as Error).message)}</span>`)
    log(`❌ Replay step failed: ${(e as Error).message}`)
  }
})

$('btn-tamper').addEventListener('click', async () => {
  if (!lastJwt || !identity) return
  // Flip the last two chars of the payload segment (keep the signature) and show
  // exactly which bytes changed.
  const [h, p, s] = lastJwt.split('.')
  const flipped = p.slice(-2) === 'AA' ? 'AB' : 'AA'
  const tamperedPayload = `${p.slice(0, -2)}${flipped}`
  const tampered = `${h}.${tamperedPayload}.${s}`
  const diff = `<div class="jwt-raw mono" style="margin-top:0.45rem;">before: …${esc(
    p.slice(-10, -2),
  )}<span class="hl">${esc(p.slice(-2))}</span><br>after:&nbsp;&nbsp;…${esc(
    tamperedPayload.slice(-10, -2),
  )}<span class="hl">${esc(flipped)}</span></div>`
  try {
    await verifyJWT(
      tampered,
      { resolver },
      new WebAuthnVerifier(identity.rpId, { requireDeviceBound: deviceBoundRequired() }),
    )
    stepOut(6, `<span class="warn">⚠️ Tampered JWT unexpectedly verified — that would be a bug.</span>${diff}`)
    log('⚠️ Tampered JWT unexpectedly verified — that would be a bug.')
  } catch (e) {
    setStep(6, 'done')
    stepOut(6, `<span class="ok">✓ Correctly rejected.</span> <span class="mono">${esc((e as Error).message)}</span>${diff}`)
    log(`✅ Tampered JWT correctly rejected by verifyJWT(): ${(e as Error).message}`)
  }
})

$('btn-copy-jwt').addEventListener('click', async () => {
  if (!lastJwt) return
  const btn = $('btn-copy-jwt')
  try {
    await navigator.clipboard.writeText(lastJwt)
    const prev = btn.textContent
    btn.textContent = 'Copied ✓'
    setTimeout(() => (btn.textContent = prev), 1200)
  } catch {
    log('❌ Clipboard write failed (needs a secure context / user gesture).')
  }
})

$('btn-reset').addEventListener('click', () => {
  localStorage.removeItem(STORAGE_KEY)
  identity = null
  lastJwt = null
  presentedVp = null
  for (const n of [1, 2, 3, 4, 5, 6]) $(`out-${n}`).classList.remove('show')
  $('inspector').innerHTML = '<span class="empty">Sign a credential (step 2) to populate.</span>'
  renderIdentity()
  renderDidDoc()
  refreshGates()
  log('🔄 Reset — passkey identity cleared from localStorage.')
})

$('btn-clear-log').addEventListener('click', () => {
  $('log').innerHTML = '<span class="empty">Events appear here, newest first.</span>'
})

// ---- Init ---------------------------------------------------------------
if (!window.PublicKeyCredential) {
  log('❌ WebAuthn is not available in this browser/context (needs HTTPS or localhost).')
}
renderIdentity()
renderDidDoc()
refreshGates()
