import { act, useState } from 'react'
//import reactLogo from './assets/react.svg'
//import viteLogo from './assets/vite.svg'
//import heroImg from './assets/hero.png'
import './App.css'
import type { PasskeyIdentity } from './utils/registration'

import { Resolver } from 'did-resolver'

// Demo Components
import Step1Register from './components/Step1Register'
import Step2Sign from './components/Step2Sign'
import Step3Verify from './components/Step3Verify'
import Step4Present from './components/Step4Present'
import { getJwkResolver } from 'did-jwt-webauthn-signer'
import Step5Replay from './components/Step5Replay'
import Step6Tamper from './components/Step6Tamper'

// Support components
import IdentityPanel from './components/IdentityPanel'
import PresentedVpPanel from './components/PresentedVpPanel'
import JwtPanel from './components/JwtPanel'
import SdIdentityPanel from './components/SdIdentityPanel'

const STORAGE_KEY = 'passkey-identities'

export interface PresentedVp {
  jwt: string
  nonce: string
}

const resolver = new Resolver(getJwkResolver())

function App() {
    const [identities, setIdentities] = useState<PasskeyIdentity[]>(loadIdentities())
    const [issuerIdentity, setIssuerIdentity] = useState<PasskeyIdentity | null>(identities[0] ?? null)
    const [holderIdentity, setHolderIdentity] = useState<PasskeyIdentity | null>(identities[0] ?? null)
    //const [activeIdentity, setActiveIdentity] = useState<PasskeyIdentity | null>(identities[0] ?? null)
    const [lastJwt, setLastJwt] = useState<string|null>(null)
    const [presentedVp, setPresentedVp] = useState<PresentedVp|null>(null)
    const [deviceBoundRequired, setDeviceBoundRequired] = useState<boolean>(false)

    const log = (msg: string, obj?: unknown) => console.log(msg, obj)

    const handleRegistered = (id: PasskeyIdentity) => {
      const next = [...identities, id]
      localStorage.setItem(STORAGE_KEY, JSON.stringify(next))
      setIdentities(next)
      // First registration seeds both roles; later ones don't silently steal a role
      // out from under whatever the user already selected.
      if (!issuerIdentity) setIssuerIdentity(id)
      if (!holderIdentity) setHolderIdentity(id)
      setLastJwt(null)
      setPresentedVp(null)
    }

    const handleReset = () => {
      localStorage.removeItem(STORAGE_KEY)
      setIdentities([])
      setHolderIdentity(null)
      setIssuerIdentity(null)
      setLastJwt(null)
      setPresentedVp(null)
    }

    const handleIssuerResolved = (id: PasskeyIdentity) => {
      setIssuerIdentity(id)
    }

    const handleHolderResolved = (id: PasskeyIdentity) => {
      setHolderIdentity(id)
    }


    return (

      <div id="center">
        <h1>did-jwt x WebAuthn passkey</h1>

        <label>
          <input
            type="checkbox"
            checked={deviceBoundRequired}
            onChange={(e) => setDeviceBoundRequired(e.target.checked)}
          />
          Require device-bound passkey (reject syncable, BE flag = 0)
        </label>

        <button onClick={handleReset} disabled={identities.length === 0}>Reset</button>

        <IdentitySelect label="Subject/ Issuer identity" identities={identities} value={issuerIdentity} onChange={setIssuerIdentity} />
        <IdentitySelect label="Holder identity" identities={identities} value={holderIdentity} onChange={setHolderIdentity} />

        <div className="layout">
          <div className="steps-column">
            <Step1Register deviceBoundRequired={deviceBoundRequired} onRegistered={handleRegistered} log={log} />
            <Step2Sign identity={issuerIdentity} identities={identities} onIdentityResolved={handleIssuerResolved} onSigned={setLastJwt} log={log} />
            <Step3Verify deviceBoundRequired={deviceBoundRequired} identity={issuerIdentity} jwt={lastJwt} resolver={resolver} log={log} />
            <Step4Present deviceBoundRequired={deviceBoundRequired} holderIdentity={holderIdentity} jwt={lastJwt} resolver={resolver} onPresented={setPresentedVp} log={log} />
            <SdIdentityPanel identity={holderIdentity} jwt={lastJwt} resolver={resolver} deviceBoundRequired={deviceBoundRequired} log={log} />
            <Step5Replay identity={holderIdentity} presentedVp={presentedVp} resolver={resolver} log={log} />
            <Step6Tamper identity={issuerIdentity} jwt={lastJwt} resolver={resolver} deviceBoundRequired={deviceBoundRequired} log={log} />
          </div>
          <div className="helper-column">
            <IdentityPanel identity={issuerIdentity} />
            <PresentedVpPanel presentedVp={presentedVp} />
            <JwtPanel jwt={lastJwt} />
          </div>
        </div>

      </div>

    )
}

export default App


/*function loadIdentities(): PasskeyIdentity[] {
  const raw = localStorage.getItem(STORAGE_KEY)
  return raw ? (JSON.parse(raw) as PasskeyIdentity[]) : []
}*/
function loadIdentities(): PasskeyIdentity[] {
  const raw = localStorage.getItem(STORAGE_KEY)
  if (!raw) return []
  try {
    const parsed = JSON.parse(raw)
    return Array.isArray(parsed) ? parsed : []
  } catch {
    return []
  }
}

function IdentitySelect({ label, identities, value, onChange }: {
  label: string
  identities: PasskeyIdentity[]
  value: PasskeyIdentity | null
  onChange: (id: PasskeyIdentity) => void
}) {
  return (
    <label style={{ display: 'block', margin: '6px 0' }}>
      {label}{' '}
      <select
        value={value?.credentialId ?? ''}
        onChange={(e) => {
          const found = identities.find((i) => i.credentialId === e.target.value)
          if (found) onChange(found)
        }}
      >
        {identities.map((i) => (
          <option key={i.credentialId} value={i.credentialId}>
            {i.didJwk.slice(0, 28)}…
          </option>
        ))}
      </select>
    </label>
  )
}