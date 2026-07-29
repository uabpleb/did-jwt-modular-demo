import { useState } from 'react'
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

const STORAGE_KEY = 'passkey-identity'

export interface PresentedVp {
  jwt: string
  nonce: string
}

function loadIdentity(): PasskeyIdentity | null {
  const raw = localStorage.getItem(STORAGE_KEY)
  return raw ? (JSON.parse(raw) as PasskeyIdentity) : null
}

const resolver = new Resolver(getJwkResolver())

function App() {
    const [identity, setIdentity] = useState<PasskeyIdentity | null>(loadIdentity())
    const [lastJwt, setLastJwt] = useState<string|null>(null)
    const [presentedVp, setPresentedVp] = useState<PresentedVp|null>(null)
    const [deviceBoundRequired, setDeviceBoundRequired] = useState<boolean>(false)

    const log = (msg: string, obj?: unknown) => console.log(msg, obj)

    const handleRegistered = (id: PasskeyIdentity) => {
      console.log('handleRegistered called', Date.now())
      localStorage.setItem(STORAGE_KEY, JSON.stringify(id))
      setIdentity(id)
      setLastJwt(null)
      setPresentedVp(null)
    }

    const handleReset = () => {
      localStorage.removeItem(STORAGE_KEY)
      setIdentity(null)
      setLastJwt(null)
      setPresentedVp(null)
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

        <button onClick={handleReset} disabled={!identity}>Reset</button>

        <IdentityPanel identity={identity} />
        
        <Step1Register deviceBoundRequired={deviceBoundRequired} onRegistered={handleRegistered} log={log} />
        <Step2Sign identity={identity} onSigned={setLastJwt} log={log} />
        <Step3Verify deviceBoundRequired={deviceBoundRequired} identity={identity} jwt={lastJwt} resolver={resolver} log={log} />
        <Step4Present deviceBoundRequired={deviceBoundRequired} identity={identity} jwt={lastJwt} resolver={resolver} onPresented={setPresentedVp} log={log} />
        <Step5Replay identity={identity} presentedVp={presentedVp} resolver={resolver} log={log} />
        <Step6Tamper identity={identity} jwt={lastJwt} resolver={resolver} deviceBoundRequired={deviceBoundRequired} log={log} />

        <PresentedVpPanel presentedVp={presentedVp} />
        <JwtPanel jwt={lastJwt} />

      </div>

    )
}

export default App
