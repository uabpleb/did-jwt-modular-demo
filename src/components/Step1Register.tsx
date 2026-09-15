import { useState } from "react"
import { registerPasskey } from "../utils/registration"
import { type PasskeyIdentity } from 'did-jwt-webauthn-signer'
import { type StepResult } from "./step-types"

interface Props {
    deviceBoundRequired: boolean,
    onRegistered: (identity: PasskeyIdentity) => void
    log: (msg: string, obj?: unknown) => void
}

const RP_NAME= 'did-jwt passkey demo'
const rpId = location.hostname

export default function Step1Register({deviceBoundRequired, onRegistered, log}: Props) {
    const [result, setResult] = useState<StepResult>({ok: true, msg: ''})
    const [pending, setPending] = useState(false)

    const handleClick = async (requestAttestation: boolean) => {
        if(pending) return
        setPending(true)
        try {
            const identity = await registerPasskey({
                rpId,
                rpName: RP_NAME,
                userName: `user-${Date.now()}`,
                requireDeviceBound: deviceBoundRequired,
                attestation: requestAttestation ? 'direct' : 'none', //no 'business' AttestationConveyancePreference option, it needs to be set up
            })
            onRegistered(identity)
            setResult({ok: true, msg: 'Registered. The passkey is now the DID controller'})
        } catch (e) {
            const errMsg = (e as Error).message
            setResult({ok: false, msg: errMsg})
            log('Step 1: ' + errMsg)
        } finally {
            setPending(false)
        }
    }

    return (
        <div className="step">
            <h2>1. Register a passkey</h2>
            <button type="button" onClick={() => handleClick(false)} disabled={pending}>
                {pending ? 'Registering...': 'Register a passkey'}
            </button>
            <button type="button" onClick={() => handleClick(true)} disabled={pending}>
                {pending ? 'Registering...': 'Register a passkey (request also an attestation)'}
            </button>
            {result && <p className={String(result.ok)}>{result.msg}</p>}
        </div>
    )
}