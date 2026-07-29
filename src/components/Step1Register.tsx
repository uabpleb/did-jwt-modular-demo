import { useState } from "react"
import { registerPasskey, type PasskeyIdentity } from "../utils/registration"
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

    const handleClick = async () => {
        try {
            const identity = await registerPasskey({
                rpId,
                rpName: RP_NAME,
                userName: `user-${Date.now()}`,
                requireDeviceBound: deviceBoundRequired,
            })
            onRegistered(identity)
            setResult({ok: true, msg: 'Registered. The passkey is now the DID controller'})
        } catch (e) {
            const errMsg = (e as Error).message
            setResult({ok: false, msg: errMsg})
            log('Step 1: ' + errMsg)
        }
    }

    return (
        <div className="step">
            <h2>1. Register a passkey</h2>
            <button type="button" onClick={handleClick}>Register a passkey</button>
            {result && <p className={String(result.ok)}>{result.msg}</p>}
        </div>
    )
}