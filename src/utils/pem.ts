/**
 * pem.ts
 *
 * Minimal PEM -> DER conversion for pasting root certificates into the demo's
 * UI (e.g. a manufacturer's published attestation root, to see attestation
 * trustLevel reach "chain-verified"). Browser-only: uses atob(), not Node's
 * Buffer - this file is never imported by the test suite.
 */

export function pemToDer(pem: string): Uint8Array {
    const base64 = pem
        .replace(/-----BEGIN CERTIFICATE-----/g, '')
        .replace(/-----END CERTIFICATE-----/g, '')
        .replace(/\s+/g, '')
    const binary = atob(base64)
    const bytes = new Uint8Array(binary.length)
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
    return bytes
}

/** Splits a textarea's contents into individual PEM certificate blocks and converts each to DER. */
export function parsePemRoots(text: string): Uint8Array[] {
    const blocks = text.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g)
    if (!blocks) return []
    return blocks.map(pemToDer)
}

/**
 * Pre-filled default for the demo's trusted-roots textarea (see App.tsx) -
 * Chromium's own DevTools/virtual-authenticator attestation certificate, NOT
 * a real hardware manufacturer's trust anchor. This is what lets "Check
 * attestation" reach trustLevel: "chain-verified" out of the box when testing
 * against Chrome's virtual authenticator (chrome://inspect or Playwright/
 * Puppeteer's WebAuthn API), which is what this demo has actually been
 * exercised against. Replace with a real vendor root (e.g. Yubico's
 * published attestation root) to test against genuine hardware - a
 * chain-verified result against THIS cert only tells you "this is Chromium's
 * virtual authenticator," not "this is trustworthy hardware."
 */
export const DEVTOOLS_VIRTUAL_AUTHENTICATOR_ROOT_PEM = `-----BEGIN CERTIFICATE-----
MIIB1DCCAXqgAwIBAgIBATAKBggqhkjOPQQDAjBgMQswCQYDVQQGEwJVUzERMA8G
A1UECgwIQ2hyb21pdW0xIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRp
b24xGjAYBgNVBAMMEUJhdGNoIENlcnRpZmljYXRlMB4XDTE3MDcxNDAyNDAwMFoX
DTQ2MDgwNDE0NTk1N1owYDELMAkGA1UEBhMCVVMxETAPBgNVBAoMCENocm9taXVt
MSIwIAYDVQQLDBlBdXRoZW50aWNhdG9yIEF0dGVzdGF0aW9uMRowGAYDVQQDDBFC
YXRjaCBDZXJ0aWZpY2F0ZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABI1hfmXJ
UI5kvMVnOsgqZ5naPBRGaCwljEY//99Y39L6Pmw3i1PXlcSk3/tBme3Xhi8jq68C
A7S4kRugVpmU4QGjJTAjMAwGA1UdEwEB/wQCMAAwEwYLKwYBBAGC5RwCAQEEBAMC
BSAwCgYIKoZIzj0EAwIDSAAwRQIgQW6pcL/q9Q2Dmrn5/1HYiHk4Khi34HwyWXsz
VOGp+gwCIQCckpBfk3b6lnEvQp7sL3pYWlJ0FS9UC7ux82pKGLhisg==
-----END CERTIFICATE-----`