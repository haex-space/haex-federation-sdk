/**
 * Build FEDERATION server-to-server auth headers.
 *
 * Used by RELAY SERVERS to forward requests to origin servers.
 * The header proves relay identity (Ed25519 signature over payload)
 * and carries the user's embedded authorization.
 *
 * Format: `FEDERATION <base64url(payload)>.<base64url(signature)>`
 */

import { base64urlEncode } from './encoding'
import type { BuildFederationAuthHeaderOptions } from './types'

const DEFAULT_EXPIRY_MS = 30_000 // 30 seconds

export async function buildFederationAuthHeader(options: BuildFederationAuthHeaderOptions): Promise<string> {
  const { serverDid, privateKeyPkcs8Base64, action, body, ucanToken, userAuthorization, expiresInMs } = options

  const bodyBytes = new TextEncoder().encode(body)
  const bodyHashBuffer = await crypto.subtle.digest('SHA-256', bodyBytes)
  const bodyHash = base64urlEncode(new Uint8Array(bodyHashBuffer))

  const now = Date.now()
  const payload = JSON.stringify({
    did: serverDid,
    action,
    timestamp: now,
    expiresAt: now + (expiresInMs ?? DEFAULT_EXPIRY_MS),
    bodyHash,
    ucan: ucanToken,
    ...(userAuthorization !== undefined ? { userAuthorization } : {}),
  })

  const payloadEncoded = base64urlEncode(new TextEncoder().encode(payload))

  const privateKey = await importEd25519PrivateKey(privateKeyPkcs8Base64)
  const signature = new Uint8Array(
    await crypto.subtle.sign('Ed25519', privateKey, new TextEncoder().encode(payloadEncoded)),
  )

  return `FEDERATION ${payloadEncoded}.${base64urlEncode(signature)}`
}

async function importEd25519PrivateKey(base64: string): Promise<CryptoKey> {
  const binary = atob(base64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return crypto.subtle.importKey('pkcs8', bytes, { name: 'Ed25519' }, false, ['sign'])
}