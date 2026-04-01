/**
 * Create federated DID-Auth headers.
 *
 * Used by the CLIENT to sign requests that will flow through a relay server.
 * The signature binds to: user + relay + home server + space + request content + expiry.
 */

import { base64urlEncode } from './encoding'
import { computeRequestHash } from './requestHash'
import type { CreateFederatedAuthOptions, FederatedAuthPayload } from './types'

const DEFAULT_EXPIRY_MS = 10_000 // 10 seconds

/**
 * Create a federated DID-Auth Authorization header value.
 *
 * Format: `DID <base64url(payload)>.<base64url(signature)>`
 *
 * The payload contains all federation fields, signed by the user's Ed25519 key.
 * Neither the relay nor the home server can modify any field without
 * invalidating the signature.
 */
export async function createFederatedAuthHeader(options: CreateFederatedAuthOptions): Promise<string> {
  const { did, privateKeyBase64, action, federation, body, queryString, expiresInMs } = options

  const requestHash = await computeRequestHash(body ?? '', queryString ?? '')

  const now = Date.now()
  const payload: FederatedAuthPayload = {
    did,
    action,
    timestamp: now,
    expiresAt: now + (expiresInMs ?? DEFAULT_EXPIRY_MS),
    requestHash,
    spaceId: federation.spaceId,
    serverDid: federation.serverDid,
    relayDid: federation.relayDid,
  }

  const payloadJson = JSON.stringify(payload)
  const payloadEncoded = base64urlEncode(new TextEncoder().encode(payloadJson))

  const privateKey = await importEd25519PrivateKey(privateKeyBase64)
  const signature = new Uint8Array(
    await crypto.subtle.sign('Ed25519', privateKey, new TextEncoder().encode(payloadEncoded)),
  )

  return `DID ${payloadEncoded}.${base64urlEncode(signature)}`
}

async function importEd25519PrivateKey(base64: string): Promise<CryptoKey> {
  const binary = atob(base64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return crypto.subtle.importKey('pkcs8', bytes, { name: 'Ed25519' }, false, ['sign'])
}