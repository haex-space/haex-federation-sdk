/**
 * Create federated DID-Auth headers.
 *
 * Used by the CLIENT to sign requests that will flow through a relay server.
 * The signature binds to: user + relay + home server + space + request content + expiry.
 */

import { base64urlEncode } from './encoding'
import { computeRequestHash } from './requestHash'
import type { FederatedAuthParams, FederatedAuthPayload } from './types'

const DEFAULT_EXPIRY_MS = 10_000 // 10 seconds

/**
 * Sign function type — takes raw bytes and returns an Ed25519 signature.
 * This abstraction allows both WebCrypto (browser/Bun) and Node crypto.
 */
export type SignFn = (data: Uint8Array) => Promise<Uint8Array>

/**
 * Create a federated DID-Auth Authorization header value.
 *
 * Format: `DID <base64url(payload)>.<base64url(signature)>`
 *
 * The payload contains all federation fields, signed by the user's Ed25519 key.
 * Neither the relay nor the home server can modify any field without
 * invalidating the signature.
 */
export async function createFederatedAuthHeader(
  did: string,
  sign: SignFn,
  action: string,
  federation: FederatedAuthParams,
  body?: string,
  queryString?: string,
  expiresInMs?: number,
): Promise<string> {
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

  const signature = await sign(new TextEncoder().encode(payloadEncoded))

  return `DID ${payloadEncoded}.${base64urlEncode(signature)}`
}
