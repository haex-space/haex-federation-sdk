/**
 * Verify federated DID-Auth tokens.
 *
 * Used by BOTH relay and home server to validate user-signed requests.
 * - Relay: checks `relayDid` matches itself
 * - Home: checks `serverDid` matches itself, verifies membership + role
 */

import { base64urlDecode } from './encoding'
import { computeRequestHash } from './requestHash'
import type { FederatedAuthPayload, VerifiedFederatedAuth, VerifyFederatedAuthOptions } from './types'

/**
 * Verify function type — takes a raw Ed25519 public key (32 bytes),
 * signature, and signed data. Returns true if valid.
 */
export type VerifyFn = (publicKey: Uint8Array, signature: Uint8Array, data: Uint8Array) => Promise<boolean>

/**
 * DID → raw public key function type.
 * Extracts the 32-byte Ed25519 public key from a did:key DID.
 */
export type DidToPublicKeyFn = (did: string) => Uint8Array

/**
 * Parse a federated DID-Auth header without verifying the signature.
 * Used by the relay to quickly extract `relayDid` for routing.
 *
 * Returns null if the header is not a valid federated DID-Auth token.
 */
export function parseFederatedAuthHeader(authHeader: string): FederatedAuthPayload | null {
  if (!authHeader.startsWith('DID ')) return null

  const token = authHeader.slice(4)
  const dotIndex = token.indexOf('.')
  if (dotIndex === -1) return null

  try {
    const payloadEncoded = token.slice(0, dotIndex)
    const payloadBytes = base64urlDecode(payloadEncoded)
    const payload = JSON.parse(new TextDecoder().decode(payloadBytes)) as Partial<FederatedAuthPayload>

    // Must have federation fields to be a federated auth (not a direct DID-Auth)
    if (!payload.spaceId || !payload.serverDid || !payload.relayDid) return null

    return payload as FederatedAuthPayload
  } catch {
    return null
  }
}

/**
 * Fully verify a federated DID-Auth token.
 *
 * Checks:
 * 1. Token format (DID <payload>.<signature>)
 * 2. All required fields present
 * 3. Not expired (expiresAt > now)
 * 4. Ed25519 signature valid (user identity proven)
 * 5. requestHash matches actual request content
 *
 * Does NOT check serverDid/relayDid — caller must do that.
 * Does NOT check space membership — caller must do that.
 */
export async function verifyFederatedAuth(options: VerifyFederatedAuthOptions): Promise<VerifiedFederatedAuth | { error: string }> {
  const { authHeader, verify, didToPublicKey, requestBody, requestQueryString } = options

  if (!authHeader.startsWith('DID ')) {
    return { error: 'Invalid auth scheme — expected DID' }
  }

  const token = authHeader.slice(4)
  const dotIndex = token.indexOf('.')
  if (dotIndex === -1) {
    return { error: 'Malformed DID auth token' }
  }

  const payloadEncoded = token.slice(0, dotIndex)
  const signatureEncoded = token.slice(dotIndex + 1)

  // 1. Decode payload
  let payload: FederatedAuthPayload
  try {
    const payloadBytes = base64urlDecode(payloadEncoded)
    payload = JSON.parse(new TextDecoder().decode(payloadBytes))
  } catch {
    return { error: 'Invalid payload encoding' }
  }

  // 2. Validate required fields
  const required: (keyof FederatedAuthPayload)[] = [
    'did', 'action', 'timestamp', 'expiresAt', 'requestHash',
    'spaceId', 'serverDid', 'relayDid',
  ]
  for (const field of required) {
    if (payload[field] === undefined || payload[field] === null) {
      return { error: `Missing required field: ${field}` }
    }
  }

  // 3. Check expiry
  if (payload.expiresAt <= Date.now()) {
    return { error: 'Federated auth expired' }
  }

  // 4. Verify Ed25519 signature
  let publicKeyBytes: Uint8Array
  try {
    publicKeyBytes = didToPublicKey(payload.did)
  } catch {
    return { error: 'Invalid DID format' }
  }

  const signatureBytes = base64urlDecode(signatureEncoded)
  const payloadBytes = new TextEncoder().encode(payloadEncoded)

  let valid: boolean
  try {
    valid = await verify(publicKeyBytes, signatureBytes, payloadBytes)
  } catch {
    return { error: 'Signature verification failed' }
  }

  if (!valid) {
    return { error: 'Invalid signature — user authentication failed' }
  }

  // 5. Verify requestHash
  const expectedHash = await computeRequestHash(requestBody, requestQueryString)
  if (payload.requestHash !== expectedHash) {
    return { error: 'Request hash mismatch — request content was tampered' }
  }

  return {
    did: payload.did,
    action: payload.action,
    spaceId: payload.spaceId,
    serverDid: payload.serverDid,
    relayDid: payload.relayDid,
    requestHash: payload.requestHash,
    expiresAt: payload.expiresAt,
  }
}