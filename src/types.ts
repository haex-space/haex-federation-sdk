/**
 * Federation auth types.
 */

/**
 * Parameters for creating a federated DID-Auth header.
 * Binds the request to a specific user + relay + home server + space.
 */
export interface FederatedAuthParams {
  spaceId: string
  serverDid: string
  relayDid: string
}

/**
 * Payload of a federated DID-Auth token.
 * Every field is signed by the user — none can be modified without invalidating the signature.
 */
export interface FederatedAuthPayload {
  did: string
  action: string
  timestamp: number
  expiresAt: number
  requestHash: string
  spaceId: string
  serverDid: string
  relayDid: string
}

/**
 * Result of verifying a federated user auth token.
 */
export interface VerifiedFederatedAuth {
  did: string
  action: string
  spaceId: string
  serverDid: string
  relayDid: string
  requestHash: string
  expiresAt: number
}
