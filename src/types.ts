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

/**
 * Options for creating a federated DID-Auth header.
 */
export interface CreateFederatedAuthOptions {
  did: string
  privateKeyBase64: string
  action: string
  federation: FederatedAuthParams
  body?: string
  queryString?: string
  expiresInMs?: number
}

/**
 * Options for verifying a federated DID-Auth token.
 */
export interface VerifyFederatedAuthOptions {
  authHeader: string
  verify: (publicKey: Uint8Array, signature: Uint8Array, data: Uint8Array) => Promise<boolean>
  didToPublicKey: (did: string) => Uint8Array
  requestBody: string
  requestQueryString: string
}

/**
 * Options for building a FEDERATION server-to-server auth header.
 * Used by relay servers to forward requests to home servers.
 */
export interface BuildFederationAuthHeaderOptions {
  serverDid: string
  privateKeyPkcs8Base64: string
  action: string
  body: string
  ucanToken: string
  userAuthorization?: string
  expiresInMs?: number
}
