// Types
export type {
  FederatedAuthParams,
  FederatedAuthPayload,
  VerifiedFederatedAuth,
} from './types'

// Creating federated auth headers (client-side)
export { createFederatedAuthHeader, type SignFn } from './create'

// Verifying federated auth tokens (server-side)
export {
  verifyFederatedAuth,
  parseFederatedAuthHeader,
  type VerifyFn,
  type DidToPublicKeyFn,
} from './verify'

// Request hash computation (shared)
export { computeRequestHash } from './requestHash'

// Encoding utilities (shared)
export { base64urlEncode, base64urlDecode, hexEncode } from './encoding'
