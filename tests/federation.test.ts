import { describe, it, expect } from 'vitest'
import {
  createFederatedAuthHeader,
  verifyFederatedAuth,
  parseFederatedAuthHeader,
  computeRequestHash,
  type VerifyFn,
  type DidToPublicKeyFn,
} from '../src/index'

// ── Test helpers ─────────────────────────────────────────────────────

const { subtle } = crypto

async function generateTestKeypair() {
  const keypair = await subtle.generateKey('Ed25519', true, ['sign', 'verify']) as CryptoKeyPair
  const rawPublicKey = new Uint8Array(await subtle.exportKey('raw', keypair.publicKey))
  const pkcs8 = new Uint8Array(await subtle.exportKey('pkcs8', keypair.privateKey))
  const privateKeyBase64 = btoa(String.fromCharCode(...pkcs8))

  // Build did:key from raw public key
  const multicodec = new Uint8Array(2 + 32)
  multicodec[0] = 0xed
  multicodec[1] = 0x01
  multicodec.set(rawPublicKey, 2)

  // base58btc encode
  const BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
  const digits = [0]
  for (const byte of multicodec) {
    let carry = byte
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j]! * 256
      digits[j] = carry % 58
      carry = Math.floor(carry / 58)
    }
    while (carry > 0) {
      digits.push(carry % 58)
      carry = Math.floor(carry / 58)
    }
  }
  let encoded = ''
  for (const byte of multicodec) {
    if (byte !== 0) break
    encoded += '1'
  }
  for (let i = digits.length - 1; i >= 0; i--) {
    encoded += BASE58[digits[i]!]
  }
  const did = `did:key:z${encoded}`

  return { did, rawPublicKey, privateKeyBase64, keypair }
}

// base58btc decode for didToPublicKey
function base58btcDecode(str: string): Uint8Array {
  const BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
  let zeros = 0
  for (const c of str) { if (c !== '1') break; zeros++ }
  const bytes: number[] = []
  for (const c of str) {
    const value = BASE58.indexOf(c)
    if (value === -1) throw new Error(`Invalid base58 character: ${c}`)
    let carry = value
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j]! * 58; bytes[j] = carry & 0xff; carry >>= 8
    }
    while (carry > 0) { bytes.push(carry & 0xff); carry >>= 8 }
  }
  const result = new Uint8Array(zeros + bytes.length)
  for (let i = 0; i < bytes.length; i++) result[zeros + i] = bytes[bytes.length - 1 - i]!
  return result
}

const didToPublicKey: DidToPublicKeyFn = (did: string) => {
  if (!did.startsWith('did:key:z')) throw new Error('Unsupported DID')
  const decoded = base58btcDecode(did.slice('did:key:z'.length))
  if (decoded[0] !== 0xed || decoded[1] !== 0x01) throw new Error('Not Ed25519')
  return decoded.slice(2)
}

const verifyEd25519: VerifyFn = async (publicKey, signature, data) => {
  const key = await subtle.importKey('raw', new Uint8Array(publicKey), { name: 'Ed25519' }, false, ['verify'])
  return subtle.verify('Ed25519', key, new Uint8Array(signature), new Uint8Array(data))
}

// ── Tests ────────────────────────────────────────────────────────────

describe('requestHash', () => {
  it('produces deterministic hash for same input', async () => {
    const hash1 = await computeRequestHash('body', 'b=2&a=1')
    const hash2 = await computeRequestHash('body', 'a=1&b=2')
    expect(hash1).toBe(hash2) // sorted query params
  })

  it('different body produces different hash', async () => {
    const hash1 = await computeRequestHash('body1', 'a=1')
    const hash2 = await computeRequestHash('body2', 'a=1')
    expect(hash1).not.toBe(hash2)
  })

  it('different query produces different hash', async () => {
    const hash1 = await computeRequestHash('body', 'a=1')
    const hash2 = await computeRequestHash('body', 'a=2')
    expect(hash1).not.toBe(hash2)
  })
})

describe('createFederatedAuthHeader', () => {
  it('creates a valid DID auth header', async () => {
    const { did, privateKeyBase64 } = await generateTestKeypair()

    const header = await createFederatedAuthHeader(did, privateKeyBase64, 'sync-pull', {
      spaceId: 'space-123',
      serverDid: 'did:web:home.example.com',
      relayDid: 'did:web:relay.example.com',
    }, '', 'spaceId=space-123')

    expect(header).toMatch(/^DID [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/)
  })
})

describe('parseFederatedAuthHeader', () => {
  it('parses a federated auth header', async () => {
    const { did, privateKeyBase64 } = await generateTestKeypair()

    const header = await createFederatedAuthHeader(did, privateKeyBase64, 'sync-pull', {
      spaceId: 'space-123',
      serverDid: 'did:web:home.example.com',
      relayDid: 'did:web:relay.example.com',
    })

    const parsed = parseFederatedAuthHeader(header)
    expect(parsed).not.toBeNull()
    expect(parsed!.did).toBe(did)
    expect(parsed!.spaceId).toBe('space-123')
    expect(parsed!.serverDid).toBe('did:web:home.example.com')
    expect(parsed!.relayDid).toBe('did:web:relay.example.com')
  })

  it('returns null for non-federated DID auth', () => {
    // A standard DID-Auth header without federation fields
    const parsed = parseFederatedAuthHeader('DID eyJkaWQiOiJ0ZXN0IiwiYWN0aW9uIjoic3luYyIsInRpbWVzdGFtcCI6MCwiYm9keUhhc2giOiJ4In0.fake')
    expect(parsed).toBeNull()
  })
})

describe('verifyFederatedAuth', () => {
  it('verifies a valid federated auth token', async () => {
    const { did, privateKeyBase64 } = await generateTestKeypair()
    const body = '{"data":true}'
    const query = 'spaceId=space-123'

    const header = await createFederatedAuthHeader(did, privateKeyBase64, 'sync-push', {
      spaceId: 'space-123',
      serverDid: 'did:web:home.example.com',
      relayDid: 'did:web:relay.example.com',
    }, body, query)

    const result = await verifyFederatedAuth(header, verifyEd25519, didToPublicKey, body, query)
    expect('error' in result).toBe(false)
    if (!('error' in result)) {
      expect(result.did).toBe(did)
      expect(result.spaceId).toBe('space-123')
      expect(result.serverDid).toBe('did:web:home.example.com')
      expect(result.relayDid).toBe('did:web:relay.example.com')
    }
  })

  it('rejects tampered body', async () => {
    const { did, privateKeyBase64 } = await generateTestKeypair()
    const body = '{"data":true}'
    const query = 'spaceId=space-123'

    const header = await createFederatedAuthHeader(did, privateKeyBase64, 'sync-push', {
      spaceId: 'space-123',
      serverDid: 'did:web:home.example.com',
      relayDid: 'did:web:relay.example.com',
    }, body, query)

    // Verify with tampered body
    const result = await verifyFederatedAuth(header, verifyEd25519, didToPublicKey, '{"data":false}', query)
    expect('error' in result).toBe(true)
    if ('error' in result) {
      expect(result.error).toContain('tampered')
    }
  })

  it('rejects tampered query', async () => {
    const { did, privateKeyBase64 } = await generateTestKeypair()
    const body = ''
    const query = 'spaceId=space-123'

    const header = await createFederatedAuthHeader(did, privateKeyBase64, 'sync-pull', {
      spaceId: 'space-123',
      serverDid: 'did:web:home.example.com',
      relayDid: 'did:web:relay.example.com',
    }, body, query)

    const result = await verifyFederatedAuth(header, verifyEd25519, didToPublicKey, body, 'spaceId=space-EVIL')
    expect('error' in result).toBe(true)
  })

  it('rejects expired token', async () => {
    const { did, privateKeyBase64 } = await generateTestKeypair()

    // Create with 1ms expiry
    const header = await createFederatedAuthHeader(did, privateKeyBase64, 'sync-pull', {
      spaceId: 'space-123',
      serverDid: 'did:web:home.example.com',
      relayDid: 'did:web:relay.example.com',
    }, '', '', 1)

    // Wait for expiry
    await new Promise(r => setTimeout(r, 10))

    const result = await verifyFederatedAuth(header, verifyEd25519, didToPublicKey, '', '')
    expect('error' in result).toBe(true)
    if ('error' in result) {
      expect(result.error).toContain('expired')
    }
  })

  it('rejects when Eve signs but claims to be Alice', async () => {
    const alice = await generateTestKeypair()
    const eve = await generateTestKeypair()

    // Eve signs a request claiming to be Alice (uses Alice's DID but Eve's key)
    const header = await createFederatedAuthHeader(alice.did, eve.privateKeyBase64, 'sync-pull', {
      spaceId: 'space-123',
      serverDid: 'did:web:home.example.com',
      relayDid: 'did:web:relay.example.com',
    })

    // Verification extracts public key from Alice's DID but signature is Eve's → mismatch
    const result = await verifyFederatedAuth(header, verifyEd25519, didToPublicKey, '', '')
    expect('error' in result).toBe(true)
    if ('error' in result) {
      expect(result.error).toContain('Invalid signature')
    }
  })
})
