/**
 * Compute a deterministic hash of a request's content (body + query parameters).
 *
 * Format: SHA-256(body + '?' + sortedQueryString) → hex string
 *
 * The query parameters are sorted alphabetically for deterministic hashing.
 * The '?' separator ensures no collision between body and query content.
 *
 * Examples:
 *   POST with body and query: SHA-256('{"data":true}?limit=100&spaceId=abc')
 *   GET with query only:      SHA-256('?afterUpdatedAt=...&spaceId=abc')
 *   POST with body, no query: SHA-256('{"data":true}?')
 */

import { hexEncode } from './encoding'

export async function computeRequestHash(body: string, queryString: string): Promise<string> {
  const params = new URLSearchParams(queryString)
  const sorted = new URLSearchParams([...params.entries()].sort())
  const input = body + '?' + sorted.toString()
  const hash = new Uint8Array(
    await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input)),
  )
  return hexEncode(hash)
}
