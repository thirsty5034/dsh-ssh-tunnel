import { createHash } from 'node:crypto'

/** True when stored value is a sha256 hex digest (not legacy raw-key String(Buffer)). */
export function isUsableHostFingerprint(fp) {
  return typeof fp === 'string' && /^[0-9a-f]{64}$/.test(fp.trim().toLowerCase())
}

/**
 * Normalize ssh2 hostVerifier input to a stable sha256 hex fingerprint.
 * - With connect option hostHash:'sha256', key is already a hex string.
 * - Raw Buffer (no hostHash) is hashed here as a safe fallback.
 */
export function fingerprintFromHostKey(key) {
  if (key == null) return ''
  if (typeof key === 'string') {
    const s = key.trim().toLowerCase()
    if (/^[0-9a-f]{64}$/.test(s)) return s
    if (/^[0-9a-f]+$/.test(s) && s.length >= 32) return createHash('sha256').update(Buffer.from(s, 'hex')).digest('hex')
    return createHash('sha256').update(Buffer.from(key, 'utf8')).digest('hex')
  }
  if (typeof Buffer !== 'undefined' && Buffer.isBuffer(key)) {
    return createHash('sha256').update(key).digest('hex')
  }
  return createHash('sha256').update(Buffer.from(String(key))).digest('hex')
}

/** Human-facing label for trust prompts / logs. */
export function formatHostFingerprint(fp, algo = 'SHA256') {
  if (!fp) return ''
  const hex = String(fp).trim().toLowerCase()
  return `${algo}:${hex}`
}
