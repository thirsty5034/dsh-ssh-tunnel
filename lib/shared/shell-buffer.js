/**
 * Incremental shell output slice for polling clients.
 *
 * Cursor unit: UTF-16 code units (JS string indices), matching
 * `fullText.slice(start)` and `fullText.length`. The client must advance
 * its cursor with `length` (or `since`) from this module — never with
 * `chunk.length` arithmetic of its own, and the two MUST NOT be mixed:
 * server-side `Buffer.byteLength` bookkeeping (ring eviction in
 * session.js) is a byte budget only and never leaks into this cursor.
 */
export function chunkFromBuffer(fullText, since) {
  const full = fullText == null ? '' : String(fullText)
  const start = Math.max(0, Math.min(Number(since) || 0, full.length))
  return {
    chunk: full.slice(start),
    length: full.length,
    since: start,
  }
}
