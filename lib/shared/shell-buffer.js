/** Incremental shell output slice for polling clients. */
export function chunkFromBuffer(fullText, since) {
  const full = fullText == null ? '' : String(fullText)
  const start = Math.max(0, Math.min(Number(since) || 0, full.length))
  return {
    chunk: full.slice(start),
    length: full.length,
    since: start,
  }
}
