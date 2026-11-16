#!/usr/bin/env node
/**
 * Offline smoke tests (no SSH, no DSH process).
 * Run: node scripts/smoke-test.mjs
 */
import assert from 'node:assert/strict'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { existsSync, mkdirSync, symlinkSync, unlinkSync, writeFileSync } from 'node:fs'
import { normalizeProjectKey, isPathInsideRoots, joinUnderRoot, constrainToWorkspace } from '../lib/shared/path.js'
import {
  hostCredentialConfigured,
  publicHost,
  modelHostSummary,
  assertNoSecretFields,
} from '../lib/shared/host-summary.js'
import { chunkFromBuffer } from '../lib/shared/shell-buffer.js'
import {
  fingerprintFromHostKey,
  formatHostFingerprint,
  isUsableHostFingerprint,
} from '../lib/shared/host-key.js'
import {
  clampTimeoutMs,
  defaultTimeoutMsForAction,
  findReusableLive,
  pickOldestTombstone,
  withTimeout,
  SSH_TIMEOUT_MIN_MS,
  SSH_TIMEOUT_MAX_MS,
  SSH_EXEC_DEFAULT_TIMEOUT_MS,
  SSH_SFTP_TRANSFER_TIMEOUT_MS,
  SSH_STATUS_CONNECTED,
  SSH_STATUS_DISCONNECTED,
  disconnectedSessionError,
  kbiUnsupportedError,
} from '../lib/shared/session-policy.js'
import { createSessionRegistry } from '../lib/session.js'
import { isLoopbackHostname, isWildcardHost, isTrustedRequest, apiTrustDecision } from '../lib/shared/http-trust.js'
import {
  findExistingHostByEndpoint,
  readJsonFile,
  writeJsonAtomic,
} from '../lib/shared/persist.js'
import {
  assertSessionStillAuthorized,
  discardRevokedLocalFile,
} from '../lib/shared/session-auth.js'
import {
  VENDOR_ASSETS,
  isVendorAssetAllowed,
  resolveVendorAsset,
} from '../lib/shared/vendor.js'

let failed = 0
const pending = []
function test(name, fn) {
  const run = () => {
    try {
      const result = fn()
      if (result && typeof result.then === 'function') {
        return result.then(
          () => console.log('ok  ', name),
          (e) => {
            failed++
            console.error('FAIL', name, e && e.message ? e.message : e)
          },
        )
      }
      console.log('ok  ', name)
    } catch (e) {
      failed++
      console.error('FAIL', name, e && e.message ? e.message : e)
    }
  }
  const out = run()
  if (out && typeof out.then === 'function') pending.push(out)
}

test('normalizeProjectKey strips trailing slash', () => {
  assert.equal(normalizeProjectKey('/workspace/DSH-plugin/'), '/workspace/DSH-plugin')
})

test('normalizeProjectKey empty', () => {
  assert.equal(normalizeProjectKey(''), '')
  assert.equal(normalizeProjectKey(null), '')
})

test('isPathInsideRoots allows children only', () => {
  assert.equal(isPathInsideRoots('/workspace/DSH-plugin/a', ['/workspace/DSH-plugin']), true)
  assert.equal(isPathInsideRoots('/workspace/other', ['/workspace/DSH-plugin']), false)
  assert.equal(isPathInsideRoots('/workspace/DSH-plugin', ['/workspace/DSH-plugin']), true)
})

test('joinUnderRoot rejects escape', () => {
  assert.throws(() => joinUnderRoot('/workspace/DSH-plugin', '../../etc/passwd'))
  const ok = joinUnderRoot('/workspace/DSH-plugin', 'sub/file.txt')
  assert.ok(ok.endsWith('/workspace/DSH-plugin/sub/file.txt') || ok.includes('DSH-plugin/sub/file.txt'))
})

test('constrainToWorkspace rejects lexical escape', () => {
  assert.throws(() => constrainToWorkspace('/home/node/.dsh/ssh-tunnel/secrets.json'), /must be under \/workspace/)
  assert.throws(() => constrainToWorkspace('/tmp'), /must be under \/workspace/)
})

test('persist: corrupt json throws; atomic write replaces', () => {
  const dir = join(tmpdir(), `dsh-ssh-persist-${process.pid}`)
  mkdirSync(dir, { recursive: true })
  const p = join(dir, 'secrets.json')
  writeFileSync(p, '{not json', 'utf8')
  assert.throws(() => readJsonFile(p, { version: 1, byHostId: {} }), /corrupt json/)
  writeJsonAtomic(p, { version: 1, byHostId: { h1: { password: 'x' } } }, 0o600)
  const loaded = readJsonFile(p, null)
  assert.equal(loaded.byHostId.h1.password, 'x')
  assert.equal(existsSync(p + '.tmp'), false)
  assert.equal(findExistingHostByEndpoint(
    [{ host: 'a', port: 22, username: 'root', id: '1' }],
    'a',
    22,
    'root',
  )?.id, '1')
  assert.equal(findExistingHostByEndpoint(
    [{ host: 'a', port: 22, username: 'root', id: '1' }],
    'a',
    22,
    'other',
  ), undefined)
})

test('http-trust: 0.0.0.0 is not loopback', () => {
  assert.equal(isLoopbackHostname('127.0.0.1'), true)
  assert.equal(isLoopbackHostname('::1'), true)
  assert.equal(isLoopbackHostname('0.0.0.0'), false)
})

test('apiTrustDecision: connection service is authoritative when mounted', () => {
  const req = { headers: { host: '127.0.0.1:3080' } }
  const conn = (verdict) => ({ requestRejection: () => verdict })
  assert.equal(apiTrustDecision({ connection: conn(undefined) }, req), undefined)
  assert.equal(apiTrustDecision({ connection: conn(401) }, req), 401)
  assert.equal(apiTrustDecision({ connection: conn(403) }, req), 403)
})

test('apiTrustDecision: webStartup trustedHosts fence when connection is absent', () => {
  // Same explicit port on Host and Origin (the S1 rule: origin port must
  // equal the request port, so same-hostname-different-port cannot pass).
  const req = { headers: { host: 'dsh.example.com:8443', origin: 'https://dsh.example.com:8443' } }
  const evil = { headers: { host: 'dsh.example.com:8443', origin: 'https://evil.example' } }
  const evilPort = { headers: { host: 'dsh.example.com:8443', origin: 'https://dsh.example.com:9999' } }
  assert.equal(apiTrustDecision({ webStartup: { trustedHosts: ['dsh.example.com'] } }, req), undefined)
  assert.equal(apiTrustDecision({ webStartup: { trustedHosts: ['dsh.example.com'] } }, evil), 403)
  assert.equal(apiTrustDecision({ webStartup: { trustedHosts: ['dsh.example.com'] } }, evilPort), 403)
  // No trusted hosts configured -> the layer admits nothing.
  assert.equal(apiTrustDecision({ webStartup: { trustedHosts: [] } }, req), 403)
})

test('isTrustedRequest: same-hostname cross-port origin is rejected (S1)', () => {
  const req = { headers: { host: 'dsh.example.com:3080', origin: 'http://dsh.example.com:9999' } }
  assert.equal(isTrustedRequest(req, ['dsh.example.com']), false)
  const samePort = { headers: { host: 'dsh.example.com:3080', origin: 'http://dsh.example.com:3080' } }
  assert.equal(isTrustedRequest(samePort, ['dsh.example.com']), true)
  const hostWithPort = { headers: { host: 'dsh.example.com:3080', origin: 'http://dsh.example.com:3080' } }
  assert.equal(isTrustedRequest(hostWithPort, ['dsh.example.com:3080']), true)
})

test('apiTrustDecision: listener bind address is a fallback authority (fork issue #7)', () => {
  // LAN deployment: dsh web started with --host 192.168.1.10 --port 3092
  // and no --trusted-host. The bind address must admit same-host
  // requests; wildcard binds authorize nothing.
  const ctx = { webStartup: { host: '192.168.1.10', port: 3092, trustedHosts: [] } }
  const lanReq = { headers: { host: '192.168.1.10:3092', origin: 'http://192.168.1.10:3092' } }
  const lanNoOrigin = { headers: { host: '192.168.1.10:3092' } }
  const evil = { headers: { host: '192.168.1.10:3092', origin: 'http://evil.example' } }
  assert.equal(apiTrustDecision(ctx, lanReq), undefined)
  assert.equal(apiTrustDecision(ctx, lanNoOrigin), undefined)
  assert.equal(apiTrustDecision(ctx, evil), 403)
  // Wildcard bind never becomes an authority.
  const wildcardCtx = { webStartup: { host: '0.0.0.0', port: 3080, trustedHosts: [] } }
  const remote = { headers: { host: 'dsh.example.com:3080' } }
  assert.equal(apiTrustDecision(wildcardCtx, remote), 403)
  // Explicit --trusted-host still works alongside the bind address.
  // (Host and Origin must carry the same explicit port per the S1 rule.)
  const bothCtx = { webStartup: { host: '192.168.1.10', port: 3092, trustedHosts: ['vpn.example.com'] } }
  assert.equal(apiTrustDecision(bothCtx, { headers: { host: 'vpn.example.com:8443', origin: 'https://vpn.example.com:8443' } }), undefined)
  assert.equal(apiTrustDecision(bothCtx, { headers: { host: 'vpn.example.com:8443', origin: 'https://vpn.example.com:9999' } }), 403)
})

test('apiTrustDecision: loopback-only last resort without connection/webStartup', () => {
  const loop = { headers: { host: '127.0.0.1:3080' } }
  const loopSameOrigin = { headers: { host: '127.0.0.1:3080', origin: 'http://127.0.0.1:3080' } }
  const loopCrossOrigin = { headers: { host: '127.0.0.1:3080', origin: 'http://evil.example' } }
  const remote = { headers: { host: 'dsh.example.com' } }
  const wildcard = { headers: { host: '0.0.0.0:3080' } }
  assert.equal(apiTrustDecision({}, loop), undefined)
  assert.equal(apiTrustDecision({}, loopSameOrigin), undefined)
  assert.equal(apiTrustDecision({}, loopCrossOrigin), 403)
  assert.equal(apiTrustDecision({}, remote), 403)
  assert.equal(apiTrustDecision({}, wildcard), 403)
})

test('apiTrustDecision: connection missing but method present still uses connection', () => {
  // A connection object without requestRejection is not the fence owner;
  // fall through to webStartup/loopback rather than calling a broken shape.
  const loop = { headers: { host: '127.0.0.1:3080' } }
  assert.equal(apiTrustDecision({ connection: {} }, loop), undefined)
  assert.equal(apiTrustDecision({ connection: { requestRejection: 'not-a-function' } }, loop), undefined)
})

test('constrainToWorkspace rejects outbound symlink', () => {
  const link = '/workspace/DSH-plugin/.audit-path-guard-link'
  try {
    try { unlinkSync(link) } catch {}
    symlinkSync('/home/node/.dsh', link)
    assert.throws(
      () => constrainToWorkspace(link + '/ssh-tunnel/_nope'),
      /escapes \/workspace via symlink/,
    )
    const unlinked = constrainToWorkspace(link, { forUnlink: true })
    assert.equal(unlinked, link)
  } finally {
    try { unlinkSync(link) } catch {}
  }
})

test('credential + publicHost never leak secrets', () => {
  const host = {
    id: 'h1',
    name: 'n',
    host: '1.2.3.4',
    port: 22,
    username: 'root',
    authType: 'password',
  }
  const secrets = { byHostId: { h1: { password: 's3cret', privateKeyPem: 'BEGIN' } } }
  assert.equal(hostCredentialConfigured(host, secrets), true)
  const pub = publicHost(host, secrets)
  assert.equal(pub.passwordConfigured, true)
  assert.equal(pub.credentialStatus, 'saved')
  assert.equal('password' in pub, false)
  assert.equal('privateKeyPem' in pub, false)
  assertNoSecretFields(pub)
  const model = modelHostSummary(host, secrets)
  assertNoSecretFields(model)
  assert.equal(model.credentialStatus, 'saved')
})

test('retired keyboard-interactive is unsupported, not a usable credential', () => {
  const host = { id: 'h2', authType: 'keyboardInteractive', host: 'x', username: 'u' }
  const pub = publicHost(host, { byHostId: {} })
  assert.equal(pub.credentialStatus, 'unsupported')
  assert.equal(pub.credentialConfigured, false)
})

test('chunkFromBuffer incremental', () => {
  const a = chunkFromBuffer('hello', 0)
  assert.equal(a.chunk, 'hello')
  assert.equal(a.length, 5)
  const b = chunkFromBuffer('hello world', 5)
  assert.equal(b.chunk, ' world')
  assert.equal(b.since, 5)
})

test('issue #11 repro: two overlapping shellRead polls with same cursor must not double-write', async () => {
  // Mirrors the CenterBash polling tick in lib/client.js (see the
  // readInFlight guard there). KEEP IN SYNC: if the component's tick
  // guard/cursor logic changes, update this mirror so the regression
  // keeps covering the real shape (a shared extracted poll helper would
  // remove the drift risk entirely).
  // Scenario: the interval fires again while the first shellRead is
  // still awaited, both requests carry since=0, and the host returns the
  // same chunk to both. The in-flight guard must make the second tick a
  // no-op, so the terminal sees 'abc' exactly once and the cursor
  // advances once.
  let shellReadCalls = 0
  const written = []
  const term = { write(s) { written.push(s) } }
  let since = 0
  let readInFlight = false
  const api = async (method, body) => {
    assert.equal(method, 'shellRead')
    shellReadCalls += 1
    const call = shellReadCalls
    if (call === 1) await new Promise((r) => setTimeout(r, 30)) // first poll hangs
    return { chunk: 'abc', length: 3, since: body.since }
  }
  const poll = async () => {
    // Mirrors the fixed CenterBash tick: the in-flight guard is checked
    // at entry and released only when the awaited read settles; the
    // cursor follows the host's authoritative r.length (byte offset),
    // never chunk.length (UTF-16 chars).
    if (readInFlight) return
    readInFlight = true
    try {
      const r = await api('shellRead', { since })
      if (r.chunk) {
        term.write(r.chunk)
        if (r.length != null) since = r.length
      } else if (r.length != null) since = r.length
    } finally {
      readInFlight = false
    }
  }
  const tick1 = poll() // tick 1 starts the read and stays in flight
  await poll() // tick 2 must be a no-op while tick 1 is awaited
  await tick1 // let tick 1's hung read resolve and release the guard
  assert.deepEqual(written, ['abc']) // no 'abcabc'
  assert.equal(since, 3)
  assert.equal(shellReadCalls, 1)
})

test('issue #11 repro: cancelled poll must not write to a disposed terminal', async () => {
  // Mirrors the CenterBash cleanup race in lib/client.js. KEEP IN SYNC
  // with the component's post-await `cancelled || !termRef.current`
  // check. (The `!term` arm below is a faithful mirror of the component
  // shape; `term` never becomes null in this isolated harness.)
  let cancelled = false
  const written = []
  const term = { write(s) { written.push(s) } }
  const api = async () => {
    await new Promise((r) => setTimeout(r, 20))
    return { chunk: 'late', length: 4, since: 0 }
  }
  const poll = async () => {
    const r = await api('shellRead', { since: 0 })
    if (cancelled || !term) return // post-await guard under test
    term.write(r.chunk)
  }
  const p = poll()
  cancelled = true // cleanup fires mid-flight
  await p
  assert.deepEqual(written, [])
})

test('cursor advance follows the host cursor unit, not a client-side re-derivation', () => {
  // chunkFromBuffer's cursor unit is the UTF-16 code unit (JS string
  // index): length === full.length, since === slice start. The client
  // must adopt r.length verbatim; deriving it from chunk.length or
  // Buffer.byteLength would desync the cursor on non-ASCII output.
  const full = '中文输出'
  const sliced = chunkFromBuffer(full, 0)
  assert.equal(sliced.chunk, full)
  assert.equal(sliced.length, full.length) // 4 UTF-16 units, NOT Buffer.byteLength
  assert.equal(sliced.since, 0)
  // Simulate the fixed tick's cursor update for this response.
  let since = 0
  const r = { chunk: sliced.chunk, length: sliced.length, since: sliced.since }
  if (r.chunk) {
    if (r.length != null) since = r.length
  }
  assert.equal(since, 4) // cursor unit == string index
  // A later slice from that cursor must not repeat text.
  const more = chunkFromBuffer(full + '!', 4)
  assert.equal(more.chunk, '!')
  assert.equal(more.since, 4)
})

test('host key fingerprint is stable sha256 hex (no UTF-8 collision)', () => {
  const prefix = Buffer.concat([
    Buffer.from([0, 0, 0, 11]),
    Buffer.from('ssh-ed25519'),
    Buffer.from([0, 0, 0, 32]),
  ])
  const k1 = Buffer.concat([prefix, Buffer.alloc(32, 0x80)])
  const k2 = Buffer.concat([prefix, Buffer.alloc(32, 0x81)])
  // Legacy bug: String(buf) collapsed different keys via U+FFFD.
  assert.equal(String(k1) === String(k2), true)
  const f1 = fingerprintFromHostKey(k1)
  const f2 = fingerprintFromHostKey(k2)
  assert.equal(isUsableHostFingerprint(f1), true)
  assert.equal(isUsableHostFingerprint(f2), true)
  assert.notEqual(f1, f2)
  // ssh2 hostHash path: already-hex digest is kept as-is (lowercased).
  assert.equal(fingerprintFromHostKey(f1.toUpperCase()), f1)
  assert.equal(formatHostFingerprint(f1), 'SHA256:' + f1)
  // Legacy binary stored strings are rejected as unusable.
  assert.equal(isUsableHostFingerprint(String(k1)), false)
  assert.equal(isUsableHostFingerprint('\u0000ssh-ed25519'), false)
})

test('clampTimeoutMs bounds and fallback', () => {
  assert.equal(clampTimeoutMs(undefined, 30_000), 30_000)
  assert.equal(clampTimeoutMs(0, 30_000), 30_000)
  assert.equal(clampTimeoutMs(500, 30_000), SSH_TIMEOUT_MIN_MS)
  assert.equal(clampTimeoutMs(999_999, 30_000), SSH_TIMEOUT_MAX_MS)
})

test('defaultTimeoutMsForAction', () => {
  assert.equal(defaultTimeoutMsForAction('exec'), SSH_EXEC_DEFAULT_TIMEOUT_MS)
  assert.equal(defaultTimeoutMsForAction('sftp_upload'), SSH_SFTP_TRANSFER_TIMEOUT_MS)
  assert.equal(defaultTimeoutMsForAction('sftp_list'), 30_000)
})

test('reuse live vs tombstone pick', () => {
  const key = '/workspace'
  const sessions = [
    { id: 'dead', hostId: 'h1', projectPathKey: key, status: 'disconnected', running: false, sftpEnabled: true, createdAt: 1 },
    { id: 'live', hostId: 'h1', projectPathKey: key, status: 'connected', running: true, sftpEnabled: true, createdAt: 2 },
  ]
  assert.equal(findReusableLive(sessions, { projectPathKey: key, hostId: 'h1', needsSftp: true }).id, 'live')
  assert.equal(pickOldestTombstone(sessions, { projectPathKey: key, hostId: 'h1', needsSftp: true }).id, 'dead')
  assert.equal(
    findReusableLive(
      sessions.filter((s) => s.id === 'dead'),
      { projectPathKey: key, hostId: 'h1', needsSftp: true },
    ),
    undefined,
  )
})

test('withTimeout rejects and calls onTimeout', async () => {
  let hit = false
  await assert.rejects(
    () => withTimeout(new Promise(() => {}), 1000, { onTimeout: () => { hit = true } }),
    (e) => e.timedOut === true && hit === true,
  )
})

test('disconnectedSessionError is stable English for the model', () => {
  assert.match(disconnectedSessionError(), /disconnected/i)
})

test('kbiUnsupportedError tells the model to switch auth', () => {
  assert.match(kbiUnsupportedError(), /not supported/i)
  assert.match(kbiUnsupportedError(), /password or private key/i)
})

/* ------------------------------------------------------------------ *
 * Security regression: revoking a host's project grant must make its  *
 * established tunnel sessions unusable AND unreconnectable, and revoke *
 * must terminate those sessions (DSH plugin upgrade audit 2026-09-08). *
 * ------------------------------------------------------------------ */

function makeRegistry({ isHostAuthorized = () => true } = {}) {
  return createSessionRegistry({
    connectClient: async () => {
      throw new Error('connectClient must not be used in offline tests')
    },
    loadSecrets: () => ({ byHostId: {} }),
    getPrompt: () => undefined,
    getHostById: (id) => ({
      id,
      name: 'x',
      host: '1.2.3.4',
      port: 22,
      username: 'root',
      authType: 'password',
    }),
    isHostAuthorized,
  })
}

function liveRec(id, hostId, projectPathKey) {
  return {
    id,
    hostId,
    projectPathKey,
    status: SSH_STATUS_CONNECTED,
    running: true,
    client: {},
    sftpEnabled: true,
    closing: false,
    createdAt: Date.now(),
    updatedAt: Date.now(),
    reconnectRunner: false,
    reconnectAttempt: 0,
    connectionGeneration: 1,
    title: `t-${id}`,
    endpoint: '',
  }
}

test('revoked host: requireLiveSession refuses use of established session', () => {
  const registry = makeRegistry({ isHostAuthorized: () => false })
  const key = '/workspace/DSH-plugin'
  registry.sessions.set('s1', liveRec('s1', 'h-sg', key))
  // Shell / SFTP operations all go through requireLiveSession; a revoked host
  // must not be usable even though the session object is still live.
  assert.throws(() => registry.requireLiveSession('s1', key), /not authorized/)
})

test('granted host: requireLiveSession still allows use', () => {
  const registry = makeRegistry({ isHostAuthorized: () => true })
  const key = '/workspace/DSH-plugin'
  registry.sessions.set('s1', liveRec('s1', 'h-sg', key))
  assert.equal(registry.requireLiveSession('s1', key).id, 's1')
})

test('closeAll terminates every live session and survives a failing close', () => {
  // Fork 431e465: plugin unload must not leak live SSH sessions; one
  // failing close must not stop the rest.
  const registry = makeRegistry({ isHostAuthorized: () => true })
  const key = '/workspace/DSH-plugin'
  const bad = liveRec('bad', 'h1', key)
  bad.client = { end() { throw new Error('client.end exploded') } }
  const good = liveRec('good', 'h2', key)
  let ended = 0
  good.client = { end() { ended += 1 } }
  registry.sessions.set('bad', bad)
  registry.sessions.set('good', good)
  const r = registry.closeAll()
  assert.equal(r.closed, 2)
  assert.deepEqual([...r.sessionIds].sort(), ['bad', 'good'])
  assert.equal(registry.sessions.size, 0)
  assert.equal(ended, 1)
})

test('canGoUp root boundary: POSIX, drive and UNC roots cannot go up', () => {
  // Extracted from fork 2ed6a8b (canGoUp): the SFTP "Up" button must be
  // disabled at filesystem roots instead of looping to "/".
  // canGoUp is mirrored from lib/client.js (KEEP IN SYNC).
  const canGoUp = (p) => {
    const s = String(p || '')
    if (!s || s === '/') return false
    if (s.startsWith('/')) {
      // "//server/share" is a UNC root, not a POSIX parent chain.
      if (/^\/\/[^/]+\/[^/]+\/?$/.test(s)) return false
      return s.replace(/\/+$/, '') !== '/'
    }
    const winDrive = /^[a-zA-Z]:[\\/]?$/
    const unc = /^\/\/[^/]+\/[^/]+\/?$/
    return !(winDrive.test(s) || unc.test(s) || (() => {
      if (!s || s === '/') return true
      const n = String(s).replace(/\/+$/, '')
      const i = n.lastIndexOf('/')
      const parent = i <= 0 ? '/' : n.slice(0, i) || '/'
      return parent === s
    })())
  }
  assert.equal(canGoUp('/'), false)
  assert.equal(canGoUp('/workspace'), true)
  assert.equal(canGoUp('/workspace/DSH-plugin'), true)
  assert.equal(canGoUp('C:\\'), false)
  assert.equal(canGoUp('C:/'), false)
  assert.equal(canGoUp('//server/share'), false)
  assert.equal(canGoUp(''), false)
  assert.equal(canGoUp(null), false)
})

test('revoked host: reconnect refuses to resurrect the session', async () => {
  const registry = makeRegistry({ isHostAuthorized: () => false })
  const key = '/workspace/DSH-plugin'
  const rec = liveRec('s1', 'h-sg', key)
  rec.status = SSH_STATUS_DISCONNECTED
  rec.running = false
  registry.sessions.set('s1', rec)
  await assert.rejects(
    () => registry.reconnectSession('s1', { manual: true, projectPathKey: key }),
    /not authorized/,
  )
})

test('requireLiveSession and closeSession require projectPathKey', () => {
  const registry = makeRegistry()
  const key = '/workspace/DSH-plugin'
  registry.sessions.set('s1', liveRec('s1', 'h-sg', key))
  assert.throws(() => registry.requireLiveSession('s1'), /projectPathKey required/)
  assert.throws(() => registry.requireLiveSession('s1', ''), /projectPathKey required/)
  assert.throws(() => registry.requireLiveSession('s1', '/workspace/hk'), /not in this project/)
  assert.throws(() => registry.closeSession('s1'), /projectPathKey required/)
  assert.equal(registry.closeSession('s1', key).ok, true)
  assert.equal(registry.sessions.has('s1'), false)
})

test('closeSessionsForHost terminates only the revoked host sessions in the project', () => {
  const registry = makeRegistry()
  const keyA = '/workspace/DSH-plugin'
  const keyB = '/workspace/other'
  registry.sessions.set('a1', liveRec('a1', 'h-sg', keyA)) // revoked host, this project
  registry.sessions.set('b1', liveRec('b1', 'h2', keyA)) // other host, same project
  registry.sessions.set('c1', liveRec('c1', 'h-sg', keyB)) // same host, other project
  const out = registry.closeSessionsForHost(keyA, 'h-sg')
  assert.equal(out.closed, 1)
  assert.equal(registry.sessions.has('a1'), false)
  assert.equal(registry.sessions.has('b1'), true)
  assert.equal(registry.sessions.has('c1'), true)
})

/* ------------------------------------------------------------------ *
 * Security regression (v0.4.3): a tool result must not be delivered   *
 * after the host's grant is revoked mid-operation, and a downloaded    *
 * file must not survive a mid-transfer revocation.                     *
 * ------------------------------------------------------------------ */

test('result gate: revoked host denies tool result delivery', () => {
  assert.throws(
    () =>
      assertSessionStillAuthorized(
        { projectPathKey: '/workspace/DSH-plugin', hostId: 'h-sg' },
        () => false,
      ),
    /not authorized/,
  )
})

test('result gate: granted host still delivers tool results', () => {
  assert.doesNotThrow(() =>
    assertSessionStillAuthorized({ projectPathKey: '/workspace/DSH-plugin', hostId: 'h-sg' }, () => true),
  )
})

test('result gate: absent predicate is fail-closed', () => {
  assert.throws(
    () =>
      assertSessionStillAuthorized({ projectPathKey: '/workspace/DSH-plugin', hostId: 'h-sg' }, undefined),
    /predicate required/,
  )
})

test('download discard: revoked host removes the local file', () => {
  const p = join(tmpdir(), `dsh-ssh-tunnel-revoke-${process.pid}.txt`)
  writeFileSync(p, 'secret data', 'utf8')
  const discarded = discardRevokedLocalFile(
    { projectPathKey: '/workspace/DSH-plugin', hostId: 'h-sg' },
    p,
    () => false,
  )
  assert.equal(discarded, true)
  assert.equal(existsSync(p), false)
})

test('download discard: granted host keeps the local file', () => {
  const p = join(tmpdir(), `dsh-ssh-tunnel-grant-${process.pid}.txt`)
  writeFileSync(p, 'data', 'utf8')
  try {
    const discarded = discardRevokedLocalFile(
      { projectPathKey: '/workspace/DSH-plugin', hostId: 'h-sg' },
      p,
      () => true,
    )
    assert.equal(discarded, false)
    assert.equal(existsSync(p), true)
  } finally {
    try {
      unlinkSync(p)
    } catch {}
  }
})

test('vendor: allowlist resolves the three xterm assets to existing files', () => {
  assert.deepEqual(Object.keys(VENDOR_ASSETS).sort(), ['addon-fit.js', 'xterm.css', 'xterm.js'])
  for (const [name, entry] of Object.entries(VENDOR_ASSETS)) {
    assert.equal(isVendorAssetAllowed(name), true, name)
    const r = resolveVendorAsset(name)
    assert.equal(existsSync(r.path), true, `${name} -> ${r.path}`)
    assert.equal(typeof r.type, 'string')
  }
})

test('vendor: unknown or traversing names are rejected', () => {
  assert.equal(isVendorAssetAllowed('../../etc/passwd'), false)
  assert.equal(isVendorAssetAllowed('xterm.js?x=1'), false)
  assert.equal(isVendorAssetAllowed('xterm.js/../'), false)
  assert.throws(() => resolveVendorAsset('../../etc/passwd'), /not allowed/)
  assert.throws(() => resolveVendorAsset(''), /not allowed/)
})

await Promise.all(pending)
if (failed) {
  console.error(`\n${failed} failed`)
  process.exit(1)
}
console.log('\nall passed')
