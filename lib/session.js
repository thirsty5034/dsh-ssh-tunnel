/**
 * In-memory SSH session registry: live / tombstone / close.
 * Transport connect (host-key prompts) is injected as connectClient.
 */
import { randomUUID } from 'node:crypto'
import { StringDecoder } from 'node:string_decoder'
import { chunkFromBuffer } from './shared/shell-buffer.js'
import { normalizeProjectKey } from './shared/path.js'
import {
  SSH_EXEC_DEFAULT_TIMEOUT_MS,
  SSH_READY_TIMEOUT_MS,
  SSH_RECONNECT_ATTEMPT_TIMEOUT_MS,
  SSH_RECONNECT_DELAYS_MS,
  SSH_RECONNECT_MAX_ATTEMPTS,
  SSH_SFTP_META_TIMEOUT_MS,
  SSH_SHELL_OPEN_TIMEOUT_MS,
  SSH_STATUS_CONNECTED,
  SSH_STATUS_DISCONNECTED,
  SSH_STATUS_RECONNECTING,
  clampTimeoutMs,
  findReusableLive,
  isLiveStatus,
  kbiReconnectError,
  kbiUnsupportedError,
  withTimeout,
} from './shared/session-policy.js'

const MAX_OUT = 512 * 1024

async function openSftp(client, opts = {}) {
  return withTimeout(
    new Promise((resolve, reject) => {
      client.sftp((err, sftp) => (err ? reject(err) : resolve(sftp)))
    }),
    opts.timeoutMs ?? SSH_SFTP_META_TIMEOUT_MS,
    { signal: opts.signal },
  )
}

function applyStatus(rec, status) {
  rec.status = status
  rec.running = status === SSH_STATUS_CONNECTED
  rec.updatedAt = Date.now()
}

function tombstone(rec) {
  if (rec.closing) return
  applyStatus(rec, SSH_STATUS_DISCONNECTED)
  try {
    rec.shellStream?.close()
  } catch {}
  rec.shellStream = null
  rec.sftp = null
  rec.client = null
}

function attachTransport(rec, client, onDrop) {
  const handle = () => {
    if (rec.closing) return
    if (rec.client !== client) return
    onDrop(rec, client)
  }
  client.on('close', handle)
  client.on('end', handle)
  client.on('error', handle)
}

function sleep(ms, signal) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(resolve, ms)
    const onAbort = () => {
      clearTimeout(timer)
      const err = new Error('Cancelled')
      err.aborted = true
      reject(err)
    }
    if (!signal) return
    if (signal.aborted) {
      onAbort()
      return
    }
    signal.addEventListener('abort', onAbort, { once: true })
  })
}

function sessionSummary(s) {
  return {
    session_id: s.id,
    host_id: s.hostId,
    projectPathKey: s.projectPathKey,
    status: s.status,
    sftpEnabled: !!s.sftpEnabled,
    title: s.title,
    running: !!s.running,
    created_at: s.createdAt,
    updated_at: s.updatedAt,
    endpoint: s.endpoint || '',
    reconnect_attempt: s.reconnectAttempt || 0,
    reconnect_max_attempts: SSH_RECONNECT_MAX_ATTEMPTS,
  }
}

function makeRecord({ id, host, projectPathKey, title, endpoint, client, sftp, now }) {
  const outputBuf = []
  let outputBytes = 0
  // H1 fix: ssh2 channel chunks do not respect UTF-8 boundaries. Decode
  // incrementally with StringDecoder so a multi-byte character split
  // across packets is held back until its remaining bytes arrive,
  // instead of being emitted as U+FFFD.
  const decoder = new StringDecoder('utf8')
  const rec = {
    id,
    hostId: host.id,
    projectPathKey: normalizeProjectKey(projectPathKey),
    status: SSH_STATUS_CONNECTED,
    sftpEnabled: !!sftp,
    title: title || `SSH: ${host.name || host.host}`,
    running: true,
    createdAt: now,
    updatedAt: now,
    endpoint,
    client,
    sftp,
    shellStream: null,
    closing: false,
    reconnectRunner: false,
    reconnectAttempt: 0,
    connectionGeneration: 0,
    outputBuf,
    outputSeq: 0,
    pushOutput(chunk) {
      const decoded = decoder.write(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk), 'utf8'))
      if (!decoded) return
      outputBuf.push(decoded)
      outputBytes += Buffer.byteLength(decoded)
      rec.outputSeq = (rec.outputSeq || 0) + 1
      // H2 fix: evict by CURSOR UNIT (UTF-16 code units), the same unit
      // chunkFromBuffer/chunkFrom expose to clients. Evicting by
      // Buffer.byteLength while clients count string indices silently
      // skips unread output whenever the eviction boundary lands inside
      // multi-byte content.
      outputBytes += decoded.length
      while (outputBytes > MAX_OUT && outputBuf.length > 1) {
        const dropped = outputBuf.shift()
        outputBytes -= dropped.length
      }
    },
    getOutputText() {
      return outputBuf.join('')
    },
    chunkFrom(since) {
      const full = outputBuf.join('')
      const sliced = chunkFromBuffer(full, since)
      return { full, chunk: sliced.chunk, length: sliced.length, since: sliced.since }
    },
  }
  return rec
}

export function createSessionRegistry({
  connectClient,
  loadSecrets,
  getPrompt,
  getHostById,
  isHostAuthorized,
}) {
  const sessions = new Map()

  function listSessionsForProject(projectPathKey) {
    const key = normalizeProjectKey(projectPathKey)
    return [...sessions.values()].filter((s) => s.projectPathKey === key).map(sessionSummary)
  }

  function findReusableSession(projectPathKey, hostId, needsSftp) {
    return findReusableLive([...sessions.values()], {
      projectPathKey: normalizeProjectKey(projectPathKey),
      hostId,
      needsSftp,
    })
  }

  async function createLiveSession(params) {
    const { host, projectPathKey, title, sftpEnabled, trustHostKey } = params
    const secrets = loadSecrets()
    const id = randomUUID()
    const now = Date.now()
    const endpoint = `${host.username}@${host.host}:${host.port || 22}`

    if (host.authType === 'keyboardInteractive') {
      throw new Error(kbiUnsupportedError())
    }

    let client
    try {
      client = await withTimeout(
        connectClient(host, secrets, {
          trustHostKey: !!trustHostKey,
        }),
        SSH_READY_TIMEOUT_MS,
        { signal: params.signal },
      )
    } catch (e) {
      if (e && e.message === 'SSH_PROMPT') {
        return {
          ok: false,
          sshPrompt: getPrompt?.(e.promptId),
          promptId: e.promptId,
          message: '请先在 SSH 隧道 Tab 手动完成连接/信任/MFA 后重试。',
        }
      }
      throw e
    }

    // M4 fix (TOCTOU): the grant was checked before the (possibly
    // seconds-long) SSH handshake; re-check after it completes so a
    // revoke during the handshake cannot leave a live connection to an
    // unauthorized host. Fail closed: missing predicate also refuses.
    if (typeof isHostAuthorized === 'function') {
      const key = normalizeProjectKey(projectPathKey)
      if (!key || !isHostAuthorized(key, host.id)) {
        try { client.end() } catch {}
        throw new Error('SSH session host is not authorized for the current project.')
      }
    }

    let sftp = null
    if (sftpEnabled !== false) {
      try {
        sftp = await openSftp(client)
      } catch {
        sftp = null
      }
    }

    const rec = makeRecord({ id, host, projectPathKey, title, endpoint, client, sftp, now })
    rec.connectionGeneration += 1
    attachTransport(rec, client, onTransportDrop)
    sessions.set(id, rec)
    return { ok: true, session: sessionSummary(rec) }
  }

  function markReconnecting(rec, attempt) {
    rec.reconnectAttempt = attempt
    applyStatus(rec, SSH_STATUS_RECONNECTING)
    rec.sftp = null
    rec.shellStream = null
  }

  async function reconnectOnce(rec, { signal } = {}) {
    if (rec.projectPathKey && typeof isHostAuthorized === 'function' && !isHostAuthorized(rec.projectPathKey, rec.hostId)) {
      throw new Error('SSH session host is not authorized for the current project.')
    }
    const host = getHostById?.(rec.hostId)
    if (!host) throw new Error('host not found')
    if (host.authType === 'keyboardInteractive') throw new Error(kbiReconnectError())
    const secrets = loadSecrets()
    try {
      rec.shellStream?.close()
    } catch {}
    rec.shellStream = null
    const oldClient = rec.client
    rec.client = null
    try {
      oldClient?.end()
    } catch {}
    const client = await withTimeout(
      connectClient(host, secrets, { trustHostKey: false }),
      SSH_RECONNECT_ATTEMPT_TIMEOUT_MS,
      { signal },
    )
    if (rec.closing) {
      try { client.end() } catch {}
      throw new Error('SSH session is closing')
    }
    let sftp = null
    if (rec.sftpEnabled) {
      try {
        sftp = await openSftp(client)
      } catch {
        sftp = null
      }
    }
    if (rec.closing) {
      try { client.end() } catch {}
      throw new Error('SSH session is closing')
    }
    rec.client = client
    rec.sftp = sftp
    rec.connectionGeneration += 1
    rec.reconnectAttempt = 0
    applyStatus(rec, SSH_STATUS_CONNECTED)
    attachTransport(rec, client, onTransportDrop)
    return sessionSummary(rec)
  }

  async function runAutoReconnect(rec) {
    if (rec.closing || rec.reconnectRunner) return
    const host = getHostById?.(rec.hostId)
    if (host && host.authType === 'keyboardInteractive') {
      tombstone(rec)
      return
    }
    rec.reconnectRunner = true
    try {
      for (let attempt = 1; attempt <= SSH_RECONNECT_MAX_ATTEMPTS; attempt++) {
        if (rec.closing) return
        if (
          rec.projectPathKey &&
          typeof isHostAuthorized === 'function' &&
          !isHostAuthorized(rec.projectPathKey, rec.hostId)
        ) {
          // Host was revoked while disconnected: tombstone it, never resurrect.
          tombstone(rec)
          return
        }
        markReconnecting(rec, attempt)
        const delay = SSH_RECONNECT_DELAYS_MS[attempt - 1] || SSH_RECONNECT_DELAYS_MS[SSH_RECONNECT_DELAYS_MS.length - 1]
        try {
          await sleep(delay)
        } catch {
          return
        }
        if (rec.closing) return
        try {
          await reconnectOnce(rec)
          return
        } catch {
          // try next attempt
        }
      }
      tombstone(rec)
    } finally {
      rec.reconnectRunner = false
    }
  }

  function onTransportDrop(rec) {
    if (rec.closing) return
    const host = getHostById?.(rec.hostId)
    if (host && host.authType === 'keyboardInteractive') {
      tombstone(rec)
      return
    }
    void runAutoReconnect(rec)
  }

  async function reconnectSession(sessionId, { manual = true, signal, projectPathKey } = {}) {
    const rec = sessions.get(String(sessionId || ''))
    if (!rec) throw new Error('session not found')
    const key = normalizeProjectKey(projectPathKey)
    if (!key) throw new Error('projectPathKey required')
    if (rec.projectPathKey !== key) throw new Error('session not in this project')
    if (rec.closing) throw new Error('SSH session is closing')
    if (isLiveStatus(rec.status, rec.running) && rec.client) return { ok: true, session: sessionSummary(rec) }
    if (rec.reconnectRunner) throw new Error('SSH reconnect already in progress')
    const host = getHostById?.(rec.hostId)
    if (host && host.authType === 'keyboardInteractive') throw new Error(kbiReconnectError())
    rec.reconnectRunner = true
    try {
      markReconnecting(rec, 1)
      const session = await reconnectOnce(rec, { signal })
      return { ok: true, session }
    } catch (e) {
      tombstone(rec)
      throw e
    } finally {
      rec.reconnectRunner = false
    }
  }

  function waitForLive(sessionId, timeoutMs) {
    const rec = sessions.get(String(sessionId || ''))
    if (!rec) return Promise.reject(new Error('session not found'))
    if (isLiveStatus(rec.status, rec.running) && rec.client) return Promise.resolve(rec)
    const deadline = Date.now() + (Number(timeoutMs) || SSH_RECONNECT_ATTEMPT_TIMEOUT_MS)
    return new Promise((resolve, reject) => {
      const tick = () => {
        const cur = sessions.get(String(sessionId || ''))
        if (!cur) {
          reject(new Error('session not found'))
          return
        }
        if (isLiveStatus(cur.status, cur.running) && cur.client) {
          resolve(cur)
          return
        }
        if (cur.status === SSH_STATUS_DISCONNECTED || Date.now() >= deadline) {
          reject(new Error('session not running'))
          return
        }
        setTimeout(tick, 100)
      }
      tick()
    })
  }

  function requireLiveSession(sessionId, projectPathKey) {
    const s = sessions.get(String(sessionId || ''))
    if (!s) throw new Error('session not found')
    const key = normalizeProjectKey(projectPathKey)
    if (!key) throw new Error('projectPathKey required')
    if (s.projectPathKey !== key) throw new Error('session not in this project')
    if (!isLiveStatus(s.status, s.running) || !s.client) throw new Error('session not running')
    // Grant revocation must take effect on established sessions, not only new
    // connections. The session is bound to one project; re-check it on every use.
    if (s.projectPathKey && typeof isHostAuthorized === 'function' && !isHostAuthorized(s.projectPathKey, s.hostId)) {
      throw new Error('SSH session host is not authorized for the current project.')
    }
    return s
  }

  function closeSessionsForHost(projectPathKey, hostId) {
    const key = normalizeProjectKey(projectPathKey)
    const closed = []
    for (const s of [...sessions.values()]) {
      if (s.projectPathKey === key && s.hostId === String(hostId) && !s.closing) {
        closeSession(s.id, s.projectPathKey, { force: true })
        closed.push(s.id)
      }
    }
    return { closed: closed.length, sessionIds: closed }
  }

  function closeSession(sessionId, projectPathKey, { force = false } = {}) {
    const s = sessions.get(sessionId)
    if (!s) return { ok: false, error: 'session not found' }
    if (!force) {
      const key = normalizeProjectKey(projectPathKey)
      if (!key) throw new Error('projectPathKey required')
      if (s.projectPathKey !== key) throw new Error('session not in this project')
    }
    s.closing = true
    try {
      if (s.shellStream) s.shellStream.close()
    } catch {}
    try {
      s.client?.end()
    } catch {}
    applyStatus(s, SSH_STATUS_DISCONNECTED)
    sessions.delete(sessionId)
    return { ok: true }
  }

  /** Terminate every live session (plugin unload); one failure must not stop the rest. */
  function closeAll() {
    const closed = []
    for (const s of [...sessions.values()]) {
      try {
        closeSession(s.id, s.projectPathKey, { force: true })
        closed.push(s.id)
      } catch {}
    }
    return { closed: closed.length, sessionIds: closed }
  }

  async function execOnSession(session, command, opts = {}) {
    const client = session.client
    if (!isLiveStatus(session.status, session.running) || !client) {
      throw new Error('session not running')
    }
    const timeoutMs = clampTimeoutMs(opts.timeoutMs, SSH_EXEC_DEFAULT_TIMEOUT_MS)
    const maxBytes = opts.maxBytes || 256 * 1024
    const cwd = opts.cwd != null ? String(opts.cwd).trim() : ''
    const cmd =
      cwd.startsWith('/')
        ? `cd -- ${JSON.stringify(cwd)} && ${command}`
        : command
    let stream
    return withTimeout(
      new Promise((resolve, reject) => {
        client.exec(cmd, (err, st) => {
          if (err) {
            reject(err)
            return
          }
          stream = st
          // M1+H1 fix: decode incrementally (StringDecoder holds back a
          // multi-byte char split across packets) and cap the output by
          // BYTES. The old `stdout.slice(0, maxBytes)` cut at a UTF-16
          // index, so the promised byte budget could be exceeded up to
          // 3x on CJK / 4x on emoji.
          const dec = new StringDecoder('utf8')
          const errDec = new StringDecoder('utf8')
          const outParts = []
          const errParts = []
          let truncated = false
          const feed = (parts, decoder_, d) => {
            const text = decoder_.write(Buffer.isBuffer(d) ? d : Buffer.from(String(d), 'utf8'))
            if (text) parts.push(text)
          }
          const byteCap = (parts) => {
            let total = 0
            for (const p of parts) total += Buffer.byteLength(p)
            if (total <= maxBytes) return
            const full = Buffer.concat(parts.map((p) => Buffer.from(p, 'utf8')))
            truncated = true
            // Cut at a character boundary: slicing mid-code-point would
            // turn the partial bytes into U+FFFD (3 bytes) on decode,
            // re-inflating past the budget. Back off until the decoded
            // prefix fits.
            let end = Math.min(full.length, maxBytes)
            while (end > 0 && Buffer.byteLength(full.subarray(0, end).toString('utf8')) > maxBytes) {
              end -= 1
            }
            parts.length = 0
            parts.push(end > 0 ? full.subarray(0, end).toString('utf8') : '')
          }
          stream.on('data', (d) => {
            feed(outParts, dec, d)
            byteCap(outParts)
          })
          stream.stderr.on('data', (d) => {
            feed(errParts, errDec, d)
            byteCap(errParts)
          })
          stream.on('close', (code, sig) => {
            const tail = dec.end()
            if (tail) outParts.push(tail)
            const errTail = errDec.end()
            if (errTail) errParts.push(errTail)
            byteCap(outParts)
            byteCap(errParts)
            resolve({
              stdout: outParts.join(''),
              stderr: errParts.join(''),
              code: code ?? 0,
              signal: sig || null,
              truncated: truncated || undefined,
            })
          })
          stream.on('error', reject)
        })
      }),
      timeoutMs,
      {
        signal: opts.signal,
        onTimeout: () => {
          try {
            stream?.close()
          } catch {}
          try {
            stream?.destroy?.()
          } catch {}
        },
      },
    )
  }

  async function ensureShell(session, opts = {}) {
    // M3 fix: serialize concurrent shell opens. Two overlapping callers
    // (e.g. shellOpen + read_session) previously each ran client.shell(),
    // leaking an orphan PTY whose output kept feeding the buffer. The
    // first caller opens; the rest await the same stream.
    if (session.shellStream) return session.shellStream
    if (session.shellOpenPromise) return session.shellOpenPromise
    if (!session.client) throw new Error('session not running')
    const timeoutMs = clampTimeoutMs(opts.timeoutMs, SSH_SHELL_OPEN_TIMEOUT_MS)
    let opened
    let cancelled = false
    const openPromise = withTimeout(
      new Promise((resolve, reject) => {
        session.client.shell({ term: 'xterm-color' }, (err, stream) => {
          if (cancelled) {
            try { stream?.close() } catch {}
            return
          }
          if (err) return reject(err)
          opened = stream
          session.shellStream = stream
          stream.on('data', (d) => session.pushOutput(d))
          stream.stderr?.on?.('data', (d) => session.pushOutput(d))
          stream.on('close', () => {
            session.shellStream = null
          })
          resolve(stream)
        })
      }),
      timeoutMs,
      {
        signal: opts.signal,
        onTimeout: () => {
          cancelled = true
          try { opened?.close() } catch {}
          try { opened?.destroy?.() } catch {}
          if (session.shellStream === opened) session.shellStream = null
        },
      },
    )
    session.shellOpenPromise = openPromise
    try {
      return await openPromise
    } finally {
      if (session.shellOpenPromise === openPromise) session.shellOpenPromise = null
    }
  }

  return {
    sessions,
    sessionSummary,
    listSessionsForProject,
    findReusableSession,
    createLiveSession,
    requireLiveSession,
    closeSession,
    closeSessionsForHost,
    closeAll,
    execOnSession,
    ensureShell,
    openSftp,
    reconnectSession,
    waitForLive,
    get(id) {
      return sessions.get(id)
    },
  }
}
