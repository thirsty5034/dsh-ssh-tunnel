/**
 * Loopback / Origin checks for the local HTTP API.
 * 0.0.0.0 is NOT loopback (it is a bind-all address).
 *
 * Trust chain (mirrors fork 52d6150):
 * 1. `connection.requestRejection` — host/Origin/browser-auth fence owned by
 *    the DSH 0.2+ Connection service (authoritative when present);
 * 2. `webStartup.trustedHosts` — self-managed `--trusted-host` fence for
 *    deployments where the connection service is not mounted;
 * 3. loopback-only admission — last-resort fallback that never trusts a
 *    non-loopback Host or a cross-origin request.
 */

export function isLoopbackHostname(hostname) {
  const h = String(hostname || '').replace(/^\[|\]$/g, '').toLowerCase()
  return h === 'localhost' || h === '127.0.0.1' || h === '::1'
}

/** Wildcard bind targets are never trusted authorities. */
export function isWildcardHost(hostname) {
  const h = String(hostname || '').replace(/^\[|\]$/g, '').toLowerCase()
  return h === '0.0.0.0' || h === '::' || h === ''
}

function originHostPort(originHeader) {
  try {
    const u = new URL(String(originHeader))
    const host = u.hostname.replace(/^\[|\]$/g, '').toLowerCase()
    const port = u.port || (u.protocol === 'https:' ? '443' : u.protocol === 'http:' ? '80' : '')
    return { host, port, hostHeaderLike: port ? `${host}:${port}` : host }
  } catch {
    return null
  }
}

function reqHostPort(req) {
  const hostHeader = req.headers?.host || req.headers?.Host
  if (!hostHeader) return null
  try {
    const url = new URL('http://' + hostHeader)
    const host = url.hostname.replace(/^\[|\]$/g, '').toLowerCase()
    return { host, port: url.port || '80', hostHeader: String(hostHeader) }
  } catch {
    return null
  }
}

/**
 * @param {object} req Node HTTP request
 * @param {string[]} trustedHosts
 */
export function isTrustedRequest(req, trustedHosts) {
  try {
    const reqInfo = reqHostPort(req)
    if (!reqInfo) return false
    if (isWildcardHost(reqInfo.host)) return false
    const list = Array.isArray(trustedHosts) ? trustedHosts : []
    const hostOk =
      isLoopbackHostname(reqInfo.host) ||
      list.some((entry) => {
        const e = String(entry)
        return e === reqInfo.hostHeader || e === reqInfo.host || e === `${reqInfo.host}:${reqInfo.port}`
      })
    if (!hostOk) return false

    const origin = req.headers?.origin || req.headers?.Origin
    if (!origin) return true
    const parsed = originHostPort(origin)
    if (!parsed) return false
    if (isLoopbackHostname(parsed.host) && isLoopbackHostname(reqInfo.host)) {
      if (parsed.port && parsed.port !== reqInfo.port) return false
      return true
    }
    return list.some((entry) => {
      const e = String(entry)
      return e === parsed.hostHeaderLike || e === parsed.host || e === origin
    })
  } catch {
    return false
  }
}

/** Extract the trusted-host list from the webStartup service, when mounted. */
export function trustedHostsFromStartup(ctx) {
  try {
    const hosts = ctx?.webStartup?.trustedHosts
    return Array.isArray(hosts) ? hosts.map(String) : []
  } catch {
    return []
  }
}

/**
 * Layered admission: connection fence first, then webStartup trusted hosts,
 * then loopback-only. `undefined` admits; otherwise 401/403.
 * @param {object} ctx cordis context
 * @param {object} req Node HTTP request
 * @returns {401 | 403 | undefined}
 */
export function apiTrustDecision(ctx, req) {
  const connection = ctx?.connection
  if (connection && typeof connection.requestRejection === 'function') {
    return connection.requestRejection(req)
  }
  // connection absent: fall back to self-managed --trusted-host authorities.
  const trustedHosts = trustedHostsFromStartup(ctx)
  if (trustedHosts.length > 0) {
    return isTrustedRequest(req, trustedHosts) ? undefined : 403
  }
  // Last resort: admit only same-host loopback traffic without a foreign Origin.
  const reqInfo = reqHostPort(req)
  if (!reqInfo || !isLoopbackHostname(reqInfo.host) || isWildcardHost(reqInfo.host)) return 403
  const origin = req.headers?.origin || req.headers?.Origin
  if (!origin) return undefined
  const parsed = originHostPort(origin)
  if (!parsed) return 403
  return isLoopbackHostname(parsed.host) ? undefined : 403
}

export const MAX_JSON_BODY_BYTES = 2 * 1024 * 1024
