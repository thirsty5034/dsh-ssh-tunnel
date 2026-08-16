#!/usr/bin/env node
/**
 * Offline smoke tests (no SSH, no DSH process).
 * Run: node scripts/smoke-test.mjs
 */
import assert from 'node:assert/strict'
import { normalizeProjectKey, isPathInsideRoots, joinUnderRoot } from '../lib/shared/path.js'
import {
  hostCredentialConfigured,
  publicHost,
  modelHostSummary,
  assertNoSecretFields,
} from '../lib/shared/host-summary.js'
import { chunkFromBuffer } from '../lib/shared/shell-buffer.js'

let failed = 0
function test(name, fn) {
  try {
    fn()
    console.log('ok  ', name)
  } catch (e) {
    failed++
    console.error('FAIL', name, e && e.message ? e.message : e)
  }
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

test('interactive credential status', () => {
  const host = { id: 'h2', authType: 'keyboardInteractive', host: 'x', username: 'u' }
  const pub = publicHost(host, { byHostId: {} })
  assert.equal(pub.credentialStatus, 'interactive')
})

test('chunkFromBuffer incremental', () => {
  const a = chunkFromBuffer('hello', 0)
  assert.equal(a.chunk, 'hello')
  assert.equal(a.length, 5)
  const b = chunkFromBuffer('hello world', 5)
  assert.equal(b.chunk, ' world')
  assert.equal(b.since, 5)
})

if (failed) {
  console.error(`\n${failed} failed`)
  process.exit(1)
}
console.log('\nall passed')
