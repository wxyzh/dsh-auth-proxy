/**
 * Smoke test for the built auth-proxy plugin (lib/types/index.js).
 *
 * Drives apply() with a stub cordis context (no settings service; a fake
 * webServer so the /api/dsh-auth-proxy/config routes register), then verifies:
 *   1. no token / placeholder 'change-me' -> proxy does NOT listen
 *   2. real token -> login flow works (401 wrong token, cookie + redirect)
 *   3. X-Forwarded-For spoofing does NOT bypass the IP allowlist
 *   4. PUT (banner-only change) returns 200 with the response written BEFORE
 *      any rebuild (fix #3), and the proxy keeps serving on the same port
 *   5. PUT port change rebuilds and the new port listens
 *   6. PUT token='change-me' disables the proxy
 *   7. listen host policy: wildcard/public refused, private LAN accepted
 *   8. forwarded HTML carries both the UUID polyfill and the loopback-compat
 *      shim (web-ui settings stay editable behind the proxy)
 *   9. stateless sessions: a cookie issued by one instance authenticates
 *      against a brand-new instance (restart survival, no session table),
 *      and changing the token invalidates every issued cookie (global logout)
 *
 * Run: node scripts/smoke.mjs
 */
import { createServer as httpCreateServer, request as httpRequest } from 'node:http'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Readable } from 'node:stream'
import { apply } from '../lib/types/index.js'

// Isolate from the real user config: the plugin's config file lives under
// $DSH_HOME, and on this machine ~/.dsh/dsh-auth-proxy.json exists — the
// file layer is supposed to win, but the smoke test needs a clean slate.
const newHome = () => mkdtempSync(join(tmpdir(), 'dsh-auth-proxy-smoke-'))
process.env.DSH_HOME = newHome()

let passed = 0
let failed = 0

function ok(cond, label) {
  if (cond) {
    passed++
    console.log(`  [PASS] ${label}`)
  } else {
    failed++
    console.error(`  [FAIL] ${label}`)
  }
}

function freePort() {
  return new Promise((resolve, reject) => {
    const srv = httpCreateServer()
    srv.on('error', reject)
    srv.listen(0, '127.0.0.1', () => {
      const p = srv.address().port
      srv.close(() => resolve(p))
    })
  })
}

/** Whether a TCP connect to host:port succeeds. */
function canConnect(port, host = '127.0.0.1', tries = 10, delay = 50) {
  return new Promise((resolve) => {
    const attempt = (n) => {
      const req = httpRequest({ host, port, path: '/', method: 'GET', timeout: 500 }, (res) => {
        res.resume()
        resolve(true)
      })
      req.on('timeout', () => req.destroy())
      req.on('error', () => {
        if (n > 0) setTimeout(() => attempt(n - 1), delay)
        else resolve(false)
      })
      req.end()
    }
    attempt(tries)
  })
}

function httpGet(port, path, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = httpRequest({ host: '127.0.0.1', port, path, method: 'GET', headers, timeout: 2000 }, (res) => {
      let body = ''
      res.on('data', (c) => (body += c))
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }))
    })
    req.on('timeout', () => req.destroy())
    req.on('error', reject)
    req.end()
  })
}

function httpPost(port, path, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = httpRequest({
      host: '127.0.0.1', port, path, method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers },
    }, (res) => {
      let data = ''
      res.on('data', (c) => (data += c))
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data }))
    })
    req.on('error', reject)
    req.end(body)
  })
}

/** Fresh stub context + route capture per scenario. */
function scenario() {
  // Fresh home per scenario: a PUT persists the file layer, which must not
  // leak into the next scenario (the file winning over the entry is the
  // point of fix #4, but each scenario starts from a clean slate).
  process.env.DSH_HOME = newHome()
  const routes = []
  const disposers = []
  const ctx = {
    logger: {
      info: (...a) => console.log('      [info]', ...a),
      warn: (...a) => console.log('      [warn]', ...a),
      error: (...a) => console.log('      [error]', ...a),
      debug: () => {},
    },
    effect: (cb) => {
      const d = cb()
      disposers.push(d)
      return d
    },
    inject: (names, cb) => {
      if (names.includes('webServer')) {
        const wctx = {
          effect: (cb2) => cb2(),
          webServer: {
            register: (route) => {
              routes.push(route)
              return () => {}
            },
          },
        }
        cb(wctx)
      }
      // 'settings' intentionally absent: the plugin must fall back to the
      // composition entry as its base layer.
    },
  }
  const configRoute = () => routes.find((r) => r.path === '/api/dsh-auth-proxy/config')
  const closeAll = () => disposers.forEach((d) => { try { d() } catch {} })
  return { ctx, configRoute, closeAll }
}

/** Invoke the config route handler with a fake req/res. */
function callApi(route, method, bodyObj) {
  return new Promise((resolve) => {
    const res = {
      _status: 0,
      _headers: {},
      _body: '',
      writeHead(status, headers) { this._status = status; this._headers = headers || {} },
      end(text) { this._body = text ?? ''; resolve({ status: this._status, headers: this._headers, body: this._body }) },
    }
    const req = Readable.from([JSON.stringify(bodyObj ?? {})])
    req.method = method
    route.handler(req, res).catch((err) => { console.error('      api handler error', err) })
  })
}

const tick = () => new Promise((r) => setImmediate(r))

// ── 1. no token / placeholder -> not listening ──────────────────────────
{
  console.log('scenario 1: empty token')
  const s = scenario()
  const p = await freePort()
  apply(s.ctx, { enabled: true, host: '127.0.0.1', port: p, targetPort: 9, token: '' })
  await new Promise((r) => setTimeout(r, 150))
  ok((await canConnect(p)) === false, `no token -> port ${p} not listening`)
  s.closeAll()
}

{
  console.log('scenario 2: placeholder token change-me')
  const s = scenario()
  const p = await freePort()
  apply(s.ctx, { enabled: true, host: '127.0.0.1', port: p, targetPort: 9, token: 'change-me' })
  await new Promise((r) => setTimeout(r, 150))
  ok((await canConnect(p)) === false, `placeholder token -> port ${p} not listening`)
  s.closeAll()
}

// ── 2. real token -> login flow ─────────────────────────────────────────
{
  console.log('scenario 3: login flow')
  const s = scenario()
  const p = await freePort()
  apply(s.ctx, { enabled: true, host: '127.0.0.1', port: p, targetPort: 9, token: 's3cret' })
  ok((await canConnect(p)) === true, `listening on ${p}`)

  const root = await httpGet(p, '/')
  ok(root.status === 302 && root.headers.location === '/__dsh_auth/login', 'GET / -> 302 to login')

  const bad = await httpPost(p, '/__dsh_auth/login', 'token=wrong')
  ok(bad.status === 401, 'wrong token -> 401')

  const good = await httpPost(p, '/__dsh_auth/login', 'token=s3cret')
  const cookie = good.headers['set-cookie']?.[0] ?? ''
  ok(good.status === 302 && cookie.includes('dsh_auth_session='), 'right token -> 302 + session cookie')
  ok(cookie.includes('Max-Age=315360000'), 'session cookie is permanent (10-year Max-Age)')

  const fwd = await httpGet(p, '/api/whatever', { cookie: cookie.split(';')[0] })
  ok(fwd.status === 502, 'authenticated request forwarded (502 upstream unavailable expected)')

  const unauth = await httpGet(p, '/api/whatever')
  ok(unauth.status === 401, 'unauthenticated /api -> JSON 401')
  s.closeAll()
}

// ── 3. X-Forwarded-For spoofing does not bypass allowlist ───────────────
{
  console.log('scenario 4: XFF spoofing')
  const s = scenario()
  const p = await freePort()
  apply(s.ctx, { enabled: true, host: '127.0.0.1', port: p, targetPort: 9, token: 's3cret', allowedIps: ['10.0.0.0/8'] })
  ok((await canConnect(p)) === true, `listening on ${p}`)

  const spoofed = await httpGet(p, '/', { 'x-forwarded-for': '10.0.0.1' })
  ok(spoofed.status === 302 && spoofed.headers.location === '/__dsh_auth/login',
    'XFF-spoofed request does NOT bypass the allowlist (still login redirect)')
  s.closeAll()
}

// ── 4. PUT banner-only change: 200 returned, no rebuild ─────────────────
{
  console.log('scenario 5: PUT banner-only (hot update)')
  const s = scenario()
  const p = await freePort()
  apply(s.ctx, { enabled: true, host: '127.0.0.1', port: p, targetPort: 9, token: 's3cret' })
  ok((await canConnect(p)) === true, `listening on ${p}`)
  const route = s.configRoute()
  ok(route !== undefined, 'config API route registered (via fake webServer)')

  const res = await callApi(route, 'PUT', { banner: 'SMOKE-BANNER', accessUrls: ['https://dsh.example.com', 'http://lan.local:8443'] })
  const parsed = JSON.parse(res.body)
  ok(res.status === 200 && parsed.ok === true, 'PUT banner -> 200 ok (response written before any rebuild)')

  const get = await callApi(route, 'GET', {})
  const view = JSON.parse(get.body)
  ok(view.banner === 'SMOKE-BANNER' && view.tokenSet === true, 'GET reflects new banner + tokenSet')
  ok(view.listening === true, 'GET reports the proxy is listening')
  ok(Array.isArray(view.accessUrls) && view.accessUrls.length === 2 && view.accessUrls[0] === 'https://dsh.example.com',
    'GET reports the configured access URLs')

  const login = await httpGet(p, '/__dsh_auth/login')
  ok(login.body.includes('SMOKE-BANNER'), 'login page serves the new banner (same server, no rebuild)')
  ok(login.body.includes('https://dsh.example.com'), 'login page lists the configured access URL')
  ok((await canConnect(p)) === true, 'proxy still listening on the same port')
  s.closeAll()
}

// ── 5. PUT port change: rebuild, new port listens ───────────────────────
{
  console.log('scenario 6: PUT port change (rebuild)')
  const s = scenario()
  const p1 = await freePort()
  const p2 = await freePort()
  apply(s.ctx, { enabled: true, host: '127.0.0.1', port: p1, targetPort: 9, token: 's3cret' })
  ok((await canConnect(p1)) === true, `listening on ${p1}`)
  const route = s.configRoute()

  const res = await callApi(route, 'PUT', { port: p2 })
  ok(res.status === 200, 'PUT port change -> 200 (response delivered first)')

  await tick()
  await tick()
  await new Promise((r) => setTimeout(r, 100))
  ok((await canConnect(p2)) === true, `new port ${p2} listening after rebuild`)
  s.closeAll()
}

// ── 6. PUT token=change-me disables the proxy ───────────────────────────
{
  console.log('scenario 7: PUT placeholder token disables')
  const s = scenario()
  const p = await freePort()
  apply(s.ctx, { enabled: true, host: '127.0.0.1', port: p, targetPort: 9, token: 's3cret' })
  ok((await canConnect(p)) === true, `listening on ${p}`)
  const route = s.configRoute()

  const res = await callApi(route, 'PUT', { token: 'change-me' })
  ok(res.status === 200 && JSON.parse(res.body).tokenSet === false, 'PUT change-me -> 200 + tokenSet=false')

  await tick()
  await new Promise((r) => setTimeout(r, 100))
  ok((await canConnect(p)) === false, 'proxy disabled after placeholder token saved')
  s.closeAll()
}

// ── 7. listen host policy: no TLS -> wildcard/public refused ────────────
{
  console.log('scenario 8: listen host policy')
  const s = scenario()
  const p = await freePort()
  // No host given: the default must be 127.0.0.1 (loopback).
  apply(s.ctx, { enabled: true, port: p, targetPort: 9, token: 's3cret' })
  ok((await canConnect(p)) === true, `default listen host 127.0.0.1 -> listening on ${p}`)
  const route = s.configRoute()
  ok(route !== undefined, 'config API route registered')

  for (const bad of ['0.0.0.0', '::', '8.8.8.8', '203.0.113.9', 'example.com']) {
    const r = await callApi(route, 'PUT', { host: bad })
    ok(r.status === 400, `PUT host ${bad} -> 400 rejected (no TLS)`)
  }
  const lan = await callApi(route, 'PUT', { host: '192.168.1.50' })
  ok(lan.status === 200, 'PUT host 192.168.1.50 -> 200 accepted (private LAN)')
  s.closeAll()
}

// ── 8. forwarded HTML carries both injected scripts ─────────────────────
{
  console.log('scenario 9: HTML injection (UUID polyfill + loopback compat)')
  const upstream = httpCreateServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' })
    res.end('<!doctype html><html><head><title>x</title></head><body>ok</body></html>')
  })
  const up = await new Promise((resolve, reject) => {
    upstream.on('error', reject)
    upstream.listen(0, '127.0.0.1', () => resolve(upstream.address().port))
  })
  const s = scenario()
  const p = await freePort()
  apply(s.ctx, { enabled: true, host: '127.0.0.1', port: p, targetPort: up, token: 's3cret' })
  ok((await canConnect(p)) === true, `listening on ${p}`)

  const good = await httpPost(p, '/__dsh_auth/login', 'token=s3cret')
  const cookie = good.headers['set-cookie']?.[0]?.split(';')[0] ?? ''
  const page = await httpGet(p, '/', { cookie })
  ok(page.status === 200 && String(page.headers['content-type']).includes('text/html'),
    'authenticated HTML forwarded from upstream')
  ok(page.body.includes('crypto.randomUUID') && page.body.includes('dsh-client-connection'),
    'HTML carries the UUID polyfill and the loopback-compat shim')
  ok(page.body.includes('isLoopback') && page.body.includes('__ModuleLoader__'),
    'compat shim targets the client connection loopback flag')
  s.closeAll()
  await new Promise((r) => upstream.close(r))
}

// ── 9. stateless sessions: restart survival + token rotation = global logout ──
{
  console.log('scenario 10: stateless session (restart survival + token rotation)')
  // First "process": login and capture the signed cookie.
  const s1 = scenario()
  const p1 = await freePort()
  apply(s1.ctx, { enabled: true, host: '127.0.0.1', port: p1, targetPort: 9, token: 's3cret' })
  ok((await canConnect(p1)) === true, `first instance listening on ${p1}`)
  const good = await httpPost(p1, '/__dsh_auth/login', 'token=s3cret')
  const cookie = good.headers['set-cookie']?.[0]?.split(';')[0] ?? ''
  ok(good.status === 302 && cookie.startsWith('dsh_auth_session='), 'login -> 302 + session cookie')
  ok(cookie.includes('.'), 'cookie is signed (payload.signature format)')
  s1.closeAll()

  // Second "process": a brand-new plugin instance with zero session memory.
  const s2 = scenario()
  const p2 = await freePort()
  apply(s2.ctx, { enabled: true, host: '127.0.0.1', port: p2, targetPort: 9, token: 's3cret' })
  ok((await canConnect(p2)) === true, `restarted instance listening on ${p2}`)
  const fwd = await httpGet(p2, '/api/whatever', { cookie })
  ok(fwd.status === 502, 'cookie from the old instance still authenticates after restart (502 = forwarded)')
  const unauth = await httpGet(p2, '/api/whatever')
  ok(unauth.status === 401, 'no cookie -> still 401')

  // Token rotation = global logout: the old cookie must stop working.
  const route = s2.configRoute()
  const res = await callApi(route, 'PUT', { token: 'newtok' })
  ok(res.status === 200 && JSON.parse(res.body).tokenSet === true, 'PUT token -> 200 ok')
  await tick()
  await tick()
  const after = await httpGet(p2, '/api/whatever', { cookie })
  ok(after.status === 401, 'old cookie rejected after token change (global logout)')

  // The new token logs in fine and its cookie authenticates.
  const again = await httpPost(p2, '/__dsh_auth/login', 'token=newtok')
  ok(again.status === 302 && (again.headers['set-cookie']?.[0] ?? '').includes('dsh_auth_session='),
    'login with the new token works')
  const fresh = again.headers['set-cookie']?.[0]?.split(';')[0] ?? ''
  const againFwd = await httpGet(p2, '/api/whatever', { cookie: fresh })
  ok(againFwd.status === 502, 'cookie issued after rotation authenticates (502 = forwarded)')
  s2.closeAll()
}

console.log(`\n${passed} passed, ${failed} failed`)
process.exit(failed === 0 ? 0 : 1)
