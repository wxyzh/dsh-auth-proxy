/**
 * Smoke test for the built auth-proxy plugin (lib/types/index.js).
 *
 * Drives apply() with a stub cordis context. The config write path is the
 * dsh-settings scope: a minimal in-memory settings provider backs the namespace
 * installSettingsSection registers, and tests drive writes through it — the same
 * seam the browser card uses. A read-only status route
 * (/api/dsh-auth-proxy/status) exposes runtime introspection. Verifies:
 *   1. no token / placeholder 'change-me' -> proxy does NOT listen
 *   2. real token -> login flow works (401 wrong token, cookie + redirect)
 *   3. X-Forwarded-For spoofing does NOT bypass the IP allowlist
 *   4. settings write (banner-only) -> validator accepts, no re-listen change
 *   5. settings write changes port -> validator accepts, rebuild, new port listens
 *   6. settings write token='change-me' -> proxy becomes disabled (legal value)
 *   7. settings validator rejects wildcard/public listen hosts
 *   8. forwarded HTML carries both the UUID polyfill and the loopback-compat shim
 *   9. stateless sessions: restart survival + token rotation = global logout
 *
 * Run: node scripts/smoke.mjs
 */
import { createServer as httpCreateServer, request as httpRequest } from 'node:http'
import { apply, AUTH_SETTINGS_NAMESPACE } from '../lib/types/index.js'

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

function canConnect(port, host = '127.0.0.1', tries = 14, delay = 60) {
  return new Promise((resolve) => {
    const attempt = (n) => {
      const req = httpRequest({ host, port, path: '/', method: 'GET', timeout: 400 }, (res) => {
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

/**
 * Minimal in-memory settings provider with the surface installSettingsSection
 * exercises: register(ns, schema, {base, validate}) returns scope
 * { get, watch, update }, where update merges a patch over the user layer,
 * validates the resolved candidate (the plugin's REAL validator runs here), stores,
 * bumps the revision, and wakes watchers (which drive the plugin's onChange ->
 * sync()). `updateNs` lets tests drive the exact write path the browser card uses.
 */
function makeSettingsProvider() {
  const documents = {}
  const regs = new Map()
  const provider = {
    register(ns, schema, options = {}) {
      const user = documents[ns] ?? {}
      const reg = {
        ns, schema, base: options.base ?? {}, validate: options.validate, revision: 0, resolved: null,
        watchers: new Set(),
      }
      const resolved = () => {
        const candidate = reg.schema({ ...reg.base, ...(documents[ns] ?? {}) })
        if (reg.validate) reg.validate(candidate)
        return candidate
      }
      reg.resolved = resolved()
      const scope = {
        get: () => reg.resolved,
        watch: (cb) => { reg.watchers.add(cb); return () => reg.watchers.delete(cb) },
        update: async (patch) => {
          const merged = { ...(documents[ns] ?? {}), ...patch }
          const candidate = reg.schema({ ...reg.base, ...merged })
          if (reg.validate) reg.validate(candidate)
          documents[ns] = merged
          reg.revision += 1
          reg.resolved = candidate
          for (const w of [...reg.watchers]) w(candidate, reg.resolved)
        },
      }
      reg.scope = scope
      regs.set(ns, reg)
      return scope
    },
    /** Drive a write through a registered namespace's scope (the card's write path). */
    async updateNs(ns, patch) {
      const reg = regs.get(ns)
      if (!reg) throw new Error(`namespace ${ns} not registered`)
      await reg.scope.update(patch)
    },
    user(ns) { return documents[ns] ?? {} },
  }
  return provider
}

/** Fresh stub context + in-memory settings provider + route capture per scenario. */
async function scenario(entry) {
  const routes = []
  const disposers = []
  const settingsProvider = makeSettingsProvider()
  const ctx = {
    fiber: { state: 0 }, // RUNNING: not unloading, so isUnloading(ctx) is false
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
        const wctx = { effect: (cb2) => cb2(), webServer: { register: (route) => { routes.push(route); return () => {} } } }
        cb(wctx)
      }
      if (names.includes('settings')) {
        cb({ effect: () => () => {}, settings: settingsProvider })
      }
    },
  }
  apply(ctx, entry)
  const statusRoute = () => routes.find((r) => r.path === '/api/dsh-auth-proxy/status')
  const closeAll = () => disposers.forEach((d) => { try { d() } catch {} })
  return { ctx, statusRoute, settingsProvider, closeAll }
}

async function getStatus(route) {
  const res = {
    _status: 0, _body: '',
    writeHead(status, headers) { this._status = status; this._headers = headers || {} },
    end(text) { this._body = text ?? ''; resolve0({ status: this._status, body: this._body }) },
  }
  let resolve0
  const promise = new Promise((r) => { resolve0 = r })
  route.handler({}, res).catch((err) => { resolve0({ status: 500, body: String(err) }) })
  return promise
}

const settle = () => new Promise((r) => setTimeout(r, 400))

// ── 1. no token / placeholder -> not listening ──────────────────────────
for (const [label, token] of [['empty token', ''], ['placeholder change-me', 'change-me']]) {
  console.log(`scenario ${label} -> not listening`)
  const p = await freePort()
  const s = await scenario({ enabled: true, host: '127.0.0.1', port: p, targetPort: 9, token })
  await settle()
  const v = JSON.parse((await getStatus(s.statusRoute())).body)
  ok(v.listening === false, `${label} -> not listening (status.listening=false)`)
  s.closeAll()
}

// ── 2. real token -> login flow ─────────────────────────────────────────
{
  console.log('scenario: login flow')
  const p = await freePort()
  const s = await scenario({ enabled: true, host: '127.0.0.1', port: p, targetPort: 9, token: 's3cret' })
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
  console.log('scenario: XFF spoofing')
  const p = await freePort()
  const s = await scenario({ enabled: true, host: '127.0.0.1', port: p, targetPort: 9, token: 's3cret', allowedIps: ['10.0.0.0/8'] })
  const spoofed = await httpGet(p, '/', { 'x-forwarded-for': '10.0.0.1' })
  ok(spoofed.status === 302 && spoofed.headers.location === '/__dsh_auth/login',
    'XFF-spoofed request does NOT bypass the allowlist (still login redirect)')
  s.closeAll()
}

// ── 4. settings write (banner-only): validator accepts, no re-listen change ──
{
  console.log('scenario: banner update via settings scope (hot, no rebuild)')
  const p = await freePort()
  const s = await scenario({ enabled: true, host: '127.0.0.1', port: p, targetPort: 9, token: 's3cret' })
  ok((await canConnect(p)) === true, `listening on ${p}`)
  await s.settingsProvider.updateNs(AUTH_SETTINGS_NAMESPACE, { banner: 'SMOKE-BANNER', accessUrls: ['https://dsh.example.com'] })
  await settle()
  ok(s.settingsProvider.user(AUTH_SETTINGS_NAMESPACE).banner === 'SMOKE-BANNER', 'settings write persisted the banner to the user layer')
  const login = await httpGet(p, '/__dsh_auth/login')
  ok(login.body.includes('SMOKE-BANNER'), 'login page serves the new banner (same server, no rebuild)')
  const v = JSON.parse((await getStatus(s.statusRoute())).body)
  ok(v.listening === true, 'still listening (no rebuild for non-listening changes)')
  ok(Array.isArray(v.accessUrls) && v.accessUrls[0] === 'https://dsh.example.com', 'status reports configured access URLs')
  s.closeAll()
}

// ── 5. settings write changes port: rebuild, new port listens ─────────
{
  console.log('scenario: port change via settings scope (rebuild)')
  const p1 = await freePort()
  const p2 = await freePort()
  const s = await scenario({ enabled: true, host: '127.0.0.1', port: p1, targetPort: 9, token: 's3cret' })
  ok((await canConnect(p1)) === true, `listening on ${p1}`)
  await s.settingsProvider.updateNs(AUTH_SETTINGS_NAMESPACE, { port: p2 })
  await settle()
  await settle()
  ok((await canConnect(p2)) === true, `new port ${p2} listening after rebuild`)
  ok((await canConnect(p1)) === false, `old port ${p1} released after rebuild`)
  s.closeAll()
}

// ── 6. settings write token='change-me' disables the proxy ────────────
{
  console.log('scenario: settings write placeholder token disables')
  const p = await freePort()
  const s = await scenario({ enabled: true, host: '127.0.0.1', port: p, targetPort: 9, token: 's3cret' })
  ok((await canConnect(p)) === true, `listening on ${p}`)
  await s.settingsProvider.updateNs(AUTH_SETTINGS_NAMESPACE, { token: 'change-me' })
  await settle()
  ok(s.settingsProvider.user(AUTH_SETTINGS_NAMESPACE).token === 'change-me', 'settings write persisted the placeholder token')
  ok((await canConnect(p)) === false, 'proxy disabled after placeholder token saved')
  s.closeAll()
}

// ── 7. validator rejects wildcard/public listen hosts ─────────────────
{
  console.log('scenario: settings validator rejects public listen hosts')
  const p = await freePort()
  const s = await scenario({ enabled: true, host: '127.0.0.1', port: p, targetPort: 9, token: 's3cret' })
  let acceptedBad = false
  for (const bad of ['0.0.0.0', '::', '8.8.8.8', '203.0.113.9']) {
    let rejected = false
    try { await s.settingsProvider.updateNs(AUTH_SETTINGS_NAMESPACE, { host: bad }) } catch { rejected = true }
    if (!rejected) acceptedBad = true
    ok(rejected === true, `reject host ${bad}`)
  }
  // A private LAN host is accepted.
  await s.settingsProvider.updateNs(AUTH_SETTINGS_NAMESPACE, { host: '192.168.1.50' }).then(() => ok(true, 'accept host 192.168.1.50 (private LAN)'), () => ok(false, 'accept host 192.168.1.50'))
  await settle()
  ok(acceptedBad === false, 'no public/wildcard host write was accepted (no accidental exposure)')
  s.closeAll()
}

// ── 8. forwarded HTML carries both injected scripts ─────────────────────
{
  console.log('scenario: HTML injection (UUID polyfill + loopback compat)')
  const upstream = httpCreateServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' })
    res.end('<!doctype html><html><head><title>x</title></head><body>ok</body></html>')
  })
  const up = await new Promise((resolve, reject) => {
    upstream.on('error', reject)
    upstream.listen(0, '127.0.0.1', () => resolve(upstream.address().port))
  })
  const p = await freePort()
  const s = await scenario({ enabled: true, host: '127.0.0.1', port: p, targetPort: up, token: 's3cret' })
  const good = await httpPost(p, '/__dsh_auth/login', 'token=s3cret')
  const cookie = good.headers['set-cookie']?.[0]?.split(';')[0] ?? ''
  const page = await httpGet(p, '/', { cookie })
  ok(page.status === 200 && String(page.headers['content-type']).includes('text/html'), 'authenticated HTML forwarded from upstream')
  ok(page.body.includes('crypto.randomUUID') && page.body.includes('dsh-client-connection'), 'HTML carries the UUID polyfill and the loopback-compat shim')
  ok(page.body.includes('isLoopback') && page.body.includes('__ModuleLoader__'), 'compat shim targets the client connection loopback flag')
  s.closeAll()
  await new Promise((r) => upstream.close(r))
}

// ── 9. stateless sessions: restart survival + token rotation = global logout ──
{
  console.log('scenario: stateless session (restart survival + token rotation = global logout)')
  const p1 = await freePort()
  const s1 = await scenario({ enabled: true, host: '127.0.0.1', port: p1, targetPort: 9, token: 's3cret' })
  const good = await httpPost(p1, '/__dsh_auth/login', 'token=s3cret')
  const cookie = good.headers['set-cookie']?.[0]?.split(';')[0] ?? ''
  ok(good.status === 302 && cookie.startsWith('dsh_auth_session='), 'login -> 302 + session cookie')
  ok(cookie.includes('.'), 'cookie is signed (payload.signature format)')
  s1.closeAll()

  const p2 = await freePort()
  const s2 = await scenario({ enabled: true, host: '127.0.0.1', port: p2, targetPort: 9, token: 's3cret' })
  ok((await httpGet(p2, '/api/whatever', { cookie })).status === 502, 'cookie from the old instance still authenticates after restart (502 = forwarded)')
  ok((await httpGet(p2, '/api/whatever')).status === 401, 'no cookie -> still 401')

  // Token rotation through the settings scope = global logout under the same instance.
  await s2.settingsProvider.updateNs(AUTH_SETTINGS_NAMESPACE, { token: 'newtok' })
  await settle()
  ok((await httpGet(p2, '/api/whatever', { cookie })).status === 401, 'old cookie rejected after token change (global logout)')
  const again = await httpPost(p2, '/__dsh_auth/login', 'token=newtok')
  ok(again.status === 302 && (again.headers['set-cookie']?.[0] ?? '').includes('dsh_auth_session='), 'login with the new token works')
  const fresh = again.headers['set-cookie']?.[0]?.split(';')[0] ?? ''
  ok((await httpGet(p2, '/api/whatever', { cookie: fresh })).status === 502, 'cookie issued after rotation authenticates')
  s2.closeAll()
}

console.log(`\n${passed} passed, ${failed} failed`)
process.exit(failed === 0 ? 0 : 1)
