/**
 * dsh-auth-proxy — host half.
 *
 * A token-auth reverse proxy in front of the dsh web webserver:
 *
 *   browser ──► auth proxy :8443 (127.0.0.1) ──► dsh webserver 127.0.0.1:3080
 *                  ├─ unauthenticated → built-in login page
 *                  ├─ POST token → HttpOnly session cookie
 *                  └─ authenticated → forward HTTP + WebSocket upgrade
 *
 * The proxy rewrites Host/Origin to the loopback target so the harness's
 * own /api browser-trust fence (Host whitelist) keeps working, while the
 * browser still sees one same-origin server. Nothing in the dsh source is
 * modified: the dsh webserver itself stays on 127.0.0.1, and this plugin
 * owns the network-facing socket.
 *
 * The proxy offers no TLS, so it refuses to bind a wildcard or public
 * address: the default listen host is 127.0.0.1, and only loopback and
 * private/LAN addresses are accepted (listenHostIssue). External access
 * must terminate TLS in front (reverse proxy), pointing back at the
 * loopback listener.
 *
 * Sessions are stateless: the cookie carries a random payload signed with
 * HMAC-SHA256 keyed by the configured token (`payload.signature`), so they
 * never expire (10-year Max-Age) AND survive restarts — there is no
 * server-side session table to lose. Rotating the token changes the signing
 * key and invalidates every issued cookie at once (global logout); logout
 * merely clears the client cookie. The token is
 * read from config (e.g. `!!js process.env.DSH_AUTH_TOKEN`) and compared
 * with a timing-safe hash; an empty token — or the placeholder `change-me`
 * from the bundle patch — disables the proxy entirely, never a listening
 * port with a well-known secret. Config is edited live from the Web UI via
 * the plugin's own settings card (Settings > Plugin config), persisted to
 * ~/.dsh/dsh-auth-proxy.json. The file layer always wins over the
 * composition entry (which feeds the dsh-settings scope as its base layer),
 * so changes saved from the card survive restarts.
 */

import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto'
import { createServer, request as httpRequest, type IncomingMessage, type ServerResponse } from 'node:http'
import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve as resolvePath } from 'node:path'
import { homedir } from 'node:os'
import type { Duplex } from 'node:stream'
import type { Context } from '@deepseek-ai/cordis'
import { installSettingsSection, settingsNamespace } from '@deepseek-ai/dsh-settings'
import type {} from '@deepseek-ai/dsh-host-webserver'
import z from 'schemastery'
import { clearInterval, clearTimeout, setInterval, setTimeout } from 'node:timers'

/** Stable cordis plugin name. */
export const name = 'auth-proxy'

/** No host services are required — this plugin stands alone on its own socket. */
export const inject: string[] = []

/**
 * Settings namespace of this plugin — the section the Web settings surface
 * edits. Lowercase kebab-case (the dsh-settings contract).
 */
export const AUTH_SETTINGS_NAMESPACE = settingsNamespace('dsh-auth-proxy')

/** Plugin config, validated by the same-named schemastery schema. */
export interface Config {
  /** Master switch; when false the proxy stops listening. */
  enabled?: boolean
  /** External listen host (default: all interfaces). */
  host?: string
  /** External listen port. */
  port: number
  /** Loopback target the proxy forwards to. */
  targetHost?: string
  /** Loopback target port. */
  targetPort?: number
  /** The shared access token. Prefer an env reference: `!!js process.env.DSH_AUTH_TOKEN`. */
  token: string
  /** Optional banner text shown on the login page. */
  banner?: string
  /** CIDR / IP allowlist bypassing the token (e.g. ["127.0.0.1", "10.0.0.0/8"]). Empty = token always required. */
  allowedIps?: string[]
  /**
   * Public entry URLs (may be https domains) the proxy is reachable through.
   * Display only: shown on the settings card and the login page.
   */
  accessUrls?: string[]
  /** Failed login attempts before an IP is locked out (0 disables lockout). */
  maxFailures?: number
  /** Lockout duration in minutes after maxFailures. */
  lockoutMinutes?: number
}

export const Config: z<Config> = z.object({
  enabled: z.boolean().default(true),
  host: z.string().default('127.0.0.1'),
  port: z.natural().max(65535).required(),
  targetHost: z.string().default('127.0.0.1'),
  targetPort: z.natural().max(65535).default(3080),
  token: z.string().role('secret').default(''),
  banner: z.string().default(''),
  allowedIps: z.array(z.string()).default([]),
  accessUrls: z.array(z.string()).default([]),
  maxFailures: z.natural().default(0),
  lockoutMinutes: z.natural().min(1).default(15),
})

/** Fully-resolved config shape (every field materialized). */
type Resolved = Required<Omit<Config, 'banner' | 'allowedIps' | 'accessUrls'>> & {
  banner: string
  allowedIps: string[]
  accessUrls: string[]
}

const COOKIE_NAME = 'dsh_auth_session'

/** Placeholder token from the bundle patch (`env ?? 'change-me'`) — treated as "not configured" everywhere. */
const TOKEN_PLACEHOLDER = 'change-me'

/** Whether a token value counts as configured (non-empty, not the placeholder). */
function tokenConfigured(token: string): boolean {
  const trimmed = token.trim()
  return trimmed !== '' && trimmed !== TOKEN_PLACEHOLDER
}

/**
 * The proxy offers no TLS, so binding a wildcard or public address would put
 * the plaintext token on the open network. Only loopback and private/LAN
 * addresses are acceptable listen hosts. Returns a human-readable reason when
 * the host is not allowed, null when it is.
 */
function listenHostIssue(host: string): string | null {
  let h = host.trim().toLowerCase()
  if (h === '') return '监听地址不能为空'
  if (h === 'localhost') return null
  if (h === '0.0.0.0' || h === '::') {
    return '禁止监听通配地址（无 TLS，会把明文令牌暴露到整个网络）；请改为回环或内网地址'
  }
  if (h === '::1') return null
  if (h.startsWith('::ffff:')) h = h.slice('::ffff:'.length)
  const octets = h.split('.').map(Number)
  if (octets.length !== 4 || octets.some((o) => !Number.isInteger(o) || o < 0 || o > 255)) {
    return '监听地址必须是回环或内网 IP（主机名除 localhost 外不支持）'
  }
  const [a, b] = octets
  const privateOrLocal =
    a === 10 || a === 127
    || (a === 172 && b >= 16 && b <= 31)
    || (a === 192 && b === 168)
    || (a === 169 && b === 254)
  if (!privateOrLocal) return '禁止监听公网 IP（无 TLS，令牌会明文暴露）；仅允许回环与内网地址'
  return null
}

/** User-editable config document (~/.dsh/dsh-auth-proxy.json). */
function configFilePath(): string {
  const dshHome = process.env.DSH_HOME ?? join(homedir(), '.dsh')
  return join(dshHome, 'dsh-auth-proxy.json')
}

/** Load the user config file, or null when absent/invalid. */
function loadConfigFile(): Partial<Config> | null {
  try {
    const raw = readFileSync(configFilePath(), 'utf8')
    const parsed: unknown = JSON.parse(raw)
    return typeof parsed === 'object' && parsed !== null ? parsed as Partial<Config> : null
  } catch {
    return null
  }
}

/** Persist the user config file (tmp + atomic rename: a crash never leaves a half-written document). */
function saveConfigFile(value: Partial<Config>): void {
  const file = configFilePath()
  mkdirSync(dirname(file), { recursive: true })
  const tmp = `${file}.tmp`
  writeFileSync(tmp, JSON.stringify(value, null, 2), 'utf8')
  renameSync(tmp, file)
}

/** In-memory failed-login counter per IP: ip -> { count, lockUntil?, lastFailAt }. */
const failures = new Map<string, { count: number; lockUntil?: number; lastFailAt: number }>()

/** Sessions are stateless signed cookies: browser-side Max-Age 10 years. */
const SESSION_TTL_MS = 10 * 365 * 24 * 60 * 60 * 1000

/** Periodic sweep cadence and the idle window after which failure records drop. */
const SWEEP_INTERVAL_MS = 30 * 60 * 1000
const FAILURE_IDLE_MS = 60 * 60 * 1000

function hash(value: string): Buffer {
  return createHash('sha256').update(value).digest()
}

function safeEqual(a: string, b: string): boolean {
  const ha = hash(a)
  const hb = hash(b)
  return ha.length === hb.length && timingSafeEqual(ha, hb)
}

function parseCookies(req: IncomingMessage): Record<string, string> {
  const header = req.headers.cookie
  const out: Record<string, string> = {}
  if (!header) return out
  for (const part of header.split(';')) {
    const idx = part.indexOf('=')
    if (idx === -1) continue
    const key = part.slice(0, idx).trim()
    const value = part.slice(idx + 1).trim()
    if (key) out[key] = decodeURIComponent(value)
  }
  return out
}

function clientIp(req: IncomingMessage): string {
  // This proxy is the network-facing edge: no trusted reverse proxy sits in
  // front, so a client-supplied X-Forwarded-For must never be believed —
  // trusting it would let anyone spoof past the IP allowlist and the login
  // lockout. Use the actual peer address only.
  return req.socket.remoteAddress ?? ''
}

/** Minimal CIDR match (IPv4 only; plain IPs are treated as /32). */
function ipInCidr(ip: string, cidr: string): boolean {
  const norm = ip.replace(/^::ffff:/, '')
  const [rawNet, rawBits] = cidr.split('/')
  const bits = rawBits === undefined ? 32 : Number(rawBits)
  const octets = (rawNet: string): number[] | null => {
    const parts = rawNet.split('.').map(Number)
    return parts.length === 4 && parts.every((p) => Number.isInteger(p) && p >= 0 && p <= 255) ? parts : null
  }
  const a = octets(norm)
  const b = octets(rawNet)
  if (!a || !b) return false
  if (bits < 0 || bits > 32) return false
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0
  const toInt = (o: number[]): number => ((o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3]) >>> 0
  return (toInt(a) & mask) === (toInt(b) & mask)
}

function isAllowedIp(ip: string, allowed: string[]): boolean {
  if (!ip) return false
  for (const entry of allowed) {
    if (entry.includes('/')) {
      if (ipInCidr(ip, entry)) return true
    } else if (ip === entry) {
      return true
    }
  }
  return false
}

function isLockedOut(ip: string): boolean {
  const rec = failures.get(ip)
  if (!rec?.lockUntil) return false
  if (rec.lockUntil > Date.now()) return true
  failures.delete(ip)
  return false
}

function recordFailure(ip: string, maxFailures: number, lockoutMinutes: number): void {
  if (maxFailures <= 0) return
  const rec = failures.get(ip) ?? { count: 0, lastFailAt: 0 }
  rec.count += 1
  rec.lastFailAt = Date.now()
  if (rec.count >= maxFailures) {
    rec.lockUntil = Date.now() + lockoutMinutes * 60_000
    rec.count = 0
  }
  failures.set(ip, rec)
}

/**
 * Stateless session cookies: `payload.signature` where payload is a random
 * nonce and signature is HMAC-SHA256 over it, keyed by the configured token.
 * The server keeps no session table, so cookies survive restarts; rotating
 * the token changes the key and invalidates every issued cookie at once
 * (global logout). There is no per-client revocation — logout only clears
 * the client cookie.
 */
const sessionKey = (token: string): Buffer => hash(token)

function issueSession(res: ServerResponse, token: string): void {
  const payload = randomBytes(24).toString('base64url')
  const signature = createHmac('sha256', sessionKey(token)).update(payload).digest('base64url')
  res.setHeader('Set-Cookie', [
    `${COOKIE_NAME}=${payload}.${signature}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`,
  ])
}

function isValidSession(req: IncomingMessage, token: string): boolean {
  const cookie = parseCookies(req)[COOKIE_NAME]
  if (!cookie) return false
  const idx = cookie.lastIndexOf('.')
  if (idx <= 0 || idx === cookie.length - 1) return false
  const expected = createHmac('sha256', sessionKey(token)).update(cookie.slice(0, idx)).digest()
  const given = Buffer.from(cookie.slice(idx + 1), 'base64url')
  return given.length === expected.length && timingSafeEqual(given, expected)
}

/**
 * Injected into every forwarded HTML response: crypto.randomUUID only exists in
 * secure contexts (HTTPS or http://localhost). When the proxy is reached over
 * plain HTTP on a LAN address (insecure context) the browser lacks it and DSH
 * frontend RPCs (message/RPC ids) crash with "crypto.randomUUID is not a
 * function". getRandomValues IS available in insecure contexts, so a v4 UUID
 * polyfill keeps everything working over HTTP.
 */
const UUID_POLYFILL = `<script>
(function () {
  if (typeof globalThis.crypto !== 'object' || typeof globalThis.crypto.randomUUID === 'function') return;
  if (typeof globalThis.crypto.getRandomValues !== 'function') return;
  var buf = new Uint8Array(16);
  globalThis.crypto.randomUUID = function () {
    globalThis.crypto.getRandomValues(buf);
    buf[6] = (buf[6] & 0x0f) | 0x40;
    buf[8] = (buf[8] & 0x3f) | 0x80;
    var h = '';
    for (var i = 0; i < 16; i++) h += buf[i].toString(16).padStart(2, '0');
    return h.slice(0, 8) + '-' + h.slice(8, 12) + '-' + h.slice(12, 16) + '-' + h.slice(16, 20) + '-' + h.slice(20);
  };
})();
<\/script>`

/**
 * Injected into every forwarded HTML response beside the UUID polyfill. dsh
 * web's browser half classifies the connection by the page origin: a
 * non-loopback origin is treated as a remote browser, and the whole settings
 * plane goes read-only — every settingsScope-bound surface (theme, language,
 * composer policy, the plugin-configuration cards) constructs "memory"
 * persistence and can no longer be modified.
 *
 * Through this proxy that classification is wrong: the socket terminates on
 * the loopback webserver, Host/Origin are rewritten back to the loopback
 * target, and the /api Host fence (the privileged settings/credentials
 * methods included) already treats every request as loopback. Forcing the
 * client flag open simply mirrors what the server already grants; the proxy
 * itself remains the token-auth edge.
 *
 * The script wraps window.__ModuleLoader__.load and, for the
 * @deepseek-ai/dsh-client-connection bundle, wraps its apply() so the
 * connection handle's isLoopback is forced open right after the service is
 * provided — before any consumer plugin binds a settings scope, whatever the
 * plugin load order is.
 */
const LOOPBACK_COMPAT_SCRIPT = `<script>
(function () {
  try {
    var realLoader = undefined;
    var installed = false;
    Object.defineProperty(globalThis, '__ModuleLoader__', {
      configurable: true,
      enumerable: true,
      get: function () { return realLoader; },
      set: function (loader) {
        if (installed) { realLoader = loader; return; }
        installed = true;
        var originalLoad = loader.load.bind(loader);
        loader.load = function (entry) {
          if (entry && typeof entry === 'object'
              && entry.id === '@deepseek-ai/dsh-client-connection'
              && typeof entry.factory === 'function') {
            var originalFactory = entry.factory;
            entry.factory = function (require) {
              var exports = originalFactory(require);
              if (exports && typeof exports.apply === 'function') {
                var originalApply = exports.apply;
                exports.apply = function (ctx) {
                  var result = originalApply.apply(this, arguments);
                  try {
                    var handle = ctx && typeof ctx.get === 'function' ? ctx.get('connection') : undefined;
                    if (handle && typeof handle === 'object' && handle.isLoopback === false) {
                      handle.isLoopback = true;
                    }
                  } catch (err) { /* keep the read-only behavior on failure */ }
                  return result;
                };
              }
              return exports;
            };
          }
          return originalLoad(entry);
        };
        realLoader = loader;
      }
    });
  } catch (err) { /* keep the read-only behavior on failure */ }
})();
<\/script>`

/** Escape user-supplied text before interpolating it into the login page HTML. */
function htmlEscape(value: string): string {
  return value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
}

const LOGIN_PAGE = (banner: string, locked = false, accessUrls: string[] = []): string => `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DSH 访问鉴权</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    min-height: 100vh; display: flex; align-items: center; justify-content: center;
    background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
    font-family: -apple-system, "Segoe UI", "Microsoft YaHei", sans-serif; color: #e2e8f0;
  }
  .card {
    width: min(92vw, 380px); background: #1e293b; border: 1px solid #334155;
    border-radius: 16px; padding: 36px 32px; box-shadow: 0 20px 60px rgba(0,0,0,.45);
  }
  h1 { font-size: 20px; font-weight: 600; margin-bottom: 6px; }
  .sub { font-size: 13px; color: #94a3b8; margin-bottom: 24px; }
  .banner { font-size: 13px; color: #7dd3fc; margin-bottom: 16px; }
  input {
    width: 100%; padding: 12px 14px; border-radius: 10px; border: 1px solid #334155;
    background: #0f172a; color: #f1f5f9; font-size: 15px; outline: none; margin-bottom: 16px;
  }
  input:focus { border-color: #38bdf8; }
  button {
    width: 100%; padding: 12px; border: 0; border-radius: 10px; background: #0ea5e9;
    color: #082f49; font-size: 15px; font-weight: 600; cursor: pointer;
  }
  button:hover { background: #38bdf8; }
  .err { color: #f87171; font-size: 13px; margin-top: 12px; min-height: 18px; }
  .locked { color: #fbbf24; font-size: 13px; margin-top: 12px; min-height: 18px; }
  .urls { margin-top: 20px; padding-top: 14px; border-top: 1px solid #334155; font-size: 12px; color: #94a3b8; line-height: 1.8; }
  .urls a { color: #7dd3fc; text-decoration: none; }
  .urls a:hover { text-decoration: underline; }
</style>
</head>
<body>
<div class="card">
  <h1>DSH Web 访问鉴权</h1>
  <div class="sub">请输入访问令牌以继续</div>
  ${banner ? `<div class="banner">${htmlEscape(banner)}</div>` : ''}
  ${locked ? '<div class="locked">尝试次数过多，已临时锁定，请稍后再试</div>' : `
  <form method="post" action="/__dsh_auth/login">
    <input type="password" name="token" placeholder="访问令牌" autofocus autocomplete="current-password">
    <button type="submit">进入</button>
  </form>
  <div class="err"></div>`}
  ${accessUrls.length > 0
    ? `<div class="urls">访问地址：${accessUrls.map((u) => `<a href="${htmlEscape(u)}">${htmlEscape(u)}</a>`).join('、')}</div>`
    : ''}
</div>
</body>
</html>`

/** Read the request body as text (capped). */
function readBody(req: IncomingMessage, cap = 64 * 1024): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []
    let total = 0
    req.on('data', (chunk: Buffer) => {
      total += chunk.length
      if (total > cap) {
        reject(new Error('body too large'))
        req.destroy()
        return
      }
      chunks.push(chunk)
    })
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')))
    req.on('error', reject)
  })
}

/** Schema defaults, re-read for hand-built test contexts (the loader applies them normally). */
const DEFAULTS: Resolved = {
  enabled: true,
  host: '127.0.0.1',
  port: 8443,
  targetHost: '127.0.0.1',
  targetPort: 3080,
  token: '',
  banner: '',
  allowedIps: [],
  accessUrls: [],
  maxFailures: 0,
  lockoutMinutes: 15,
}

/**
 * Mount the auth proxy. Configuration resolves as: dsh-settings scope (or the
 * composition entry when no settings service is present) as the base layer,
 * with the user config file (~/.dsh/dsh-auth-proxy.json) on top — the file is
 * what the settings card edits, so its changes survive restarts.
 * @param ctx - host plugin context.
 * @param config - resolved plugin config.
 */
export function apply(ctx: Context, config?: Config): void {
  /** The user config file overrides everything else (highest precedence). */
  let fileConfig: Partial<Config> = loadConfigFile() ?? {}
  /**
   * Base layer of the config resolution: the dsh-settings scope while one is
   * attached (installSettingsSection re-points this), otherwise the
   * composition entry. The user config file always wins over it.
   */
  let base: () => Config = () => (config ?? {}) as Config
  /** Single resolution: base layer, then the user config file on top. */
  let current: () => Config = () => ({ ...base(), ...fileConfig }) as Config
  const resolve = (): Resolved => {
    const value = current()
    return {
      enabled: value.enabled ?? DEFAULTS.enabled,
      host: value.host ?? DEFAULTS.host,
      port: value.port ?? DEFAULTS.port,
      targetHost: value.targetHost ?? DEFAULTS.targetHost,
      targetPort: value.targetPort ?? DEFAULTS.targetPort,
      token: value.token ?? DEFAULTS.token,
      banner: value.banner ?? DEFAULTS.banner,
      allowedIps: value.allowedIps ?? DEFAULTS.allowedIps,
      accessUrls: value.accessUrls ?? DEFAULTS.accessUrls,
      maxFailures: value.maxFailures ?? DEFAULTS.maxFailures,
      lockoutMinutes: value.lockoutMinutes ?? DEFAULTS.lockoutMinutes,
    }
  }

  /** Last resolved config snapshot; request handlers read this per request. */
  let live: Resolved = resolve()
  /** Whether the disabled state was already announced (avoid log spam). */
  let announcedDisabled = false
  /** Whether the listen socket is currently up (reported by the config API). */
  let serverUp = false

  /**
   * Terminal-visible announce. dsh web prints its own URL line with a plain
   * console.log (dsh-web-app) but does not route plugin ctx.logger output to
   * the console — so the state changes the operator must see are echoed here.
   * The ctx.logger call still feeds the in-memory log buffer.
   */
  const say = (line: string): void => {
    ctx.logger.info(`dsh-auth-proxy: ${line}`)
    console.log(`dsh-auth-proxy: ${line}`)
  }
  const sayWarn = (line: string): void => {
    ctx.logger.warn(`dsh-auth-proxy: ${line}`)
    console.log(`dsh-auth-proxy: ${line}`)
  }

  const loginPath = '/__dsh_auth/login'
  const logoutPath = '/__dsh_auth/logout'

  /** One live server; recreated only when the listen socket must move. */
  let server: ReturnType<typeof createServer> | undefined
  /** Disposer of the fiber effect owning the current server (fiber unload = force-close). */
  let disposeServer: (() => void) | undefined
  /** Force-close timer armed by a graceful (rebuild) teardown. */
  let graceKill: ReturnType<typeof setTimeout> | undefined

  /**
   * Drop the current listen socket. `graceful` (rebuild path) stops accepting
   * new connections but lets in-flight responses finish, force-closing
   * lingering keep-alive/WebSocket connections after a short grace; the
   * immediate mode (disable / fiber unload) cuts everything at once.
   */
  const teardownServer = (graceful = false): void => {
    const srv = server
    if (srv === undefined) return
    server = undefined
    serverUp = false
    if (disposeServer !== undefined) {
      // The old effect's disposer calls teardownServer(false), which no-ops
      // now that `server` is undefined — releasing it keeps the fiber clean.
      disposeServer()
      disposeServer = undefined
    }
    if (graceKill !== undefined) {
      clearTimeout(graceKill)
      graceKill = undefined
    }
    if (graceful) {
      srv.close()
      graceKill = setTimeout(() => srv.closeAllConnections(), 1500)
      graceKill.unref()
    } else {
      srv.closeAllConnections()
      srv.close()
    }
  }

  const sync = (): void => {
    const next = resolve()
    const wasListening = server !== undefined
    // No TLS: never bind a wildcard or public address even if the config says
    // so (the PUT handler already rejects it, but a stale user file can hold
    // an old 0.0.0.0) — such a host keeps the proxy disabled.
    const hostIssue = listenHostIssue(next.host)
    const shouldListen = next.enabled && tokenConfigured(next.token) && hostIssue === null
    const bindChanged = next.host !== live.host || next.port !== live.port
    const stateChanged = wasListening !== shouldListen
    live = next

    // Hot update: non-socket config (token, banner, accessUrls, allowlist, lockout)
    // takes effect on the next request via `live` — no rebuild, no dropped
    // connections, no dead WebSockets.
    if (!bindChanged && !stateChanged) {
      if (!shouldListen && !announcedDisabled) {
        announcedDisabled = true
        if (!tokenConfigured(next.token)) {
          sayWarn('disabled — no token configured (empty or placeholder `change-me`); set `token` in the plugin config')
        } else if (hostIssue) {
          sayWarn(`disabled — refusing to listen on ${next.host}: ${hostIssue}`)
        } else {
          say('disabled')
        }
      }
      return
    }

    // Immediate teardown when the listen state flips (disable / token
    // invalidated); graceful when only the bind address moved, so the
    // in-flight config-save response still reaches the browser.
    teardownServer(stateChanged ? false : true)
    if (!shouldListen) {
      announcedDisabled = true
      if (!tokenConfigured(next.token)) {
        sayWarn('disabled — no token configured (empty or placeholder `change-me`); set `token` in the plugin config')
      } else if (hostIssue) {
        sayWarn(`disabled — refusing to listen on ${next.host}: ${hostIssue}`)
      } else {
        say('disabled')
      }
      return
    }
    announcedDisabled = false

    const srv = createServer((req, res) => {
      // The response may hit a vanished client after headers were sent.
      res.on('error', (err) => {
        ctx.logger.debug(`dsh-auth-proxy: response error ${String(err)}`)
      })
      handleRequest(req, res).catch((err) => {
        ctx.logger.warn(err instanceof Error ? err : new Error(String(err)))
        if (!res.headersSent) {
          res.writeHead(500)
          res.end('proxy error')
        } else {
          res.destroy()
        }
      })
    })

    // A bind failure (port in use, no permission) must not crash the harness.
    srv.on('error', (err) => {
      ctx.logger.error(`dsh-auth-proxy: listen failed ${String(err)}`)
    })

    /** Patch content-length for a rewritten response body, or strip it. */
    const fixLength = (res: ServerResponse, headers: Record<string, string | string[] | number | undefined>, bodyLen: number): void => {
      const out = { ...headers }
      if (out['content-length'] !== undefined) out['content-length'] = String(bodyLen)
      res.writeHead(200, out)
    }

    /**
     * Forward one HTTP request to the loopback target, rewriting host/origin.
     * HTML responses get the UUID polyfill injected so the DSH frontend works
     * over plain HTTP on LAN addresses (insecure context).
     */
    const forward = (req: IncomingMessage, res: ServerResponse): void => {
      // A client reset mid-transfer (refresh/cancel) surfaces as 'error' on
      // the incoming stream; without a listener it crashes the process.
      req.on('error', (err) => {
        ctx.logger.debug(`dsh-auth-proxy: client stream error ${String(err)}`)
      })
      res.on('error', (err) => {
        ctx.logger.debug(`dsh-auth-proxy: client response error ${String(err)}`)
      })
      const targetUrl = `http://${live.targetHost}:${live.targetPort}${req.url ?? '/'}`
      const headers = { ...req.headers }
      headers.host = `${live.targetHost}:${live.targetPort}`
      if (headers.origin) headers.origin = `http://${live.targetHost}:${live.targetPort}`
      // The proxy is the network edge: never forward a client-spoofed
      // X-Forwarded-For / X-Real-IP to the loopback target.
      delete headers['x-forwarded-for']
      delete headers['x-real-ip']
      const proxy = httpRequest(targetUrl, {
        method: req.method,
        headers,
      }, (upstream) => {
        upstream.on('error', (err) => {
          ctx.logger.debug(`dsh-auth-proxy: upstream stream error ${String(err)}`)
          res.destroy()
        })
        const contentType = String(upstream.headers['content-type'] ?? '')
        const isHtml = contentType.toLowerCase().includes('text/html')
        if (!isHtml) {
          res.writeHead(upstream.statusCode ?? 502, upstream.statusMessage, upstream.headers)
          upstream.pipe(res)
          return
        }
        // Buffer HTML so we can inject the polyfills before </head>.
        const chunks: Buffer[] = []
        upstream.on('data', (c: Buffer) => chunks.push(c))
        upstream.on('end', () => {
          let body = Buffer.concat(chunks).toString('utf8')
          if (body.includes('</head>')) {
            body = body.replace('</head>', `${UUID_POLYFILL}\n${LOOPBACK_COMPAT_SCRIPT}\n</head>`)
          }
          const out = Buffer.from(body, 'utf8')
          const headersOut = { ...upstream.headers } as Record<string, string | string[] | number | undefined>
          fixLength(res, headersOut, out.length)
          res.end(out)
        })
        upstream.on('error', () => res.destroy())
      })
      proxy.on('error', (err) => {
        ctx.logger.warn(`dsh-auth-proxy: upstream error ${String(err)}`)
        if (!res.headersSent) {
          res.writeHead(502)
          res.end('upstream unavailable')
        } else {
          res.destroy()
        }
      })
      req.pipe(proxy)
    }

    async function handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
      const c = live
      const pathname = new URL(req.url ?? '/', 'http://x').pathname
      const ip = clientIp(req)

      // IP allowlist bypasses the token entirely.
      if (isAllowedIp(ip, c.allowedIps)) {
        forward(req, res)
        return
      }

      if (isLockedOut(ip)) {
        if (pathname === loginPath) {
          res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' })
          res.end(LOGIN_PAGE(c.banner, true, c.accessUrls))
        } else {
          res.writeHead(403, { 'content-type': 'text/plain' })
          res.end('locked out')
        }
        return
      }

      if (pathname === loginPath) {
        if (req.method === 'POST') {
          const body = await readBody(req)
          const token = new URLSearchParams(body).get('token') ?? ''
          if (safeEqual(token, c.token)) {
            failures.delete(ip)
            issueSession(res, c.token)
            res.writeHead(302, { location: '/' })
            res.end()
          } else {
            recordFailure(ip, c.maxFailures, c.lockoutMinutes)
            res.writeHead(401, { 'content-type': 'text/html; charset=utf-8' })
            res.end(LOGIN_PAGE(c.banner, false, c.accessUrls).replace('<div class="err"></div>', '<div class="err">令牌错误，请重试</div>'))
          }
          return
        }
        res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' })
        res.end(LOGIN_PAGE(c.banner, false, c.accessUrls))
        return
      }

      if (pathname === logoutPath && req.method === 'POST') {
        // Stateless session: there is nothing to revoke server-side — just
        // expire the client cookie.
        res.writeHead(302, { location: '/', 'set-cookie': `${COOKIE_NAME}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0` })
        res.end()
        return
      }

      if (!isValidSession(req, c.token)) {
        // API calls get a JSON 401 (fetch-friendly); page navigations get a redirect.
        if (pathname.startsWith('/api/') || pathname === '/api') {
          res.writeHead(401, { 'content-type': 'application/json' })
          res.end(JSON.stringify({ error: 'unauthorized' }))
          return
        }
        res.writeHead(302, { location: loginPath })
        res.end()
        return
      }

      forward(req, res)
    }

    srv.on('upgrade', (req, socket, head) => {
      // A client can reset the connection at any moment (refresh, cancel,
      // network drop); an unhandled 'error' on this raw socket would crash
      // the whole process. Swallow-and-destroy is the correct treatment.
      const onSocketError = (err: Error): void => {
        ctx.logger.debug(`dsh-auth-proxy: upgrade socket error ${String(err)}`)
        socket.destroy()
      }
      socket.on('error', onSocketError)
      socket.once('close', () => socket.off('error', onSocketError))
      const ip = clientIp(req)
      if (isAllowedIp(ip, live.allowedIps)) {
        doUpgrade(req, socket, head)
        return
      }
      if (isLockedOut(ip) || !isValidSession(req, live.token)) {
        socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n')
        socket.destroy()
        return
      }
      doUpgrade(req, socket, head)
    })

    srv.listen(next.port, next.host, () => {
      serverUp = true
      // Bind hosts are loopback or LAN-only by policy, so the bound URL is
      // always concrete and clickable — no separate reachable-URLs line needed.
      say(`listening on http://${next.host}:${next.port} -> http://${next.targetHost}:${next.targetPort}`)
    })

    server = srv
    // Fiber unload must cut immediately; rebuilds use the graceful path in
    // teardownServer, leaving this disposer's force-close as the backstop.
    disposeServer = ctx.effect(() => () => teardownServer(false), 'dsh-auth-proxy: server')
  }

  /** Forward a WebSocket upgrade, rewriting host/origin for the trust fence. */
  function doUpgrade(req: IncomingMessage, socket: Duplex, head: Buffer): void {
    if (req.headers.host) req.headers.host = `${live.targetHost}:${live.targetPort}`
    if (req.headers.origin) req.headers.origin = `http://${live.targetHost}:${live.targetPort}`
    delete req.headers['x-forwarded-for']
    delete req.headers['x-real-ip']
    const targetUrl = `http://${live.targetHost}:${live.targetPort}${req.url ?? '/'}`
    const proxy = httpRequest(targetUrl, { method: req.method, headers: req.headers })
    const onSocketError = (err: Error): void => {
      ctx.logger.debug(`dsh-auth-proxy: tunnel socket error ${String(err)}`)
      socket.destroy()
    }
    proxy.on('upgrade', (upstreamRes, upstreamSocket, upstreamHead) => {
      // Both pipe ends are raw sockets too — the client may vanish mid-stream.
      upstreamSocket.on('error', onSocketError)
      upstreamSocket.once('close', () => upstreamSocket.off('error', onSocketError))
      // A 101 needs Connection: Upgrade / Upgrade: <proto> on the wire or the
      // client treats it as a plain response and never switches protocols
      // (workspace events then never arrive). Forward the upgrade headers as-is
      // and drop only hop-by-hop headers that node already manages.
      socket.write(`HTTP/1.1 ${upstreamRes.statusCode ?? 101} ${upstreamRes.statusMessage ?? 'Switching Protocols'}\r\n`)
      for (const [key, value] of Object.entries(upstreamRes.headers)) {
        const lower = key.toLowerCase()
        if (lower === 'transfer-encoding' || lower === 'connection') continue
        socket.write(`${key}: ${value}\r\n`)
      }
      const connHdr = upstreamRes.headers.connection
      if (connHdr !== undefined) socket.write(`Connection: ${connHdr}\r\n`)
      socket.write('\r\n')
      if (upstreamHead.length) upstreamSocket.unshift(upstreamHead)
      upstreamSocket.pipe(socket)
      socket.pipe(upstreamSocket)
    })
    proxy.on('error', (err) => {
      ctx.logger.warn(`dsh-auth-proxy: upgrade error ${String(err)}`)
      socket.destroy()
    })
    proxy.end(head)
  }

  // The dsh-settings scope (when present) is the BASE layer of the config
  // resolution; the user config file always wins over it. Kept registered so
  // host-driven settings surfaces still see this namespace, while the file —
  // the only store the settings card writes — is what actually survives
  // restarts.
  installSettingsSection(ctx, AUTH_SETTINGS_NAMESPACE, Config, config ?? ({} as Config), {
    setSource: (source) => {
      base = source
      sync()
    },
    onChange: sync,
  })

  // ── self-served config API (bypasses the dsh-settings exposed whitelist) ──
  // The user config document is the editable layer; the API is only reachable
  // through the harness webserver, so it inherits the /api browser-trust
  // fence (loopback or --trusted-host) plus our own auth-proxy session gate
  // when the browser enters through :8443.
  const writeJson = (res: ServerResponse, status: number, body: unknown): void => {
    const text = JSON.stringify(body)
    res.writeHead(status, { 'content-type': 'application/json; charset=utf-8' })
    res.end(text)
  }
  const apiRoutes: Array<{ kind: 'exact'; path: string; handler: (req: IncomingMessage, res: ServerResponse) => Promise<void> }> = [
    {
      kind: 'exact',
      path: '/api/dsh-auth-proxy/config',
      handler: async (req, res) => {
        const method = req.method ?? 'GET'
        if (method === 'GET') {
          // Return the effective config minus the secret token value.
          const effective = resolve()
          writeJson(res, 200, {
            enabled: effective.enabled,
            host: effective.host,
            port: effective.port,
            targetHost: effective.targetHost,
            targetPort: effective.targetPort,
            banner: effective.banner,
            allowedIps: effective.allowedIps,
            accessUrls: effective.accessUrls,
            maxFailures: effective.maxFailures,
            lockoutMinutes: effective.lockoutMinutes,
            listening: serverUp,
            tokenSet: tokenConfigured(effective.token),
          })
          return
        }
        if (method === 'PUT') {
          let raw = ''
          for await (const chunk of req) raw += chunk
          let next: Partial<Config>
          try {
            next = JSON.parse(raw) as Partial<Config>
          } catch {
            writeJson(res, 400, { error: 'invalid JSON body' })
            return
          }
          // Validate the merged shape before persisting. The token may come
          // from the composition env (never persisted to the user file), so
          // probe with the effective default when absent.
          const merged = { ...fileConfig, ...next }
          try {
            const probe = {
              enabled: merged.enabled ?? DEFAULTS.enabled,
              host: merged.host ?? DEFAULTS.host,
              port: merged.port ?? DEFAULTS.port,
              targetHost: merged.targetHost ?? DEFAULTS.targetHost,
              targetPort: merged.targetPort ?? DEFAULTS.targetPort,
              token: merged.token ?? resolve().token ?? DEFAULTS.token,
              banner: merged.banner ?? DEFAULTS.banner,
              allowedIps: merged.allowedIps ?? DEFAULTS.allowedIps,
              accessUrls: merged.accessUrls ?? DEFAULTS.accessUrls,
              maxFailures: merged.maxFailures ?? DEFAULTS.maxFailures,
              lockoutMinutes: merged.lockoutMinutes ?? DEFAULTS.lockoutMinutes,
            }
            Config(probe)
          } catch (err) {
            writeJson(res, 400, { error: `invalid config: ${String(err)}` })
            return
          }
          // No TLS: a wildcard or public listen host is refused outright.
          const hostIssue = listenHostIssue(merged.host ?? DEFAULTS.host)
          if (hostIssue) {
            writeJson(res, 400, { error: 'invalid-config', detail: hostIssue })
            return
          }
          fileConfig = merged
          saveConfigFile(merged)
          // `current` is always base() + fileConfig — no re-pointing needed.
          const effective = resolve()
          writeJson(res, 200, {
            ok: true,
            port: effective.port,
            tokenSet: tokenConfigured(effective.token),
          })
          // Defer the rebuild: the response above must reach the browser before
          // the listen socket is recreated (relevant only when host/port/enabled
          // changed; other changes are hot-applied without a rebuild at all).
          setImmediate(sync)
          return
        }
        writeJson(res, 405, { error: `method not allowed: ${method}` })
      },
    },
  ]
  ctx.inject(['webServer'], (wctx) => {
    for (const route of apiRoutes) {
      wctx.effect(() => wctx.webServer.register(route), 'dsh-auth-proxy: config api')
    }
  })

  // Periodic sweep bounds the in-memory failure table. Sessions are
  // stateless (signed cookies), so there is nothing server-side to expire.
  const sweepTimer = setInterval(() => {
    const now = Date.now()
    for (const [ip, rec] of failures) {
      if ((rec.lockUntil !== undefined && rec.lockUntil < now) || now - rec.lastFailAt > FAILURE_IDLE_MS) {
        failures.delete(ip)
      }
    }
  }, SWEEP_INTERVAL_MS)
  sweepTimer.unref()
  ctx.effect(() => () => clearInterval(sweepTimer), 'dsh-auth-proxy: sweep')

  // Initial registration from the composition entry (covers deployments with
  // no settings service, whose installSettingsSection never fires its hooks).
  sync()
}

export type { Duplex }
