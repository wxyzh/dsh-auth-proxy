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
 * the plugin's own settings card (Settings > Plugin config), which writes
 * through the official dsh-settings scope. The namespace is registered by
 * installSettingsSection, whose registered scope resolves schema defaults, the
 * composition entry (base), and the user document section (the deployment's
 * dsh-settings-file provider persists it) — there is no bespoke config file.
 */

import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { createServer, request as httpRequest, type IncomingMessage, type ServerResponse } from 'node:http'
import type { Duplex } from 'node:stream'
import type { Context } from '@deepseek-ai/cordis'
import type {} from '@deepseek-ai/dsh-settings'
import type {} from '@deepseek-ai/dsh-host-webserver'
import z from 'schemastery'
import { clearInterval, clearTimeout, setInterval, setTimeout } from 'node:timers'

/** Stable cordis plugin name. */
export const name = 'auth-proxy'

/**
 * No host services are required — this plugin stands alone on its own socket.
 * The dsh-settings scope is optional (installSettingsSection self-detects a
 * provider and falls back to the composition entry), so `settings` is not a hard
 * inject.
 */
export const inject: string[] = []

/**
 * Settings namespace of this plugin — the section the Web settings surface
 * edits. Lowercase kebab-case (the dsh-settings contract).
 */
export const AUTH_SETTINGS_NAMESPACE = 'dsh-auth-proxy' as const

export interface Brand {
  /** Master switch — when false the whole brand layer is skipped. */
  enabled?: boolean
  /**
   * Tab title brand: replaces "DeepSeek Harness" in the static <title> and in
   * document.title (setter override). Empty string = no title rewrite.
   */
  title?: string
  /** Sidebar wordmark text rendered next to the brand mark (default "Copilot"). */
  wordmark?: string
  /** Inject the Copilot slot-occupant script (sidebar.brand.mark/name + conversation.hero.brand.mark). */
  logo?: boolean
  /** Favicon source: inline SVG markup or a host-readable SVG file path. */
  icon?: {
    /** Inline SVG markup (uploaded through the settings card). */
    inline?: string
    /** Absolute path to an SVG file on the host, read at serve time. */
    file?: string
  }
}

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
  /**
   * Brand layer: rewrites the forwarded pages' tab title, favicon and PWA
   * manifest, and optionally injects Copilot brand slot occupants (sidebar
   * brand mark/name + conversation hero mark). All rewrites run on the proxy
   * forward path only — direct loopback access (127.0.0.1:3080) never sees
   * them. The master switch is `brand.enabled`; each sub-feature has its own
   * flag. Empty object = whole layer off.
   */
  brand?: Brand
  /** @deprecated replaced by `brand.title` (mapped automatically). */
  brandTitle?: string
  /** CIDR / IP allowlist bypassing the token (e.g. ["127.0.0.1", "10.0.0.0/8"]). Empty = token always required. */
  allowedIps?: string[]
  /**
   * Public entry URLs (may be https domains) the proxy is reachable through.
   * Shown on the settings card and the login page, AND used as the loopback
   * whitelist: when non-empty, only pages whose origin/host matches an entry
   * are treated as loopback (local-admin) — everything else reached through
   * the proxy stays remote read-only. Empty list = every proxied page counts
   * as loopback (legacy behavior).
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
  brand: z.object({
    enabled: z.boolean().default(false),
    title: z.string().default(''),
    wordmark: z.string().default('Copilot'),
    logo: z.boolean().default(false),
    icon: z.object({
      inline: z.string().default(''),
      file: z.string().default(''),
    }),
  }),
  /** @deprecated replaced by `brand.title` (mapped automatically). */
  brandTitle: z.string().default(''),
  allowedIps: z.array(z.string()).default([]),
  accessUrls: z.array(z.string()).default([]),
  maxFailures: z.natural().default(0),
  lockoutMinutes: z.natural().min(1).default(15),
})

/** Fully-defaulted brand layer (every field materialized). */
type BrandResolved = {
  enabled: boolean
  title: string
  wordmark: string
  logo: boolean
  icon: { inline: string; file: string }
}

/** Fully-resolved config shape (every field materialized). */
type Resolved = Required<Omit<Config, 'banner' | 'allowedIps' | 'accessUrls' | 'brand' | 'brandTitle'>> & {
  banner: string
  allowedIps: string[]
  accessUrls: string[]
  brand: BrandResolved
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
</script>`

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
 * The script keeps the dsh web module facade (`window.__ModuleLoader__`)
 * alive no matter when the boot HTML materializes it, and — for the
 * @deepseek-ai/dsh-client-connection bundle — wraps its apply() so the
 * connection handle's isLoopback is forced open right after the service is
 * provided — before any consumer plugin binds a settings scope, whatever the
 * plugin load order is.
 *
 * dsh rc.8 moved the facade INTO the served HTML at the top of `<head>`:
 * `injectBootManifest` now inlines the queue facade + preloads synchronously
 * there, while this script still runs just before `</head>`. The previous
 * defineProperty-accessor capture therefore REPLACED the already-assigned
 * loader with a getter that never returned it, and boot failed with
 * `window.__ModuleLoader__ bootstrap facade is missing`. The fix: when the
 * facade already exists, wrap its `load` in place and interpose on `create`
 * so live-mode registrations (the loader is swapped during create) stay
 * wrapped too; the accessor path remains only for older boots that assign
 * the loader later.
 */
/**
 * Build the loopback-compat shim injected into every forwarded HTML response.
 * When `trustedOrigins` is non-empty, the shim only forces the connection
 * loopback flag for page origins/hosts that match the list (the proxy's own
 * access URLs); any other source reached through the proxy stays remote
 * read-only. An empty list keeps the historical unconditional behavior —
 * every proxied page is treated as loopback, matching the pre-whitelist state.
 */
export function loopbackCompatScript(trustedOrigins: string[] = []): string {
  const list = JSON.stringify(trustedOrigins)
  return `<script>
(function () {
  // Diagnostic ring: reports every step this shim takes so a real-browser console
  // can be checked for where the chain broke (window.__dshLoopbackDiag).
  var diag = [];
  var pushDiag = function (msg) {
    try { diag.push(msg); if (diag.length > 60) diag.shift(); window.__dshLoopbackDiag = diag.slice(); } catch (err) {}
  };
  // Optional trusted-origin whitelist (auth-proxy accessUrls). Empty = every
  // proxied page counts as loopback (legacy behavior); non-empty = only pages
  // whose origin/host matches get the local-admin identity.
  var TRUSTED_ORIGINS = ${list};
  var isTrustedOrigin = function () {
    if (!TRUSTED_ORIGINS || TRUSTED_ORIGINS.length === 0) return true;
    try {
      var origin = String(location.origin || '').toLowerCase().replace(/\\/+$/, '');
      var host = String(location.host || location.hostname || '').toLowerCase();
      var hostname = String(location.hostname || '').toLowerCase();
      for (var i = 0; i < TRUSTED_ORIGINS.length; i++) {
        var t = String(TRUSTED_ORIGINS[i]).toLowerCase().replace(/\\/+$/, '');
        var tOrigin = t;
        var tHost = t.indexOf('://') >= 0 ? t.slice(t.indexOf('://') + 3) : t;
        if (tOrigin === origin) return true;
        if (tHost === host || tHost === hostname) return true;
      }
      return false;
    } catch (err) { return false; }
  };
  try {
    pushDiag('LOOPBACK_COMPAT_SCRIPT start');
    if (!isTrustedOrigin()) { pushDiag('origin not trusted; skipping seed'); return; }
    // dsh-client-connection computes "isLoopback" from transport.ownsHost
    // (lib/client.js:4729). The transport global is never assigned anywhere in
    // the dsh web app - web shell reads o?.loadBundle, the connection bundle
    // reads transport?.fetch/openStream, all through optional chaining - so
    // seeding __DSH_TRANSPORT__ with ownsHost:true makes the proxied page count
    // as loopback WITHOUT touching the module system at all. This is the whole
    // point: no __ModuleLoader__ wrapping, no ctx.provide patching, nothing that
    // could disturb service registration (which is what white-screened boot).
    var prev = globalThis.__DSH_TRANSPORT__;
    globalThis.__DSH_TRANSPORT__ = Object.assign(
      {},
      prev && typeof prev === 'object' ? prev : {},
      { ownsHost: true }
    );
    pushDiag('seeded __DSH_TRANSPORT__.ownsHost = true');
  } catch (err) { pushDiag('seed error: ' + String(err)); }
})();
</script>`
}

/** Legacy export: the unconditional loopback shim (empty whitelist = force every proxied page). Kept for downstream imports and the smoke suite. */
export const LOOPBACK_COMPAT_SCRIPT = loopbackCompatScript()

/**
 * Mobile settings-dialog nav collapse (2026-09-03, web-all 0.3.13 responsive
 * layer): the settings dialog renders a fixed 188px left nav column even on
 * narrow viewports, squeezing the content pane to ~130px. This injects a
 * bottom-left floating toggle that collapses the nav to a 44px icon rail on
 * screens ≤768px (labels/title hidden, cells centered); tapping toggles back
 * to the full nav. Pure presentation, no web-all source change; class names
 * are matched by structure (`> nav` / `[class*="nav*"]`) so web-all upgrades
 * that rehash CSS modules do not break it. Desktop viewports are untouched.
 */
const MOBILE_SETTINGS_NAV_FIX = `<style>
@media (max-width: 768px) {
  [role="dialog"][data-dsh-surface] > nav {
    width: 44px !important;
    min-width: 44px !important;
    flex: 0 0 44px !important;
    padding: 22px 4px 0 !important;
  }
  [role="dialog"][data-dsh-surface] > nav [class*="navLabel"],
  [role="dialog"][data-dsh-surface] > nav [class*="navTitle"] {
    display: none !important;
  }
  [role="dialog"][data-dsh-surface] > nav [class*="navCell"] {
    justify-content: center !important;
    padding: 9px 0 !important;
  }
  [role="dialog"][data-dsh-surface][data-dsh-settings-nav="expanded"] > nav {
    width: 188px !important;
    min-width: 188px !important;
    flex: 0 0 188px !important;
    padding: 22px 12px 0 !important;
  }
  [role="dialog"][data-dsh-surface][data-dsh-settings-nav="expanded"] > nav [class*="navLabel"],
  [role="dialog"][data-dsh-surface][data-dsh-settings-nav="expanded"] > nav [class*="navTitle"] {
    display: block !important;
  }
  [role="dialog"][data-dsh-surface][data-dsh-settings-nav="expanded"] > nav [class*="navCell"] {
    justify-content: flex-start !important;
    padding: 9px 16px 9px 12px !important;
  }
}
</style>
<script>
(function () {
  var TOGGLE_ID = 'dsh-settings-nav-toggle';
  function isNarrow() { return window.matchMedia('(max-width: 768px)').matches; }
  function findPanel() { return document.querySelector('[role="dialog"][data-dsh-surface]'); }
  var btn = null;
  function ensureButton() {
    if (btn && btn.isConnected) return btn;
    btn = document.createElement('button');
    btn.id = TOGGLE_ID;
    btn.setAttribute('aria-label', '\u5c55\u5f00/\u6536\u8d77\u8bbe\u7f6e\u5bfc\u822a');
    btn.setAttribute('title', '\u5c55\u5f00/\u6536\u8d77\u8bbe\u7f6e\u5bfc\u822a');
    btn.textContent = '\u2261';
    btn.style.cssText = 'position:fixed;left:8px;bottom:16px;z-index:2147483647;width:40px;height:40px;border-radius:50%;border:none;background:var(--dsw-alias-bg-layer-2, #2a2a33);color:var(--dsw-alias-label-primary, #eee);font-size:20px;cursor:pointer;box-shadow:0 2px 10px rgba(0,0,0,.3);display:none;align-items:center;justify-content:center;';
    document.body.appendChild(btn);
    btn.addEventListener('click', function () {
      var panel = findPanel();
      if (!panel) return;
      var expanded = panel.getAttribute('data-dsh-settings-nav') === 'expanded';
      panel.setAttribute('data-dsh-settings-nav', expanded ? 'collapsed' : 'expanded');
    });
    return btn;
  }
  function sync() {
    var panel = findPanel();
    var toggle = ensureButton();
    if (!panel || !isNarrow()) { toggle.style.display = 'none'; return; }
    toggle.style.display = 'flex';
    if (!panel.hasAttribute('data-dsh-settings-nav')) panel.setAttribute('data-dsh-settings-nav', 'collapsed');
  }
  function boot() {
    sync();
    var mo = new MutationObserver(function () { sync(); });
    mo.observe(document.body, { childList: true, subtree: true });
    window.addEventListener('resize', sync);
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();
</script>`

/**
 * Client script that renames the browser tab to a custom brand. dsh's own
 * DocumentTitle projection (dsh-client-ui-renderer) writes the product title
 * ("DeepSeek Harness") into document.title — bare, and as the
 * "<session> — DeepSeek Harness" suffix — with the string hardcoded in its
 * client bundle. Rewriting only the static <title> in index.html is therefore
 * immediately overwritten by the client; intercepting the document.title
 * setter replaces every occurrence in one hook, covering the no-session,
 * session-suffix and restore paths alike.
 *
 * The brand is JSON-escaped (every `<` turned into \u003c) so arbitrary admin
 * input can never escape the string literal or terminate the script tag.
 * @param brand - the replacement brand; must already be non-empty.
 */
export function titleBrandScript(brand: string): string {
  const literal = JSON.stringify(brand)
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029')
    .replace(/</g, '\\u003c')
  return `<script>
(function () {
  var brand = ${literal};
  if (!brand) return;
  if (typeof Document !== 'function') return;
  try {
    var desc = Object.getOwnPropertyDescriptor(Document.prototype, 'title');
    if (!desc || typeof desc.set !== 'function') return;
    Object.defineProperty(document, 'title', {
      configurable: true,
      enumerable: desc.enumerable,
      get: function () { return desc.get.call(document); },
      set: function (value) { desc.set.call(document, String(value).split('DeepSeek Harness').join(brand)); }
    });
  } catch (err) { /* keep the default title on failure */ }
})();
</script>`
}

/**
 * Build an SVG data URI usable as a favicon `<link rel="icon" href=...>` or a
 * PWA-manifest icon src.
 */
function svgDataUri(svg: string): string {
  return 'data:image/svg+xml,' + encodeURIComponent(svg.trim())
}

/** Fallback brand mark when no icon is configured: the Copilot four-pointed sparkle. */
const DEFAULT_BRAND_SPARKLE = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 18" fill="currentColor"><path d="M12 0.5C14.8 3.2 17.2 6 23.2 9C17.2 12 14.8 14.8 12 17.5C9.2 14.8 6.8 12 0.8 9C6.8 6 9.2 3.2 12 0.5Z"/></svg>`

/** Minimal logger surface used by the icon resolver (kept structural for tests). */
interface DebugLogger { warn(message: string): void }

/**
 * Resolve the configured brand icon to its SVG source: inline SVG first, else a
 * host SVG file read at serve time, else the built-in sparkle. Never throws.
 */
function resolveBrandIcon(brand: BrandResolved, logger: DebugLogger): string {
  const inline = brand.icon.inline.trim()
  if (inline) return inline
  const file = brand.icon.file.trim()
  if (file) {
    try {
      return readFileSync(file, 'utf8')
    } catch (err) {
      logger.warn(`dsh-auth-proxy: brand icon file unreadable (${file}) — falling back to the sparkle: ${String(err)}`)
    }
  }
  return DEFAULT_BRAND_SPARKLE
}

/**
 * Rewrite a forwarded PWA manifest: name/short_name to the brand title and the
 * icons list to the configured/ default brand SVG. Non-JSON bodies pass through.
 */
export function rewriteManifest(body: string, brand: BrandResolved, logger: DebugLogger): string {
  try {
    const manifest: Record<string, unknown> = JSON.parse(body)
    if (manifest === null || typeof manifest !== 'object' || Array.isArray(manifest)) return body
    if (brand.title) {
      manifest.name = brand.title
      manifest.short_name = brand.title.length > 63 ? brand.title.slice(0, 62) : brand.title
    }
    if (brand.enabled) {
      const icon = svgDataUri(resolveBrandIcon(brand, logger))
      manifest.icons = [
        { src: icon, sizes: 'any', type: 'image/svg+xml', purpose: 'any' },
        { src: icon, sizes: '512x512', type: 'image/svg+xml', purpose: 'maskable' },
      ]
    }
    return JSON.stringify(manifest)
  } catch {
    return body
  }
}

/**
 * Client script (proxy-injected, no new client graph entry) that makes the
 * Copilot brand the rendered winner in the sidebar and hero. It wraps the graph-
 * resident `@deepseek-ai/dsh-client-ui-brand-official` bundle (the same
 * presentational-rewrite technique as {\@link LOOPBACK_COMPAT_SCRIPT}): after
 * that plugin's apply runs — so its ctx already carries the `slots` service — it
 * registers our Copilot mark / wordmark / hero occupants at priority -1, which
 * single slots elect ahead of the official 0. Pure rewrite, proxy-only.
 * The wordmark is JSON-escaped (every < -> \\u003c) so admin input can never
 * break out of the string literal or terminate the script tag.
 */
export function brandVisualScript(wordmark: string): string {
  const literal = JSON.stringify(wordmark)
    .replace(/</g, '\\u003c')
  return `<script>
(function () {
  var BRAND_ID = "@deepseek-ai/dsh-client-ui-brand-official";
  var WORDMARK = ${literal};
  var wrapFactory = function (factory) {
    return function (require) {
      var mod = factory(require);
      if (mod && typeof mod.apply === "function") {
        var originalApply = mod.apply;
        mod.apply = function (ctx) {
          var result = originalApply.apply(this, arguments);
          try {
            var f = require("react/jsx-runtime");
            function CopilotSparkle(props) {
              var size = props && props.size || 24;
              return f.jsx("svg", {
                width: size, height: size * 18 / 24, className: props && props.className,
                viewBox: "0 0 24 18", fill: "none", "aria-hidden": "true",
                children: f.jsx("path", { d: "M12 0.5C14.8 3.2 17.2 6 23.2 9C17.2 12 14.8 14.8 12 17.5C9.2 14.8 6.8 12 0.8 9C6.8 6 9.2 3.2 12 0.5Z", fill: "currentColor" })
              });
            }
            function CopilotWordmark(props) {
              return f.jsx("span", {
                className: props && props.className,
                style: { fontFamily: "var(--ds-font-family-code, ui-monospace, SFMono-Regular, monospace)", letterSpacing: "0.02em", whiteSpace: "nowrap", userSelect: "none" },
                children: WORDMARK
              });
            }
            var PRIORITY = -1;
            if (ctx.slots && typeof ctx.slots.inject === "function") {
              ctx.slots.inject("sidebar.brand.mark", function () { return ctx.slots.register({ name: "sidebar.brand.mark", priority: PRIORITY }, CopilotSparkle); });
              ctx.slots.inject("sidebar.brand.name", function () { return ctx.slots.register({ name: "sidebar.brand.name", priority: PRIORITY }, CopilotWordmark); });
              ctx.slots.inject("conversation.hero.brand.mark", function () { return ctx.slots.register({ name: "conversation.hero.brand.mark", priority: PRIORITY }, CopilotSparkle); });
            }
          } catch (err) { /* brand visuals are cosmetic; swallow */ }
          return result;
        };
      }
      return mod;
    };
  };
  var wrapLoad = function (load) {
    return function (registration) {
      if (registration && typeof registration === "object"
          && registration.id === BRAND_ID
          && typeof registration.factory === "function") {
        registration.factory = wrapFactory(registration.factory);
      }
      return load.apply(this, arguments);
    };
  };
  var wrapCreate = function (create) {
    return function (options) {
      var result = create.call(this, options);
      if (this && typeof this.load === "function") this.load = wrapLoad(this.load);
      return result;
    };
  };
  try {
    var existing = globalThis.__ModuleLoader__;
    if (existing && typeof existing.load === "function") {
      existing.load = wrapLoad(existing.load);
      if (typeof existing.create === "function") existing.create = wrapCreate(existing.create);
      return;
    }
    var realLoader = undefined;
    var installed = false;
    Object.defineProperty(globalThis, "__ModuleLoader__", {
      configurable: true, enumerable: true,
      get: function () { return realLoader; },
      set: function (loader) {
        if (!loader || typeof loader.load !== "function") return;
        if (installed) { realLoader = loader; return; }
        installed = true;
        realLoader = loader;
        loader.load = wrapLoad(loader.load);
        if (typeof loader.create === "function") loader.create = wrapCreate(loader.create);
      }
    });
  } catch (err) { /* keep the default brand on failure */ }
})();
</script>`
}

/** Escape user-supplied text before interpolating it into the login page HTML. */
function htmlEscape(value: string): string {
  return value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
}

/**
 * Shared HTML decoration for forwarded pages: brand <title> rewrite, the UUID
 * polyfill + loopback-compat scripts, brand title/logo scripts and the favicon
 * link swap — all injected before `</head>`. Used by both the normal forward
 * path and the 401-gate retry path so branding applies on the first load too.
 */
function decorateHtml(body: string, brand: BrandResolved, logger: DebugLogger, trustedOrigins: string[] = []): string {
  // Rename the static <title> so the pre-client frame shows the brand (the
  // upstream may carry any hardcoded product title, e.g. "DeepSeek Harness" or
  // a brand plugin's "Copilot Harness"); the injected setter override keeps
  // document.title branded once the React title projection engages.
  if (brand.enabled && brand.title) {
    body = body.replace(/<title>([^<]*)<\/title>/i, () => `<title>${htmlEscape(brand.title)}</title>`)
  }
  if (body.includes('</head>')) {
    const injections = [`${UUID_POLYFILL}\n${loopbackCompatScript(trustedOrigins)}\n${MOBILE_SETTINGS_NAV_FIX}`]
    if (brand.enabled && brand.title) injections.push(titleBrandScript(brand.title))
    // Copilot sidebar/hero visual occupants (wraps the official brand graph entry).
    if (brand.enabled && brand.logo) injections.push(brandVisualScript(brand.wordmark || 'Copilot'))
    // Favicon: replace the upstream stock icon link with the brand SVG.
    if (brand.enabled) {
      const iconHref = svgDataUri(resolveBrandIcon(brand, logger))
      if (/<link[^>]*rel=["']?icon["']?[^>]*>/i.test(body)) {
        body = body.replace(/<link[^>]*rel=["']?icon["']?[^>]*>/i, `<link rel="icon" type="image/svg+xml" href="${iconHref}" />`)
      } else {
        injections.push(`<link rel="icon" type="image/svg+xml" href="${iconHref}" />`)
      }
    }
    body = body.replace('</head>', `${injections.join('\n')}\n</head>`)
  }
  return body
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
/**
 * Strip the web-all remote-web-ui client's `/remote` gate prefix from a
 * request URL. The client (bundled inside web-all/client.js, inseparable)
 * rewrites `/api/*`, `/sidebar/*`, `/git/*`, `/pet/*` onto a `/remote`
 * mirror whenever the page origin is non-loopback — which is always true
 * behind this proxy. The plugin's host half stays disabled here (pairing
 * is not used, token auth only), so no `/remote` mirror route exists
 * upstream; rewriting back to the original path keeps RPC/stream endpoints
 * reachable. A request that is not on the `/remote` gate is untouched.
 */
function stripRemoteGatePrefix(raw: string): string {
  if (!raw.startsWith('/remote')) return raw
  const rest = raw.slice('/remote'.length)
  if (rest === '' || rest.startsWith('/')) return rest === '' ? '/' : rest
  // `/remotefoo/...` is not the gate; leave untouched.
  return raw
}

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

// ── upstream (dsh web) browser-token auth auto-exchange ──────────────
// DSH 0.1.2-alpha.x enables a per-process launch-token gate on the Host index
// (browser-auth, constant-on, no disable switch). The token is printed to the
// dsh web process stdout as `dsh web: http://127.0.0.1:<port>/?token=<t>` and
// lives only in that process. The launch-token cookie is authority-bound (the
// proxy rewrites Host to targetHost:targetPort, so the authority is stable), not
// browser-bound — an exchanged cookie is therefore reusable for every client.
// This module performs the exchange server-side (auto-consume 303 + Set-Cookie)
// and replays the client's request with the cookie, so remote users never see
// the `dsh web authentication required` 401.

interface UpstreamAuthState {
  /** Exchanged `dsh-auth-<authority>` cookie value, reused until invalidated. */
  cookie: string | undefined
  /** stdout log path we last read the token from. */
  lastLogPath: string | undefined
  /** Number of bytes at last successful read (detect dsh-web restart/new token). */
  lastLogSize: number
  /** Monotonic guard against concurrent exchanges. */
  exchanging: boolean
}

const upstreamAuth: UpstreamAuthState = {
  cookie: undefined,
  lastLogPath: undefined,
  lastLogSize: 0,
  exchanging: false,
}

const UPSTREAM_AUTH_401_BODY = 'dsh web authentication required'
const SUPERVIISORD_LOG_DIR = process.env.DSH_AUTH_PROXY_LOG_DIR
  ?? 'C:/tools/home/supervisord/logs'
const DSH_WEB_STDOUT_FILE = process.env.DSH_AUTH_PROXY_STDOUT_LOG
  ?? `${SUPERVIISORD_LOG_DIR}/dsh-web-stdout.log`

/**
 * Extract the newest `token=` value from the dsh web stdout log. Returns
 * undefined when the log is unreadable or carries no launch URL yet.
 */
function readLaunchToken(): string | undefined {
  try {
    const text = readFileSync(DSH_WEB_STDOUT_FILE, 'utf8')
    const match = [...text.matchAll(/dsh web: http:\/\/[^\s]+\?token=([A-Za-z0-9_-]+)/g)]
    if (match.length === 0) return undefined
    const last = match[match.length - 1]
    // Track size so a later dsh-web restart (superseding token) is caught.
    upstreamAuth.lastLogSize = Buffer.byteLength(text)
    return last[1] ?? undefined
  } catch {
    return undefined
  }
}

/**
 * Perform the launch-token exchange against the loopback target and store the
 * issued cookie. Replaces the guard's own Set-Cookie response (303) with the
 * cookie value for reuse. Idempotent per dsh-web activation; a failure clears
 * the cached cookie so the next 401 triggers a retry.
 */
async function exchangeUpstreamToken(
  targetHost: string,
  targetPort: number,
  logger: { warn?: (msg: string) => void },
): Promise<boolean> {
  if (upstreamAuth.exchanging) return false
  const token = readLaunchToken()
  if (token === undefined) return false
  upstreamAuth.exchanging = true
  try {
    const cookie = await new Promise<string | undefined>((resolveP, rejectP) => {
      const target = `http://${targetHost}:${targetPort}/?token=${token}`
      const headers = { host: `${targetHost}:${targetPort}` }
      const req = httpRequest(target, {
        method: 'GET',
        headers,
        timeout: 5000,
      }, (upstream) => {
        upstream.on('data', () => {})
        upstream.on('end', () => {
          const setCookie = upstream.headers['set-cookie']
          if (setCookie === undefined) { rejectP(new Error('no set-cookie from exchange')); return }
          const list = Array.isArray(setCookie) ? setCookie : [setCookie]
          const authCookie = list.find((c) => c.toLowerCase().startsWith('dsh-auth-'))
          if (authCookie === undefined) { rejectP(new Error('no dsh-auth cookie')); return }
          resolveP(authCookie)
        })
      })
      req.on('error', (err) => rejectP(err))
      req.on('timeout', () => {
        req.destroy(new Error('exchange timeout'))
        rejectP(new Error('exchange timeout'))
      })
      req.end()
    })
    upstreamAuth.cookie = cookie
    upstreamAuth.exchanging = false
    return cookie !== undefined
  } catch (err) {
    logger.warn?.(`dsh-auth-proxy: upstream token exchange failed ${String(err)}`)
    upstreamAuth.exchanging = false
    upstreamAuth.cookie = undefined
    return false
  }
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
  brand: {
    enabled: false,
    title: '',
    wordmark: 'Copilot',
    logo: false,
    icon: { inline: '', file: '' },
  },
  allowedIps: [],
  accessUrls: [],
  maxFailures: 0,
  lockoutMinutes: 15,
}

/**
 * Mount the auth proxy. Configuration resolves as: dsh-settings scope (or the
 * composition entry when no settings service is present) is the single
 * resolution — the settings scope layers schema defaults, the composition
 * entry (base), and the user-document section persisted by the deployment's
 * settings provider.
 * @param ctx - host plugin context.
 * @param config - resolved plugin config.
 */
export function apply(ctx: Context, config?: Config): void {
  /**
   * The config source: the dsh-settings scope while one is attached
   * (installSettingsSection re-points this), otherwise the composition entry.
   */
  let base: () => Config = () => (config ?? {}) as Config
  /** Single resolution: the current base source. */
  const resolve: () => Resolved = () => {
    const value = base()
    // Legacy `brandTitle` (flat) maps onto `brand.title` when the nested brand
    // layer leaves it empty — old profile patches keep working unchanged.
    const legacyTitle = (value.brandTitle ?? '').trim()
    const brandInput = value.brand ?? {}
    const brandEnabled = brandInput.enabled ?? (legacyTitle !== '' ? true : DEFAULTS.brand.enabled)
    const brandTitle = brandInput.title ?? (legacyTitle !== '' ? legacyTitle : DEFAULTS.brand.title)
    return {
      enabled: value.enabled ?? DEFAULTS.enabled,
      host: value.host ?? DEFAULTS.host,
      port: value.port ?? DEFAULTS.port,
      targetHost: value.targetHost ?? DEFAULTS.targetHost,
      targetPort: value.targetPort ?? DEFAULTS.targetPort,
      token: value.token ?? DEFAULTS.token,
      banner: value.banner ?? DEFAULTS.banner,
      brand: {
        enabled: brandEnabled,
        title: brandTitle,
        wordmark: brandInput.wordmark ?? DEFAULTS.brand.wordmark,
        logo: brandInput.logo ?? DEFAULTS.brand.logo,
        icon: {
          inline: brandInput.icon?.inline ?? DEFAULTS.brand.icon.inline,
          file: brandInput.icon?.file ?? DEFAULTS.brand.icon.file,
        },
      },
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
  /** Pre-warm retry timer for the upstream launch-token exchange. */
  let warmTimer: ReturnType<typeof setTimeout> | undefined

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
    if (warmTimer !== undefined) {
      clearTimeout(warmTimer)
      warmTimer = undefined
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
      // We always respond uncompressed (upstream was asked for identity); never
      // advertise an encoding we did not actually apply.
      delete out['content-encoding']
      if (out['content-length'] !== undefined) out['content-length'] = String(bodyLen)
      res.writeHead(200, out)
    }

    /**
     * Strip any content-encoding from an upsream response header set before
     * relaying to the client (used on the non-HTML pass-through, whose body is
     * piped untouched — so it must not promise an encoding nodover). Since we
     * always ask upstream for identity, this is defensive.
     */
    const strippedHeaders = (headers: Record<string, string | string[] | number | undefined>): Record<string, string | string[] | number | undefined> => {
      const out = { ...headers }
      delete out['content-encoding']
      delete out['transfer-encoding']
      return out
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
      // Strip the web-all remote-web-ui client's `/remote` gate prefix (the
      // client rewrites `/api/*` → `/remote/api/*` whenever the page origin is
      // non-loopback, which is always true behind this proxy). The plugin's
      // host half stays disabled (pairing is not used), so no `/remote` mirror
      // route exists upstream — rewriting back to the original path keeps the
      // RPC/stream endpoints reachable.
      const targetUrl = `http://${live.targetHost}:${live.targetPort}${stripRemoteGatePrefix(req.url ?? '/')}`
      const headers = { ...req.headers }
      headers.host = `${live.targetHost}:${live.targetPort}`
      if (headers.origin) headers.origin = `http://${live.targetHost}:${live.targetPort}`
      // Force upstream to reply uncompressed: the proxy buffers and rewrites HTML
      // bodies (`</head>` injection, brand), and has no decompressor — passing a
      // browser's Accept-Encoding through yields gzip bytes that get mutilated
      // and then mislabeled `content-encoding: gzip`, crashing the browser with
      // ERR_CONTENT_DECODING_FAILED (blank page). Respond to the client still
      // allowing compression only if we ever actually compress; today we do not.
      delete headers['accept-encoding']
      headers['accept-encoding'] = 'identity'
      // Attach the upstream launch-token cookie to every forward by MERGING it into
      // whatever the client sent — a logged-in browser always carries its own proxy-
      // session cookie (`dsh_auth_session`), so requiring an empty Cookie header
      // meant the upstream `dsh-auth-*` cookie was never attached after login
      // (every /api/* -> 401, manifest returned the 401 text, and HTML always
      // fell down the un-decorated retry branch so the brand rewrite never ran).
      if (upstreamAuth.cookie !== undefined) {
        const authName = upstreamAuth.cookie.split(';')[0].split('=')[0]
        const existing = headers.cookie
        const already = existing !== undefined && existing
          .split(';').some((c) => c.trim().startsWith(authName + '='))
        if (!already) {
          headers.cookie = existing ? `${existing}; ${upstreamAuth.cookie}` : upstreamAuth.cookie
        }
      }
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
        const pathname = new URL(req.url ?? '/', 'http://x').pathname
        const isHtml = contentType.toLowerCase().includes('text/html')
        const isManifest = contentType.toLowerCase().includes('manifest') || /\.(?:web)?manifest$/i.test(pathname)
        // DSH 0.1.2-alpha.x browser-token gate answers the HTML index with a
        // text/plain 401 `dsh web authentication required...`. Intercept ANY
        // such 401 on the root path (regardless of client Accept — real browsers
        // always send text/html, but a bare curl/reloader must not leak the
        // gate), swap the launch token server-side and replay with the cookie
        // so remote users never see the gate. `/api/*` and other paths keep
        // their own status codes and pass through untouched.
        const isUpstreamAuth401 = (upstream.statusCode ?? 0) === 401
          && pathname === '/'
          && !isManifest
        if (!isHtml && !isManifest && !isUpstreamAuth401) {
          res.writeHead(upstream.statusCode ?? 502, upstream.statusMessage, strippedHeaders(upstream.headers as Record<string, string | string[] | number | undefined>))
          upstream.pipe(res)
          return
        }
        // Buffer HTML (inject polyfills/brand before </head>) and PWA manifests
        // (rewrite name/icons) so we can edit the body before forwarding.
        const chunks: Buffer[] = []
        upstream.on('data', (c: Buffer) => chunks.push(c))
        upstream.on('end', () => {
          let body = Buffer.concat(chunks).toString('utf8')
          // DSH 0.1.2-alpha.x browser-token gate: the Host index answers 401
          // `dsh web authentication required...` (no session cookie). Swap the
          // launch token server-side and replay this navigation with the cookie
          // so the remote client never sees the gate. Only page navigations are
          // intercepted (the gate only gates the HTML index; API/WS keep their
          // own status codes, which the non-HTML branch already passes through).
          if (
            isUpstreamAuth401
            && body.includes(UPSTREAM_AUTH_401_BODY)
          ) {
            const exchange = async (): Promise<void> => {
              if (upstreamAuth.cookie === undefined) {
                await exchangeUpstreamToken(live.targetHost, live.targetPort, ctx.logger)
              }
              if (upstreamAuth.cookie === undefined) {
                // Still no cookie: surface the gate honestly instead of a loop.
                res.writeHead(401, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' })
                res.end(`${UPSTREAM_AUTH_401_BODY}; retry after dsh-web prints a launch URL.\n`)
                return
              }
              const retryHeaders = { ...req.headers }
              delete retryHeaders['cookie']
              retryHeaders.cookie = upstreamAuth.cookie
              retryHeaders.host = `${live.targetHost}:${live.targetPort}`
              delete retryHeaders['accept-encoding']
              retryHeaders['accept-encoding'] = 'identity'
              const retry = httpRequest(targetUrl, { method: req.method, headers: retryHeaders }, (retryUpstream) => {
                const retryChunks: Buffer[] = []
                retryUpstream.on('data', (c: Buffer) => retryChunks.push(c))
                retryUpstream.on('end', () => {
                  const retryBody = Buffer.concat(retryChunks).toString('utf8')
                  const retryHeadersOut = { ...retryUpstream.headers } as Record<string, string | string[] | number | undefined>
                  if ((retryUpstream.statusCode ?? 0) === 401) {                    // The cookie expired between reads (dsh-web restarted): clear and retry once more.
                    upstreamAuth.cookie = undefined
                    exchangeUpstreamToken(live.targetHost, live.targetPort, ctx.logger)
                      .then((ok) => {
                        if (!ok || upstreamAuth.cookie === undefined) {
                          res.writeHead(401, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' })
                          res.end(`${UPSTREAM_AUTH_401_BODY}; retry after dsh-web prints a launch URL.\n`)
                          return
                        }
                        retryHeaders.cookie = upstreamAuth.cookie
                        const retry2 = httpRequest(targetUrl, { method: req.method, headers: retryHeaders }, (r2) => {
                          const r2Chunks: Buffer[] = []
                          r2.on('data', (c: Buffer) => r2Chunks.push(c))
                          r2.on('end', () => {
                            const r2Headers = { ...r2.headers } as Record<string, string | string[] | number | undefined>
                            const r2Body = Buffer.concat(r2Chunks).toString('utf8')
                            const out2 = decorateHtml(r2Body, live.brand, ctx.logger, live.accessUrls)
                            const outBuf2 = Buffer.from(out2, 'utf8')
                            fixLength(res, r2Headers, outBuf2.length)
                            res.end(outBuf2)
                          })
                        })
                        retry2.on('error', () => res.destroy())
                        retry2.end()
                      })
                      .catch(() => {
                        res.writeHead(502)
                        res.end('upstream unavailable')
                      })
                    return
                  }
                  const outBody = decorateHtml(retryBody, live.brand, ctx.logger, live.accessUrls)
                  const outBuf = Buffer.from(outBody, 'utf8')
                  fixLength(res, retryHeadersOut, outBuf.length)
                  res.end(outBuf)
                })
                retryUpstream.on('error', () => res.destroy())
              })
              retry.on('error', (err) => {
                ctx.logger.warn(`dsh-auth-proxy: upstream retry error ${String(err)}`)
                if (!res.headersSent) {
                  res.writeHead(502)
                  res.end('upstream unavailable')
                } else {
                  res.destroy()
                }
              })
              retry.end()
            }
            exchange().catch((err) => {
              ctx.logger.warn(`dsh-auth-proxy: exchange handler error ${String(err)}`)
              if (!res.headersSent) {
                res.writeHead(502)
                res.end('proxy exchange error')
              } else {
                res.destroy()
              }
            })
            return
          }
          const brand = live.brand
          if (isManifest) {
            body = rewriteManifest(body, brand, ctx.logger)
          } else {
            body = decorateHtml(body, brand, ctx.logger, live.accessUrls)
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
      // Pre-warm the upstream launch-token exchange as early as possible
      // (see warmUpstreamExchange below).
      warmUpstreamExchange()
    })

    server = srv
    // Fiber unload must cut immediately; rebuilds use the graceful path in
    // teardownServer, leaving this disposer's force-close as the backstop.
    disposeServer = ctx.effect(() => () => teardownServer(false), 'dsh-auth-proxy: server')

    /**
     * Exchange the upstream launch token shortly after the proxy starts
     * listening, so the first browser navigation never trips the lazy
     * 401-swap race (fresh dsh-web restart invalidates the previous cookie;
     * the exchange is idle until a request hits the 401). dsh web prints its
     * per-process launch URL to the stdout log shortly after boot, so an
     * immediate read may find nothing yet — retry briefly, then give up
     * quietly: the lazy swap on the first real 401 stays as the fallback.
     */
    const warmUpstreamExchange = (remaining = 15, delayMs = 2000): void => {
      if (upstreamAuth.cookie !== undefined) return
      exchangeUpstreamToken(live.targetHost, live.targetPort, ctx.logger)
        .then((done) => {
          if (done) {
            say('upstream launch-token exchange pre-warmed')
            return
          }
          if (remaining <= 0) {
            ctx.logger.info('dsh-auth-proxy: pre-warm gave up; lazy 401 swap will cover the first request')
            return
          }
          warmTimer = setTimeout(() => warmUpstreamExchange(remaining - 1, delayMs), delayMs)
          warmTimer.unref()
        })
        .catch(() => {
          if (remaining > 0) {
            warmTimer = setTimeout(() => warmUpstreamExchange(remaining - 1, delayMs), delayMs)
            warmTimer.unref()
          }
        })
    }
  }

  /** Forward a WebSocket upgrade, rewriting host/origin for the trust fence. */
  function doUpgrade(req: IncomingMessage, socket: Duplex, head: Buffer): void {
    if (req.headers.host) req.headers.host = `${live.targetHost}:${live.targetPort}`
    if (req.headers.origin) req.headers.origin = `http://${live.targetHost}:${live.targetPort}`
    delete req.headers['x-forwarded-for']
    delete req.headers['x-real-ip']
    // The upstream launch-token cookie must ride along on the WS handshake too;
    // merge instead of requiring an empty Cookie header (same rationale as forward()).
    if (upstreamAuth.cookie !== undefined) {
      const authName = upstreamAuth.cookie.split(';')[0].split('=')[0]
      const existing = req.headers.cookie
      const already = existing !== undefined && existing
        .split(';').some((c) => c.trim().startsWith(authName + '='))
      if (!already) {
        req.headers.cookie = existing ? `${existing}; ${upstreamAuth.cookie}` : upstreamAuth.cookie
      }
    }
    const targetUrl = `http://${live.targetHost}:${live.targetPort}${stripRemoteGatePrefix(req.url ?? '/')}`
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

  // The dsh-settings scope (when present) is the single config source: the
  // settings provider persists a per-namespace user document, the composition
  // entry is the `base` layer, and the registered scope resolves the three.
  // installSection keeps the plugin working when no settings service is
  // composed (falls back to the composition entry).
  //
  // The `validate` hook is the write gate that _rejects_ a stored section the
  // plugin could not act on — the guard rails no schema can express. This is
  // where the listen-host policy and the token-placeholder refusal live, exactly as
  // the settings Service Definition intends: the Host is the only authority on
  // whether a write landed.
  ctx.inject(['settings'], (settingsCtx) => {
    settingsCtx.settings.installSection(ctx, AUTH_SETTINGS_NAMESPACE, Config, config ?? ({} as Config), {
      setSource: (source) => {
        base = source
        sync()
      },
      onChange: sync,
      validate: (value) => {
        const v = { ...DEFAULTS, ...(value as Partial<Config>) }
        // A placeholder/empty token is a LEGAL stored value — the proxy simply stays
        // disabled — so only the listen-host policy is a hard rejection (no TLS).
        const hostIssue = listenHostIssue(v.host ?? DEFAULTS.host)
        if (hostIssue) throw new Error(hostIssue)
      },
    })
  })

  // ── read-only runtime status (the write path is the dsh-settings scope) ──
  // Serves only introspection facts the settings section does not carry — whether
  // the socket is up and whether a real token is configured (the token value, a
  // schema secret, never rides a response). Mutations flow exclusively through the
  // settings scope above.
  const statusRoute = {
    kind: 'exact' as const,
    path: '/api/dsh-auth-proxy/status',
    handler: async (_req: IncomingMessage, res: ServerResponse): Promise<void> => {
      const effective = resolve()
      res.writeHead(200, { 'content-type': 'application/json; charset=utf-8' })
      res.end(JSON.stringify({
        enabled: effective.enabled,
        port: effective.port,
        listening: serverUp,
        tokenSet: tokenConfigured(effective.token),
        accessUrls: effective.accessUrls,
      }))
    },
  }
  ctx.inject(['webServer'], (wctx) => {
    wctx.effect(() => wctx.webServer.register(statusRoute), 'dsh-auth-proxy: status api')
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
