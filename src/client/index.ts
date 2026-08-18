/**
 * dsh-auth-proxy — browser half. Runs inside the dsh web GUI.
 *
 * Registers the auth-proxy configuration as its OWN settings section (a
 * `settings.section` row, e.g. an entry alongside Models/General), not a card
 * tucked inside the configurable-plugins tab, so the config gets a full-content
 * settings page. The page reads and writes through `ctx.settingsScope`, the official
 * dsh-settings transport: field writes are revision-fenced document mutations
 * validated and persisted by the Host (and its settings provider). There is no
 * bespoke config API — the only extra route is a read-only runtime status probe.
 */

import type { ClientContext } from '@deepseek-ai/dsh-client-runtime/client'
import type { SettingsScope, SettingsScopeSnapshot } from '@deepseek-ai/dsh-client-runtime/client'
import type {} from '@deepseek-ai/dsh-client-locale/client'
import type {} from '@deepseek-ai/dsh-client-ui-slots'
import type {} from '@deepseek-ai/dsh-client-ui-settings/client'
import { AuthProxySettingsCard, type AuthProxyCardFace } from './AuthProxySettingsCard.tsx'
import { en, zh, type AuthProxyKey } from './locales.ts'

/** Locale namespace this plugin owns. */
const NS = 'auth-proxy'

/**
 * The editable section this page stages over the `dsh-auth-proxy` settings
 * namespace (mirrors the Host Config schema; the token is a write-only secret
 * and is never seeded from a response).
 */
export interface AuthProxySection {
  enabled?: boolean
  host?: string
  port?: number
  targetHost?: string
  targetPort?: number
  banner?: string
  allowedIps?: string[]
  accessUrls?: string[]
  maxFailures?: number
  lockoutMinutes?: number
  token?: string
}

declare module '@deepseek-ai/dsh-client-ui-slots' {
  interface LocaleNamespaceMap {
    /** Auth-proxy settings page copy. */
    'auth-proxy': AuthProxyKey
  }
}

/** Required services (fiber inject waiting — the settings transport is up first). */
export const inject = ['slots', 'locale', 'settingsScope', 'connection', 'remote']

/**
 * Mount the auth-proxy settings page.
 * @param ctx - client root context.
 */
export function apply(ctx: ClientContext): void {
  ctx.effect(() => ctx.locale.register(NS, { zh, en }), 'auth-proxy: dictionaries')

  // The slot registry types are opaque to a third-party package; keep the surface
  // loose and type the options down to what the settings slot observes. The label is
  // a THUNK the shell re-reads on every nav projection (its nav cache is keyed on
  // the locale revision), so localized text follows the active locale without any
  // locale/change re-registration.
  const slots = ctx.slots as unknown as {
    inject: (
      name: 'settings.section',
      register: () => unknown,
    ) => unknown
    register: (opts: {
      name: 'settings.section'
      id: string
      order: number
      label: () => string
      locale: string
      inject: () => AuthProxyCardFace
    }, component: unknown) => unknown
  }

  // The settings nav label is registrant-supplied, localized copy; the bind gives a
  // stable translate for the active locale so we can name our section consistently.
  const t = ctx.locale.bind(NS) as (key: AuthProxyKey) => string

  // Bind the settings scope for this namespace on this plugin's fiber. The binder
  // resolves the transport and subscribes invalidation on OUR lifecycle; the
  // consumer injects `connection` (transport) and `remote` (forwarded invalidation).
  const scope = ctx.settingsScope.bind<AuthProxySection>({ namespace: 'dsh-auth-proxy' })
  const face: AuthProxyCardFace = {
    scope,
    getSnapshot: () => scope.getSnapshot(),
  }

  // Register the section through `slots.inject`, which defers until the
  // `settings.section` declaration is on the ledger (it is declared by the
  // settings shell's `sidebar.settings` parent entry). Registering a slot before
  // it is declared throws; `inject` reconciles and installs the effect the moment
  // the declaration exists, independent of load order.
  slots.inject('settings.section', () =>
    slots.register(
      {
        name: 'settings.section',
        id: 'dsh-auth-proxy',
        order: 300,
        label: () => t('title'),
        locale: NS,
        inject: () => face,
      },
      AuthProxySettingsCard as unknown,
    ),
  )
}
