/**
 * dsh-auth-proxy — browser half. Runs inside the dsh web GUI.
 *
 * Renders the plugin configuration card into the Settings > Plugins >
 * configurable-plugins tab, keyed by the settings namespace this package
 * owns. The card reads and writes through `ctx.settingsScope`, the official
 * dsh-settings transport: field writes are revision-fenced document mutations
 * validated and persisted by the Host (and its settings provider). There is no
 * bespoke config API — the only extra route is a read-only runtime status probe.
 */

import type { ClientContext } from '@deepseek-ai/dsh-client-runtime/client'
import type { SettingsScope, SettingsScopeSnapshot } from '@deepseek-ai/dsh-client-runtime/client'
import type {} from '@deepseek-ai/dsh-client-locale/client'
import type {} from '@deepseek-ai/dsh-client-ui-slots'
import type {} from '@deepseek-ai/dsh-client-ui-settings/client'
import type {} from '@deepseek-ai/dsh-client-ui-settings-plugins/client'
import { AuthProxySettingsCard, type AuthProxyCardProps } from './AuthProxySettingsCard.tsx'
import { en, zh, type AuthProxyKey } from './locales.ts'

/** Locale namespace this plugin owns. */
const NS = 'auth-proxy'

/**
 * The editable section this card stages over the `dsh-auth-proxy` settings
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
    /** Auth proxy card copy. */
    'auth-proxy': AuthProxyKey
  }
}

/**
 * The registrar-side business face the card's slot entry injects: the bound
 * scope plus a sync snapshot selector for the card's form.
 */
export interface AuthProxyCardFace {
  /** Reactive handle over the `dsh-auth-proxy` namespace section. */
  scope: SettingsScope<AuthProxySection>
  /** Sync snapshot source for the card's form (uSES getSnapshot). */
  getSnapshot: () => SettingsScopeSnapshot<AuthProxySection>
}

/** Required services (fiber inject waiting — the settings transport is up first). */
export const inject = ['slots', 'locale', 'settingsScope', 'connection', 'remote']

/**
 * Mount the auth-proxy configuration card.
 * @param ctx - client root context.
 */
export function apply(ctx: ClientContext): void {
  ctx.effect(() => ctx.locale.register(NS, { zh, en }), 'auth-proxy: dictionaries')

  // Bind the settings scope for this namespace on this plugin's fiber. The binder
  // resolves the transport and subscribes invalidation on OUR lifecycle; the
  // consumer injects `connection` (transport) and `remote` (forwarded invalidation).
  const scope = ctx.settingsScope.bind<AuthProxySection>({ namespace: 'dsh-auth-proxy' })
  const face: AuthProxyCardFace = {
    scope,
    getSnapshot: () => scope.getSnapshot(),
  }

  // Register the card into the configurable-plugins tab, keyed by the namespace
  // it edits — the pairing the official tab performs without learning what the
  // namespace means. The business face arrives through the slot `inject` factory;
  // the locale `t` seat arrives from the slot runtime.
  const slots = ctx.slots as unknown as {
    inject: (key: string, cb: () => unknown) => unknown
    register: (opts: unknown, component: unknown) => unknown
  }
  slots.inject('settings.plugin.item', () =>
    slots.register(
      { name: 'settings.plugin.item', key: 'dsh-auth-proxy', locale: NS, inject: () => face },
      AuthProxySettingsCard as unknown,
    ),
  )
}

/** Type-only re-export of the card props for consumers who need the shape. */
export type { AuthProxyCardProps }
