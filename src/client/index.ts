/**
 * dsh-auth-proxy — browser half. Runs inside the dsh web GUI.
 *
 * Renders the plugin configuration card into the Settings > Plugin config
 * section. The card talks to the plugin's own /api/dsh-auth-proxy/config
 * route (not the dsh-settings seam, whose exposed-namespace whitelist is
 * hard-coded and closed to third-party plugins), so port, token, IP
 * allowlist and lockout policy are editable live from the GUI.
 */

import type { ClientContext } from '@deepseek-ai/dsh-client-runtime/client'
// Type-only: pulls the locale plugin's Context merge (ctx.locale).
import type {} from '@deepseek-ai/dsh-client-locale/client'
// Type-only: pulls the SlotMap merge for the settings section slot.
import type {} from '@deepseek-ai/dsh-client-ui-slots'
// Type-only: pulls ctx.settingsScope and the settings-surface slot types.
import type {} from '@deepseek-ai/dsh-client-ui-settings/client'
import type { ReactElement } from 'react'
import { AuthProxySettingsCard, type AuthProxySettingsCardProps } from './AuthProxySettingsCard.tsx'
import { en, zh, type AuthProxyKey } from './locales.ts'

/** Minimal slot-component signature (official SlotComponent returns ReactNode). */
type ClientSlotComponent = (props: AuthProxySettingsCardProps) => ReactElement

/** The slot register call's composed contract — resolved once for typing only. */
type RegisterOptions = Parameters<NonNullable<Parameters<ClientContext['slots']['register']>[1]>>

/** Locale namespace this plugin owns. */
const NS = 'auth-proxy'

declare module '@deepseek-ai/dsh-client-ui-slots' {
  interface LocaleNamespaceMap {
    /** Auth proxy card copy. */
    'auth-proxy': AuthProxyKey
  }

  interface SlotMap {
    /** The plugin-configuration section's card seat (declared by ui-settings-plugins). */
    'settings.plugin.item': { kind: 'list'; scope: 'root'; owner: Record<string, never> }
  }
}

/** Required services (fiber inject waiting — the runtime must be up first). */
export const inject = ['slots', 'locale']

/** Type-only surface (export discipline: no value exports beyond the plugin contract). */
export type { AuthProxySettingsCardProps }

/**
 * Mount the auth-proxy configuration card.
 * @param ctx - client root context (locale service).
 */
export function apply(ctx: ClientContext): void {
  ctx.effect(() => ctx.locale.register(NS, { zh, en }), 'auth-proxy: dictionaries')

  const slots = ctx.slots as unknown as {
    inject: (key: string, cb: () => unknown) => unknown
    register: (...args: unknown[]) => unknown
  }
  slots.inject('settings.plugin.item', () => slots.register(
    { name: 'settings.plugin.item', id: 'auth-proxy', order: 100, locale: NS },
    AuthProxySettingsCard as unknown as ClientSlotComponent,
  ))
}
