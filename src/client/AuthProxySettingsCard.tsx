/**
 * The auth-proxy settings card. Reads and writes the `dsh-auth-proxy` settings
 * namespace through the official `settingsScope` handle (revision-fenced,
 * validated and persisted Host-side), and shows runtime introspection (listening,
 * token configured) from the plugin's read-only status endpoint. Uses inline
 * styles bound to the dsh `--dsw-alias-*` design tokens so the card follows
 * the active skin/theme (light and dark).
 */

import { useCallback, useEffect, useRef, useState, useSyncExternalStore } from 'react'
import type { SettingsScope, SettingsScopeSnapshot } from '@deepseek-ai/dsh-client-runtime/client'

/** Editable section (mirrors the Host Config; token is write-only — never seeded). */
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

/** Read-only runtime status served by the plugin (not part of the section). */
interface StatusView {
  enabled: boolean
  port: number
  listening: boolean
  tokenSet: boolean
  accessUrls: string[]
}

/** The registrar-side business face the slot entry injects. */
export interface AuthProxyCardFace {
  /** Reactive handle over the `dsh-auth-proxy` namespace section. */
  scope: SettingsScope<AuthProxySection>
  /** Sync snapshot source for the card's form. */
  getSnapshot: () => SettingsScopeSnapshot<AuthProxySection>
}

/** Card component props: the locale `t` seat plus our injected face. */
export type AuthProxyCardProps = AuthProxyCardFace & {
  /** Translate a dictionary key of the `auth-proxy` namespace. */
  t: (key: string) => string
}

/** Multi-line list helper: render a stored list as comma/whitespace-separated text. */
function toText(values: string[] | undefined): string {
  return (values ?? []).join(', ')
}

/** Persist a comma/whitespace-separated list from a text draft. */
function fromText(text: string): string[] {
  return text.split(/[,，\s]+/).map((s) => s.trim()).filter((s) => s !== '')
}

/**
 * Render the auth-proxy configuration card. The form stages local drafts and, only
 * on Save, issues revision-fenced writes through the settings scope — the Host is
 * the sole authority on whether each write lands.
 * @param props - locale reader, the bound scope, and its snapshot source.
 * @returns the card.
 */
export function AuthProxySettingsCard({ t, scope, getSnapshot }: AuthProxyCardProps) {
  const snapshot = useSyncExternalStore<SettingsScopeSnapshot<AuthProxySection>>(
    (cb) => scope.subscribe(cb),
    getSnapshot,
  )
  const value = snapshot.value
  const available = snapshot.status === 'ready'
  const writable = snapshot.writable
  const revision = snapshot.revision

  const [open, setOpen] = useState(false)
  const [status, setStatus] = useState<StatusView | null>(null)

  // One staged string per editable field.
  const [enabled, setEnabled] = useState(true)
  const [host, setHost] = useState('127.0.0.1')
  const [port, setPort] = useState('8443')
  const [targetHost, setTargetHost] = useState('127.0.0.1')
  const [targetPort, setTargetPort] = useState('3080')
  const [banner, setBanner] = useState('')
  const [allowedIps, setAllowedIps] = useState('')
  const [accessUrls, setAccessUrls] = useState('')
  const [maxFailures, setMaxFailures] = useState('0')
  const [lockoutMinutes, setLockoutMinutes] = useState('15')
  const [tokenDraft, setTokenDraft] = useState('')
  const [dirty, setDirty] = useState(false)
  const [saving, setSaving] = useState(false)
  const [failed, setFailed] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Seed drafts from the section value, and re-seed only while not mid-edit.
  const seededRev = useRef<number | undefined>(undefined)
  useEffect(() => {
    if (value === undefined || revision === seededRev.current) return
    seededRev.current = revision
    setEnabled(value.enabled ?? true)
    setHost(value.host ?? '127.0.0.1')
    setPort(String(value.port ?? 8443))
    setTargetHost(value.targetHost ?? '127.0.0.1')
    setTargetPort(String(value.targetPort ?? 3080))
    setBanner(value.banner ?? '')
    setAllowedIps(toText(value.allowedIps))
    setAccessUrls(toText(value.accessUrls))
    setMaxFailures(String(value.maxFailures ?? 0))
    setLockoutMinutes(String(value.lockoutMinutes ?? 15))
  }, [value, revision])

  // Read-only runtime status.
  useEffect(() => {
    let cancelled = false
    fetch('/api/dsh-auth-proxy/status')
      .then((res) => (res.ok ? res.json() as Promise<StatusView> : null))
      .then((view) => { if (!cancelled && view) setStatus(view) })
      .catch(() => { /* status is supplemental; the form still works */ })
    return () => { cancelled = true }
  }, [])

  const mark = useCallback(() => { setDirty(true); setFailed(false); setError(null) }, [])

  const discard = useCallback(() => {
    if (value) {
      setEnabled(value.enabled ?? true)
      setHost(value.host ?? '127.0.0.1')
      setPort(String(value.port ?? 8443))
      setTargetHost(value.targetHost ?? '127.0.0.1')
      setTargetPort(String(value.targetPort ?? 3080))
      setBanner(value.banner ?? '')
      setAllowedIps(toText(value.allowedIps))
      setAccessUrls(toText(value.accessUrls))
      setMaxFailures(String(value.maxFailures ?? 0))
      setLockoutMinutes(String(value.lockoutMinutes ?? 15))
    }
    setTokenDraft('')
    setDirty(false)
    setFailed(false)
    setError(null)
  }, [value])

  /**
   * Write every staged edit as a revision-fenced scope mutation, then reset.
   * The Host's settings validator is the authority on whether each write lands; a
   * rejected write keeps the error for the user to correct.
   */
  const save = useCallback(async () => {
    setSaving(true)
    setFailed(false)
    setError(null)
    try {
      if (tokenDraft.trim() !== '') await scope.set('token', tokenDraft.trim())
      await scope.set('enabled', enabled)
      await scope.set('host', host)
      await scope.set('port', Number(port))
      await scope.set('targetHost', targetHost)
      await scope.set('targetPort', Number(targetPort))
      await scope.set('banner', banner)
      await scope.set('allowedIps', fromText(allowedIps))
      await scope.set('accessUrls', fromText(accessUrls))
      await scope.set('maxFailures', Number(maxFailures))
      await scope.set('lockoutMinutes', Number(lockoutMinutes))
      // The scope reloads after writes; fonts out of band.
      setTokenDraft('')
      setDirty(false)
      // Refetch the runtime status now that config changed.
      const res = await fetch('/api/dsh-auth-proxy/status')
      if (res.ok) setStatus(await res.json() as StatusView)
    } catch (err) {
      setFailed(true)
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setSaving(false)
    }
  }, [tokenDraft, enabled, host, port, targetHost, targetPort, banner, allowedIps, accessUrls, maxFailures, lockoutMinutes, scope])

  const downloading = !available

  return (
    <li style={styles.card}>
      <button
        type="button"
        style={styles.header}
        aria-expanded={open}
        onClick={() => setOpen(!open)}
      >
        <span style={styles.name}>{t('title')}</span>
        <span style={styles.description}>{t('description')}</span>
        {dirty ? <span style={styles.unsavedBadge}>{t('settings.unsaved')}</span> : null}
        <span style={styles.chevron}>{open ? '▾' : '▸'}</span>
      </button>
      {open && (
        <div style={styles.body}>
          {downloading ? <p style={styles.status}>{t('settings.loading')}…</p> : null}
          {!writable ? <p style={styles.warning}>{t('settings.readOnly')}</p> : null}
          {status && (
            <p style={{ ...styles.status, ...(status.listening ? styles.statusOk : styles.statusWarn) }}>
              {status.listening
                ? `${t('status.listening')} http://${host}:${port}`
                : t('status.disabled')}
            </p>
          )}
          {status && status.accessUrls.length > 0 && (
            <p style={styles.accessUrls}>
              {t('status.accessUrls')}:{' '}
              {status.accessUrls.map((u, i) => (
                <a key={u} href={u} style={styles.accessLink}>
                  {u}{i < status.accessUrls.length - 1 ? '、' : ''}
                </a>
              ))}
            </p>
          )}
          <div style={styles.checkbox}>
            <input
              id="auth-proxy-enabled"
              type="checkbox"
              style={styles.check}
              checked={enabled}
              onChange={(e) => { setEnabled((e.target as HTMLInputElement).checked); mark() }}
            />
            <label htmlFor="auth-proxy-enabled" style={styles.label}>{t('fields.enabled')}</label>
          </div>
          <div style={styles.row}>
            <Field label={t('fields.port')} numeric value={port} onChange={(v) => { setPort(v); mark() }} width="half" />
            <Field label={t('fields.targetPort')} numeric value={targetPort} onChange={(v) => { setTargetPort(v); mark() }} width="half" />
          </div>
          <div style={styles.row}>
            <Field label={t('fields.host')} value={host} onChange={(v) => { setHost(v); mark() }} width="half" />
            <Field label={t('fields.targetHost')} value={targetHost} onChange={(v) => { setTargetHost(v); mark() }} width="half" />
          </div>
          <Field
            label={t('fields.token')}
            value={tokenDraft}
            onChange={(v) => { setTokenDraft(v); mark() }}
            hint={status && status.tokenSet ? t('fields.tokenHint') : undefined}
            type="password"
          />
          <Field label={t('fields.allowedIps')} value={allowedIps} onChange={(v) => { setAllowedIps(v); mark() }} />
          <Field label={t('fields.banner')} value={banner} onChange={(v) => { setBanner(v); mark() }} />
          <Field label={t('fields.accessUrls')} value={accessUrls} onChange={(v) => { setAccessUrls(v); mark() }} />
          <div style={styles.row}>
            <Field label={t('fields.maxFailures')} numeric value={maxFailures} onChange={(v) => { setMaxFailures(v); mark() }} width="half" />
            <Field label={t('fields.lockoutMinutes')} numeric value={lockoutMinutes} onChange={(v) => { setLockoutMinutes(v); mark() }} width="half" />
          </div>
          {failed ? <p style={styles.error}>{error ?? t('settings.saveFailed')}</p> : null}
          <div style={styles.footer}>
            <button type="button" style={{ ...styles.button, ...styles.discard }} disabled={!dirty || saving} onClick={discard}>
              {t('settings.discard')}
            </button>
            <button type="button" style={{ ...styles.button, ...styles.save }} disabled={!dirty || saving || !writable} onClick={save}>
              {t(saving ? 'settings.saving' : 'settings.save')}
            </button>
          </div>
        </div>
      )}
    </li>
  )
}

/** One staged text field. */
function Field(props: {
  label: string
  value: string
  onChange: (v: string) => void
  hint?: string
  numeric?: boolean
  type?: 'text' | 'password'
  width?: 'full' | 'half'
}) {
  const style = props.width === 'half' ? { ...styles.field, ...styles.half } : styles.field
  return (
    <div style={style}>
      <label style={styles.label}>{props.label}</label>
      <input
        style={styles.input}
        type={props.type ?? 'text'}
        inputMode={props.numeric ? 'numeric' : undefined}
        value={props.value}
        onChange={(e) => props.onChange((e.target as HTMLInputElement).value)}
      />
      {props.hint ? <p style={styles.hint}>{props.hint}</p> : null}
    </div>
  )
}

const styles = {
  card: {
    listStyle: 'none',
    border: '1px solid var(--dsw-alias-border-l2)',
    borderRadius: '10px',
    margin: '4px 0',
    background: 'var(--dsw-alias-bg-layer-3)',
    overflow: 'hidden',
  } as const,
  header: {
    display: 'flex',
    alignItems: 'center',
    width: '100%',
    background: 'transparent',
    border: '0',
    color: 'var(--dsw-alias-label-primary)',
    padding: '12px 16px',
    cursor: 'pointer',
    fontSize: '14px',
    textAlign: 'left' as const,
  },
  name: { fontWeight: 600, marginRight: '12px' },
  description: { color: 'var(--dsw-alias-label-tertiary)', fontSize: '12px', flex: 1 },
  chevron: { color: 'var(--dsw-alias-label-tertiary)', marginLeft: '8px' },
  unsavedBadge: { color: '#fbbf24', fontSize: '11px', marginRight: '8px' },
  body: { padding: '4px 16px 16px', borderTop: '1px solid var(--dsw-alias-border-l2)' },
  field: { margin: '12px 0' },
  label: { display: 'block', fontSize: '12px', color: 'var(--dsw-alias-label-secondary)', marginBottom: '4px' },
  input: {
    width: '100%',
    padding: '8px 10px',
    borderRadius: '6px',
    border: '1px solid var(--dsw-alias-border-l2)',
    background: 'var(--dsw-specific-input-major)',
    color: 'var(--dsw-alias-label-primary)',
    fontSize: '13px',
    boxSizing: 'border-box' as const,
  },
  hint: { fontSize: '11px', color: 'var(--dsw-alias-label-secondary)', margin: '4px 0 0' },
  footer: { display: 'flex', gap: '8px', justifyContent: 'flex-end', marginTop: '16px' },
  button: { padding: '6px 14px', borderRadius: '6px', border: '0', fontSize: '13px', cursor: 'pointer' },
  save: {
    background: 'var(--dsw-alias-button-info-fill)',
    color: 'var(--dsw-alias-label-primary-foreground)',
    fontWeight: 600,
  },
  discard: { background: 'transparent', border: '1px solid var(--dsw-alias-border-l2)', color: 'var(--dsw-alias-label-secondary)' },
  status: { fontSize: '12px', marginTop: '8px' },
  statusOk: { color: 'var(--dsw-alias-state-success-primary)' },
  statusWarn: { color: 'var(--dsw-alias-state-warn-primary)' },
  error: { fontSize: '12px', color: 'var(--dsw-alias-state-error-primary)', marginTop: '8px' },
  warning: {
    fontSize: '12px',
    color: 'var(--dsw-alias-state-warn-primary)',
    border: '1px solid var(--dsw-alias-state-warn-primary)',
    borderRadius: '6px',
    padding: '8px 10px',
    margin: '12px 0',
  },
  accessUrls: { fontSize: '12px', color: 'var(--dsw-alias-label-secondary)', marginTop: '8px', lineHeight: 1.7 },
  accessLink: { color: 'var(--dsw-alias-state-business-primary)', textDecoration: 'none', marginRight: '6px' },
  row: { display: 'flex', gap: '12px' },
  half: { flex: 1 },
  checkbox: { display: 'flex', alignItems: 'center', gap: '8px', margin: '12px 0' },
  check: { width: '16px', height: '16px', accentColor: 'var(--dsw-alias-button-info-fill)' },
}
