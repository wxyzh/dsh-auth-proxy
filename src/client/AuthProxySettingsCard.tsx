/**
 * The auth-proxy settings card. Fetches the plugin's own config endpoint
 * (GET /api/dsh-auth-proxy/config), stages edits locally, and PUTs the whole
 * document on save. Uses inline styles — the card must not depend on a
 * sibling UI package's CSS pipeline.
 */

import { useEffect, useState } from 'react'
import type { AuthProxyKey } from './locales.ts'

/** What the config endpoint returns (token value is never sent back). */
interface ConfigView {
  enabled: boolean
  host: string
  port: number
  targetHost: string
  targetPort: number
  sessionTtlMinutes: number
  banner: string
  allowedIps: string[]
  maxFailures: number
  lockoutMinutes: number
  tokenSet: boolean
}

/** Props the renderer binds for the auth-proxy card (locale reader + runtime slot props). */
export interface AuthProxySettingsCardProps {
  /** Locale reader for this card's copy. */
  t: (key: string) => string
  /** Slot runtime share (children seat etc.) — unused by this card. */
  children?: never
}

const styles = {
  card: {
    listStyle: 'none',
    border: '1px solid #2b3a4a',
    borderRadius: '10px',
    margin: '4px 0',
    background: '#16202b',
    overflow: 'hidden',
  } as const,
  header: {
    display: 'flex',
    alignItems: 'center',
    width: '100%',
    background: 'transparent',
    border: '0',
    color: '#e2e8f0',
    padding: '12px 16px',
    cursor: 'pointer',
    fontSize: '14px',
    textAlign: 'left' as const,
  },
  name: { fontWeight: 600, marginRight: '12px' },
  description: { color: '#7c8ba1', fontSize: '12px', flex: 1 },
  chevron: { color: '#7c8ba1', marginLeft: '8px' },
  body: { padding: '4px 16px 16px', borderTop: '1px solid #243244' },
  field: { margin: '12px 0' },
  label: { display: 'block', fontSize: '12px', color: '#94a3b8', marginBottom: '4px' },
  input: {
    width: '100%',
    padding: '8px 10px',
    borderRadius: '6px',
    border: '1px solid #2b3a4a',
    background: '#0f1720',
    color: '#e2e8f0',
    fontSize: '13px',
    boxSizing: 'border-box' as const,
  },
  hint: { fontSize: '11px', color: '#5b6b80', margin: '4px 0 0' },
  footer: { display: 'flex', gap: '8px', justifyContent: 'flex-end', marginTop: '16px' },
  button: {
    padding: '6px 14px',
    borderRadius: '6px',
    border: '0',
    fontSize: '13px',
    cursor: 'pointer',
  },
  save: { background: '#0ea5e9', color: '#082f49', fontWeight: 600 },
  discard: { background: '#243244', color: '#94a3b8' },
  status: { fontSize: '12px', color: '#7dd3fc', marginTop: '8px' },
  error: { fontSize: '12px', color: '#f87171', marginTop: '8px' },
  warning: {
    fontSize: '12px',
    color: '#fbbf24',
    background: 'rgba(251, 191, 36, 0.08)',
    border: '1px solid rgba(251, 191, 36, 0.35)',
    borderRadius: '6px',
    padding: '8px 10px',
    margin: '12px 0',
  },
  row: { display: 'flex', gap: '12px' },
  half: { flex: 1 },
  checkbox: { display: 'flex', alignItems: 'center', gap: '8px', margin: '12px 0' },
  check: { width: '16px', height: '16px', accentColor: '#0ea5e9' },
}

/** One staged text field. */
function Field(props: {
  label: string
  value: string
  onChange: (v: string) => void
  hint?: string
  numeric?: boolean
  width?: 'full' | 'half'
}) {
  return (
    <div style={props.width === 'half' ? { ...styles.field, ...styles.half } : styles.field}>
      <label style={styles.label}>{props.label}</label>
      <input
        style={styles.input}
        type="text"
        inputMode={props.numeric ? 'numeric' : undefined}
        value={props.value}
        onChange={(e) => props.onChange((e.target as HTMLInputElement).value)}
      />
      {props.hint ? <p style={styles.hint}>{props.hint}</p> : null}
    </div>
  )
}

/**
 * Render the auth-proxy configuration card.
 * @param props - locale reader.
 * @returns the card.
 */
export function AuthProxySettingsCard(props: AuthProxySettingsCardProps) {
  const t = (key: string): string => {
    const dict = props.t
    return dict(key) ?? key
  }
  const [open, setOpen] = useState(false)
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState(false)
  const [saving, setSaving] = useState(false)
  const [saveFailed, setSaveFailed] = useState(false)
  const [dirty, setDirty] = useState(false)
  const [cfg, setCfg] = useState<ConfigView | null>(null)
  const [tokenDraft, setTokenDraft] = useState('')

  // One form value per editable field, staged as strings.
  const [enabled, setEnabled] = useState(true)
  const [host, setHost] = useState('0.0.0.0')
  const [port, setPort] = useState('8443')
  const [targetHost, setTargetHost] = useState('127.0.0.1')
  const [targetPort, setTargetPort] = useState('3080')
  const [ttl, setTtl] = useState('1440')
  const [banner, setBanner] = useState('')
  const [allowedIps, setAllowedIps] = useState('')
  const [maxFailures, setMaxFailures] = useState('0')
  const [lockoutMinutes, setLockoutMinutes] = useState('15')

  useEffect(() => {
    let cancelled = false
    fetch('/api/dsh-auth-proxy/config')
      .then((res) => {
        if (!res.ok) throw new Error(String(res.status))
        return res.json() as Promise<ConfigView>
      })
      .then((view) => {
        if (cancelled) return
        setCfg(view)
        setEnabled(view.enabled)
        setHost(view.host)
        setPort(String(view.port))
        setTargetHost(view.targetHost)
        setTargetPort(String(view.targetPort))
        setTtl(String(view.sessionTtlMinutes))
        setBanner(view.banner)
        setAllowedIps((view.allowedIps ?? []).join(', '))
        setMaxFailures(String(view.maxFailures))
        setLockoutMinutes(String(view.lockoutMinutes))
        setLoading(false)
      })
      .catch(() => {
        if (!cancelled) {
          setLoading(false)
          setLoadError(true)
        }
      })
    return () => { cancelled = true }
  }, [])

  const mark = (): void => { setDirty(true); setSaveFailed(false) }

  const save = async (): Promise<void> => {
    setSaving(true)
    setSaveFailed(false)
    const payload: Record<string, unknown> = {
      enabled,
      host,
      port: Number(port),
      targetHost,
      targetPort: Number(targetPort),
      sessionTtlMinutes: Number(ttl),
      banner,
      allowedIps: allowedIps.split(',').map((s) => s.trim()).filter((s) => s !== ''),
      maxFailures: Number(maxFailures),
      lockoutMinutes: Number(lockoutMinutes),
    }
    if (tokenDraft.trim() !== '') payload.token = tokenDraft.trim()
    try {
      const res = await fetch('/api/dsh-auth-proxy/config', {
        method: 'PUT',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(payload),
      })
      if (!res.ok) {
        const body = await res.json().catch(() => null) as { error?: string } | null
        throw new Error(body?.error ?? String(res.status))
      }
      setDirty(false)
      setTokenDraft('')
      setCfg((prev) => prev ? { ...prev, ...payload as unknown as Partial<ConfigView> } : prev)
    } catch {
      setSaveFailed(true)
    } finally {
      setSaving(false)
    }
  }

  const discard = (): void => {
    if (cfg) {
      setEnabled(cfg.enabled)
      setHost(cfg.host)
      setPort(String(cfg.port))
      setTargetHost(cfg.targetHost)
      setTargetPort(String(cfg.targetPort))
      setTtl(String(cfg.sessionTtlMinutes))
      setBanner(cfg.banner)
      setAllowedIps((cfg.allowedIps ?? []).join(', '))
      setMaxFailures(String(cfg.maxFailures))
      setLockoutMinutes(String(cfg.lockoutMinutes))
    }
    setTokenDraft('')
    setDirty(false)
    setSaveFailed(false)
  }

  const ui = styles
  return (
    <li style={ui.card}>
      <button
        type="button"
        style={ui.header}
        aria-expanded={open}
        onClick={() => setOpen(!open)}
      >
        <span style={ui.name}>{t('title')}</span>
        <span style={ui.description}>{t('description')}</span>
        {dirty ? <span style={{ color: '#fbbf24', fontSize: '11px', marginRight: '8px' }}>{t('settings.unsaved')}</span> : null}
        <span style={ui.chevron}>{open ? '▾' : '▸'}</span>
      </button>
      {open
        ? (
          <div style={ui.body}>
            {loading ? <p style={ui.status}>{t('settings.loading')}…</p> : null}
            {loadError ? <p style={ui.error}>{t('settings.loadFailed')}</p> : null}
            {!loading && !loadError && cfg
              ? (
                <>
                  {!cfg.tokenSet ? <p style={ui.warning}>{t('warnings.noToken')}</p> : null}
                  <div style={ui.checkbox}>
                    <input
                      id="auth-proxy-enabled"
                      type="checkbox"
                      style={ui.check}
                      checked={enabled}
                      onChange={(e) => { setEnabled((e.target as HTMLInputElement).checked); mark() }}
                    />
                    <label htmlFor="auth-proxy-enabled" style={ui.label as never}>{t('fields.enabled')}</label>
                  </div>
                  <div style={ui.row}>
                    <Field label={t('fields.port')} numeric value={port} onChange={(v) => { setPort(v); mark() }} width="half" />
                    <Field label={t('fields.targetPort')} numeric value={targetPort} onChange={(v) => { setTargetPort(v); mark() }} width="half" />
                  </div>
                  <div style={ui.row}>
                    <Field label={t('fields.host')} value={host} onChange={(v) => { setHost(v); mark() }} width="half" />
                    <Field label={t('fields.targetHost')} value={targetHost} onChange={(v) => { setTargetHost(v); mark() }} width="half" />
                  </div>
                  <Field
                    label={t('fields.token')}
                    value={tokenDraft}
                    onChange={(v) => { setTokenDraft(v); mark() }}
                    hint={cfg.tokenSet ? t('fields.tokenHint') : undefined}
                  />
                  <Field
                    label={t('fields.allowedIps')}
                    value={allowedIps}
                    onChange={(v) => { setAllowedIps(v); mark() }}
                    hint={t('fields.allowedIps')}
                  />
                  <div style={ui.row}>
                    <Field label={t('fields.sessionTtlMinutes')} numeric value={ttl} onChange={(v) => { setTtl(v); mark() }} width="half" />
                    <Field label={t('fields.banner')} value={banner} onChange={(v) => { setBanner(v); mark() }} width="half" />
                  </div>
                  <div style={ui.row}>
                    <Field label={t('fields.maxFailures')} numeric value={maxFailures} onChange={(v) => { setMaxFailures(v); mark() }} width="half" />
                    <Field label={t('fields.lockoutMinutes')} numeric value={lockoutMinutes} onChange={(v) => { setLockoutMinutes(v); mark() }} width="half" />
                  </div>
                  {saveFailed ? <p style={ui.error}>{t('settings.saveFailed')}</p> : null}
                  <div style={ui.footer}>
                    <button type="button" style={{ ...ui.button, ...ui.discard }} disabled={!dirty || saving} onClick={discard}>
                      {t('settings.discard')}
                    </button>
                    <button type="button" style={{ ...ui.button, ...ui.save }} disabled={!dirty || saving} onClick={save}>
                      {t(saving ? 'settings.saving' : 'settings.save')}
                    </button>
                  </div>
                </>
              )
              : null}
          </div>
        )
        : null}
    </li>
  )
}
