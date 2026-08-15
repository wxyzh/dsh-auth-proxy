/** Locale copy keys for the auth-proxy settings card (flat vocabulary). */
export type AuthProxyKey =
  | 'title'
  | 'description'
  | 'settings.save'
  | 'settings.saving'
  | 'settings.discard'
  | 'settings.unsaved'
  | 'settings.expand'
  | 'settings.collapse'
  | 'settings.readOnly'
  | 'settings.saveFailed'
  | 'settings.loading'
  | 'settings.loadFailed'
  | 'fields.enabled'
  | 'fields.host'
  | 'fields.port'
  | 'fields.targetHost'
  | 'fields.targetPort'
  | 'fields.token'
  | 'fields.tokenHint'
  | 'fields.sessionTtlMinutes'
  | 'fields.banner'
  | 'fields.allowedIps'
  | 'fields.maxFailures'
  | 'fields.lockoutMinutes'
  | 'warnings.noToken'

export const zh: Record<AuthProxyKey, string> = {
  title: 'DSH 访问鉴权代理',
  description: '网络端口、令牌、IP 白名单与失败锁定策略',
  'settings.save': '保存',
  'settings.saving': '保存中…',
  'settings.discard': '放弃修改',
  'settings.unsaved': '未保存',
  'settings.expand': '展开',
  'settings.collapse': '收起',
  'settings.readOnly': '当前文档为只读',
  'settings.saveFailed': '保存失败，请检查配置后重试',
  'settings.loading': '加载中…',
  'settings.loadFailed': '配置加载失败',
  'fields.enabled': '启用',
  'fields.host': '监听地址',
  'fields.port': '监听端口',
  'fields.targetHost': '目标主机',
  'fields.targetPort': '目标端口',
  'fields.token': '访问令牌',
  'fields.tokenHint': '留空保持当前令牌不变',
  'fields.sessionTtlMinutes': '会话时长（分钟）',
  'fields.banner': '登录页横幅',
  'fields.allowedIps': 'IP 白名单（逗号分隔，支持 CIDR）',
  'fields.maxFailures': '失败锁定阈值（0=关闭）',
  'fields.lockoutMinutes': '锁定时长（分钟）',
  'warnings.noToken': '未设置访问令牌（或仍为占位符 change-me），代理当前处于禁用状态',
}

export const en: Record<AuthProxyKey, string> = {
  title: 'DSH Auth Proxy',
  description: 'Listen port, token, IP allowlist and lockout policy',
  'settings.save': 'Save',
  'settings.saving': 'Saving…',
  'settings.discard': 'Discard',
  'settings.unsaved': 'Unsaved',
  'settings.expand': 'Expand',
  'settings.collapse': 'Collapse',
  'settings.readOnly': 'This document is read-only',
  'settings.saveFailed': 'Save failed — check the config and retry',
  'settings.loading': 'Loading…',
  'settings.loadFailed': 'Failed to load config',
  'fields.enabled': 'Enabled',
  'fields.host': 'Listen host',
  'fields.port': 'Listen port',
  'fields.targetHost': 'Target host',
  'fields.targetPort': 'Target port',
  'fields.token': 'Access token',
  'fields.tokenHint': 'Leave empty to keep the current token',
  'fields.sessionTtlMinutes': 'Session TTL (minutes)',
  'fields.banner': 'Login page banner',
  'fields.allowedIps': 'IP allowlist (comma-separated, CIDR supported)',
  'fields.maxFailures': 'Lockout threshold (0=off)',
  'fields.lockoutMinutes': 'Lockout duration (minutes)',
  'warnings.noToken': 'No access token set (or still the placeholder change-me) — the proxy is currently disabled',
}
