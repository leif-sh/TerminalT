import type { SessionStatus, TerminalSize } from '../session/types'
import type { TunnelProfile } from '../tunnel/types'

export type AuthType = 'password' | 'privateKey' | 'keyboardInteractive' | 'agent'

export interface AuthenticationPromptPayload {
  operationId: string
  promptId: string
  connectionTitle: string
  target: string
  name: string
  instructions: string
  prompts: Array<{ id: string; text: string; echo: boolean }>
}

export interface AuthenticationPromptResponse {
  operationId: string
  promptId: string
  answers: Array<{ id: string; value: string }>
}

export interface AgentIdentityInfo {
  fingerprintSha256: string
  algorithm: string
  comment: string
}

export type ProxyType = 'http' | 'socks5'

export interface ProxyRequest {
  proxyType: ProxyType
  host: string
  port: number
  username?: string
  password?: string
}

export interface ProxyProfile {
  proxyType: ProxyType
  host: string
  port: number
  username?: string
  credentialRef?: string
}

export interface ConnectionDraft {
  id?: string
  name: string
  host: string
  port: number
  username: string
  authType: AuthType
  password: string
  privateKeyPath: string
  privateKeyPassphrase: string
  agentKeyFingerprint: string
  timeoutSeconds: number
  groupId: string
  note: string
  rememberCredential: boolean
  proxyEnabled: boolean
  proxyType: ProxyType
  proxyHost: string
  proxyPort: number
  proxyUsername: string
  proxyPassword: string
  rememberProxyCredential: boolean
  jumpHostIds: string[]
}

export interface ConnectionRequest extends TerminalSize {
  name: string
  host: string
  port: number
  username: string
  authType: AuthType
  password: string
  privateKeyPath: string
  privateKeyPassphrase: string
  agentKeyFingerprint?: string
  timeoutSeconds: number
  keepaliveEnabled: boolean
  keepaliveSeconds: number
  proxy?: ProxyRequest
}

export interface ConnectionGroup {
  id: string
  name: string
  createdAt: string
  updatedAt: string
}

export interface ConnectionProfile {
  id: string
  name: string
  host: string
  port: number
  username: string
  authType: AuthType
  credentialRef?: string
  privateKeyPath?: string
  agentKeyFingerprint?: string
  proxy?: ProxyProfile
  jumpHostIds?: string[]
  groupId: string
  note?: string
  timeoutSeconds: number
  lastConnectedAt?: string
  createdAt: string
  updatedAt: string
}

export interface RecentTarget {
  displayTarget: string
  lastUsedAt: string
}

export interface StoredHostKeyRecord {
  host: string
  port: number
  algorithm: string
  fingerprintSha256: string
  publicKey: string
  trustedAt: string
}

export interface ConnectionAssetSnapshot {
  schemaVersion: number
  defaultGroupId: string
  groups: ConnectionGroup[]
  connections: ConnectionProfile[]
  recentTargets: RecentTarget[]
  tunnels?: TunnelProfile[]
}

export interface AssetTransferSummary {
  connections: number
  groups: number
  duplicateNames: number
  regeneratedIds: number
  path: string
}

export interface SaveConnectionRequest {
  id?: string
  name: string
  host: string
  port: number
  username: string
  authType: AuthType
  secret?: string
  rememberCredential: boolean
  privateKeyPath?: string
  agentKeyFingerprint?: string
  proxy?: ProxyRequest & { rememberCredential: boolean }
  jumpHostIds: string[]
  groupId: string
  note?: string
  timeoutSeconds: number
}

export type HostKeyStatus = 'trusted' | 'unknown' | 'changed'
export type HostKeyAction = 'useTrusted' | 'trustNew' | 'replaceChanged'

export interface HostKeyInspection {
  host: string
  port: number
  algorithm: string
  fingerprintSha256: string
  status: HostKeyStatus
  previousFingerprintSha256?: string
}

export interface HostKeyApproval {
  fingerprintSha256: string
  action: HostKeyAction
}

export interface ConnectionTestResult {
  elapsedMillis: number
  hostKey: HostKeyInspection
}

export interface ConnectionProgressPayload {
  operationId: string
  status: SessionStatus
  message: string
}

export interface ConnectionFormErrors {
  name?: string
  host?: string
  port?: string
  username?: string
  password?: string
  privateKeyPath?: string
  privateKeyPassphrase?: string
  timeoutSeconds?: string
  note?: string
  proxyHost?: string
  proxyPort?: string
  proxyUsername?: string
  proxyPassword?: string
}

export const initialConnectionDraft: ConnectionDraft = {
  name: '',
  host: '',
  port: 22,
  username: '',
  authType: 'password',
  password: '',
  privateKeyPath: '',
  privateKeyPassphrase: '',
  agentKeyFingerprint: '',
  timeoutSeconds: 15,
  groupId: 'default',
  note: '',
  rememberCredential: false,
  proxyEnabled: false,
  proxyType: 'http',
  proxyHost: '',
  proxyPort: 8080,
  proxyUsername: '',
  proxyPassword: '',
  rememberProxyCredential: false,
  jumpHostIds: [],
}

export function validateConnectionDraft(
  draft: ConnectionDraft,
  hasStoredCredential = false,
  hasStoredProxyCredential = false,
): ConnectionFormErrors {
  const errors: ConnectionFormErrors = {}
  const name = draft.name.trim() || draft.host.trim()
  if (name.length < 1 || name.length > 64) errors.name = '连接名称长度必须为 1～64 个字符'
  if (!draft.host.trim()) errors.host = '请输入 IPv4、IPv6 或域名'
  if (!Number.isInteger(draft.port) || draft.port < 1 || draft.port > 65535) errors.port = '端口必须为 1～65535'
  if (!draft.username.trim() || draft.username.trim().length > 128) errors.username = '用户名长度必须为 1～128 个字符'
  if (draft.authType === 'password' && !draft.password && !hasStoredCredential) errors.password = '请输入密码'
  if (draft.authType === 'privateKey' && !draft.privateKeyPath) errors.privateKeyPath = '请选择私钥文件'
  if (!Number.isInteger(draft.timeoutSeconds) || draft.timeoutSeconds < 5 || draft.timeoutSeconds > 60) errors.timeoutSeconds = '连接超时必须为 5～60 秒'
  if (draft.note.length > 500) errors.note = '备注不能超过 500 个字符'
  if (draft.proxyEnabled) {
    if (!draft.proxyHost.trim()) errors.proxyHost = '请输入代理主机地址'
    if (!Number.isInteger(draft.proxyPort) || draft.proxyPort < 1 || draft.proxyPort > 65535) errors.proxyPort = '代理端口必须为 1～65535'
    if (draft.proxyUsername.length > 255) errors.proxyUsername = '代理用户名不能超过 255 个字符'
    if (draft.rememberProxyCredential && draft.proxyUsername && !draft.proxyPassword && !hasStoredProxyCredential) errors.proxyPassword = '请输入需要保存的代理密码'
  }
  return errors
}

export function toConnectionRequest(
  draft: ConnectionDraft,
  size: TerminalSize = { columns: 80, rows: 24 },
  keepalive = { enabled: true, seconds: 30 },
): ConnectionRequest {
  return {
    name: draft.name.trim() || draft.host.trim(),
    host: draft.host.trim(),
    port: draft.port,
    username: draft.username.trim(),
    authType: draft.authType,
    password: draft.password,
    privateKeyPath: draft.privateKeyPath,
    privateKeyPassphrase: draft.privateKeyPassphrase,
    agentKeyFingerprint: draft.authType === 'agent' ? draft.agentKeyFingerprint || undefined : undefined,
    timeoutSeconds: draft.timeoutSeconds,
    keepaliveEnabled: keepalive.enabled,
    keepaliveSeconds: keepalive.seconds,
    proxy: draft.proxyEnabled ? {
      proxyType: draft.proxyType,
      host: draft.proxyHost.trim(),
      port: draft.proxyPort,
      username: draft.proxyUsername.trim() || undefined,
      password: draft.proxyPassword || undefined,
    } : undefined,
    ...size,
  }
}

export function draftFromProfile(profile: ConnectionProfile): ConnectionDraft {
  return {
    ...initialConnectionDraft,
    id: profile.id,
    name: profile.name,
    host: profile.host,
    port: profile.port,
    username: profile.username,
    authType: profile.authType,
    privateKeyPath: profile.privateKeyPath ?? '',
    agentKeyFingerprint: profile.agentKeyFingerprint ?? '',
    groupId: profile.groupId,
    note: profile.note ?? '',
    timeoutSeconds: profile.timeoutSeconds,
    rememberCredential: Boolean(profile.credentialRef),
    proxyEnabled: Boolean(profile.proxy),
    proxyType: profile.proxy?.proxyType ?? 'http',
    proxyHost: profile.proxy?.host ?? '',
    proxyPort: profile.proxy?.port ?? 8080,
    proxyUsername: profile.proxy?.username ?? '',
    rememberProxyCredential: Boolean(profile.proxy?.credentialRef),
    jumpHostIds: profile.jumpHostIds ?? [],
  }
}

export function toSaveConnectionRequest(draft: ConnectionDraft): SaveConnectionRequest {
  return {
    id: draft.id,
    name: draft.name.trim() || draft.host.trim(),
    host: draft.host.trim(),
    port: draft.port,
    username: draft.username.trim(),
    authType: draft.authType,
    secret: draft.authType === 'password'
      ? draft.password || undefined
      : draft.authType === 'privateKey'
        ? draft.privateKeyPassphrase || undefined
        : undefined,
    rememberCredential: ['password', 'privateKey'].includes(draft.authType) && draft.rememberCredential,
    privateKeyPath: draft.authType === 'privateKey' ? draft.privateKeyPath : undefined,
    agentKeyFingerprint: draft.authType === 'agent' ? draft.agentKeyFingerprint || undefined : undefined,
    proxy: draft.proxyEnabled ? {
      proxyType: draft.proxyType,
      host: draft.proxyHost.trim(),
      port: draft.proxyPort,
      username: draft.proxyUsername.trim() || undefined,
      password: draft.proxyPassword || undefined,
      rememberCredential: draft.rememberProxyCredential,
    } : undefined,
    jumpHostIds: draft.jumpHostIds,
    groupId: draft.groupId,
    note: draft.note.trim() || undefined,
    timeoutSeconds: draft.timeoutSeconds,
  }
}

export function toReconnectDraft(source: ConnectionDraft | ConnectionRequest): ConnectionDraft {
  return {
    ...initialConnectionDraft,
    ...source,
    password: '',
    privateKeyPassphrase: '',
    rememberCredential: 'rememberCredential' in source ? source.rememberCredential : false,
  }
}

export function parseQuickTarget(value: string): Pick<ConnectionDraft, 'host' | 'port' | 'username'> {
  const input = value.trim()
  const at = input.indexOf('@')
  if (at <= 0 || at !== input.lastIndexOf('@')) throw new Error('格式应为 user@host 或 user@host:port')
  const username = input.slice(0, at)
  const target = input.slice(at + 1)
  if (!target) throw new Error('请输入主机地址')
  if (target.startsWith('[')) {
    const match = target.match(/^\[([^\]]+)](?::(\d+))?$/)
    if (!match) throw new Error('IPv6 请使用 user@[地址]:port 格式')
    const port = match[2] ? Number(match[2]) : 22
    if (port < 1 || port > 65535) throw new Error('端口必须为 1～65535')
    return { username, host: match[1], port }
  }
  const parts = target.split(':')
  if (parts.length > 2) throw new Error('IPv6 地址必须使用方括号')
  const port = parts[1] ? Number(parts[1]) : 22
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('端口必须为 1～65535')
  return { username, host: parts[0], port }
}


export function filterConnections(profiles: ConnectionProfile[], query: string): ConnectionProfile[] {
  const normalized = query.trim().toLocaleLowerCase()
  if (!normalized) return profiles
  return profiles.filter((profile) =>
    [profile.name, profile.host, profile.username, profile.note ?? '']
      .some((value) => value.toLocaleLowerCase().includes(normalized)),
  )
}
