import type { SessionStatus, TerminalSize } from '../session/types'

export type AuthType = 'password' | 'privateKey'

export interface ConnectionDraft {
  name: string
  host: string
  port: number
  username: string
  authType: AuthType
  password: string
  privateKeyPath: string
  privateKeyPassphrase: string
  timeoutSeconds: number
}

export interface ConnectionRequest extends ConnectionDraft, TerminalSize {}

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
  timeoutSeconds?: string
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
  timeoutSeconds: 15,
}

export function validateConnectionDraft(draft: ConnectionDraft): ConnectionFormErrors {
  const errors: ConnectionFormErrors = {}
  const name = draft.name.trim() || draft.host.trim()
  if (name.length < 1 || name.length > 64) errors.name = '连接名称长度必须为 1～64 个字符'
  if (!draft.host.trim()) errors.host = '请输入 IPv4、IPv6 或域名'
  if (!Number.isInteger(draft.port) || draft.port < 1 || draft.port > 65535) errors.port = '端口必须为 1～65535'
  if (!draft.username.trim() || draft.username.trim().length > 128) errors.username = '用户名长度必须为 1～128 个字符'
  if (draft.authType === 'password' && !draft.password) errors.password = '请输入密码'
  if (draft.authType === 'privateKey' && !draft.privateKeyPath) errors.privateKeyPath = '请选择私钥文件'
  if (!Number.isInteger(draft.timeoutSeconds) || draft.timeoutSeconds < 5 || draft.timeoutSeconds > 60) errors.timeoutSeconds = '连接超时必须为 5～60 秒'
  return errors
}

export function toConnectionRequest(
  draft: ConnectionDraft,
  size: TerminalSize = { columns: 80, rows: 24 },
): ConnectionRequest {
  return {
    ...draft,
    name: draft.name.trim() || draft.host.trim(),
    host: draft.host.trim(),
    username: draft.username.trim(),
    ...size,
  }
}
