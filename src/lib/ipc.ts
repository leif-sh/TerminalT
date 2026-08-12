import { invoke } from '@tauri-apps/api/core'
import { listen, type UnlistenFn } from '@tauri-apps/api/event'
import type {
  SessionOutputPayload,
  SessionState,
  SessionStatusPayload,
  TerminalSize,
} from '../domain/session/types'
import type {
  ConnectionProgressPayload,
  ConnectionRequest,
  ConnectionTestResult,
  HostKeyApproval,
  HostKeyInspection,
  ConnectionAssetSnapshot,
  ConnectionGroup,
  ConnectionProfile,
  SaveConnectionRequest,
  StoredHostKeyRecord,
} from '../domain/connection/types'
import type { RemoteDirectoryListing, TransferDirection, TransferProgressPayload, TransferTask } from '../domain/sftp/types'

export interface HealthResponse {
  status: 'ok'
  protocolVersion: number
  appVersion: string
}

export interface AppCommandError {
  code: string
  category: string
  message: string
  technicalDetails?: string
  retryable: boolean
}

export interface KeepaliveOptions {
  enabled: boolean
  seconds: number
}

type OutputHandler = (payload: SessionOutputPayload) => void
type StatusHandler = (payload: SessionStatusPayload) => void
type ProgressHandler = (payload: ConnectionProgressPayload) => void
type TransferHandler = (payload: TransferProgressPayload) => void

const browserOutputHandlers = new Set<OutputHandler>()
const browserStatusHandlers = new Set<StatusHandler>()
const browserProgressHandlers = new Set<ProgressHandler>()
const previewAssetsKey = 'terminalt-preview-assets-v1'

function emptyPreviewAssets(): ConnectionAssetSnapshot {
  const now = new Date().toISOString()
  return { schemaVersion: 1, defaultGroupId: 'default', groups: [{ id: 'default', name: '默认分组', createdAt: now, updatedAt: now }], connections: [], recentTargets: [] }
}

function readPreviewAssets(): ConnectionAssetSnapshot {
  const stored = localStorage.getItem(previewAssetsKey)
  return stored ? JSON.parse(stored) as ConnectionAssetSnapshot : emptyPreviewAssets()
}

function writePreviewAssets(snapshot: ConnectionAssetSnapshot): void {
  localStorage.setItem(previewAssetsKey, JSON.stringify(snapshot))
}

function isTauriRuntime(): boolean {
  return '__TAURI_INTERNALS__' in window
}

function emitBrowserOutput(sessionId: string, text: string): void {
  const data = Array.from(new TextEncoder().encode(text))
  browserOutputHandlers.forEach((handler) => handler({ sessionId, data }))
}

export async function healthCheck(): Promise<HealthResponse> {
  if (!isTauriRuntime()) {
    return { status: 'ok', protocolVersion: 1, appVersion: 'browser-preview' }
  }

  return invoke<HealthResponse>('health_check')
}

export async function listConnectionAssets(): Promise<ConnectionAssetSnapshot> {
  if (!isTauriRuntime()) return readPreviewAssets()
  return invoke<ConnectionAssetSnapshot>('list_connection_assets')
}

export async function saveConnectionProfile(request: SaveConnectionRequest): Promise<ConnectionProfile> {
  if (!isTauriRuntime()) {
    const assets = readPreviewAssets()
    const now = new Date().toISOString()
    const existing = assets.connections.find((item) => item.id === request.id)
    const profile: ConnectionProfile = {
      id: request.id ?? crypto.randomUUID(), name: request.name, host: request.host, port: request.port,
      username: request.username, authType: request.authType,
      credentialRef: request.rememberCredential ? `TerminalT/preview/${request.id ?? 'new'}` : undefined,
      privateKeyPath: request.privateKeyPath, groupId: request.groupId, note: request.note,
      timeoutSeconds: request.timeoutSeconds, lastConnectedAt: existing?.lastConnectedAt,
      createdAt: existing?.createdAt ?? now, updatedAt: now,
    }
    assets.connections = assets.connections.filter((item) => item.id !== profile.id)
    assets.connections.push(profile)
    writePreviewAssets(assets)
    return profile
  }
  return invoke<ConnectionProfile>('save_connection_profile', { request })
}

export async function copyConnectionProfile(connectionId: string): Promise<ConnectionProfile> {
  if (!isTauriRuntime()) {
    const assets = readPreviewAssets()
    const source = assets.connections.find((item) => item.id === connectionId)
    if (!source) throw new Error('连接不存在')
    const now = new Date().toISOString()
    const copy = { ...source, id: crypto.randomUUID(), name: `${source.name} - 副本`, credentialRef: undefined, createdAt: now, updatedAt: now, lastConnectedAt: undefined }
    assets.connections.push(copy)
    writePreviewAssets(assets)
    return copy
  }
  return invoke<ConnectionProfile>('copy_connection_profile', { connectionId })
}

export async function deleteConnectionProfile(connectionId: string): Promise<void> {
  if (!isTauriRuntime()) {
    const assets = readPreviewAssets(); assets.connections = assets.connections.filter((item) => item.id !== connectionId); writePreviewAssets(assets); return
  }
  await invoke('delete_connection_profile', { connectionId })
}

export async function saveConnectionGroup(name: string, id?: string): Promise<ConnectionGroup> {
  if (!isTauriRuntime()) {
    const assets = readPreviewAssets(); const now = new Date().toISOString()
    const group = { id: id ?? crypto.randomUUID(), name, createdAt: assets.groups.find((item) => item.id === id)?.createdAt ?? now, updatedAt: now }
    assets.groups = assets.groups.filter((item) => item.id !== group.id); assets.groups.push(group); writePreviewAssets(assets); return group
  }
  return invoke<ConnectionGroup>('save_connection_group', { request: { id, name } })
}

export async function deleteConnectionGroup(groupId: string): Promise<void> {
  if (!isTauriRuntime()) {
    const assets = readPreviewAssets(); assets.groups = assets.groups.filter((item) => item.id !== groupId); assets.connections = assets.connections.map((item) => item.groupId === groupId ? { ...item, groupId: assets.defaultGroupId } : item); writePreviewAssets(assets); return
  }
  await invoke('delete_connection_group', { groupId })
}

export async function recordRecentTarget(target: string): Promise<void> {
  if (!isTauriRuntime()) return
  await invoke('record_recent_target', { target })
}

export async function clearRecentTargets(): Promise<void> {
  if (!isTauriRuntime()) { const assets = readPreviewAssets(); assets.recentTargets = []; writePreviewAssets(assets); return }
  await invoke('clear_recent_targets')
}

export async function listHostKeys(): Promise<StoredHostKeyRecord[]> {
  if (!isTauriRuntime()) return []
  return invoke<StoredHostKeyRecord[]>('list_host_keys')
}

export async function deleteHostKey(host: string, port: number): Promise<void> {
  if (!isTauriRuntime()) return
  await invoke('delete_host_key', { host, port })
}

export async function createMockSession(title = '架构验证会话'): Promise<SessionState> {
  if (!isTauriRuntime()) {
    const session: SessionState = {
      id: crypto.randomUUID(),
      title,
      status: 'connected',
      startedAt: new Date().toISOString(),
    }
    window.setTimeout(() => {
      browserStatusHandlers.forEach((handler) =>
        handler({ sessionId: session.id, status: 'connected' }),
      )
      emitBrowserOutput(
        session.id,
        '\u001b[38;2;50;215;168mTerminalT mock session ready.\u001b[0m\r\n' +
          'IPC protocol v1 · UTF-8: 中文 / 🚀\r\n\u001b[36mterminalt\u001b[0m $ ',
      )
    }, 80)
    return session
  }

  return invoke<SessionState>('create_mock_session')
}

export async function writeMockSession(sessionId: string, input: string): Promise<void> {
  const data = Array.from(new TextEncoder().encode(input))
  if (!isTauriRuntime()) {
    emitBrowserOutput(sessionId, input)
    if (input === '\r') {
      emitBrowserOutput(sessionId, '\n\u001b[36mterminalt\u001b[0m $ ')
    }
    return
  }

  await invoke('write_mock_session', { sessionId, data })
}

export async function resizeMockSession(
  sessionId: string,
  size: TerminalSize,
): Promise<void> {
  if (!isTauriRuntime()) return
  await invoke('resize_mock_session', { sessionId, ...size })
}

export async function closeMockSession(sessionId: string): Promise<void> {
  if (!isTauriRuntime()) {
    browserStatusHandlers.forEach((handler) =>
      handler({ sessionId, status: 'disconnected', message: '会话已关闭' }),
    )
    return
  }
  await invoke('close_mock_session', { sessionId })
}

export async function inspectSshHostKey(
  operationId: string,
  request: Pick<ConnectionRequest, 'host' | 'port' | 'timeoutSeconds'>,
): Promise<HostKeyInspection> {
  if (!isTauriRuntime()) {
    browserProgressHandlers.forEach((handler) => handler({
      operationId,
      status: 'host-key-check',
      message: '正在获取服务器指纹',
    }))
    await new Promise((resolve) => window.setTimeout(resolve, 120))
    return {
      host: request.host,
      port: request.port,
      algorithm: 'ssh-ed25519',
      fingerprintSha256: 'SHA256:BrowserPreviewFingerprint',
      status: 'unknown',
    }
  }
  return invoke<HostKeyInspection>('inspect_ssh_host_key', {
    operationId,
    host: request.host,
    port: request.port,
    timeoutSeconds: request.timeoutSeconds,
  })
}

export async function testSshConnection(
  operationId: string,
  request: ConnectionRequest,
  approval: HostKeyApproval,
): Promise<ConnectionTestResult> {
  if (!isTauriRuntime()) {
    await new Promise((resolve) => window.setTimeout(resolve, 160))
    return {
      elapsedMillis: 186,
      hostKey: {
        host: request.host,
        port: request.port,
        algorithm: 'ssh-ed25519',
        fingerprintSha256: approval.fingerprintSha256,
        status: 'trusted',
      },
    }
  }
  return invoke<ConnectionTestResult>('test_ssh_connection', {
    operationId,
    request,
    approval,
  })
}

export async function connectSsh(
  operationId: string,
  request: ConnectionRequest,
  approval: HostKeyApproval,
): Promise<SessionState> {
  if (!isTauriRuntime()) return createMockSession(request.name)
  return invoke<SessionState>('connect_ssh', { operationId, request, approval })
}

export async function testSavedConnection(
  operationId: string,
  connectionId: string,
  temporarySecret: string | undefined,
  approval: HostKeyApproval,
  keepalive: KeepaliveOptions,
): Promise<ConnectionTestResult> {
  if (!isTauriRuntime()) {
    const profile = readPreviewAssets().connections.find((item) => item.id === connectionId)
    if (!profile) throw new Error('连接不存在')
    return testSshConnection(operationId, toPreviewRequest(profile, temporarySecret), approval)
  }
  return invoke<ConnectionTestResult>('test_saved_connection', {
    operationId,
    request: { connectionId, temporarySecret, approval, keepalive },
  })
}

export async function connectSavedConnection(
  operationId: string,
  connectionId: string,
  temporarySecret: string | undefined,
  approval: HostKeyApproval,
  keepalive: KeepaliveOptions,
): Promise<SessionState> {
  if (!isTauriRuntime()) {
    const profile = readPreviewAssets().connections.find((item) => item.id === connectionId)
    if (!profile) throw new Error('连接不存在')
    return connectSsh(operationId, toPreviewRequest(profile, temporarySecret), approval)
  }
  return invoke<SessionState>('connect_saved_connection', {
    operationId,
    request: { connectionId, temporarySecret, approval, keepalive },
  })
}

export async function reconnectSsh(
  operationId: string,
  sessionId: string,
  request: ConnectionRequest,
  approval: HostKeyApproval,
): Promise<SessionState> {
  if (!isTauriRuntime()) {
    await new Promise((resolve) => window.setTimeout(resolve, 120))
    const session: SessionState = {
      id: sessionId,
      title: request.name,
      status: 'connected',
      startedAt: new Date().toISOString(),
    }
    browserStatusHandlers.forEach((handler) => handler({ sessionId, status: 'connected' }))
    emitBrowserOutput(sessionId, '\u001b[32mReconnected.\u001b[0m\r\n\u001b[36mterminalt\u001b[0m $ ')
    return session
  }
  return invoke<SessionState>('reconnect_ssh', { operationId, sessionId, request, approval })
}

export async function reconnectSavedConnection(
  operationId: string,
  sessionId: string,
  connectionId: string,
  temporarySecret: string | undefined,
  approval: HostKeyApproval,
  keepalive: KeepaliveOptions,
): Promise<SessionState> {
  if (!isTauriRuntime()) {
    const profile = readPreviewAssets().connections.find((item) => item.id === connectionId)
    if (!profile) throw new Error('连接不存在')
    return reconnectSsh(operationId, sessionId, toPreviewRequest(profile, temporarySecret), approval)
  }
  return invoke<SessionState>('reconnect_saved_connection', {
    operationId,
    request: { sessionId, connectionId, temporarySecret, approval, keepalive },
  })
}

function toPreviewRequest(profile: ConnectionProfile, secret?: string): ConnectionRequest {
  return {
    name: profile.name,
    host: profile.host,
    port: profile.port,
    username: profile.username,
    authType: profile.authType,
    password: profile.authType === 'password' ? secret ?? 'preview-stored-secret' : '',
    privateKeyPath: profile.privateKeyPath ?? '',
    privateKeyPassphrase: profile.authType === 'privateKey' ? secret ?? '' : '',
    timeoutSeconds: profile.timeoutSeconds,
    keepaliveEnabled: true,
    keepaliveSeconds: 30,
    columns: 80,
    rows: 24,
  }
}

export async function cancelOperation(operationId: string): Promise<void> {
  if (!isTauriRuntime()) return
  await invoke('cancel_operation', { operationId })
}

export async function listenToSessionOutput(handler: OutputHandler): Promise<UnlistenFn> {
  if (!isTauriRuntime()) {
    browserOutputHandlers.add(handler)
    return () => browserOutputHandlers.delete(handler)
  }
  return listen<SessionOutputPayload>('session-output', (event) => handler(event.payload))
}

export async function listenToSessionStatus(handler: StatusHandler): Promise<UnlistenFn> {
  if (!isTauriRuntime()) {
    browserStatusHandlers.add(handler)
    return () => browserStatusHandlers.delete(handler)
  }
  return listen<SessionStatusPayload>('session-status', (event) => handler(event.payload))
}

export async function listenToConnectionProgress(handler: ProgressHandler): Promise<UnlistenFn> {
  if (!isTauriRuntime()) {
    browserProgressHandlers.add(handler)
    return () => browserProgressHandlers.delete(handler)
  }
  return listen<ConnectionProgressPayload>('connection-progress', (event) => handler(event.payload))
}

export async function writeSession(sessionId: string, input: string): Promise<void> {
  const data = Array.from(new TextEncoder().encode(input))
  if (!isTauriRuntime()) return writeMockSession(sessionId, input)
  await invoke('write_session', { sessionId, data })
}

export async function resizeSession(sessionId: string, size: TerminalSize): Promise<void> {
  if (!isTauriRuntime()) return resizeMockSession(sessionId, size)
  await invoke('resize_session', { sessionId, ...size })
}

export async function closeSession(sessionId: string): Promise<void> {
  if (!isTauriRuntime()) return closeMockSession(sessionId)
  await invoke('close_session', { sessionId })
}

export async function listRemoteDirectory(
  sessionId: string,
  path?: string,
): Promise<RemoteDirectoryListing> {
  if (!isTauriRuntime()) {
    const directory = path ?? '/home/terminalt'
    return {
      path: directory,
      parentPath: directory === '/' ? undefined : directory.slice(0, directory.lastIndexOf('/')) || '/',
      truncated: false,
      entries: [
        { name: 'projects', path: `${directory.replace(/\/$/, '')}/projects`, kind: 'directory', size: 0, modifiedAt: new Date().toISOString(), permissions: 'drwxr-xr-x' },
        { name: '.config', path: `${directory.replace(/\/$/, '')}/.config`, kind: 'directory', size: 0, modifiedAt: new Date().toISOString(), permissions: 'drwx------' },
        { name: 'README.md', path: `${directory.replace(/\/$/, '')}/README.md`, kind: 'file', size: 1842, modifiedAt: new Date().toISOString(), permissions: '-rw-r--r--' },
      ],
    }
  }
  return invoke<RemoteDirectoryListing>('list_remote_directory', { sessionId, path })
}

export async function createRemoteDirectory(sessionId: string, parentPath: string, name: string): Promise<void> {
  if (!isTauriRuntime()) return
  await invoke('create_remote_directory', { sessionId, parentPath, name })
}

export async function renameRemoteEntry(sessionId: string, path: string, newName: string): Promise<void> {
  if (!isTauriRuntime()) return
  await invoke('rename_remote_entry', { sessionId, path, newName })
}

export async function deleteRemoteEntry(sessionId: string, path: string): Promise<void> {
  if (!isTauriRuntime()) return
  await invoke('delete_remote_entry', { sessionId, path })
}

export async function startTransfer(
  sessionId: string, direction: TransferDirection, source: string, target: string, overwrite: boolean,
): Promise<TransferTask> {
  if (!isTauriRuntime()) throw new Error('浏览器预览不支持真实文件传输')
  return invoke<TransferTask>('start_transfer', { sessionId, direction, source, target, overwrite })
}

export async function cancelTransfer(sessionId: string, taskId: string): Promise<void> {
  if (!isTauriRuntime()) return
  await invoke('cancel_transfer', { sessionId, taskId })
}

export async function listenToTransferProgress(handler: TransferHandler): Promise<UnlistenFn> {
  if (!isTauriRuntime()) return () => undefined
  return listen<TransferProgressPayload>('transfer-progress', (event) => handler(event.payload))
}

export function normalizeCommandError(error: unknown): AppCommandError {
  if (typeof error === 'object' && error !== null && 'code' in error && 'message' in error) {
    const candidate = error as Partial<AppCommandError>
    return {
      code: String(candidate.code),
      category: candidate.category ?? 'unknown',
      message: String(candidate.message),
      technicalDetails: candidate.technicalDetails,
      retryable: candidate.retryable ?? false,
    }
  }

  return {
    code: 'APP-UNKNOWN',
    category: 'unknown',
    message: '操作未能完成',
    technicalDetails: error instanceof Error ? error.message : String(error),
    retryable: false,
  }
}
