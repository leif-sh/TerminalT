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
} from '../domain/connection/types'

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

type OutputHandler = (payload: SessionOutputPayload) => void
type StatusHandler = (payload: SessionStatusPayload) => void
type ProgressHandler = (payload: ConnectionProgressPayload) => void

const browserOutputHandlers = new Set<OutputHandler>()
const browserStatusHandlers = new Set<StatusHandler>()
const browserProgressHandlers = new Set<ProgressHandler>()

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
