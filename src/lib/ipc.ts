import { invoke } from '@tauri-apps/api/core'
import { listen, type UnlistenFn } from '@tauri-apps/api/event'
import type {
  SessionOutputPayload,
  SessionState,
  SessionStatusPayload,
  TerminalSize,
} from '../domain/session/types'

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

const browserOutputHandlers = new Set<OutputHandler>()
const browserStatusHandlers = new Set<StatusHandler>()

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

export async function createMockSession(): Promise<SessionState> {
  if (!isTauriRuntime()) {
    const session: SessionState = {
      id: crypto.randomUUID(),
      title: '架构验证会话',
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
