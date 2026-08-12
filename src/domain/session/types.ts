export type SessionStatus =
  | 'connecting'
  | 'host-key-check'
  | 'authenticating'
  | 'connected'
  | 'disconnected'
  | 'failed'

export interface SessionState {
  id: string
  title: string
  status: SessionStatus
  startedAt: string
  lastError?: string
  disconnectReason?: string
  reconnectGeneration?: number
  reconnecting?: boolean
}

export interface SessionOutputPayload {
  sessionId: string
  data: number[]
}

export interface SessionStatusPayload {
  sessionId: string
  status: SessionStatus
  message?: string
}

export interface TerminalSize {
  columns: number
  rows: number
}
