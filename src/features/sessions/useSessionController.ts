import { useCallback, useEffect, useReducer } from 'react'
import type { SessionState, SessionStatusPayload } from '../../domain/session/types'
import {
  closeSession as closeRuntimeSession,
  connectSavedConnection,
  connectSsh,
  listenToSessionStatus,
  normalizeCommandError,
  reconnectSavedConnection,
  reconnectSsh,
  type KeepaliveOptions,
} from '../../lib/ipc'
import type { ConnectionDraft, ConnectionRequest, HostKeyApproval } from '../../domain/connection/types'

export type SessionReconnectSource =
  | { kind: 'saved'; connectionId: string; draft: ConnectionDraft }
  | { kind: 'request'; draft: ConnectionDraft }

export interface ManagedSession extends SessionState {
  reconnectSource: SessionReconnectSource
  reconnectGeneration: number
  reconnecting: boolean
}

interface SessionControllerState {
  sessions: ManagedSession[]
  activeSessionId?: string
  pending: boolean
  error?: string
}

type SessionAction =
  | { type: 'create-started' }
  | { type: 'created'; session: ManagedSession }
  | { type: 'create-failed'; message: string }
  | { type: 'status-changed'; payload: SessionStatusPayload }
  | { type: 'activated'; sessionId: string }
  | { type: 'closed'; sessionId: string }
  | { type: 'reconnect-started'; sessionId: string }
  | { type: 'reconnected'; sessionId: string; session: SessionState }
  | { type: 'reconnect-failed'; sessionId: string; message: string }

export const initialSessionControllerState: SessionControllerState = {
  sessions: [],
  pending: false,
}

export function sessionReducer(
  state: SessionControllerState,
  action: SessionAction,
): SessionControllerState {
  switch (action.type) {
    case 'create-started':
      return { ...state, pending: true, error: undefined }
    case 'created':
      return {
        ...state,
        pending: false,
        sessions: [...state.sessions, action.session],
        activeSessionId: action.session.id,
      }
    case 'create-failed':
      return { ...state, pending: false, error: action.message }
    case 'status-changed':
      return {
        ...state,
        sessions: state.sessions.map((session) =>
          session.id === action.payload.sessionId
            ? {
                ...session,
                status: action.payload.status,
                lastError: action.payload.status === 'failed' ? action.payload.message : undefined,
                disconnectReason: action.payload.status === 'disconnected'
                  ? action.payload.message
                  : undefined,
              }
            : session,
        ),
      }
    case 'activated':
      return { ...state, activeSessionId: action.sessionId }
    case 'closed': {
      const closedIndex = state.sessions.findIndex((session) => session.id === action.sessionId)
      const remaining = state.sessions.filter((session) => session.id !== action.sessionId)
      return {
        ...state,
        sessions: remaining,
        activeSessionId:
          state.activeSessionId === action.sessionId
            ? remaining[Math.min(closedIndex, remaining.length - 1)]?.id
            : state.activeSessionId,
      }
    }
    case 'reconnect-started':
      return {
        ...state,
        error: undefined,
        sessions: state.sessions.map((session) => session.id === action.sessionId
          ? {
              ...session,
              status: 'connecting',
              lastError: undefined,
              reconnecting: true,
              reconnectGeneration: session.reconnectGeneration + 1,
            }
          : session),
      }
    case 'reconnected':
      return {
        ...state,
        sessions: state.sessions.map((session) => session.id === action.sessionId
          ? {
              ...session,
              ...action.session,
              id: action.sessionId,
              reconnectSource: session.reconnectSource,
              reconnectGeneration: session.reconnectGeneration,
              reconnecting: false,
              lastError: undefined,
              disconnectReason: undefined,
            }
          : session),
      }
    case 'reconnect-failed':
      return {
        ...state,
        sessions: state.sessions.map((session) => session.id === action.sessionId
          ? { ...session, status: 'failed', reconnecting: false, lastError: action.message }
          : session),
      }
  }
}

export function useSessionController() {
  const [state, dispatch] = useReducer(sessionReducer, initialSessionControllerState)

  useEffect(() => {
    let disposed = false
    let unlisten: (() => void) | undefined
    void listenToSessionStatus((payload) => {
      if (!disposed) dispatch({ type: 'status-changed', payload })
    }).then((cleanup) => {
      if (disposed) cleanup()
      else unlisten = cleanup
    })

    return () => {
      disposed = true
      unlisten?.()
    }
  }, [])

  const startSavedSession = useCallback(async (
    operationId: string,
    connectionId: string,
    temporarySecret: string | undefined,
    approval: HostKeyApproval,
    reconnectDraft: ConnectionDraft,
    keepalive: KeepaliveOptions,
  ) => {
    dispatch({ type: 'create-started' })
    try {
      const session = await connectSavedConnection(
        operationId,
        connectionId,
        temporarySecret,
        approval,
        keepalive,
      )
      dispatch({
        type: 'created',
        session: {
          ...session,
          reconnectSource: { kind: 'saved', connectionId, draft: reconnectDraft },
          reconnectGeneration: 0,
          reconnecting: false,
        },
      })
    } catch (error) {
      dispatch({ type: 'create-failed', message: normalizeCommandError(error).message })
      throw error
    }
  }, [])

  const startSession = useCallback(async (
    operationId: string,
    request: ConnectionRequest,
    approval: HostKeyApproval,
    reconnectDraft: ConnectionDraft,
  ) => {
    dispatch({ type: 'create-started' })
    try {
      const session = await connectSsh(operationId, request, approval)
      dispatch({
        type: 'created',
        session: {
          ...session,
          reconnectSource: { kind: 'request', draft: reconnectDraft },
          reconnectGeneration: 0,
          reconnecting: false,
        },
      })
    } catch (error) {
      dispatch({ type: 'create-failed', message: normalizeCommandError(error).message })
      throw error
    }
  }, [])

  const closeSession = useCallback(async (sessionId: string) => {
    await closeRuntimeSession(sessionId)
    dispatch({ type: 'closed', sessionId })
  }, [])

  const activateSession = useCallback((sessionId: string) => {
    dispatch({ type: 'activated', sessionId })
  }, [])

  const reconnectSession = useCallback(async (
    sessionId: string,
    operationId: string,
    request: ConnectionRequest,
    approval: HostKeyApproval,
  ) => {
    dispatch({ type: 'reconnect-started', sessionId })
    try {
      const session = await reconnectSsh(operationId, sessionId, request, approval)
      dispatch({ type: 'reconnected', sessionId, session })
    } catch (error) {
      dispatch({ type: 'reconnect-failed', sessionId, message: normalizeCommandError(error).message })
      throw error
    }
  }, [])

  const reconnectSavedSession = useCallback(async (
    sessionId: string,
    operationId: string,
    connectionId: string,
    temporarySecret: string | undefined,
    approval: HostKeyApproval,
    keepalive: KeepaliveOptions,
  ) => {
    dispatch({ type: 'reconnect-started', sessionId })
    try {
      const session = await reconnectSavedConnection(
        operationId,
        sessionId,
        connectionId,
        temporarySecret,
        approval,
        keepalive,
      )
      dispatch({ type: 'reconnected', sessionId, session })
    } catch (error) {
      dispatch({ type: 'reconnect-failed', sessionId, message: normalizeCommandError(error).message })
      throw error
    }
  }, [])

  return {
    ...state,
    startSession,
    startSavedSession,
    reconnectSession,
    reconnectSavedSession,
    closeSession,
    activateSession,
  }
}
