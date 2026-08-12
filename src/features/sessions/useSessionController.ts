import { useCallback, useEffect, useReducer } from 'react'
import type { SessionState, SessionStatusPayload } from '../../domain/session/types'
import {
  closeSession as closeRuntimeSession,
  connectSavedConnection,
  connectSsh,
  listenToSessionStatus,
  normalizeCommandError,
} from '../../lib/ipc'
import type { ConnectionRequest, HostKeyApproval } from '../../domain/connection/types'

interface SessionControllerState {
  sessions: SessionState[]
  activeSessionId?: string
  pending: boolean
  error?: string
}

type SessionAction =
  | { type: 'create-started' }
  | { type: 'created'; session: SessionState }
  | { type: 'create-failed'; message: string }
  | { type: 'status-changed'; payload: SessionStatusPayload }
  | { type: 'activated'; sessionId: string }
  | { type: 'closed'; sessionId: string }

const initialState: SessionControllerState = {
  sessions: [],
  pending: false,
}

function sessionReducer(
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
  }
}

export function useSessionController() {
  const [state, dispatch] = useReducer(sessionReducer, initialState)

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
  ) => {
    dispatch({ type: 'create-started' })
    try {
      const session = await connectSavedConnection(operationId, connectionId, temporarySecret, approval)
      dispatch({ type: 'created', session })
    } catch (error) {
      dispatch({ type: 'create-failed', message: normalizeCommandError(error).message })
      throw error
    }
  }, [])

  const startSession = useCallback(async (
    operationId: string,
    request: ConnectionRequest,
    approval: HostKeyApproval,
  ) => {
    dispatch({ type: 'create-started' })
    try {
      const session = await connectSsh(operationId, request, approval)
      dispatch({ type: 'created', session })
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

  return { ...state, startSession, startSavedSession, closeSession, activateSession }
}
