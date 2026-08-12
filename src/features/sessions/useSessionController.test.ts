import { describe, expect, it } from 'vitest'
import { initialConnectionDraft } from '../../domain/connection/types'
import {
  initialSessionControllerState,
  sessionReducer,
  type ManagedSession,
} from './useSessionController'

function session(id: string): ManagedSession {
  return {
    id,
    title: id,
    status: 'connected',
    startedAt: '2026-08-12T00:00:00.000Z',
    reconnectSource: {
      kind: 'request',
      draft: { ...initialConnectionDraft, name: id, host: 'example.com', username: 'user' },
    },
    reconnectGeneration: 0,
    reconnecting: false,
  }
}

describe('session reconnect state', () => {
  it('isolates reconnect state from other tabs', () => {
    const first = session('first')
    const second = session('second')
    const state = { ...initialSessionControllerState, sessions: [first, second], activeSessionId: 'first' }

    const reconnecting = sessionReducer(state, { type: 'reconnect-started', sessionId: 'first' })

    expect(reconnecting.sessions[0]).toMatchObject({
      id: 'first',
      status: 'connecting',
      reconnecting: true,
      reconnectGeneration: 1,
    })
    expect(reconnecting.sessions[1]).toEqual(second)
  })

  it('keeps the original tab identity and reconnect source after success', () => {
    const original = { ...session('stable-tab'), reconnectGeneration: 1, reconnecting: true }
    const state = { ...initialSessionControllerState, sessions: [original], activeSessionId: original.id }

    const reconnected = sessionReducer(state, {
      type: 'reconnected',
      sessionId: original.id,
      session: {
        id: 'stable-tab',
        title: 'new shell',
        status: 'connected',
        startedAt: '2026-08-12T01:00:00.000Z',
      },
    })

    expect(reconnected.sessions[0]).toMatchObject({
      id: 'stable-tab',
      title: 'new shell',
      status: 'connected',
      reconnectGeneration: 1,
      reconnecting: false,
      reconnectSource: original.reconnectSource,
    })
  })
})
