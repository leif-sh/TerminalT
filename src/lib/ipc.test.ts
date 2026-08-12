import { describe, expect, it } from 'vitest'
import { normalizeCommandError } from './ipc'

describe('normalizeCommandError', () => {
  it('preserves the stable backend error contract', () => {
    const error = normalizeCommandError({
      code: 'SESSION-NOT-FOUND',
      category: 'session',
      message: '会话不存在或已经关闭',
      technicalDetails: 'missing session',
      retryable: false,
    })

    expect(error).toEqual({
      code: 'SESSION-NOT-FOUND',
      category: 'session',
      message: '会话不存在或已经关闭',
      technicalDetails: 'missing session',
      retryable: false,
    })
  })

  it('maps unknown failures without leaking arbitrary structure', () => {
    expect(normalizeCommandError(new Error('socket closed'))).toEqual({
      code: 'APP-UNKNOWN',
      category: 'unknown',
      message: '操作未能完成',
      technicalDetails: 'socket closed',
      retryable: false,
    })
  })
})
