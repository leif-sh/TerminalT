import { describe, expect, it } from 'vitest'
import {
  initialConnectionDraft,
  toConnectionRequest,
  validateConnectionDraft,
} from './types'

describe('connection form', () => {
  it('requires a host, username, and password', () => {
    expect(validateConnectionDraft(initialConnectionDraft)).toMatchObject({
      name: expect.any(String),
      host: expect.any(String),
      username: expect.any(String),
      password: expect.any(String),
    })
  })

  it('rejects unsafe numeric boundaries', () => {
    const draft = {
      ...initialConnectionDraft,
      host: 'server.example',
      port: 65_536,
      username: 'alice',
      password: 'secret',
      timeoutSeconds: 4,
    }

    expect(validateConnectionDraft(draft)).toMatchObject({
      port: expect.any(String),
      timeoutSeconds: expect.any(String),
    })
  })

  it('normalizes whitespace and derives an unnamed connection label', () => {
    const request = toConnectionRequest({
      ...initialConnectionDraft,
      host: '  server.example  ',
      username: '  alice  ',
      password: 'secret',
    })

    expect(request).toMatchObject({
      name: 'server.example',
      host: 'server.example',
      username: 'alice',
      columns: 80,
      rows: 24,
    })
  })

  it('requires a key path for private-key authentication', () => {
    expect(validateConnectionDraft({
      ...initialConnectionDraft,
      host: 'server.example',
      username: 'alice',
      authType: 'privateKey',
    })).toMatchObject({ privateKeyPath: expect.any(String) })
  })
})
