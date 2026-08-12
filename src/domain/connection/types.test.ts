import { describe, expect, it } from 'vitest'
import {
  initialConnectionDraft,
  toConnectionRequest,
  toReconnectDraft,
  validateConnectionDraft,
  parseQuickTarget,
  filterConnections,
} from './types'

describe('connection form', () => {
  it('removes temporary secrets from reconnect state', () => {
    const reconnect = toReconnectDraft({
      ...initialConnectionDraft,
      name: 'server',
      host: 'example.com',
      username: 'user',
      password: 'temporary-password',
      privateKeyPassphrase: 'temporary-passphrase',
    })

    expect(reconnect.password).toBe('')
    expect(reconnect.privateKeyPassphrase).toBe('')
  })

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

  it('parses quick targets including bracketed IPv6', () => {
    expect(parseQuickTarget('alice@server.example:2200')).toEqual({ username: 'alice', host: 'server.example', port: 2200 })
    expect(parseQuickTarget('root@[2001:db8::1]:2222')).toEqual({ username: 'root', host: '2001:db8::1', port: 2222 })
    expect(() => parseQuickTarget('root@2001:db8::1')).toThrow('方括号')
  })


  it('searches name, host, username, and note without case sensitivity', () => {
    const profile = {
      id: 'one', name: 'Production', host: 'api.example', port: 22, username: 'Deploy',
      authType: 'password' as const, groupId: 'default', note: 'Primary database', timeoutSeconds: 15,
      createdAt: '', updatedAt: '',
    }
    expect(filterConnections([profile], ' production ')).toHaveLength(1)
    expect(filterConnections([profile], 'EXAMPLE')).toHaveLength(1)
    expect(filterConnections([profile], 'deploy')).toHaveLength(1)
    expect(filterConnections([profile], 'database')).toHaveLength(1)
    expect(filterConnections([profile], 'missing')).toHaveLength(0)
  })
})
