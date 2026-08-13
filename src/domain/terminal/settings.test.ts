import { describe, expect, it } from 'vitest'
import { defaultTerminalSettings, normalizeTerminalSettings } from './settings'

describe('terminal settings', () => {
  it('uses safe defaults for invalid persisted data', () => {
    expect(normalizeTerminalSettings(null)).toEqual(defaultTerminalSettings)
    expect(normalizeTerminalSettings({ fontSize: 'large', cursorStyle: 'beam' })).toMatchObject({
      fontSize: 14,
      cursorStyle: 'bar',
      confirmCloseSession: true,
      keepaliveEnabled: true,
      keepaliveSeconds: 30,
      connectionTimeoutSeconds: 15,
    })
  })

  it('clamps numeric settings to supported ranges', () => {
    expect(normalizeTerminalSettings({ fontSize: 99, lineHeight: 0.5, scrollback: 300 })).toMatchObject({
      fontSize: 32,
      lineHeight: 1,
      scrollback: 1_000,
    })
  })

  it('normalizes keepalive preferences', () => {
    expect(normalizeTerminalSettings({ keepaliveEnabled: false, keepaliveSeconds: 999 })).toMatchObject({
      keepaliveEnabled: false,
      keepaliveSeconds: 300,
    })
  })

  it('normalizes connection timeout and download directory', () => {
    expect(normalizeTerminalSettings({ connectionTimeoutSeconds: 90, defaultDownloadDirectory: 'D:\\Downloads' })).toMatchObject({
      connectionTimeoutSeconds: 60,
      defaultDownloadDirectory: 'D:\\Downloads',
    })
  })
})
