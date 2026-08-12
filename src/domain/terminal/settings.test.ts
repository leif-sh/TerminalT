import { describe, expect, it } from 'vitest'
import { defaultTerminalSettings, normalizeTerminalSettings } from './settings'

describe('terminal settings', () => {
  it('uses safe defaults for invalid persisted data', () => {
    expect(normalizeTerminalSettings(null)).toEqual(defaultTerminalSettings)
    expect(normalizeTerminalSettings({ fontSize: 'large', cursorStyle: 'beam' })).toMatchObject({
      fontSize: 14,
      cursorStyle: 'bar',
      confirmCloseSession: true,
    })
  })

  it('clamps numeric settings to supported ranges', () => {
    expect(normalizeTerminalSettings({ fontSize: 99, lineHeight: 0.5, scrollback: 300 })).toMatchObject({
      fontSize: 32,
      lineHeight: 1,
      scrollback: 1_000,
    })
  })
})
