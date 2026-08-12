import type { ITerminalOptions, ITheme } from '@xterm/xterm'

export type TerminalThemeName = 'dark' | 'light'

export interface TerminalSettings {
  fontFamily: string
  fontSize: number
  lineHeight: number
  theme: TerminalThemeName
  cursorStyle: NonNullable<ITerminalOptions['cursorStyle']>
  cursorBlink: boolean
  scrollback: number
  confirmCloseSession: boolean
  keepaliveEnabled: boolean
  keepaliveSeconds: number
}

export const defaultTerminalSettings: TerminalSettings = {
  fontFamily: 'JetBrains Mono, Cascadia Code, Consolas, monospace',
  fontSize: 14,
  lineHeight: 1.2,
  theme: 'dark',
  cursorStyle: 'bar',
  cursorBlink: true,
  scrollback: 10_000,
  confirmCloseSession: true,
  keepaliveEnabled: true,
  keepaliveSeconds: 30,
}

export const terminalThemes: Record<TerminalThemeName, ITheme> = {
  dark: {
    background: '#050b15', foreground: '#d9e5f5', cursor: '#5f8cff',
    selectionBackground: '#2458a866', black: '#07101d', brightBlack: '#56708f',
    blue: '#4f8cff', brightBlue: '#79a8ff', cyan: '#22d3ee', brightCyan: '#67e8f9',
    green: '#32d7a8', brightGreen: '#6ee7c6', magenta: '#8b5cf6', brightMagenta: '#a78bfa',
    red: '#fb7185', brightRed: '#fda4af', white: '#d9e5f5', brightWhite: '#f8fbff',
    yellow: '#fbbf24', brightYellow: '#fcd34d',
  },
  light: {
    background: '#f5f7fb', foreground: '#182337', cursor: '#245dcc',
    selectionBackground: '#8ab4f866', black: '#182337', brightBlack: '#607089',
    blue: '#245dcc', brightBlue: '#3977e6', cyan: '#087f8c', brightCyan: '#0e9aaa',
    green: '#087f5b', brightGreen: '#0b9b70', magenta: '#7048b8', brightMagenta: '#875bd0',
    red: '#c9364f', brightRed: '#df5067', white: '#d7dee9', brightWhite: '#ffffff',
    yellow: '#9a6700', brightYellow: '#b77900',
  },
}

const cursorStyles = new Set<TerminalSettings['cursorStyle']>(['block', 'bar', 'underline'])

export function normalizeTerminalSettings(value: unknown): TerminalSettings {
  if (!value || typeof value !== 'object') return { ...defaultTerminalSettings }
  const input = value as Partial<TerminalSettings>
  return {
    fontFamily: typeof input.fontFamily === 'string' && input.fontFamily.trim()
      ? input.fontFamily.trim()
      : defaultTerminalSettings.fontFamily,
    fontSize: clampNumber(input.fontSize, 10, 32, defaultTerminalSettings.fontSize),
    lineHeight: clampNumber(input.lineHeight, 1, 2, defaultTerminalSettings.lineHeight),
    theme: input.theme === 'light' ? 'light' : 'dark',
    cursorStyle: input.cursorStyle && cursorStyles.has(input.cursorStyle)
      ? input.cursorStyle
      : defaultTerminalSettings.cursorStyle,
    cursorBlink: typeof input.cursorBlink === 'boolean' ? input.cursorBlink : defaultTerminalSettings.cursorBlink,
    scrollback: clampNumber(input.scrollback, 1_000, 100_000, defaultTerminalSettings.scrollback),
    confirmCloseSession: typeof input.confirmCloseSession === 'boolean'
      ? input.confirmCloseSession
      : defaultTerminalSettings.confirmCloseSession,
    keepaliveEnabled: typeof input.keepaliveEnabled === 'boolean'
      ? input.keepaliveEnabled
      : defaultTerminalSettings.keepaliveEnabled,
    keepaliveSeconds: clampNumber(input.keepaliveSeconds, 5, 300, defaultTerminalSettings.keepaliveSeconds),
  }
}

function clampNumber(value: unknown, minimum: number, maximum: number, fallback: number): number {
  return typeof value === 'number' && Number.isFinite(value)
    ? Math.min(maximum, Math.max(minimum, value))
    : fallback
}
