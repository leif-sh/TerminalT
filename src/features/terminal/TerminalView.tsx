import { useEffect, useRef } from 'react'
import { FitAddon } from '@xterm/addon-fit'
import { Terminal } from '@xterm/xterm'
import '@xterm/xterm/css/xterm.css'
import type { SessionState } from '../../domain/session/types'
import {
  listenToSessionOutput,
  resizeSession,
  writeSession,
} from '../../lib/ipc'

interface TerminalViewProps {
  session: SessionState
  active: boolean
}

export function TerminalView({ session, active }: TerminalViewProps) {
  const containerRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const container = containerRef.current
    if (!container) return

    const terminal = new Terminal({
      allowProposedApi: false,
      convertEol: false,
      cursorBlink: true,
      cursorStyle: 'bar',
      fontFamily: 'JetBrains Mono, Cascadia Code, Consolas, monospace',
      fontSize: 14,
      lineHeight: 1.25,
      scrollback: 10_000,
      theme: {
        background: '#050b15',
        foreground: '#d9e5f5',
        cursor: '#5f8cff',
        selectionBackground: '#2458a866',
        black: '#07101d',
        brightBlack: '#56708f',
        blue: '#4f8cff',
        brightBlue: '#79a8ff',
        cyan: '#22d3ee',
        brightCyan: '#67e8f9',
        green: '#32d7a8',
        brightGreen: '#6ee7c6',
        magenta: '#8b5cf6',
        brightMagenta: '#a78bfa',
        red: '#fb7185',
        brightRed: '#fda4af',
        white: '#d9e5f5',
        brightWhite: '#f8fbff',
        yellow: '#fbbf24',
        brightYellow: '#fcd34d',
      },
    })
    const fitAddon = new FitAddon()
    terminal.loadAddon(fitAddon)
    terminal.open(container)

    const resize = () => {
      fitAddon.fit()
      void resizeSession(session.id, {
        columns: terminal.cols,
        rows: terminal.rows,
      })
    }
    const observer = new ResizeObserver(resize)
    observer.observe(container)
    resize()

    const inputDisposable = terminal.onData((input) => {
      void writeSession(session.id, input)
    })

    let disposed = false
    let unlisten: (() => void) | undefined
    void listenToSessionOutput((payload) => {
      if (payload.sessionId === session.id && !disposed) {
        terminal.write(new Uint8Array(payload.data))
      }
    }).then((cleanup) => {
      if (disposed) cleanup()
      else unlisten = cleanup
    })

    return () => {
      disposed = true
      unlisten?.()
      inputDisposable.dispose()
      observer.disconnect()
      terminal.dispose()
    }
  }, [session.id])

  useEffect(() => {
    if (active) containerRef.current?.focus()
  }, [active])

  return (
    <div
      ref={containerRef}
      className="terminal-view"
      role="application"
      aria-label={`${session.title} 终端`}
      hidden={!active}
    />
  )
}
