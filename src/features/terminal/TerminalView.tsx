import { useEffect, useRef, useState } from 'react'
import { FitAddon } from '@xterm/addon-fit'
import { SearchAddon } from '@xterm/addon-search'
import { Terminal } from '@xterm/xterm'
import '@xterm/xterm/css/xterm.css'
import type { SessionState } from '../../domain/session/types'
import type { TerminalSettings } from '../../domain/terminal/settings'
import { terminalThemes } from '../../domain/terminal/settings'
import { listenToSessionOutput, resizeSession, writeSession } from '../../lib/ipc'

interface TerminalViewProps {
  session: SessionState
  active: boolean
  settings: TerminalSettings
}

interface SearchResult {
  index: number
  count: number
}

interface ContextMenuPosition {
  x: number
  y: number
}

export function TerminalView({ session, active, settings }: TerminalViewProps) {
  const containerRef = useRef<HTMLDivElement>(null)
  const terminalRef = useRef<Terminal | undefined>(undefined)
  const fitAddonRef = useRef<FitAddon | undefined>(undefined)
  const searchAddonRef = useRef<SearchAddon | undefined>(undefined)
  const statusRef = useRef(session.status)
  const initialSettingsRef = useRef(settings)
  const [searchOpen, setSearchOpen] = useState(false)
  const [query, setQuery] = useState('')
  const [caseSensitive, setCaseSensitive] = useState(false)
  const [searchResult, setSearchResult] = useState<SearchResult>({ index: -1, count: 0 })
  const [pendingPaste, setPendingPaste] = useState<string>()
  const [contextMenu, setContextMenu] = useState<ContextMenuPosition>()

  statusRef.current = session.status

  useEffect(() => {
    const container = containerRef.current
    if (!container) return
    const initialSettings = initialSettingsRef.current

    const terminal = new Terminal({
      convertEol: false,
      cursorBlink: initialSettings.cursorBlink,
      cursorStyle: initialSettings.cursorStyle,
      fontFamily: initialSettings.fontFamily,
      fontSize: initialSettings.fontSize,
      lineHeight: initialSettings.lineHeight,
      scrollback: initialSettings.scrollback,
      theme: terminalThemes[initialSettings.theme],
    })
    const fitAddon = new FitAddon()
    const searchAddon = new SearchAddon()
    terminal.loadAddon(fitAddon)
    terminal.loadAddon(searchAddon)
    terminal.open(container)
    terminalRef.current = terminal
    fitAddonRef.current = fitAddon
    searchAddonRef.current = searchAddon

    let resizeTimer: number | undefined
    const resize = () => {
      window.clearTimeout(resizeTimer)
      resizeTimer = window.setTimeout(() => {
        fitAddon.fit()
        void resizeSession(session.id, { columns: terminal.cols, rows: terminal.rows })
      }, 100)
    }
    const observer = new ResizeObserver(resize)
    observer.observe(container)
    resize()

    const inputDisposable = terminal.onData((input) => {
      if (statusRef.current === 'connected') void writeSession(session.id, input)
    })
    const searchDisposable = searchAddon.onDidChangeResults((result) => {
      setSearchResult({ index: result.resultIndex, count: result.resultCount })
    })
    terminal.attachCustomKeyEventHandler((event) => {
      if (event.type !== 'keydown') return true
      const key = event.key.toLowerCase()
      if (event.ctrlKey && event.shiftKey && key === 'c') {
        void copySelection(terminal)
        return false
      }
      if (event.ctrlKey && !event.shiftKey && key === 'c' && terminal.hasSelection()) {
        void copySelection(terminal)
        return false
      }
      if (event.ctrlKey && event.shiftKey && key === 'v') {
        void readClipboardForPaste(terminal, setPendingPaste)
        return false
      }
      if (event.ctrlKey && !event.shiftKey && key === 'f') {
        setSearchOpen(true)
        return false
      }
      return true
    })

    let disposed = false
    let unlisten: (() => void) | undefined
    void listenToSessionOutput((payload) => {
      if (payload.sessionId === session.id && !disposed) terminal.write(new Uint8Array(payload.data))
    }).then((cleanup) => {
      if (disposed) cleanup()
      else unlisten = cleanup
    })

    return () => {
      disposed = true
      window.clearTimeout(resizeTimer)
      unlisten?.()
      inputDisposable.dispose()
      searchDisposable.dispose()
      observer.disconnect()
      terminal.dispose()
      terminalRef.current = undefined
      fitAddonRef.current = undefined
      searchAddonRef.current = undefined
    }
  }, [session.id])

  useEffect(() => {
    const terminal = terminalRef.current
    if (!terminal) return
    terminal.options.fontFamily = settings.fontFamily
    terminal.options.fontSize = settings.fontSize
    terminal.options.lineHeight = settings.lineHeight
    terminal.options.cursorStyle = settings.cursorStyle
    terminal.options.cursorBlink = settings.cursorBlink
    terminal.options.scrollback = settings.scrollback
    terminal.options.theme = terminalThemes[settings.theme]
    fitAddonRef.current?.fit()
    void resizeSession(session.id, { columns: terminal.cols, rows: terminal.rows })
  }, [session.id, settings])

  useEffect(() => {
    if (active && !searchOpen) terminalRef.current?.focus()
  }, [active, searchOpen])

  useEffect(() => {
    if (!searchOpen || !query) {
      searchAddonRef.current?.clearDecorations()
      setSearchResult({ index: -1, count: 0 })
      return
    }
    searchAddonRef.current?.findNext(query, searchOptions(caseSensitive, true))
  }, [caseSensitive, query, searchOpen])

  const paste = (text: string) => {
    if (statusRef.current === 'connected') terminalRef.current?.paste(text)
    setPendingPaste(undefined)
    setContextMenu(undefined)
  }
  const requestPaste = () => {
    const terminal = terminalRef.current
    setContextMenu(undefined)
    if (terminal) void readClipboardForPaste(terminal, setPendingPaste)
  }
  const closeSearch = () => {
    setSearchOpen(false)
    searchAddonRef.current?.clearDecorations()
    window.setTimeout(() => terminalRef.current?.focus())
  }

  return (
    <section className={`terminal-pane terminal-theme-${settings.theme}`} hidden={!active}>
      {searchOpen && (
        <div className="terminal-search" role="search">
          <input
            autoFocus
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            onKeyDown={(event) => { if (event.key === 'Escape') closeSearch() }}
            placeholder="查找终端内容"
            aria-label="查找终端内容"
          />
          <span>{searchResult.count ? `${searchResult.index + 1}/${searchResult.count}` : '无匹配'}</span>
          <button type="button" onClick={() => searchAddonRef.current?.findPrevious(query, searchOptions(caseSensitive))} aria-label="上一个匹配">↑</button>
          <button type="button" onClick={() => searchAddonRef.current?.findNext(query, searchOptions(caseSensitive))} aria-label="下一个匹配">↓</button>
          <button className={caseSensitive ? 'active' : ''} type="button" onClick={() => setCaseSensitive((value) => !value)} aria-pressed={caseSensitive}>Aa</button>
          <button type="button" onClick={closeSearch} aria-label="关闭搜索">×</button>
        </div>
      )}
      {session.status !== 'connected' && (
        <div className="terminal-disconnected" role="status">
          <strong>{session.status === 'failed' ? '连接失败' : '会话已断开'}</strong>
          <span>{session.lastError ?? session.disconnectReason ?? '远端会话不可用'}</span>
        </div>
      )}
      <div
        ref={containerRef}
        className="terminal-view"
        role="application"
        aria-label={`${session.title} 终端`}
        onContextMenu={(event) => {
          event.preventDefault()
          setContextMenu({ x: event.clientX, y: event.clientY })
        }}
        onPointerDown={() => setContextMenu(undefined)}
      />
      {contextMenu && (
        <div className="terminal-context-menu" style={{ left: contextMenu.x, top: contextMenu.y }} role="menu">
          <button type="button" role="menuitem" disabled={!terminalRef.current?.hasSelection()} onClick={() => { if (terminalRef.current) void copySelection(terminalRef.current); setContextMenu(undefined) }}>复制</button>
          <button type="button" role="menuitem" disabled={session.status !== 'connected'} onClick={requestPaste}>粘贴</button>
          <button type="button" role="menuitem" onClick={() => { terminalRef.current?.selectAll(); setContextMenu(undefined) }}>全选</button>
          <button type="button" role="menuitem" onClick={() => { terminalRef.current?.clear(); setContextMenu(undefined) }}>清屏</button>
        </div>
      )}
      {pendingPaste !== undefined && (
        <div className="paste-confirm-backdrop" role="presentation">
          <div className="paste-confirm" role="alertdialog" aria-modal="true" aria-labelledby={`paste-title-${session.id}`}>
            <span className="eyebrow">PASTE PROTECTION</span>
            <h2 id={`paste-title-${session.id}`}>确认粘贴到远端？</h2>
            <p>内容包含多行或超过 1,000 个字符，粘贴后可能立即在远端执行。</p>
            <pre>{pendingPaste.slice(0, 4_000)}{pendingPaste.length > 4_000 ? '\n…（预览已截断）' : ''}</pre>
            <div>
              <button className="secondary-button" type="button" onClick={() => setPendingPaste(undefined)}>取消</button>
              <button className="danger-button" type="button" onClick={() => paste(pendingPaste)}>仍然粘贴</button>
            </div>
          </div>
        </div>
      )}
    </section>
  )
}

function searchOptions(caseSensitive: boolean, incremental = false) {
  return {
    caseSensitive,
    incremental,
    decorations: {
      matchBackground: '#284c78',
      matchOverviewRuler: '#5f8cff',
      activeMatchBackground: '#a76714',
      activeMatchColorOverviewRuler: '#fbbf24',
    },
  }
}

async function copySelection(terminal: Terminal): Promise<void> {
  const selection = terminal.getSelection()
  if (selection) await navigator.clipboard.writeText(selection)
}

async function readClipboardForPaste(
  terminal: Terminal,
  setPendingPaste: (value: string) => void,
): Promise<void> {
  const text = await navigator.clipboard.readText()
  if (!text) return
  if (text.includes('\n') || text.includes('\r') || text.length > 1_000) setPendingPaste(text)
  else terminal.paste(text)
}
