import { useEffect, useState } from 'react'
import './App.css'
import { Icon } from './components/Icon'
import { TerminalView } from './features/terminal/TerminalView'
import { useSessionController } from './features/sessions/useSessionController'
import { ConnectionDialog } from './features/connections/ConnectionDialog'
import type { ConnectionRequest, HostKeyApproval } from './domain/connection/types'
import { healthCheck, normalizeCommandError, type HealthResponse } from './lib/ipc'
import { t } from './lib/i18n'

type View = 'connections' | 'settings'

function App() {
  const [view, setView] = useState<View>('connections')
  const [health, setHealth] = useState<HealthResponse | null>(null)
  const [healthError, setHealthError] = useState<string>()
  const [connectionDialogOpen, setConnectionDialogOpen] = useState(false)
  const {
    sessions,
    activeSessionId,
    error,
    startSession,
    closeSession,
    activateSession,
  } = useSessionController()

  useEffect(() => {
    let disposed = false
    void healthCheck()
      .then((response) => {
        if (!disposed) setHealth(response)
      })
      .catch((cause) => {
        if (!disposed) setHealthError(normalizeCommandError(cause).message)
      })
    return () => {
      disposed = true
    }
  }, [])

  const activeSession = sessions.find((session) => session.id === activeSessionId)

  return (
    <main className="app-shell">
      <nav className="primary-nav" aria-label="主导航">
        <div className="brand" aria-label={t('appName')}>
          <span className="brand-mark"><span /><span /><span /></span>
          <span>{t('appName')}</span>
        </div>

        <div className="nav-items">
          <button
            className={view === 'connections' ? 'nav-item active' : 'nav-item'}
            type="button"
            onClick={() => setView('connections')}
            aria-current={view === 'connections' ? 'page' : undefined}
          >
            <Icon name="connection" />
            {t('connections')}
          </button>
          <button
            className={view === 'settings' ? 'nav-item active' : 'nav-item'}
            type="button"
            onClick={() => setView('settings')}
            aria-current={view === 'settings' ? 'page' : undefined}
          >
            <Icon name="settings" />
            {t('settings')}
          </button>
        </div>

        <div className="nav-footer">
          <span className="phase-chip">{t('stageZeroLabel')}</span>
          <div className="health-row">
            <span className={`health-dot ${healthError ? 'error' : health ? 'ready' : ''}`} />
            <span>{healthError ?? (health ? t('healthReady') : t('healthChecking'))}</span>
          </div>
          {health?.appVersion === 'browser-preview' && (
            <span className="preview-label">{t('healthUnavailable')}</span>
          )}
        </div>
      </nav>

      <section className="application-area">
        {view === 'connections' ? (
          <>
            <ConnectionsPanel
              hasSession={sessions.length > 0}
              onNewConnection={() => setConnectionDialogOpen(true)}
            />
            <SessionWorkspace
              sessions={sessions}
              activeSessionId={activeSessionId}
              activeSessionTitle={activeSession?.title}
              error={error}
              onNewConnection={() => setConnectionDialogOpen(true)}
              onActivateSession={activateSession}
              onCloseSession={closeSession}
            />
          </>
        ) : (
          <SettingsView />
        )}
      </section>
      <ConnectionDialog
        open={connectionDialogOpen}
        onClose={() => setConnectionDialogOpen(false)}
        onConnect={async (
          operationId: string,
          request: ConnectionRequest,
          approval: HostKeyApproval,
        ) => startSession(operationId, request, approval)}
      />
    </main>
  )
}

interface ConnectionsPanelProps {
  hasSession: boolean
  onNewConnection: () => void
}

function ConnectionsPanel({ hasSession, onNewConnection }: ConnectionsPanelProps) {
  return (
    <aside className="connections-panel" aria-label={t('connectionCenter')}>
      <header className="panel-header">
        <div>
          <span className="eyebrow">SSH</span>
          <h1>{t('connectionCenter')}</h1>
        </div>
        <button className="icon-button" type="button" onClick={onNewConnection} disabled={hasSession} aria-label={t('newConnection')} title={hasSession ? '阶段 1 仅支持单会话' : t('newConnection')}>
          <Icon name="plus" />
        </button>
      </header>

      <label className="search-field">
        <Icon name="search" />
        <input type="search" placeholder={t('searchConnections')} disabled aria-label={t('searchConnections')} />
        <kbd>⌘ K</kbd>
      </label>

      <div className="group-heading">
        <span><Icon name="chevron" />{t('defaultGroup')}</span>
        <span className="count-badge">0</span>
      </div>

      <div className="empty-list">
        <div className="empty-icon"><Icon name="server" /></div>
        <h2>{t('noConnections')}</h2>
        <p>{t('noConnectionsHint')}</p>
      </div>

      <div className="prototype-card connection-entry">
        <div className="prototype-icon"><Icon name="connection" /></div>
        <div>
          <strong>临时 SSH 连接</strong>
          <span>密码和私钥只在当前连接流程中使用，不会保存。</span>
        </div>
        <button type="button" onClick={onNewConnection} disabled={hasSession}>
          {hasSession ? '已有活动会话' : '新建连接'}
        </button>
      </div>
    </aside>
  )
}

interface SessionWorkspaceProps {
  sessions: ReturnType<typeof useSessionController>['sessions']
  activeSessionId?: string
  activeSessionTitle?: string
  error?: string
  onNewConnection: () => void
  onActivateSession: (sessionId: string) => void
  onCloseSession: (sessionId: string) => Promise<void>
}

function SessionWorkspace({
  sessions,
  activeSessionId,
  activeSessionTitle,
  error,
  onNewConnection,
  onActivateSession,
  onCloseSession,
}: SessionWorkspaceProps) {
  return (
    <section className="workspace" aria-label={t('workspaceTitle')}>
      <header className="workspace-toolbar">
        <div>
          <span className="workspace-context">{activeSessionTitle ?? t('workspaceTitle')}</span>
          <span className="workspace-state">
            <span className={`status-dot ${activeSessionId ? 'online' : ''}`} />
            {activeSessionId ? t('terminalReady') : '等待会话'}
          </span>
        </div>
        <button className="primary-button" type="button" onClick={onNewConnection} disabled={sessions.length > 0}>
          <Icon name="plus" />
          {t('newConnection')}
        </button>
      </header>

      {sessions.length > 0 && (
        <div className="session-tabs" role="tablist" aria-label="会话标签">
          {sessions.map((session) => (
            <div
              key={session.id}
              className={session.id === activeSessionId ? 'session-tab active' : 'session-tab'}
              role="tab"
              aria-selected={session.id === activeSessionId}
            >
              <button
                className="tab-activate"
                type="button"
                onClick={() => onActivateSession(session.id)}
              >
                <span className={`status-dot ${session.status === 'connected' ? 'online' : ''}`} />
                <span>{session.title}</span>
              </button>
              <button
                className="tab-close"
                type="button"
                aria-label={t('closeSession')}
                onClick={(event) => {
                  event.stopPropagation()
                  void onCloseSession(session.id)
                }}
              >
                <Icon name="close" />
              </button>
            </div>
          ))}
        </div>
      )}

      <div className="workspace-content">
        {error && <div className="inline-error" role="alert">{error}</div>}
        {sessions.length === 0 ? (
          <EmptyWorkspace onNewConnection={onNewConnection} />
        ) : (
          sessions.map((session) => (
            <TerminalView
              key={session.id}
              session={session}
              active={session.id === activeSessionId}
            />
          ))
        )}
      </div>

      <footer className="workspace-footer">
        <span><Icon name="shield" />本地优先 · 模拟会话不访问网络</span>
        <span>IPC v1</span>
      </footer>
    </section>
  )
}

function EmptyWorkspace({
  onNewConnection,
}: Pick<SessionWorkspaceProps, 'onNewConnection'>) {
  return (
    <div className="empty-workspace">
      <div className="terminal-orbit" aria-hidden="true">
        <span className="orbit orbit-one" />
        <span className="orbit orbit-two" />
        <span className="terminal-core"><Icon name="terminal" /></span>
      </div>
      <span className="eyebrow">TERMINAL WORKSPACE</span>
      <h2>{t('workspaceTitle')}</h2>
      <p>{t('workspaceDescription')}</p>
      <button className="primary-button large" type="button" onClick={onNewConnection}>
        <Icon name="terminal" />
        {t('newConnection')}
      </button>
      <span className="empty-footnote">密码和私钥仅用于本次连接，不会保存。</span>
    </div>
  )
}

function SettingsView() {
  return (
    <section className="settings-layout">
      <aside className="settings-sidebar">
        <header className="panel-header">
          <div><span className="eyebrow">PREFERENCES</span><h1>{t('settings')}</h1></div>
        </header>
        <button className="settings-nav active" type="button"><Icon name="settings" />{t('generalSettings')}</button>
        <button className="settings-nav" type="button" disabled><Icon name="terminal" />{t('terminalSettings')}<span>{t('comingLater')}</span></button>
      </aside>
      <div className="settings-content">
        <header>
          <span className="eyebrow">APPLICATION</span>
          <h2>{t('settingsTitle')}</h2>
          <p>{t('settingsDescription')}</p>
        </header>
        <div className="settings-card">
          <SettingRow icon="shield" label={t('theme')} value={t('darkTheme')} />
          <SettingRow icon="connection" label={t('language')} value={t('simplifiedChinese')} />
        </div>
        <div className="architecture-note">
          <Icon name="server" />
          <div>
            <strong>设置结构已就绪</strong>
            <span>统一配置服务与持久化将在对应功能阶段接入。</span>
          </div>
        </div>
      </div>
    </section>
  )
}

function SettingRow({ icon, label, value }: { icon: 'shield' | 'connection'; label: string; value: string }) {
  return (
    <div className="setting-row">
      <span className="setting-icon"><Icon name={icon} /></span>
      <div><strong>{label}</strong><span>全局应用设置</span></div>
      <button type="button" disabled>{value}<Icon name="chevron" /></button>
    </div>
  )
}

export default App
