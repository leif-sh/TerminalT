import { useCallback, useEffect, useState, type ReactNode } from 'react'
import './App.css'
import { Icon } from './components/Icon'
import { TerminalView } from './features/terminal/TerminalView'
import { SftpPanel } from './features/sftp/SftpPanel'
import { useSessionController } from './features/sessions/useSessionController'
import { ConnectionDialog } from './features/connections/ConnectionDialog'
import type { ConnectionAssetSnapshot, ConnectionDraft, ConnectionProfile, ConnectionRequest, HostKeyApproval, SaveConnectionRequest } from './domain/connection/types'
import { draftFromProfile, filterConnections, initialConnectionDraft, parseQuickTarget, toReconnectDraft } from './domain/connection/types'
import {
  copyConnectionProfile, deleteConnectionGroup, deleteConnectionProfile, healthCheck,
  listConnectionAssets, normalizeCommandError, recordRecentTarget, saveConnectionGroup,
  saveConnectionProfile, type HealthResponse,
} from './lib/ipc'
import { t } from './lib/i18n'
import type { TerminalSettings } from './domain/terminal/settings'
import { normalizeTerminalSettings } from './domain/terminal/settings'

type View = 'connections' | 'settings'
const terminalSettingsKey = 'terminalt-terminal-settings-v1'

function App() {
  const [view, setView] = useState<View>('connections')
  const [health, setHealth] = useState<HealthResponse | null>(null)
  const [healthError, setHealthError] = useState<string>()
  const [connectionDialogOpen, setConnectionDialogOpen] = useState(false)
  const [dialogDraft, setDialogDraft] = useState<ConnectionDraft>()
  const [quickSource, setQuickSource] = useState<string>()
  const [assets, setAssets] = useState<ConnectionAssetSnapshot>()
  const [assetError, setAssetError] = useState<string>()
  const [reconnectSessionId, setReconnectSessionId] = useState<string>()
  const [terminalSettings, setTerminalSettings] = useState(readTerminalSettings)
  const {
    sessions,
    activeSessionId,
    error,
    startSession,
    startSavedSession,
    reconnectSession,
    reconnectSavedSession,
    closeSession,
    activateSession,
  } = useSessionController()

  const refreshAssets = async () => {
    try {
      setAssets(await listConnectionAssets())
      setAssetError(undefined)
    } catch (cause) {
      setAssetError(normalizeCommandError(cause).message)
    }
  }
  const runAssetAction = async (action: () => Promise<unknown>) => {
    try {
      await action()
      await refreshAssets()
    } catch (cause) {
      setAssetError(normalizeCommandError(cause).message)
    }
  }

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

  useEffect(() => { void refreshAssets() }, [])

  useEffect(() => {
    localStorage.setItem(terminalSettingsKey, JSON.stringify(terminalSettings))
  }, [terminalSettings])

  const requestCloseSession = useCallback(async (sessionId: string) => {
    const session = sessions.find((candidate) => candidate.id === sessionId)
    if (!session) return
    if (
      terminalSettings.confirmCloseSession
      && session.status === 'connected'
      && !window.confirm(`关闭“${session.title}”？会话将断开。`)
    ) return
    await closeSession(sessionId)
  }, [closeSession, sessions, terminalSettings.confirmCloseSession])

  useEffect(() => {
    const handleShortcut = (event: KeyboardEvent) => {
      if (connectionDialogOpen || view !== 'connections') return
      const target = event.target as HTMLElement | null
      if (target?.matches('input, select, textarea') && !target.closest('.xterm')) return
      if (!event.ctrlKey || event.altKey || event.metaKey) return
      if (event.key.toLowerCase() === 'w' && activeSessionId) {
        event.preventDefault()
        void requestCloseSession(activeSessionId)
        return
      }
      if (event.key === 'Tab' && sessions.length > 1) {
        event.preventDefault()
        const index = sessions.findIndex((session) => session.id === activeSessionId)
        activateSession(sessions[(index + 1) % sessions.length].id)
        return
      }
      const tabNumber = Number(event.key)
      if (tabNumber >= 1 && tabNumber <= 9 && sessions[tabNumber - 1]) {
        event.preventDefault()
        activateSession(sessions[tabNumber - 1].id)
      }
    }
    window.addEventListener('keydown', handleShortcut)
    return () => window.removeEventListener('keydown', handleShortcut)
  }, [activeSessionId, activateSession, connectionDialogOpen, requestCloseSession, sessions, view])

  const activeSession = sessions.find((session) => session.id === activeSessionId)
  const reconnectTarget = sessions.find((session) => session.id === reconnectSessionId)
  const closeConnectionDialog = () => {
    setConnectionDialogOpen(false)
    setDialogDraft(undefined)
    setQuickSource(undefined)
    setReconnectSessionId(undefined)
  }
  const openReconnect = (sessionId: string) => {
    const session = sessions.find((candidate) => candidate.id === sessionId)
    if (!session || session.reconnecting) return
    setQuickSource(undefined)
    setReconnectSessionId(sessionId)
    setDialogDraft(session.reconnectSource.draft)
    setConnectionDialogOpen(true)
  }

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
              assets={assets}
              activeSessionTitles={new Set(sessions.map((session) => session.title))}
              error={assetError}
              onNewConnection={() => { setQuickSource(undefined); setDialogDraft(undefined); setConnectionDialogOpen(true) }}
              onOpenConnection={(profile) => { setQuickSource(undefined); setDialogDraft(draftFromProfile(profile)); setConnectionDialogOpen(true) }}
              onQuickConnection={(draft, source) => { setQuickSource(source); setDialogDraft(draft); setConnectionDialogOpen(true) }}
              onCopy={(id) => runAssetAction(() => copyConnectionProfile(id))}
              onDelete={async (profile) => {
                if (window.confirm(`删除连接“${profile.name}”？已建立的会话不会关闭，私钥文件不会被删除。`)) {
                  await runAssetAction(() => deleteConnectionProfile(profile.id))
                }
              }}
              onCreateGroup={(name) => runAssetAction(() => saveConnectionGroup(name))}
              onRenameGroup={(id, name) => runAssetAction(() => saveConnectionGroup(name, id))}
              onDeleteGroup={async (id, name) => {
                if (window.confirm(`删除分组“${name}”？其中连接将移入默认分组。`)) {
                  await runAssetAction(() => deleteConnectionGroup(id))
                }
              }}
            />
            <SessionWorkspace
              sessions={sessions}
              activeSessionId={activeSessionId}
              activeSessionTitle={activeSession?.title}
              error={error}
              onNewConnection={() => { setQuickSource(undefined); setDialogDraft(undefined); setConnectionDialogOpen(true) }}
              onActivateSession={activateSession}
              settings={terminalSettings}
              onCloseSession={requestCloseSession}
              onReconnectSession={openReconnect}
            />
          </>
        ) : (
          <SettingsView settings={terminalSettings} onChange={setTerminalSettings} />
        )}
      </section>
      <ConnectionDialog
        open={connectionDialogOpen}
        reconnecting={Boolean(reconnectTarget)}
        keepalive={{
          enabled: terminalSettings.keepaliveEnabled,
          seconds: terminalSettings.keepaliveSeconds,
        }}
        initialDraft={dialogDraft}
        groups={assets?.groups}
        onClose={closeConnectionDialog}
        onSave={quickSource || reconnectTarget ? undefined : async (request: SaveConnectionRequest) => { await saveConnectionProfile(request); await refreshAssets() }}
        onConnect={async (
          operationId: string,
          request: ConnectionRequest,
          approval: HostKeyApproval,
        ) => {
          if (reconnectTarget) {
            await reconnectSession(reconnectTarget.id, operationId, request, approval)
          } else {
            await startSession(operationId, request, approval, toReconnectDraft(request))
            if (quickSource) await recordRecentTarget(quickSource)
          }
        }}
        onConnectSaved={async (operationId, connectionId, temporarySecret, approval) => {
          if (reconnectTarget) {
            await reconnectSavedSession(
              reconnectTarget.id,
              operationId,
              connectionId,
              temporarySecret,
              approval,
              {
                enabled: terminalSettings.keepaliveEnabled,
                seconds: terminalSettings.keepaliveSeconds,
              },
            )
          } else {
            const profile = assets?.connections.find((candidate) => candidate.id === connectionId)
            if (!profile) throw new Error('连接配置不存在，请刷新后重试')
            await startSavedSession(
              operationId,
              connectionId,
              temporarySecret,
              approval,
              toReconnectDraft(draftFromProfile(profile)),
              {
                enabled: terminalSettings.keepaliveEnabled,
                seconds: terminalSettings.keepaliveSeconds,
              },
            )
          }
          await refreshAssets()
        }}
      />
    </main>
  )
}

interface ConnectionsPanelProps {
  assets?: ConnectionAssetSnapshot
  activeSessionTitles: Set<string>
  error?: string
  onNewConnection: () => void
  onOpenConnection: (profile: ConnectionProfile) => void
  onQuickConnection: (draft: ConnectionDraft, source: string) => void
  onCopy: (id: string) => Promise<void>
  onDelete: (profile: ConnectionProfile) => Promise<void>
  onCreateGroup: (name: string) => Promise<void>
  onRenameGroup: (id: string, name: string) => Promise<void>
  onDeleteGroup: (id: string, name: string) => Promise<void>
}

function ConnectionsPanel({ assets, activeSessionTitles, error, onNewConnection, onOpenConnection, onQuickConnection, onCopy, onDelete, onCreateGroup, onRenameGroup, onDeleteGroup }: ConnectionsPanelProps) {
  const [query, setQuery] = useState('')
  const [quickTarget, setQuickTarget] = useState('')
  const [quickError, setQuickError] = useState<string>()
  const [groupName, setGroupName] = useState('')
  const [selectedId, setSelectedId] = useState<string>()
  const filteredIds = new Set(filterConnections(assets?.connections ?? [], query).map((profile) => profile.id))
  const openQuick = () => {
    try {
      const parsed = parseQuickTarget(quickTarget)
      setQuickError(undefined)
      onQuickConnection({ ...initialConnectionDraft, ...parsed, name: parsed.host }, quickTarget)
    } catch (cause) {
      setQuickError(cause instanceof Error ? cause.message : String(cause))
    }
  }
  return (
    <aside className="connections-panel" aria-label={t('connectionCenter')}>
      <header className="panel-header">
        <div>
          <span className="eyebrow">SSH</span>
          <h1>{t('connectionCenter')}</h1>
        </div>
        <button className="icon-button" type="button" onClick={onNewConnection} aria-label={t('newConnection')} title={t('newConnection')}>
          <Icon name="plus" />
        </button>
      </header>

      <label className="search-field">
        <Icon name="search" />
        <input type="search" placeholder={t('searchConnections')} value={query} onChange={(event) => setQuery(event.target.value)} aria-label={t('searchConnections')} />
        <kbd>⌘ K</kbd>
      </label>

      {error && <div className="inline-error" role="alert">{error}</div>}
      <div className="group-create">
        <input value={groupName} onChange={(event) => setGroupName(event.target.value)} placeholder="新建分组" maxLength={64} />
        <button type="button" onClick={() => { if (groupName.trim()) { void onCreateGroup(groupName.trim()); setGroupName('') } }}><Icon name="plus" /></button>
      </div>

      {assets?.groups.map((group) => {
        const profiles = assets.connections.filter((profile) => profile.groupId === group.id && filteredIds.has(profile.id))
        if (query.trim() && profiles.length === 0) return null
        return <section className="connection-group" key={group.id}>
          <div className="group-heading">
            <span><Icon name="chevron" />{group.name}</span>
            <span className="group-tools"><span className="count-badge">{profiles.length}</span>{group.id !== assets.defaultGroupId && <><button type="button" aria-label={`重命名${group.name}`} onClick={() => { const name = window.prompt('新的分组名称', group.name); if (name?.trim()) void onRenameGroup(group.id, name.trim()) }}>✎</button><button type="button" aria-label={`删除${group.name}`} onClick={() => void onDeleteGroup(group.id, group.name)}>×</button></>}</span>
          </div>
          {profiles.map((profile) => <article className={selectedId === profile.id ? 'connection-list-item selected' : 'connection-list-item'} key={profile.id} onDoubleClick={() => onOpenConnection(profile)}>
            <span className="connection-list-icon"><Icon name="server" /></span>
            <button className="connection-main" type="button" onClick={() => setSelectedId(profile.id)}><strong><span className={`status-dot ${activeSessionTitles.has(profile.name) ? 'online' : ''}`} />{profile.name}</strong><span>{profile.username}@{profile.host}:{profile.port}</span></button>
            <div className="connection-actions"><button type="button" onClick={() => onOpenConnection(profile)} aria-label={`编辑${profile.name}`}>✎</button><button type="button" onClick={() => void onCopy(profile.id)} aria-label={`复制${profile.name}`}>⧉</button><button type="button" onClick={() => void onDelete(profile)} aria-label={`删除${profile.name}`}>×</button></div>
          </article>)}
        </section>
      })}

      {(!assets || assets.connections.length === 0) && <div className="empty-list">
        <div className="empty-icon"><Icon name="server" /></div>
        <h2>{t('noConnections')}</h2>
        <p>{t('noConnectionsHint')}</p>
      </div>}

      <div className="prototype-card connection-entry">
        <div className="prototype-icon"><Icon name="connection" /></div>
        <div>
          <strong>快速连接</strong>
          <span>输入 user@host 或 user@host:port，不保存连接配置。</span>
        </div>
        <input className="quick-target" value={quickTarget} onChange={(event) => setQuickTarget(event.target.value)} placeholder="user@host:22" aria-label="快速连接目标" />
        {quickError && <span className="quick-error">{quickError}</span>}
        <button type="button" onClick={openQuick}>继续</button>
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
  onReconnectSession: (sessionId: string) => void
  settings: TerminalSettings
}

function SessionWorkspace({
  sessions,
  activeSessionId,
  activeSessionTitle,
  error,
  onNewConnection,
  onActivateSession,
  onCloseSession,
  onReconnectSession,
  settings,
}: SessionWorkspaceProps) {
  const [sftpSessions, setSftpSessions] = useState<Set<string>>(() => new Set())
  const sftpOpen = activeSessionId ? sftpSessions.has(activeSessionId) : false

  const toggleSftp = () => {
    if (!activeSessionId) return
    setSftpSessions((current) => {
      const next = new Set(current)
      if (next.has(activeSessionId)) next.delete(activeSessionId)
      else next.add(activeSessionId)
      return next
    })
  }

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
        <div className="workspace-actions">
          <button className={sftpOpen ? 'toolbar-button active' : 'toolbar-button'} type="button" disabled={!activeSessionId} onClick={toggleSftp}>
            <Icon name="folder" />文件
          </button>
          <button className="primary-button" type="button" onClick={onNewConnection}>
            <Icon name="plus" />
            {t('newConnection')}
          </button>
        </div>
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
          sessions.map((session) => {
            const active = session.id === activeSessionId
            const panelOpen = sftpSessions.has(session.id)
            return (
              <div className="session-surface" hidden={!active} key={session.id}>
                <TerminalView
                  session={session}
                  active={active}
                  settings={settings}
                  onReconnect={() => onReconnectSession(session.id)}
                />
                <SftpPanel
                  session={session}
                  visible={active && panelOpen}
                  onClose={() => setSftpSessions((current) => {
                    const next = new Set(current); next.delete(session.id); return next
                  })}
                />
              </div>
            )
          })
        )}
      </div>

      <footer className="workspace-footer">
        <span><Icon name="shield" />本地优先 · 凭据由 Windows 安全存储</span>
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
      <span className="empty-footnote">秘密仅在明确授权时保存到 Windows 凭据库。</span>
    </div>
  )
}

function SettingsView({ settings, onChange }: { settings: TerminalSettings; onChange: (settings: TerminalSettings) => void }) {
  const update = <Key extends keyof TerminalSettings>(key: Key, value: TerminalSettings[Key]) => {
    onChange(normalizeTerminalSettings({ ...settings, [key]: value }))
  }
  return (
    <section className="settings-layout">
      <aside className="settings-sidebar">
        <header className="panel-header">
          <div><span className="eyebrow">PREFERENCES</span><h1>{t('settings')}</h1></div>
        </header>
        <button className="settings-nav" type="button"><Icon name="settings" />{t('generalSettings')}</button>
        <button className="settings-nav active" type="button"><Icon name="terminal" />{t('terminalSettings')}</button>
      </aside>
      <div className="settings-content">
        <header>
          <span className="eyebrow">TERMINAL</span>
          <h2>终端显示与会话</h2>
          <p>修改会立即应用到所有已打开终端，并同步更新远端 PTY 尺寸。</p>
        </header>
        <div className="settings-card">
          <SettingControl label="字体族" hint="优先使用已安装的等宽字体"><input value={settings.fontFamily} onChange={(event) => update('fontFamily', event.target.value)} /></SettingControl>
          <SettingControl label="字号" hint="10～32 px"><input type="number" min="10" max="32" value={settings.fontSize} onChange={(event) => update('fontSize', Number(event.target.value))} /></SettingControl>
          <SettingControl label="行高" hint="1.0～2.0"><input type="number" min="1" max="2" step="0.1" value={settings.lineHeight} onChange={(event) => update('lineHeight', Number(event.target.value))} /></SettingControl>
          <SettingControl label="终端主题" hint="内置浅色与深色主题"><select value={settings.theme} onChange={(event) => update('theme', event.target.value as TerminalSettings['theme'])}><option value="dark">深色</option><option value="light">浅色</option></select></SettingControl>
          <SettingControl label="光标形状" hint="块、竖线或下划线"><select value={settings.cursorStyle} onChange={(event) => update('cursorStyle', event.target.value as TerminalSettings['cursorStyle'])}><option value="block">块</option><option value="bar">竖线</option><option value="underline">下划线</option></select></SettingControl>
          <SettingControl label="光标闪烁" hint="应用到全部会话"><input type="checkbox" checked={settings.cursorBlink} onChange={(event) => update('cursorBlink', event.target.checked)} /></SettingControl>
          <SettingControl label="滚动缓冲" hint="1,000～100,000 行"><input type="number" min="1000" max="100000" step="1000" value={settings.scrollback} onChange={(event) => update('scrollback', Number(event.target.value))} /></SettingControl>
          <SettingControl label="关闭会话确认" hint="连接中的标签关闭前提示"><input type="checkbox" checked={settings.confirmCloseSession} onChange={(event) => update('confirmCloseSession', event.target.checked)} /></SettingControl>
          <SettingControl label="SSH Keepalive" hint="新会话和手动重连时生效"><input type="checkbox" checked={settings.keepaliveEnabled} onChange={(event) => update('keepaliveEnabled', event.target.checked)} /></SettingControl>
          <SettingControl label="Keepalive 间隔" hint="5～300 秒"><input type="number" min="5" max="300" disabled={!settings.keepaliveEnabled} value={settings.keepaliveSeconds} onChange={(event) => update('keepaliveSeconds', Number(event.target.value))} /></SettingControl>
        </div>
        <div className="architecture-note">
          <Icon name="server" />
          <div>
            <strong>设置已自动保存</strong>
            <span>终端设置保存在本机，不包含服务器或凭据信息。</span>
          </div>
        </div>
      </div>
    </section>
  )
}

function SettingControl({ label, hint, children }: { label: string; hint: string; children: ReactNode }) {
  return (
    <div className="setting-row">
      <span className="setting-icon"><Icon name="terminal" /></span>
      <div><strong>{label}</strong><span>{hint}</span></div>
      <div className="setting-control">{children}</div>
    </div>
  )
}

function readTerminalSettings(): TerminalSettings {
  try {
    return normalizeTerminalSettings(JSON.parse(localStorage.getItem(terminalSettingsKey) ?? 'null'))
  } catch {
    return normalizeTerminalSettings(null)
  }
}


export default App
