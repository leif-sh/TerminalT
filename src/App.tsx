import { useEffect, useState } from 'react'
import './App.css'
import { Icon } from './components/Icon'
import { TerminalView } from './features/terminal/TerminalView'
import { useSessionController } from './features/sessions/useSessionController'
import { ConnectionDialog } from './features/connections/ConnectionDialog'
import type { ConnectionAssetSnapshot, ConnectionDraft, ConnectionProfile, ConnectionRequest, HostKeyApproval, SaveConnectionRequest } from './domain/connection/types'
import { draftFromProfile, filterConnections, initialConnectionDraft, parseQuickTarget } from './domain/connection/types'
import {
  copyConnectionProfile, deleteConnectionGroup, deleteConnectionProfile, healthCheck,
  listConnectionAssets, normalizeCommandError, recordRecentTarget, saveConnectionGroup,
  saveConnectionProfile, type HealthResponse,
} from './lib/ipc'
import { t } from './lib/i18n'

type View = 'connections' | 'settings'

function App() {
  const [view, setView] = useState<View>('connections')
  const [health, setHealth] = useState<HealthResponse | null>(null)
  const [healthError, setHealthError] = useState<string>()
  const [connectionDialogOpen, setConnectionDialogOpen] = useState(false)
  const [dialogDraft, setDialogDraft] = useState<ConnectionDraft>()
  const [quickSource, setQuickSource] = useState<string>()
  const [assets, setAssets] = useState<ConnectionAssetSnapshot>()
  const [assetError, setAssetError] = useState<string>()
  const {
    sessions,
    activeSessionId,
    error,
    startSession,
    startSavedSession,
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
              onCloseSession={closeSession}
            />
          </>
        ) : (
          <SettingsView />
        )}
      </section>
      <ConnectionDialog
        open={connectionDialogOpen}
        initialDraft={dialogDraft}
        groups={assets?.groups}
        onClose={() => { setConnectionDialogOpen(false); setDialogDraft(undefined); setQuickSource(undefined) }}
        onSave={quickSource ? undefined : async (request: SaveConnectionRequest) => { await saveConnectionProfile(request); await refreshAssets() }}
        onConnect={async (
          operationId: string,
          request: ConnectionRequest,
          approval: HostKeyApproval,
        ) => { await startSession(operationId, request, approval); if (quickSource) await recordRecentTarget(quickSource) }}
        onConnectSaved={async (operationId, connectionId, temporarySecret, approval) => {
          await startSavedSession(operationId, connectionId, temporarySecret, approval)
          await refreshAssets()
        }}
      />
    </main>
  )
}

interface ConnectionsPanelProps {
  hasSession: boolean
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

function ConnectionsPanel({ hasSession, assets, activeSessionTitles, error, onNewConnection, onOpenConnection, onQuickConnection, onCopy, onDelete, onCreateGroup, onRenameGroup, onDeleteGroup }: ConnectionsPanelProps) {
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
        <button className="icon-button" type="button" onClick={onNewConnection} disabled={hasSession} aria-label={t('newConnection')} title={hasSession ? '阶段 1 仅支持单会话' : t('newConnection')}>
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
          {profiles.map((profile) => <article className={selectedId === profile.id ? 'connection-list-item selected' : 'connection-list-item'} key={profile.id} onDoubleClick={() => !hasSession && onOpenConnection(profile)}>
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
        <button type="button" onClick={openQuick} disabled={hasSession}>{hasSession ? '已有活动会话' : '继续'}</button>
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
