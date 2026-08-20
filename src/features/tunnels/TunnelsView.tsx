import { useEffect, useMemo, useState } from 'react'
import type { ConnectionAssetSnapshot } from '../../domain/connection/types'
import type { SessionState } from '../../domain/session/types'
import type { SaveTunnelRequest, TunnelKind, TunnelProfile, TunnelRuntimeState } from '../../domain/tunnel/types'
import { deleteTunnelProfile, listRuntimeTunnels, normalizeCommandError, onTunnelStatus, saveTunnelProfile, startTunnel, stopTunnel } from '../../lib/ipc'

interface Props {
  assets?: ConnectionAssetSnapshot
  sessions: SessionState[]
  onAssetsChanged: () => Promise<void>
}

const emptyDraft = (connectionId = ''): SaveTunnelRequest => ({
  name: '', connectionId, kind: 'local', bindHost: '127.0.0.1', bindPort: 0,
  targetHost: '', targetPort: 0, startPolicy: 'manual', allowNonLoopback: false,
})

export function TunnelsView({ assets, sessions, onAssetsChanged }: Props) {
  const [selectedId, setSelectedId] = useState<string>()
  const [editing, setEditing] = useState(false)
  const [draft, setDraft] = useState<SaveTunnelRequest>(() => emptyDraft())
  const [runtime, setRuntime] = useState<TunnelRuntimeState[]>([])
  const [sessionId, setSessionId] = useState('')
  const [error, setError] = useState<string>()
  const profiles = assets?.tunnels ?? []
  const selected = profiles.find((profile) => profile.id === selectedId)
  const connectedSessions = sessions.filter((session) => session.status === 'connected')

  useEffect(() => {
    void listRuntimeTunnels().then(setRuntime).catch((cause) => setError(normalizeCommandError(cause).message))
    let dispose: (() => void) | undefined
    void onTunnelStatus(({ tunnel }) => setRuntime((items) => [...items.filter((item) => item.runtimeId !== tunnel.runtimeId), tunnel]))
      .then((unlisten) => { dispose = unlisten })
    return () => dispose?.()
  }, [])

  useEffect(() => {
    if (!sessionId && connectedSessions[0]) setSessionId(connectedSessions[0].id)
  }, [connectedSessions, sessionId])

  const active = useMemo(() => runtime.find((item) => item.profileId === selectedId && ['starting', 'running', 'stopping'].includes(item.status)), [runtime, selectedId])
  const connectionName = (id: string) => assets?.connections.find((item) => item.id === id)?.name ?? '连接已删除'
  const openEditor = (profile?: TunnelProfile) => {
    setDraft(profile ? { ...profile, allowNonLoopback: false } : emptyDraft(assets?.connections[0]?.id))
    setEditing(true); setError(undefined)
  }
  const save = async () => {
    try {
      if (!draft.name.trim() || !draft.connectionId || !draft.bindHost.trim()) throw new Error('请完整填写名称、连接和监听地址')
      if (draft.kind !== 'dynamic' && (!draft.targetHost?.trim() || !draft.targetPort)) throw new Error('本地和远程转发必须填写目标地址与端口')
      const nonLoopback = ['local', 'dynamic'].includes(draft.kind) && !['127.0.0.1', '::1', 'localhost'].includes(draft.bindHost.trim().toLowerCase())
      const request = { ...draft, allowNonLoopback: nonLoopback ? window.confirm('该监听地址可能向局域网或公网暴露端口。确认继续保存？') : false }
      if (nonLoopback && !request.allowNonLoopback) return
      const saved = await saveTunnelProfile(request); await onAssetsChanged(); setSelectedId(saved.id); setEditing(false)
    } catch (cause) { setError(normalizeCommandError(cause).message) }
  }
  const run = async () => {
    if (!selected || !sessionId) return
    try { const state = await startTunnel(sessionId, selected.id); setRuntime((items) => [...items.filter((item) => item.profileId !== selected.id), state]); setError(undefined) }
    catch (cause) { setError(normalizeCommandError(cause).message) }
  }
  const stop = async () => {
    if (!active) return
    try { const state = await stopTunnel(active.runtimeId); setRuntime((items) => [...items.filter((item) => item.runtimeId !== active.runtimeId), state]); setError(undefined) }
    catch (cause) { setError(normalizeCommandError(cause).message) }
  }

  return <div className="tunnels-layout">
    <aside className="tunnels-sidebar">
      <header className="panel-header"><div><span className="eyebrow">NETWORK PATH</span><h1>隧道</h1></div><button className="icon-button" onClick={() => openEditor()} aria-label="新建隧道">＋</button></header>
      <p className="tunnel-help">通过现有 SSH 会话建立本地、远程或 SOCKS5 动态转发。</p>
      <div className="tunnel-list">{profiles.map((profile) => {
        const state = runtime.find((item) => item.profileId === profile.id)
        return <button key={profile.id} className={profile.id === selectedId ? 'tunnel-row selected' : 'tunnel-row'} onClick={() => setSelectedId(profile.id)}>
          <span className={`status-dot ${state?.status === 'running' ? 'online' : ''}`} />
          <span><strong>{profile.name}</strong><small>{profile.kind.toUpperCase()} · {profile.bindHost}:{state?.boundPort ?? profile.bindPort}</small></span>
        </button>
      })}</div>
      {!profiles.length && <div className="empty-list"><h2>还没有隧道规则</h2><p>先保存一个连接，再创建安全的端口转发规则。</p></div>}
    </aside>
    <section className="tunnels-content">
      {error && <div className="settings-error">{error}</div>}
      {editing ? <TunnelEditor draft={draft} connections={assets?.connections ?? []} onChange={setDraft} onCancel={() => setEditing(false)} onSave={() => void save()} /> : selected ? <>
        <header><span className="eyebrow">TUNNEL PROFILE</span><h2>{selected.name}</h2><p>{connectionName(selected.connectionId)} · {describeTunnel(selected)}</p></header>
        <div className="tunnel-runtime-card">
          <div><span>运行状态</span><strong>{active?.status ?? runtime.find((item) => item.profileId === selected.id)?.status ?? 'stopped'}</strong></div>
          <div><span>活动连接</span><strong>{active?.activeConnections ?? 0}</strong></div>
          <div><span>上行 / 下行</span><strong>{formatBytes(active?.bytesUp ?? 0)} / {formatBytes(active?.bytesDown ?? 0)}</strong></div>
        </div>
        <div className="tunnel-session-row"><label>复用 SSH 会话<select value={sessionId} onChange={(event) => setSessionId(event.target.value)}><option value="">请选择已连接会话</option>{connectedSessions.map((session) => <option key={session.id} value={session.id}>{session.title}</option>)}</select></label></div>
        <div className="tunnel-actions"><button onClick={() => openEditor(selected)}>编辑规则</button>{active ? <button className="danger" onClick={() => void stop()}>停止隧道</button> : <button className="primary-button" disabled={!sessionId} onClick={() => void run()}>启动隧道</button>}<button className="danger" disabled={Boolean(active)} onClick={async () => { if (window.confirm(`删除隧道“${selected.name}”？`)) { await deleteTunnelProfile(selected.id); setSelectedId(undefined); await onAssetsChanged() } }}>删除</button></div>
      </> : <div className="empty-workspace"><h2>选择一个隧道规则</h2><p>运行态端口、连接数和流量会在这里实时展示。</p></div>}
    </section>
  </div>
}

function TunnelEditor({ draft, connections, onChange, onCancel, onSave }: { draft: SaveTunnelRequest; connections: NonNullable<ConnectionAssetSnapshot['connections']>; onChange: (value: SaveTunnelRequest) => void; onCancel: () => void; onSave: () => void }) {
  const set = <K extends keyof SaveTunnelRequest>(key: K, value: SaveTunnelRequest[K]) => onChange({ ...draft, [key]: value })
  return <div className="tunnel-editor"><header><span className="eyebrow">TUNNEL RULE</span><h2>{draft.id ? '编辑隧道' : '新建隧道'}</h2><p>监听地址默认仅绑定本机回环，端口填 0 可由系统自动分配。</p></header>
    <div className="tunnel-form-grid"><label>规则名称<input value={draft.name} onChange={(e) => set('name', e.target.value)} /></label><label>SSH 连接<select value={draft.connectionId} onChange={(e) => set('connectionId', e.target.value)}><option value="">请选择</option>{connections.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}</select></label><label>转发类型<select value={draft.kind} onChange={(e) => set('kind', e.target.value as TunnelKind)}><option value="local">本地转发</option><option value="remote">远程转发</option><option value="dynamic">动态 SOCKS5</option></select></label><label>启动策略<select value={draft.startPolicy} onChange={(e) => set('startPolicy', e.target.value as SaveTunnelRequest['startPolicy'])}><option value="manual">手动启动</option><option value="withConnection">随连接启动</option></select></label><label>监听地址<input value={draft.bindHost} onChange={(e) => set('bindHost', e.target.value)} /></label><label>监听端口<input type="number" min="0" max="65535" value={draft.bindPort} onChange={(e) => set('bindPort', Number(e.target.value))} /></label>{draft.kind !== 'dynamic' && <><label>目标地址<input value={draft.targetHost ?? ''} onChange={(e) => set('targetHost', e.target.value)} /></label><label>目标端口<input type="number" min="1" max="65535" value={draft.targetPort ?? 0} onChange={(e) => set('targetPort', Number(e.target.value))} /></label></>}</div>
    <div className="tunnel-actions"><button onClick={onCancel}>取消</button><button className="primary-button" onClick={onSave}>保存规则</button></div>
  </div>
}

function describeTunnel(profile: TunnelProfile): string {
  const source = `${profile.bindHost}:${profile.bindPort || '自动'}`
  return profile.kind === 'dynamic' ? `${source} → SOCKS5` : `${source} → ${profile.targetHost}:${profile.targetPort}`
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`
  return `${(bytes / 1024 / 1024).toFixed(1)} MiB`
}
