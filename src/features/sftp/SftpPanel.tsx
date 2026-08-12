import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { Icon } from '../../components/Icon'
import type { RemoteDirectoryEntry, RemoteDirectoryListing } from '../../domain/sftp/types'
import type { SessionState } from '../../domain/session/types'
import { createRemoteDirectory, deleteRemoteEntry, listRemoteDirectory, normalizeCommandError, renameRemoteEntry } from '../../lib/ipc'

interface SftpPanelProps {
  session: SessionState
  visible: boolean
  onClose: () => void
}

function formatSize(size: number): string {
  if (size < 1024) return `${size} B`
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`
  if (size < 1024 * 1024 * 1024) return `${(size / 1024 / 1024).toFixed(1)} MB`
  return `${(size / 1024 / 1024 / 1024).toFixed(1)} GB`
}

export function SftpPanel({ session, visible, onClose }: SftpPanelProps) {
  const [listing, setListing] = useState<RemoteDirectoryListing>()
  const [path, setPath] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string>()
  const [selected, setSelected] = useState<RemoteDirectoryEntry>()
  const [dialog, setDialog] = useState<'create' | 'rename' | 'delete'>()
  const [name, setName] = useState('')
  const [mutating, setMutating] = useState(false)

  const browse = useCallback(async (target?: string) => {
    if (session.status !== 'connected') return
    setLoading(true)
    setError(undefined)
    try {
      const next = await listRemoteDirectory(session.id, target)
      setListing(next)
      setPath(next.path)
      setSelected(undefined)
    } catch (cause) {
      setError(normalizeCommandError(cause).message)
    } finally {
      setLoading(false)
    }
  }, [session.id, session.status])

  useEffect(() => {
    if (visible && !listing && !loading && !error && session.status === 'connected') void browse()
  }, [visible, listing, loading, error, session.status, browse])

  const submitPath = (event: FormEvent) => {
    event.preventDefault()
    if (path.trim()) void browse(path.trim())
  }

  const openDialog = (kind: 'create' | 'rename' | 'delete') => {
    setName(kind === 'rename' ? selected?.name ?? '' : '')
    setDialog(kind)
  }

  const submitOperation = async (event: FormEvent) => {
    event.preventDefault()
    if (!listing || !dialog || (dialog !== 'create' && !selected)) return
    setMutating(true)
    setError(undefined)
    try {
      if (dialog === 'create') await createRemoteDirectory(session.id, listing.path, name)
      if (dialog === 'rename' && selected) await renameRemoteEntry(session.id, selected.path, name)
      if (dialog === 'delete' && selected) await deleteRemoteEntry(session.id, selected.path)
      setDialog(undefined)
      await browse(listing.path)
    } catch (cause) {
      setError(normalizeCommandError(cause).message)
      setDialog(undefined)
    } finally {
      setMutating(false)
    }
  }

  return (
    <aside className="sftp-panel" hidden={!visible} aria-label={`${session.title} 文件浏览器`}>
      <header className="sftp-header">
        <div><Icon name="folder" /><strong>远端文件</strong><span>SFTP</span></div>
        <button type="button" onClick={onClose} aria-label="关闭文件面板"><Icon name="close" /></button>
      </header>
      <form className="sftp-pathbar" onSubmit={submitPath}>
        <button type="button" disabled={!listing?.parentPath || loading} onClick={() => void browse(listing?.parentPath)} aria-label="上级目录">↑</button>
        <input value={path} onChange={(event) => setPath(event.target.value)} placeholder="远端路径" aria-label="远端路径" />
        <button type="button" disabled={loading} onClick={() => void browse(listing?.path)} aria-label="刷新">↻</button>
      </form>
      <div className="sftp-actions">
        <button type="button" disabled={!listing || loading} onClick={() => openDialog('create')}>新建文件夹</button>
        <button type="button" disabled={!selected || loading} onClick={() => openDialog('rename')}>重命名</button>
        <button className="danger" type="button" disabled={!selected || loading} onClick={() => openDialog('delete')}>删除</button>
      </div>
      {error && <div className="sftp-error" role="alert"><span>{error}</span><button type="button" onClick={() => void browse(listing?.path)}>重试</button></div>}
      {loading && !listing ? <div className="sftp-loading">正在建立 SFTP 通道…</div> : (
        <div className="sftp-list" role="list">
          {listing?.entries.map((entry) => (
            <button
              className="sftp-entry"
              type="button"
              role="listitem"
              key={entry.path}
              data-selected={selected?.path === entry.path}
              onClick={() => setSelected(entry)}
              onDoubleClick={() => entry.kind === 'directory' && void browse(entry.path)}
            >
              <Icon name={entry.kind === 'directory' ? 'folder' : 'terminal'} />
              <span className="sftp-entry-main"><strong>{entry.name}</strong><small>{entry.permissions}</small></span>
              <span className="sftp-entry-meta"><span>{entry.kind === 'directory' ? '目录' : formatSize(entry.size)}</span><small>{entry.modifiedAt ? new Date(entry.modifiedAt).toLocaleString() : '—'}</small></span>
            </button>
          ))}
          {listing && listing.entries.length === 0 && <div className="sftp-empty">此目录为空</div>}
        </div>
      )}
      {listing?.truncated && <footer className="sftp-notice">目录超过 5000 项，仅显示前 5000 项</footer>}
      {dialog && (
        <div className="sftp-dialog-backdrop">
          <form className="sftp-dialog" onSubmit={submitOperation}>
            <span className="eyebrow">REMOTE OPERATION</span>
            <h2>{dialog === 'create' ? '新建文件夹' : dialog === 'rename' ? '重命名' : '删除远端对象'}</h2>
            {dialog === 'delete' ? (
              <p>确定删除“{selected?.name}”吗？远端删除通常无法恢复。非空目录将被拒绝。</p>
            ) : (
              <label>名称<input autoFocus value={name} onChange={(event) => setName(event.target.value)} maxLength={255} /></label>
            )}
            <div>
              <button type="button" disabled={mutating} onClick={() => setDialog(undefined)}>取消</button>
              <button className={dialog === 'delete' ? 'danger' : 'confirm'} type="submit" disabled={mutating || (dialog !== 'delete' && !name.trim())}>
                {mutating ? '处理中…' : dialog === 'delete' ? '确认删除' : '确认'}
              </button>
            </div>
          </form>
        </div>
      )}
    </aside>
  )
}
