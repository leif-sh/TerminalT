import { useCallback, useEffect, useMemo, useRef, useState, type DragEvent, type FormEvent, type MouseEvent } from 'react'
import { open } from '@tauri-apps/plugin-dialog'
import { Icon } from '../../components/Icon'
import { ErrorDetails } from '../../components/ErrorDetails'
import type { RemoteDirectoryEntry, RemoteDirectoryListing, TransferConflictPolicy, TransferTask } from '../../domain/sftp/types'
import type { SessionState } from '../../domain/session/types'
import { cancelTransfer, changeRemotePermissions, clearCompletedTransfers, createRemoteDirectory, deleteRemoteEntries, listenToTransferProgress, listRemoteDirectory, listTransferTasks, normalizeCommandError, renameRemoteEntry, startTransfer, type AppCommandError } from '../../lib/ipc'

interface SftpPanelProps {
  session: SessionState
  visible: boolean
  onClose: () => void
  defaultDownloadDirectory?: string
}

type Dialog = 'create' | 'rename' | 'delete' | 'permissions'

function formatSize(size: number): string {
  if (size < 1024) return `${size} B`
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`
  if (size < 1024 * 1024 * 1024) return `${(size / 1024 / 1024).toFixed(1)} MB`
  return `${(size / 1024 / 1024 / 1024).toFixed(1)} GB`
}

function pathArray(value: string | string[] | null): string[] {
  if (!value) return []
  return Array.isArray(value) ? value : [value]
}

export function SftpPanel({ session, visible, onClose, defaultDownloadDirectory }: SftpPanelProps) {
  const [listing, setListing] = useState<RemoteDirectoryListing>()
  const [path, setPath] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<AppCommandError>()
  const [selectedPaths, setSelectedPaths] = useState<Set<string>>(() => new Set())
  const [selectionAnchor, setSelectionAnchor] = useState<number>()
  const [dialog, setDialog] = useState<Dialog>()
  const [name, setName] = useState('')
  const [mode, setMode] = useState(0o755)
  const [recursive, setRecursive] = useState(false)
  const [conflictPolicy, setConflictPolicy] = useState<TransferConflictPolicy>('ask')
  const [mutating, setMutating] = useState(false)
  const [dragging, setDragging] = useState(false)
  const [tasks, setTasks] = useState<TransferTask[]>([])
  const panelRef = useRef<HTMLElement>(null)

  const selected = useMemo(
    () => listing?.entries.filter((entry) => selectedPaths.has(entry.path)) ?? [],
    [listing, selectedPaths],
  )

  const browse = useCallback(async (target?: string, cursor?: string) => {
    if (session.status !== 'connected') return
    setLoading(true)
    setError(undefined)
    try {
      const next = await listRemoteDirectory(session.id, target, cursor)
      setListing((current) => cursor && current?.path === next.path
        ? { ...next, entries: [...current.entries, ...next.entries] }
        : next)
      setPath(next.path)
      if (!cursor) {
        const available = new Set(next.entries.map((entry) => entry.path))
        setSelectedPaths((current) => new Set([...current].filter((entry) => available.has(entry))))
        setSelectionAnchor(undefined)
      }
    } catch (cause) {
      setError(normalizeCommandError(cause))
    } finally {
      setLoading(false)
    }
  }, [session.id, session.status])

  useEffect(() => {
    if (visible) void listTransferTasks(session.id).then(setTasks).catch((cause) => setError(normalizeCommandError(cause)))
  }, [session.id, visible])

  useEffect(() => {
    if (visible && !listing && !loading && !error && session.status === 'connected') void browse()
  }, [visible, listing, loading, error, session.status, browse])

  useEffect(() => {
    let dispose: (() => void) | undefined
    void listenToTransferProgress(({ task }) => {
      if (task.sessionId !== session.id) return
      setTasks((current) => [task, ...current.filter((item) => item.id !== task.id)])
      if (task.status === 'completed' && task.direction === 'upload' && listing) void browse(listing.path)
    }).then((value) => { dispose = value })
    return () => dispose?.()
  }, [session.id, listing, browse])

  const submitPath = (event: FormEvent) => {
    event.preventDefault()
    if (path.trim()) void browse(path.trim())
  }

  const chooseEntry = (event: MouseEvent, entry: RemoteDirectoryEntry, index: number) => {
    if (event.shiftKey && selectionAnchor !== undefined && listing) {
      const [start, end] = [selectionAnchor, index].sort((left, right) => left - right)
      setSelectedPaths(new Set(listing.entries.slice(start, end + 1).map((item) => item.path)))
    } else if (event.ctrlKey || event.metaKey) {
      setSelectedPaths((current) => {
        const next = new Set(current)
        if (next.has(entry.path)) next.delete(entry.path)
        else next.add(entry.path)
        return next
      })
      setSelectionAnchor(index)
    } else {
      setSelectedPaths(new Set([entry.path]))
      setSelectionAnchor(index)
    }
  }

  const openDialog = (kind: Dialog) => {
    setName(kind === 'rename' ? selected[0]?.name ?? '' : '')
    setMode(selected[0]?.permissionMode ?? 0o755)
    setRecursive(false)
    setDialog(kind)
  }

  const submitOperation = async (event: FormEvent) => {
    event.preventDefault()
    if (!listing || !dialog) return
    setMutating(true)
    setError(undefined)
    try {
      if (dialog === 'create') await createRemoteDirectory(session.id, listing.path, name)
      if (dialog === 'rename' && selected.length === 1) await renameRemoteEntry(session.id, selected[0].path, name)
      if (dialog === 'delete') await deleteRemoteEntries(session.id, selected.map((entry) => entry.path), recursive)
      if (dialog === 'permissions') await changeRemotePermissions(session.id, selected.map((entry) => entry.path), mode, recursive)
      setDialog(undefined)
      setSelectedPaths(new Set())
      await browse(listing.path)
    } catch (cause) {
      setError(normalizeCommandError(cause))
      setDialog(undefined)
    } finally {
      setMutating(false)
    }
  }

  const enqueueUpload = useCallback(async (sources: string[]) => {
    if (!listing || sources.length === 0) return
    try { await startTransfer(session.id, 'upload', sources, listing.path, conflictPolicy) }
    catch (cause) { setError(normalizeCommandError(cause)) }
  }, [listing, session.id, conflictPolicy])

  useEffect(() => {
    if (!visible || !listing || !('__TAURI_INTERNALS__' in window)) return
    let dispose: (() => void) | undefined
    let active = true
    void import('@tauri-apps/api/window').then(({ getCurrentWindow }) => getCurrentWindow().onDragDropEvent(async ({ payload }) => {
      if (!active) return
      if (payload.type === 'leave') {
        setDragging(false)
        return
      }
      const bounds = panelRef.current?.getBoundingClientRect()
      if (!bounds) return
      const scale = await getCurrentWindow().scaleFactor()
      const x = payload.position.x / scale
      const y = payload.position.y / scale
      const inside = x >= bounds.left && x <= bounds.right && y >= bounds.top && y <= bounds.bottom
      setDragging(inside)
      if (inside && payload.type === 'drop') {
        setDragging(false)
        await enqueueUpload(payload.paths)
      }
    })).then((unlisten) => {
      if (active) dispose = unlisten
      else unlisten()
    })
    return () => { active = false; dispose?.() }
  }, [visible, listing, enqueueUpload])

  const uploadFiles = async () => enqueueUpload(pathArray(await open({ multiple: true, directory: false })))
  const uploadDirectory = async () => enqueueUpload(pathArray(await open({ multiple: true, directory: true })))

  const download = async () => {
    if (selected.length === 0) return
    const target = await open({ directory: true, multiple: false, defaultPath: defaultDownloadDirectory })
    if (!target || Array.isArray(target)) return
    try { await startTransfer(session.id, 'download', selected.map((entry) => entry.path), target, conflictPolicy) }
    catch (cause) { setError(normalizeCommandError(cause)) }
  }

  const retry = async (task: TransferTask) => {
    try { await startTransfer(session.id, task.direction, task.sources, task.targetDirectory, conflictPolicy) }
    catch (cause) { setError(normalizeCommandError(cause)) }
  }

  const dropFiles = (event: DragEvent) => {
    event.preventDefault()
    setDragging(false)
    const paths = [...event.dataTransfer.files]
      .map((file) => (file as File & { path?: string }).path)
      .filter((value): value is string => Boolean(value))
    if (paths.length === 0) {
      setError({ code: 'LOCAL-DROP-UNAVAILABLE', category: 'validation', message: '当前平台未提供拖入对象的本地路径，请使用上传按钮', retryable: false })
      return
    }
    void enqueueUpload(paths)
  }

  const activeCount = tasks.filter((task) => ['queued', 'scanning', 'running'].includes(task.status)).length

  const clearFinished = async () => {
    try {
      await clearCompletedTransfers(session.id)
      setTasks((current) => current.filter((task) => ['queued', 'scanning', 'running'].includes(task.status)))
    } catch (cause) {
      setError(normalizeCommandError(cause))
    }
  }

  return (
    <aside ref={panelRef} className="sftp-panel" hidden={!visible} aria-label={`${session.title} 文件浏览器`} onDragOver={(event) => { event.preventDefault(); setDragging(true) }} onDragLeave={() => setDragging(false)} onDrop={dropFiles}>
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
        <button type="button" disabled={!listing || loading} onClick={() => void uploadFiles()}>上传文件</button>
        <button type="button" disabled={!listing || loading} onClick={() => void uploadDirectory()}>上传目录</button>
        <button type="button" disabled={selected.length === 0 || loading} onClick={() => void download()}>下载到</button>
        <button type="button" disabled={!listing || loading} onClick={() => openDialog('create')}>新建</button>
        <button type="button" disabled={selected.length !== 1 || loading} onClick={() => openDialog('rename')}>重命名</button>
        <button type="button" disabled={selected.length === 0 || loading} onClick={() => openDialog('permissions')}>权限</button>
        <button className="danger" type="button" disabled={selected.length === 0 || loading} onClick={() => openDialog('delete')}>删除</button>
      </div>
      <div className="sftp-selection-bar">
        <label>冲突<select value={conflictPolicy} onChange={(event) => setConflictPolicy(event.target.value as TransferConflictPolicy)}><option value="ask">遇到时询问</option><option value="overwrite">覆盖</option><option value="skip">跳过</option><option value="rename">自动重命名</option></select></label>
        <button type="button" disabled={!listing?.entries.length} onClick={() => setSelectedPaths(new Set(listing?.entries.map((entry) => entry.path)))}>全选当前页</button>
        <span>{selected.length} 项</span>
      </div>
      {error && <div className="sftp-error" role="alert"><ErrorDetails error={error} /><button type="button" onClick={() => setError(undefined)}>关闭</button></div>}
      {dragging && <div className="sftp-drop-target">释放到 <strong>{listing?.path}</strong>，将按队列策略上传</div>}
      {loading && !listing ? <div className="sftp-loading">正在建立 SFTP 通道…</div> : (
        <div className="sftp-list" role="listbox" aria-multiselectable="true">
          {listing?.entries.map((entry, index) => (
            <button
              className="sftp-entry"
              type="button"
              role="option"
              aria-selected={selectedPaths.has(entry.path)}
              key={entry.path}
              data-selected={selectedPaths.has(entry.path)}
              onClick={(event) => chooseEntry(event, entry, index)}
              onDoubleClick={() => entry.kind === 'directory' && void browse(entry.path)}
              title={entry.kind === 'symlink' ? `链接到 ${entry.symlinkTarget ?? '未知目标'}` : entry.path}
            >
              <Icon name={entry.kind === 'directory' ? 'folder' : 'terminal'} />
              <span className="sftp-entry-main"><strong>{entry.name}</strong><small>{entry.permissions} · {entry.permissionMode?.toString(8).padStart(3, '0') ?? '---'} · {entry.uid ?? '—'}:{entry.gid ?? '—'}</small></span>
              <span className="sftp-entry-meta"><span>{entry.kind === 'directory' ? '目录' : entry.kind === 'symlink' ? '链接' : formatSize(entry.size)}</span><small>{entry.modifiedAt ? new Date(entry.modifiedAt).toLocaleString() : '—'}</small></span>
            </button>
          ))}
          {listing && listing.entries.length === 0 && <div className="sftp-empty">此目录为空</div>}
          {listing?.nextCursor && <button className="sftp-load-more" type="button" disabled={loading} onClick={() => void browse(listing.path, listing.nextCursor)}>加载更多</button>}
        </div>
      )}
      {listing?.truncated && <footer className="sftp-notice">大目录已渐进加载，每次最多 1000 项</footer>}
      {tasks.length > 0 && <section className="transfer-tasks" aria-label="传输中心">
        <header><strong>传输中心</strong><span>{activeCount} 个进行中</span><button type="button" onClick={() => void clearFinished()}>清理完成项</button></header>
        {tasks.map((task) => {
          const percent = task.totalBytes ? Math.min(100, task.transferredBytes / task.totalBytes * 100) : 0
          return <div className="transfer-task" key={task.id}>
            <div><strong>{task.direction === 'upload' ? '↑' : '↓'} {task.fileName}</strong><span>{{ queued: '排队', scanning: '扫描', running: '传输', completed: '完成', failed: '失败', cancelled: '取消' }[task.status]}</span></div>
            <progress value={percent} max="100" />
            <small>{task.completedFiles}/{task.totalFiles} 文件 · {task.completedDirectories}/{task.totalDirectories} 目录 · 跳过 {task.skippedFiles}</small>
            <small>{formatSize(task.transferredBytes)} / {task.totalBytes === undefined ? '未知' : formatSize(task.totalBytes)} · {formatSize(task.bytesPerSecond)}/s · {task.elapsedSeconds}s</small>
            {task.currentPath && <small className="transfer-current">{task.currentPath}</small>}
            {task.error && <small className="transfer-error">{task.error}{task.errors.length ? ` · ${task.errors.slice(0, 3).join('；')}` : ''}</small>}
            {['queued', 'scanning', 'running'].includes(task.status) && <button type="button" onClick={() => void cancelTransfer(session.id, task.id)}>取消</button>}
            {['failed', 'cancelled'].includes(task.status) && <button type="button" onClick={() => void retry(task)}>重试</button>}
          </div>
        })}
      </section>}
      {dialog && (
        <div className="sftp-dialog-backdrop" role="presentation">
          <form className="sftp-dialog" role="dialog" aria-modal="true" aria-labelledby="sftp-dialog-title" onSubmit={submitOperation}>
            <span className="eyebrow">REMOTE OPERATION</span>
            <h2 id="sftp-dialog-title">{{ create: '新建文件夹', rename: '重命名', delete: '递归删除', permissions: '修改 Unix 权限' }[dialog]}</h2>
            {dialog === 'delete' && <p>将删除 {selected.length} 个对象（含 {selected.filter((entry) => entry.kind === 'directory').length} 个目录）。远端删除不可恢复，操作严格限制在所选根路径内且不会跟随软链接。</p>}
            {(dialog === 'create' || dialog === 'rename') && <label>名称<input autoFocus value={name} onChange={(event) => setName(event.target.value)} maxLength={255} /></label>}
            {dialog === 'permissions' && <PermissionEditor mode={mode} onChange={setMode} />}
            {(dialog === 'delete' || dialog === 'permissions') && selected.some((entry) => entry.kind === 'directory') && <label className="sftp-check"><input type="checkbox" checked={recursive} onChange={(event) => setRecursive(event.target.checked)} />递归处理目录内容</label>}
            <div>
              <button type="button" disabled={mutating} onClick={() => setDialog(undefined)}>取消</button>
              <button className={dialog === 'delete' ? 'danger' : 'confirm'} type="submit" disabled={mutating || ((dialog === 'create' || dialog === 'rename') && !name.trim())}>
                {mutating ? '处理中…' : dialog === 'delete' ? '确认删除' : '确认'}
              </button>
            </div>
          </form>
        </div>
      )}
    </aside>
  )
}

function PermissionEditor({ mode, onChange }: { mode: number; onChange: (mode: number) => void }) {
  const permissions = [
    ['所有者读', 0o400], ['所有者写', 0o200], ['所有者执行', 0o100],
    ['用户组读', 0o040], ['用户组写', 0o020], ['用户组执行', 0o010],
    ['其他人读', 0o004], ['其他人写', 0o002], ['其他人执行', 0o001],
  ] as const
  return <fieldset className="permission-editor"><legend>权限模式 {mode.toString(8).padStart(3, '0')}</legend>{permissions.map(([label, bit]) => <label key={bit}><input type="checkbox" checked={(mode & bit) !== 0} onChange={(event) => onChange(event.target.checked ? mode | bit : mode & ~bit)} />{label}</label>)}</fieldset>
}
