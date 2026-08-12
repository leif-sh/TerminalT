import { useEffect, useMemo, useState, type ReactNode } from 'react'
import { homeDir, join } from '@tauri-apps/api/path'
import { open } from '@tauri-apps/plugin-dialog'
import { Icon } from '../../components/Icon'
import type {
  ConnectionDraft,
  ConnectionFormErrors,
  ConnectionGroup,
  ConnectionRequest,
  HostKeyAction,
  HostKeyApproval,
  HostKeyInspection,
} from '../../domain/connection/types'
import {
  initialConnectionDraft,
  toSaveConnectionRequest,
  toConnectionRequest,
  validateConnectionDraft,
} from '../../domain/connection/types'
import {
  cancelOperation,
  inspectSshHostKey,
  listenToConnectionProgress,
  normalizeCommandError,
  testSshConnection,
  testSavedConnection,
  type AppCommandError,
} from '../../lib/ipc'

interface ConnectionDialogProps {
  open: boolean
  initialDraft?: ConnectionDraft
  groups?: ConnectionGroup[]
  onClose: () => void
  onSave?: (request: ReturnType<typeof toSaveConnectionRequest>) => Promise<void>
  onConnect: (
    operationId: string,
    request: ConnectionRequest,
    approval: HostKeyApproval,
  ) => Promise<void>
  onConnectSaved?: (
    operationId: string,
    connectionId: string,
    temporarySecret: string | undefined,
    approval: HostKeyApproval,
  ) => Promise<void>
}

type Intent = 'test' | 'connect'

export function ConnectionDialog({
  open: visible,
  initialDraft: suppliedDraft,
  groups = [],
  onClose,
  onSave,
  onConnect,
  onConnectSaved,
}: ConnectionDialogProps) {
  const [draft, setDraft] = useState<ConnectionDraft>(initialConnectionDraft)
  const [errors, setErrors] = useState<ConnectionFormErrors>({})
  const [inspection, setInspection] = useState<HostKeyInspection>()
  const [intent, setIntent] = useState<Intent>('connect')
  const [operationId, setOperationId] = useState<string>()
  const [progress, setProgress] = useState('')
  const [commandError, setCommandError] = useState<AppCommandError>()
  const [testResult, setTestResult] = useState<number>()
  const [authFailures, setAuthFailures] = useState(0)
  const [showSecret, setShowSecret] = useState(false)

  const busy = Boolean(operationId)
  const locked = authFailures >= 3
  const hasStoredCredential = Boolean(suppliedDraft?.id && suppliedDraft.rememberCredential)

  useEffect(() => {
    let disposed = false
    let cleanup: (() => void) | undefined
    void listenToConnectionProgress((payload) => {
      if (!disposed && payload.operationId === operationId) setProgress(payload.message)
    }).then((unlisten) => {
      if (disposed) unlisten()
      else cleanup = unlisten
    })
    return () => {
      disposed = true
      cleanup?.()
    }
  }, [operationId])

  useEffect(() => {
    if (visible) setDraft(suppliedDraft ?? initialConnectionDraft)
    if (!visible) {
      setDraft(initialConnectionDraft)
      setErrors({})
      setInspection(undefined)
      setIntent('connect')
      setOperationId(undefined)
      setCommandError(undefined)
      setTestResult(undefined)
      setProgress('')
      setAuthFailures(0)
      setShowSecret(false)
    }
  }, [visible, suppliedDraft])

  const normalizedRequest = useMemo(() => toConnectionRequest(draft), [draft])

  if (!visible) return null

  const update = <Key extends keyof ConnectionDraft>(key: Key, value: ConnectionDraft[Key]) => {
    setDraft((current) => ({ ...current, [key]: value }))
    setErrors((current) => ({ ...current, [key]: undefined }))
    setTestResult(undefined)
    setCommandError(undefined)
    if (key === 'password' || key === 'privateKeyPassphrase' || key === 'privateKeyPath') {
      setAuthFailures(0)
    }
  }

  const begin = async (nextIntent: Intent) => {
    const nextErrors = validateConnectionDraft(draft, hasStoredCredential)
    setErrors(nextErrors)
    setCommandError(undefined)
    setTestResult(undefined)
    if (Object.keys(nextErrors).length > 0 || locked) return

    const nextOperationId = crypto.randomUUID()
    setIntent(nextIntent)
    setOperationId(nextOperationId)
    setProgress('正在连接服务器并获取指纹…')
    try {
      const result = await inspectSshHostKey(nextOperationId, normalizedRequest)
      setInspection(result)
      if (result.status === 'trusted') {
        await execute(nextIntent, result, 'useTrusted')
      } else {
        setProgress('')
      }
    } catch (error) {
      handleError(error)
    } finally {
      setOperationId(undefined)
    }
  }

  const execute = async (
    selectedIntent: Intent,
    hostKey: HostKeyInspection,
    action: HostKeyAction,
  ) => {
    const nextOperationId = crypto.randomUUID()
    const approval: HostKeyApproval = {
      fingerprintSha256: hostKey.fingerprintSha256,
      action,
    }
    setInspection(undefined)
    setOperationId(nextOperationId)
    setProgress(selectedIntent === 'test' ? '正在测试认证信息…' : '正在创建远程终端…')
    try {
      if (selectedIntent === 'test') {
        const result = draft.id
          ? await testSavedConnection(nextOperationId, draft.id, currentSecret(draft), approval)
          : await testSshConnection(nextOperationId, normalizedRequest, approval)
        setTestResult(result.elapsedMillis)
        setProgress('')
      } else {
        if (draft.id && onConnectSaved) {
          await onConnectSaved(nextOperationId, draft.id, currentSecret(draft), approval)
        } else {
          await onConnect(nextOperationId, normalizedRequest, approval)
        }
        onClose()
      }
    } catch (error) {
      handleError(error)
    } finally {
      setOperationId(undefined)
    }
  }

  const handleError = (error: unknown) => {
    const normalized = normalizeCommandError(error)
    setCommandError(normalized)
    setProgress('')
    if (normalized.code === 'AUTHENTICATION-FAILED') {
      setAuthFailures((count) => count + 1)
    }
  }

  const cancel = async () => {
    if (operationId) await cancelOperation(operationId)
    setOperationId(undefined)
    setInspection(undefined)
    setProgress('')
  }

  const selectPrivateKey = async () => {
    let defaultPath: string | undefined
    try {
      defaultPath = await join(await homeDir(), '.ssh')
    } catch {
      // Browser preview has no native path API; the native picker still works in Tauri.
    }
    const path = await open({
      multiple: false,
      directory: false,
      title: '选择 SSH 私钥',
      defaultPath,
    })
    if (typeof path === 'string') update('privateKeyPath', path)
  }

  const save = async () => {
    const nextErrors = validateConnectionDraft(draft, true)
    if (draft.rememberCredential && !hasStoredCredential && !currentSecret(draft)) {
      if (draft.authType === 'password') nextErrors.password = '请输入需要保存的密码'
      else nextErrors.privateKeyPassphrase = '请输入私钥口令，或取消记住口令'
    }
    setErrors(nextErrors)
    if (Object.keys(nextErrors).length > 0 || !onSave) return
    setProgress('正在安全保存连接…')
    try {
      await onSave(toSaveConnectionRequest(draft))
      onClose()
    } catch (error) {
      handleError(error)
    } finally {
      setProgress('')
    }
  }

  return (
    <div className="dialog-backdrop" role="presentation">
      <section className="connection-dialog" role="dialog" aria-modal="true" aria-labelledby="connection-dialog-title">
        <header className="dialog-header">
          <div>
            <span className="eyebrow">{draft.id ? 'EDIT CONNECTION' : 'NEW SSH SESSION'}</span>
            <h2 id="connection-dialog-title">{draft.id ? '编辑连接' : '新建连接'}</h2>
            <p>普通数据只保存连接信息，秘密仅在授权时写入 Windows 凭据库。</p>
          </div>
          <button className="dialog-close" type="button" onClick={onClose} disabled={busy} aria-label="关闭"><Icon name="close" /></button>
        </header>

        <div className="connection-form">
          <Field label="连接名称" error={errors.name}>
            <input value={draft.name} onChange={(event) => update('name', event.target.value)} placeholder="默认使用主机名" maxLength={64} />
          </Field>
          {groups.length > 0 && (
            <Field label="分组">
              <select value={draft.groupId} onChange={(event) => update('groupId', event.target.value)}>
                {groups.map((group) => <option key={group.id} value={group.id}>{group.name}</option>)}
              </select>
            </Field>
          )}
          <div className="form-grid host-grid">
            <Field label="主机地址" error={errors.host}>
              <input value={draft.host} onChange={(event) => update('host', event.target.value)} placeholder="example.com 或 192.168.1.10" autoFocus />
            </Field>
            <Field label="端口" error={errors.port}>
              <input type="number" min={1} max={65535} value={draft.port} onChange={(event) => update('port', Number(event.target.value))} />
            </Field>
          </div>
          <div className="form-grid">
            <Field label="用户名" error={errors.username}>
              <input value={draft.username} onChange={(event) => update('username', event.target.value)} autoComplete="username" />
            </Field>
            <Field label="连接超时" error={errors.timeoutSeconds} suffix="秒">
              <input type="number" min={5} max={60} value={draft.timeoutSeconds} onChange={(event) => update('timeoutSeconds', Number(event.target.value))} />
            </Field>
          </div>

          <fieldset className="auth-selector">
            <legend>认证方式</legend>
            <button className={draft.authType === 'password' ? 'active' : ''} type="button" onClick={() => update('authType', 'password')}>密码</button>
            <button className={draft.authType === 'privateKey' ? 'active' : ''} type="button" onClick={() => update('authType', 'privateKey')}>私钥</button>
          </fieldset>

          {draft.authType === 'password' ? (
            <Field label="密码" error={errors.password}>
              <div className="secret-input">
                <input type={showSecret ? 'text' : 'password'} value={draft.password} onChange={(event) => update('password', event.target.value)} autoComplete="current-password" />
                <button type="button" onClick={() => setShowSecret((value) => !value)}>{showSecret ? '隐藏' : '显示'}</button>
              </div>
            </Field>
          ) : (
            <>
              <Field label="私钥文件" error={errors.privateKeyPath}>
                <div className="path-input">
                  <input value={draft.privateKeyPath} onChange={(event) => update('privateKeyPath', event.target.value)} placeholder="选择 OpenSSH 私钥文件" />
                  <button type="button" onClick={() => void selectPrivateKey()}><Icon name="folder" />选择</button>
                </div>
              </Field>
              <Field label="私钥口令（可选）" error={errors.privateKeyPassphrase}>
                <div className="secret-input">
                  <input type={showSecret ? 'text' : 'password'} value={draft.privateKeyPassphrase} onChange={(event) => update('privateKeyPassphrase', event.target.value)} />
                  <button type="button" onClick={() => setShowSecret((value) => !value)}>{showSecret ? '隐藏' : '显示'}</button>
                </div>
              </Field>
            </>
          )}
          <label className="remember-row">
            <input type="checkbox" checked={draft.rememberCredential} onChange={(event) => update('rememberCredential', event.target.checked)} />
            <span>{draft.authType === 'password' ? '记住密码' : '记住私钥口令'}（使用 Windows 凭据库）</span>
          </label>
          {onSave && (
            <Field label="备注" error={errors.note}>
              <textarea value={draft.note} onChange={(event) => update('note', event.target.value)} maxLength={500} rows={3} placeholder="用途、环境或维护信息" />
            </Field>
          )}
        </div>

        {commandError && (
          <div className="connection-error" role="alert">
            <strong>{commandError.message}</strong>
            <span>{commandError.code}</span>
            {commandError.technicalDetails && <details><summary>技术详情</summary><code>{commandError.technicalDetails}</code></details>}
          </div>
        )}
        {locked && <div className="connection-error locked" role="alert">认证已连续失败 3 次。修改认证信息后可重新尝试。</div>}
        {testResult !== undefined && <div className="test-success" role="status"><Icon name="shield" />测试连接成功 · {testResult} ms</div>}
        {progress && <div className="connection-progress" role="status"><span className="progress-spinner" />{progress}</div>}

        <footer className="dialog-actions">
          {onSave && <button className="secondary-button" type="button" onClick={() => void save()} disabled={busy}>保存</button>}
          {busy ? (
            <button className="secondary-button danger" type="button" onClick={() => void cancel()}>取消连接</button>
          ) : (
            <button className="secondary-button" type="button" onClick={() => void begin('test')} disabled={locked}>测试连接</button>
          )}
          <button className="primary-button" type="button" onClick={() => void begin('connect')} disabled={busy || locked}>连接</button>
        </footer>
      </section>

      {inspection && inspection.status !== 'trusted' && (
        <HostKeyDialog
          inspection={inspection}
          intent={intent}
          onCancel={() => setInspection(undefined)}
          onApprove={(action) => void execute(intent, inspection, action)}
        />
      )}
    </div>
  )
}

function currentSecret(draft: ConnectionDraft): string | undefined {
  const secret = draft.authType === 'password' ? draft.password : draft.privateKeyPassphrase
  return secret || undefined
}

function Field({ label, error, suffix, children }: { label: string; error?: string; suffix?: string; children: ReactNode }) {
  return (
    <label className={error ? 'form-field invalid' : 'form-field'}>
      <span>{label}{suffix && <em>{suffix}</em>}</span>
      {children}
      {error && <small>{error}</small>}
    </label>
  )
}

function HostKeyDialog({ inspection, intent, onCancel, onApprove }: {
  inspection: HostKeyInspection
  intent: Intent
  onCancel: () => void
  onApprove: (action: HostKeyAction) => void
}) {
  const changed = inspection.status === 'changed'
  return (
    <div className="host-key-layer">
      <section className={changed ? 'host-key-dialog danger' : 'host-key-dialog'} role="alertdialog" aria-modal="true" aria-labelledby="host-key-title">
        <span className="host-key-icon"><Icon name={changed ? 'shield' : 'server'} /></span>
        <span className="eyebrow">{changed ? 'HIGH RISK WARNING' : 'UNKNOWN HOST'}</span>
        <h2 id="host-key-title">{changed ? '服务器身份发生变化' : '确认服务器身份'}</h2>
        <p>{changed ? '该服务器的主机密钥与历史记录不一致。请确认服务器确实更换过密钥，否则可能存在中间人攻击。' : '这是首次连接该服务器。请核对指纹后再继续。'}</p>
        <dl>
          <div><dt>主机</dt><dd>{inspection.host}:{inspection.port}</dd></div>
          <div><dt>算法</dt><dd>{inspection.algorithm}</dd></div>
          {inspection.previousFingerprintSha256 && <div><dt>旧指纹</dt><dd>{inspection.previousFingerprintSha256}</dd></div>}
          <div><dt>新指纹</dt><dd>{inspection.fingerprintSha256}</dd></div>
        </dl>
        <div className="host-key-actions">
          <button className="secondary-button" type="button" onClick={onCancel}>取消</button>
          <button className={changed ? 'danger-button' : 'primary-button'} type="button" onClick={() => onApprove(changed ? 'replaceChanged' : 'trustNew')}>
            {changed ? `确认替换并${intent === 'test' ? '测试' : '连接'}` : `信任并${intent === 'test' ? '测试' : '继续'}`}
          </button>
        </div>
      </section>
    </div>
  )
}
