import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
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
  AuthenticationPromptPayload,
  AgentIdentityInfo,
  ConnectionProfile,
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
  listenToAuthenticationPrompt,
  listSshAgentIdentities,
  normalizeCommandError,
  respondAuthenticationPrompt,
  testSshConnection,
  testSavedConnection,
  type AppCommandError,
} from '../../lib/ipc'

interface ConnectionDialogProps {
  open: boolean
  initialDraft?: ConnectionDraft
  groups?: ConnectionGroup[]
  connections?: ConnectionProfile[]
  reconnecting?: boolean
  keepalive: { enabled: boolean; seconds: number }
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
  connections = [],
  reconnecting = false,
  keepalive,
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
  const operationIdRef = useRef<string | undefined>(undefined)
  const [progress, setProgress] = useState('')
  const [commandError, setCommandError] = useState<AppCommandError>()
  const [testResult, setTestResult] = useState<number>()
  const [authFailures, setAuthFailures] = useState(0)
  const [showSecret, setShowSecret] = useState(false)
  const [authenticationPrompt, setAuthenticationPrompt] = useState<AuthenticationPromptPayload>()
  const [promptAnswers, setPromptAnswers] = useState<Record<string, string>>({})
  const [agentIdentities, setAgentIdentities] = useState<AgentIdentityInfo[]>()
  const [agentError, setAgentError] = useState<string>()

  const busy = Boolean(operationId)
  const locked = authFailures >= 3
  const hasStoredCredential = Boolean(suppliedDraft?.id && suppliedDraft.rememberCredential)
  const hasStoredProxyCredential = Boolean(suppliedDraft?.id && suppliedDraft.rememberProxyCredential)

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
    let disposed = false
    let cleanup: (() => void) | undefined
    void listenToAuthenticationPrompt((payload) => {
      if (!disposed && payload.operationId === operationIdRef.current) {
        setAuthenticationPrompt(payload)
        setPromptAnswers(Object.fromEntries(payload.prompts.map((prompt) => [prompt.id, ''])))
      }
    }).then((unlisten) => {
      if (disposed) unlisten()
      else cleanup = unlisten
    })
    return () => {
      disposed = true
      cleanup?.()
    }
  }, [])

  useEffect(() => {
    if (!visible || draft.authType !== 'agent') return
    let disposed = false
    setAgentIdentities(undefined)
    setAgentError(undefined)
    void listSshAgentIdentities()
      .then((identities) => { if (!disposed) setAgentIdentities(identities) })
      .catch((error) => { if (!disposed) setAgentError(normalizeCommandError(error).message) })
    return () => { disposed = true }
  }, [visible, draft.authType])

  useEffect(() => {
    if (!authenticationPrompt) return
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.preventDefault()
        void cancelOperation(authenticationPrompt.operationId)
        setAuthenticationPrompt(undefined)
        setOperationId(undefined)
        setProgress('')
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [authenticationPrompt])

  useEffect(() => {
    if (visible) setDraft(suppliedDraft ?? initialConnectionDraft)
    if (!visible) {
      setDraft(initialConnectionDraft)
      setErrors({})
      setInspection(undefined)
      setIntent('connect')
      setOperationId(undefined)
      operationIdRef.current = undefined
      setCommandError(undefined)
      setTestResult(undefined)
      setProgress('')
      setAuthFailures(0)
      setShowSecret(false)
      setAuthenticationPrompt(undefined)
      setPromptAnswers({})
      setAgentIdentities(undefined)
      setAgentError(undefined)
    }
  }, [visible, suppliedDraft])

  const normalizedRequest = useMemo(
    () => toConnectionRequest(draft, undefined, keepalive),
    [draft, keepalive],
  )

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
    const nextErrors = validateConnectionDraft(draft, hasStoredCredential, hasStoredProxyCredential)
    setErrors(nextErrors)
    setCommandError(undefined)
    setTestResult(undefined)
    if (Object.keys(nextErrors).length > 0 || locked) return

    const nextOperationId = crypto.randomUUID()
    setIntent(nextIntent)
    operationIdRef.current = nextOperationId
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
      operationIdRef.current = undefined
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
    operationIdRef.current = nextOperationId
    setOperationId(nextOperationId)
    setProgress(selectedIntent === 'test' ? '正在测试认证信息…' : '正在创建远程终端…')
    try {
      if (selectedIntent === 'test') {
        const result = draft.id
          ? await testSavedConnection(nextOperationId, draft.id, currentSecret(draft), approval, keepalive)
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
      operationIdRef.current = undefined
      setOperationId(undefined)
    }
  }

  const handleError = (error: unknown) => {
    const normalized = normalizeCommandError(error)
    setCommandError(normalized)
    setProgress('')
    if (normalized.code === 'AUTHENTICATION-FAILED' || normalized.code.includes('REJECTED')) {
      setAuthFailures((count) => count + 1)
    }
  }

  const cancel = async () => {
    if (operationId) await cancelOperation(operationId)
    operationIdRef.current = undefined
    setOperationId(undefined)
    setInspection(undefined)
    setProgress('')
        setAuthenticationPrompt(undefined)
        operationIdRef.current = undefined
  }

  const submitAuthenticationPrompt = async () => {
    if (!authenticationPrompt) return
    const response = {
      operationId: authenticationPrompt.operationId,
      promptId: authenticationPrompt.promptId,
      answers: authenticationPrompt.prompts.map((prompt) => ({
        id: prompt.id,
        value: promptAnswers[prompt.id] ?? '',
      })),
    }
    try {
      await respondAuthenticationPrompt(response)
      setAuthenticationPrompt(undefined)
      setPromptAnswers({})
    } catch (error) {
      handleError(error)
    }
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
    const nextErrors = validateConnectionDraft(draft, true, hasStoredProxyCredential)
    if ((draft.authType === 'password' || draft.authType === 'privateKey') && draft.rememberCredential && !hasStoredCredential && !currentSecret(draft)) {
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
            <span className="eyebrow">{reconnecting ? 'RECONNECT SESSION' : draft.id ? 'EDIT CONNECTION' : 'NEW SSH SESSION'}</span>
            <h2 id="connection-dialog-title">{reconnecting ? `重新连接 ${draft.name}` : draft.id ? '编辑连接' : '新建连接'}</h2>
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
            <button className={draft.authType === 'keyboardInteractive' ? 'active' : ''} type="button" onClick={() => update('authType', 'keyboardInteractive')}>交互验证</button>
            <button className={draft.authType === 'agent' ? 'active' : ''} type="button" onClick={() => update('authType', 'agent')}>SSH Agent</button>
          </fieldset>

          {draft.authType === 'password' ? (
            <Field label="密码" error={errors.password}>
              <div className="secret-input">
                <input type={showSecret ? 'text' : 'password'} value={draft.password} onChange={(event) => update('password', event.target.value)} autoComplete="current-password" />
                <button type="button" onClick={() => setShowSecret((value) => !value)}>{showSecret ? '隐藏' : '显示'}</button>
              </div>
            </Field>
          ) : draft.authType === 'privateKey' ? (
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
          ) : draft.authType === 'keyboardInteractive' ? (
            <div className="auth-method-note">
              <Icon name="shield" />
              <div><strong>由服务器动态询问</strong><span>适用于验证码、双因素认证和“每次询问”场景；回答只用于本次连接，不会保存。</span></div>
            </div>
          ) : (
            <div className="agent-status" aria-live="polite">
              <Icon name="key" />
              <div>
                <strong>Windows OpenSSH Agent</strong>
                {agentError ? <span className="agent-error">{agentError}</span> : agentIdentities === undefined ? <span>正在检查 Agent…</span> : agentIdentities.length === 0 ? <span>Agent 已连接，但没有可用公钥。</span> : <span>已发现 {agentIdentities.length} 个可用公钥。</span>}
                {agentIdentities && agentIdentities.length > 0 && (
                  <select value={draft.agentKeyFingerprint} onChange={(event) => update('agentKeyFingerprint', event.target.value)} aria-label="首选 SSH Agent 密钥">
                    <option value="">自动尝试全部密钥</option>
                    {agentIdentities.map((identity) => <option key={identity.fingerprintSha256} value={identity.fingerprintSha256}>{identity.algorithm} · {identity.comment || identity.fingerprintSha256}</option>)}
                  </select>
                )}
              </div>
            </div>
          )}
          {(draft.authType === 'password' || draft.authType === 'privateKey') && (
            <label className="remember-row">
              <input type="checkbox" checked={draft.rememberCredential} onChange={(event) => update('rememberCredential', event.target.checked)} />
              <span>{draft.authType === 'password' ? '记住密码' : '记住私钥口令'}（使用 Windows 凭据库）</span>
            </label>
          )}

          <fieldset className="network-path-settings">
            <legend>网络路径</legend>
            <label className="remember-row">
              <input type="checkbox" checked={draft.proxyEnabled} onChange={(event) => update('proxyEnabled', event.target.checked)} />
              <span>通过出站代理连接</span>
            </label>
            {draft.proxyEnabled && (
              <div className="network-path-body">
                <div className="form-grid">
                  <Field label="代理协议">
                    <select value={draft.proxyType} onChange={(event) => update('proxyType', event.target.value as ConnectionDraft['proxyType'])}>
                      <option value="http">HTTP CONNECT</option>
                      <option value="socks5">SOCKS5</option>
                    </select>
                  </Field>
                  <Field label="代理端口" error={errors.proxyPort}>
                    <input type="number" min={1} max={65535} value={draft.proxyPort} onChange={(event) => update('proxyPort', Number(event.target.value))} />
                  </Field>
                </div>
                <Field label="代理主机" error={errors.proxyHost}>
                  <input value={draft.proxyHost} onChange={(event) => update('proxyHost', event.target.value)} placeholder="proxy.example.com" />
                </Field>
                <div className="form-grid">
                  <Field label="代理用户名（可选）" error={errors.proxyUsername}>
                    <input value={draft.proxyUsername} onChange={(event) => update('proxyUsername', event.target.value)} autoComplete="off" />
                  </Field>
                  <Field label="代理密码" error={errors.proxyPassword}>
                    <input type="password" value={draft.proxyPassword} onChange={(event) => update('proxyPassword', event.target.value)} autoComplete="new-password" />
                  </Field>
                </div>
                {draft.proxyUsername && <label className="remember-row"><input type="checkbox" checked={draft.rememberProxyCredential} onChange={(event) => update('rememberProxyCredential', event.target.checked)} /><span>使用 Windows 凭据库保存代理密码</span></label>}
              </div>
            )}

            {draft.id && connections.length > 1 && (
              <div className="jump-host-editor">
                <span>跳板链</span>
                <select aria-label="添加跳板连接" value="" onChange={(event) => {
                  const id = event.target.value
                  if (id && !draft.jumpHostIds.includes(id)) update('jumpHostIds', [...draft.jumpHostIds, id])
                }}>
                  <option value="">添加已有连接…</option>
                  {connections.filter((connection) => connection.id !== draft.id && !draft.jumpHostIds.includes(connection.id)).map((connection) => <option key={connection.id} value={connection.id}>{connection.name} · {connection.username}@{connection.host}</option>)}
                </select>
                {draft.jumpHostIds.map((id, index) => {
                  const connection = connections.find((candidate) => candidate.id === id)
                  return <div className="jump-host-row" key={id}><strong>{index + 1}</strong><span>{connection?.name ?? '失效连接'}</span><button type="button" disabled={index === 0} onClick={() => { const next = [...draft.jumpHostIds]; [next[index - 1], next[index]] = [next[index], next[index - 1]]; update('jumpHostIds', next) }}>上移</button><button type="button" disabled={index === draft.jumpHostIds.length - 1} onClick={() => { const next = [...draft.jumpHostIds]; [next[index], next[index + 1]] = [next[index + 1], next[index]]; update('jumpHostIds', next) }}>下移</button><button type="button" onClick={() => update('jumpHostIds', draft.jumpHostIds.filter((value) => value !== id))}>移除</button></div>
                })}
              </div>
            )}
          </fieldset>
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
      {authenticationPrompt && (
        <div className="host-key-layer">
          <section className="authentication-prompt-dialog" role="dialog" aria-modal="true" aria-labelledby="authentication-prompt-title">
            <span className="eyebrow">REMOTE AUTHENTICATION</span>
            <h2 id="authentication-prompt-title">{authenticationPrompt.name || '服务器需要继续验证'}</h2>
            <p className="authentication-target">{authenticationPrompt.connectionTitle} · {authenticationPrompt.target}</p>
            {authenticationPrompt.instructions && <p>{authenticationPrompt.instructions}</p>}
            <div className="authentication-prompt-fields">
              {authenticationPrompt.prompts.map((prompt, index) => (
                <Field key={prompt.id} label={prompt.text || `回答 ${index + 1}`}>
                  <input
                    autoFocus={index === 0}
                    type={prompt.echo ? 'text' : 'password'}
                    value={promptAnswers[prompt.id] ?? ''}
                    onChange={(event) => setPromptAnswers((current) => ({ ...current, [prompt.id]: event.target.value }))}
                    onKeyDown={(event) => { if (event.key === 'Enter') void submitAuthenticationPrompt() }}
                  />
                </Field>
              ))}
            </div>
            <div className="host-key-actions">
              <button className="secondary-button danger" type="button" onClick={() => void cancel()}>取消连接</button>
              <button className="primary-button" type="button" onClick={() => void submitAuthenticationPrompt()}>提交回答</button>
            </div>
          </section>
        </div>
      )}
    </div>
  )
}

function currentSecret(draft: ConnectionDraft): string | undefined {
  const secret = draft.authType === 'password'
    ? draft.password
    : draft.authType === 'privateKey'
      ? draft.privateKeyPassphrase
      : ''
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
