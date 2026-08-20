# 阶段 7：认证兼容性

## 1. 阶段目标

在现有密码和私钥认证基础上，补齐企业 SSH 环境常用的 keyboard-interactive、双因素认证、每次询问和 SSH Agent。阶段结束时，连接测试、首次连接和手动重连使用同一认证状态机，所有临时响应均可取消、可清理且不会进入持久化数据或日志。

## 2. 前置条件

- 阶段 0～6 已完成并通过基础版发布验收。
- 恢复 `AGENTS.md` 引用的前端设计规范、Rust 后端规范和项目级 CI skill，或修正其有效路径。
- 用最小技术验证确认当前 `russh` 版本支持 keyboard-interactive 和外部签名；不满足时先形成依赖升级或受控扩展方案。
- 准备支持 PAM/TOTP 的 OpenSSH 测试服务器和 Windows OpenSSH Agent 测试环境。
- 冻结认证提示、响应、取消和错误码的 IPC 契约后再开始界面开发。

## 3. 对应需求

- 总体开发文档 P0：keyboard-interactive、2FA、每次询问和 SSH Agent。
- 现有 `FR-SSH-002`、`FR-SSH-003` 的认证安全要求。
- 连接测试、正式连接、已保存连接和重连流程的统一认证行为。

## 4. 范围与边界

本阶段包含：

- keyboard-interactive 单轮和多轮提示；
- 密码加验证码等 2FA 组合流程；
- 每次连接时询问秘密且永不保存；
- Windows OpenSSH Agent 可用密钥发现和签名；
- 认证方式 schema 迁移、连接表单和错误反馈；
- 认证任务取消、超时、失败限制和秘密清理。

本阶段不包含：

- FIDO/U2F、PKCS#11、SSH 证书和智能卡；
- 跳板机、代理和端口转发；
- WebAuthn 或浏览器 OAuth 登录；
- 自动尝试所有本地私钥文件。

## 5. 数据模型与 IPC 契约

### 5.1 连接模型

将认证类型扩展为：

```ts
type AuthType = 'password' | 'privateKey' | 'keyboardInteractive' | 'agent'
```

约束：

- `keyboardInteractive` 只保存用户名和认证类型；
- `agent` 可保存可选公钥指纹或注释作为首选密钥，不保存私钥；
- “每次询问”是秘密获取策略，不复制成另一套密码类型；
- schema 迁移为现有连接补齐默认秘密策略，旧连接行为保持不变；
- 导出文件不得包含提示响应、Agent 签名数据或秘密缓存。

### 5.2 认证事件

建议新增版本化事件：

```ts
interface AuthenticationPromptEvent {
  operationId: string
  promptId: string
  connectionTitle: string
  instruction?: string
  prompts: Array<{ id: string; text: string; echo: boolean }>
  expiresAt?: string
}

interface AuthenticationPromptResponse {
  operationId: string
  promptId: string
  answers: Array<{ id: string; value: string }>
}
```

- 远端提示文本按不可信数据展示；
- 响应必须同时匹配 `operationId` 和 `promptId`；
- 旧提示、重复响应和已取消任务的响应必须拒绝；
- 提示超时后关闭对话框并终止对应认证步骤。

### 5.3 后端状态机

认证状态至少包含：

```text
准备认证 → 等待远端方法 → 等待用户响应 → 提交响应
        ↘ Agent 枚举 → 请求签名 → 提交公钥认证
任意状态 → 已认证 | 失败 | 已取消 | 超时
```

状态转换由 Rust 后端拥有，React 只展示提示和提交响应，不自行推断下一认证步骤。

## 6. 详细开发功能

### 6.1 keyboard-interactive

- 支持远端一次返回一个或多个提示。
- 根据 `echo` 决定普通输入或遮挡输入，但不根据提示文本猜测秘密类型。
- 显示远端 instruction、提示顺序和当前连接目标。
- 多轮交互保持同一操作上下文，上一轮响应提交后立即清理。
- 用户关闭对话框等价于取消整个认证操作。
- 远端返回空提示、重复提示或超长提示时安全处理并限制资源占用。

### 6.2 2FA 组合流程

- 支持 password 后继续 keyboard-interactive 的服务端策略。
- 支持同一轮密码和验证码两个输入框。
- 不把验证码交给 Windows 凭据库。
- 失败次数按完整认证尝试计数，不把每轮提示误计为独立失败。
- 重试必须创建新的提示 ID，旧响应不能被复用。

### 6.3 每次询问

- 已保存连接可配置“每次询问”，连接前弹出临时秘密输入。
- 临时秘密只进入本次 `operationId`，不写回 ConnectionProfile。
- 测试连接结束、连接取消、认证失败和应用退出均清理秘密。
- 手动重连再次询问，不静默复用上一次内存值。

### 6.4 SSH Agent

- 连接 Windows OpenSSH Agent，列出公钥元数据而非私钥内容。
- 支持按用户选择或已保存指纹优先尝试密钥。
- 对每个签名请求校验会话上下文，禁止跨连接复用签名结果。
- Agent 未运行、拒绝签名、无密钥和全部密钥被服务器拒绝时分别报错。
- 不在日志中输出完整公钥 blob、签名或可能敏感的 Agent 通信内容。
- Agent 失败是否回退到其他认证方式必须由用户配置或服务器协商明确决定。

### 6.5 连接表单与提示界面

- 认证方式展示密码、私钥、交互认证和 SSH Agent。
- 交互认证不显示可保存密码字段。
- Agent 模式展示可用性、首选密钥和刷新入口。
- 认证对话框锁定连接目标，避免用户误把验证码输入到其他标签。
- 对话框具备键盘焦点循环、Enter 提交和 Escape 取消。
- 所有失败提示保留稳定错误码和脱敏技术详情。

### 6.6 取消、超时与资源释放

- 连接取消同时唤醒等待用户响应的后端任务。
- 前端卸载、窗口关闭和应用退出不得留下等待中的 oneshot/channel。
- 提示等待超时与网络超时使用不同错误码。
- 认证成功后移除对应 broker 记录，迟到响应返回“提示已失效”。
- 仅保存必要的失败计数，不保存用户答案。

### 6.7 错误码

至少覆盖：

```text
AUTH-INTERACTIVE-UNAVAILABLE
AUTH-INTERACTIVE-TIMEOUT
AUTH-INTERACTIVE-REJECTED
AUTH-PROMPT-STALE
AUTH-AGENT-UNAVAILABLE
AUTH-AGENT-NO-KEYS
AUTH-AGENT-SIGN-FAILED
AUTH-AGENT-REJECTED
```

## 7. 测试与验证

### 7.1 自动化测试

- 认证状态机全部合法和非法转换。
- 单提示、多提示、多轮提示、空提示和超长提示。
- 旧 prompt 响应、重复提交、取消与响应竞态。
- schema v1 连接迁移和导入导出往返。
- Agent 无密钥、多个密钥、拒绝签名和服务不可用。
- 日志、配置、导出与错误结构的秘密扫描。

### 7.2 集成与人工测试

- OpenSSH password-only、publickey-only、keyboard-interactive-only。
- 密码加 TOTP、仅 TOTP 和错误验证码。
- Windows OpenSSH Agent 使用 RSA、ECDSA、Ed25519 密钥。
- 连接测试、连接、取消、三次失败和手动重连。
- 连续 100 次提示打开/取消后无任务、句柄和内存持续增长。

## 8. 任务拆分

1. 技术验证与协议决策：输出依赖能力结论和状态机设计。
2. 数据模型与迁移：先完成 schema、往返和兼容测试。
3. AuthenticationBroker：完成提示、响应、取消和超时。
4. keyboard-interactive：完成后端集成与 loopback 测试。
5. SSH Agent：完成枚举、选择、签名和错误映射。
6. 前端表单与认证对话框：接入稳定 IPC。
7. 端到端、安全与长稳验证：形成验收记录。

## 9. 阶段交付物

- 认证状态机和 IPC 契约文档。
- ConnectionProfile schema 迁移。
- keyboard-interactive、2FA、每次询问和 Agent 实现。
- 自动化测试、真实服务器验收记录和安全审计结果。
- 更新后的用户说明、错误码表和发布说明。

## 10. 退出条件

- 四类认证方式均可通过连接测试和正式连接进入 Shell。
- 2FA 多轮提示可完成、取消、超时和重试。
- Agent 异常安全失败且不影响密码/私钥旧流程。
- 所有秘密扫描零命中，取消后无等待任务。
- 旧连接数据无损迁移，现有密码和私钥测试全部回归通过。
- 无阻断级或严重级缺陷。
