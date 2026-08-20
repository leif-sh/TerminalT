# 阶段 7 认证兼容性验收记录

## 自动化覆盖

- `AuthenticationBroker`：操作/提示/回答 ID 绑定、正常响应、取消后失效；
- `russh` 回环服务器：隐藏式单次验证码 challenge-response 完整往返；
- 资产 schema 0、1 到 schema 2 的迁移与原子回写；
- 前端连接模型：交互认证和 Agent 不要求持久化秘密，即使旧草稿保留“记住”状态也不会生成凭据引用；
- 原有密码、私钥、会话、SFTP、资产、设置与诊断测试回归；
- lint、TypeScript 构建、Rust fmt/clippy/test、安全审计与五处版本一致性检查。

## 人工验收清单

- [ ] Windows OpenSSH Agent 服务未启动时显示 `AUTH-AGENT-UNAVAILABLE`；
- [ ] Agent 无密钥、Ed25519/RSA 多密钥及首选指纹排序；
- [ ] 真实 OpenSSH PAM/TOTP 单轮、多问题和多轮流程；
- [ ] 提示弹窗 Enter 提交、Escape/按钮取消、远端文本换行与超长文本；
- [ ] 测试连接、正式连接、保存连接及重连的行为一致；
- [ ] 连续 100 次打开/取消后无持续增长的等待任务。

人工项目需要对应的 OpenSSH/PAM/TOTP 测试主机和已装载密钥的 Windows Agent；未配置该外部环境时不把它们误记为已通过。

## 已知边界

- 本阶段只接入 Windows OpenSSH Agent，不接入 Pageant、智能卡、PKCS#11、FIDO 或 SSH 证书；
- 公钥首选项只影响尝试顺序，首选密钥被拒绝后会继续尝试其余普通公钥；
- 2FA 由 keyboard-interactive 的单轮多问题或多轮问题完成，不缓存上轮回答。
