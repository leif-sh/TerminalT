# 阶段 1 SSH 单会话架构说明

## 1. 阶段成果

阶段 1 已建立从临时连接表单到真实远端 Shell 的最小闭环：

- 密码与 OpenSSH RSA、ECDSA、Ed25519 私钥认证；
- 带口令私钥解析，私钥只在认证任务内读取；
- 首次主机指纹确认、已知指纹自动校验、变化指纹显式阻断与替换；
- 可取消的连接测试与 SSH 会话创建；
- `xterm-256color` PTY、交互式 Shell、字节流输入输出和窗口 resize；
- 单标签会话关闭、远端退出和应用退出资源回收；
- DNS、连接拒绝、超时、协议、主机密钥和认证错误的稳定错误码。

本阶段继续使用临时连接，不保存连接配置、密码或私钥口令。系统凭据库与连接资产持久化属于阶段 2。

## 2. 模块边界

```text
React
├─ domain/connection             表单、认证与主机密钥契约
├─ features/connections          临时连接及指纹确认界面
├─ features/sessions             单会话状态和生命周期
├─ features/terminal             xterm 字节流、输入和 resize
└─ lib/ipc                       唯一 Tauri 调用与事件入口

Rust
├─ models                        IPC 请求、响应及状态事件
├─ known_hosts                   主机公钥与信任记录
├─ ssh_client                    握手、认证、PTY、Shell 与 I/O 任务
├─ session                       会话命令和连接操作取消注册表
└─ lib                           Tauri Commands、事件及退出清理
```

## 3. SSH 安全流程

1. `inspect_ssh_host_key` 建立仅用于获取公钥的探测连接并立即断开。
2. 界面根据本地记录显示可信、未知或已变化状态；未知和变化状态必须由用户明确批准。
3. 正式连接使用用户刚确认的 SHA-256 指纹重新校验服务端公钥，防止探测与认证之间发生密钥替换。
4. 认证成功后才写入或替换 `known_hosts.json` 等价记录。
5. 密码和私钥口令从请求中取出后使用可清零内存包装；不进入日志、配置和技术详情。

主机记录位于 Tauri 应用数据目录，只包含主机、端口、公钥算法、公钥、SHA-256 指纹和信任时间。

## 4. IPC v1 扩展

### Commands

| 命令 | 用途 |
| --- | --- |
| `inspect_ssh_host_key` | 获取并比对服务器主机指纹 |
| `test_ssh_connection` | 完成握手、指纹校验和认证后立即断开 |
| `connect_ssh` | 完成认证并创建 PTY/Shell 会话 |
| `cancel_operation` | 取消探测、测试或建连任务 |
| `write_session` | 向远端会话发送原始字节 |
| `resize_session` | 同步远端 PTY 行列数 |
| `close_session` | 关闭并移除 SSH 会话 |

### Events

| 事件 | 用途 |
| --- | --- |
| `connection-progress` | 连接、指纹检查、认证和失败状态 |
| `session-output` | SSH channel 输出字节 |
| `session-status` | 已连接、已断开和失败状态 |

## 5. 会话生命周期

每个 SSH 会话拥有独立异步任务和有界命令通道。任务同时等待前端输入/resize/关闭命令与远端 channel 消息；任一结束路径都会发送 SSH disconnect、移除注册表条目并通知前端断开状态。应用退出时统一取消未完成操作并关闭全部会话。

会话创建的总超时覆盖 TCP、SSH 握手、认证、PTY 请求和 Shell 创建。连接表单的取消操作通过一次性取消信号丢弃整个建连 future，从而释放尚未移交会话注册表的网络资源。

## 6. 已验证项目

- 前端表单必填项、数值边界、请求规范化和私钥条件校验；
- 浏览器预览中的字段错误、未知主机指纹确认、临时会话、关闭后凭据清空；
- 本地进程内 SSH 服务上的密码认证、PTY/Shell 和字节输出；
- RSA、ECDSA、Ed25519 与带口令 OpenSSH 私钥认证；
- 错误密码拒绝且技术详情不包含秘密；
- 主机指纹未知、信任后匹配和变化阻断；
- 会话与操作取消注册表的关闭和清理。

## 7. 当前边界

- 阶段 1 仅允许一个活动会话；多标签、keepalive、断线重连和完整终端快捷键属于阶段 3。
- 尚未执行 Ubuntu、Debian、Rocky Linux 实机兼容矩阵以及 `vim`、`top`、`less` 长时间交互验收；发布前仍需按阶段 6 补齐。
- 浏览器预览使用模拟终端验证界面；真实 SSH 协议由 Rust 本地集成测试覆盖，桌面端仍需在目标服务器环境做人工验收。
- 仓库当前没有 `design/FRONTEND_DESIGN_PROMPT.md`、`docs/rust-backend-development-guidelines.md` 和两个项目级 CI/Rust skill 文件；本阶段沿用阶段 0 记录的视觉与安全边界。
- 首屏仍包含 xterm，生产包存在 Vite 大于 500 kB 的非阻断提示；后续阶段应按工作区拆包。
