# 阶段 0 工程架构说明

## 1. 当前成果

阶段 0 建立了可以承载真实 SSH 与 SFTP 功能的最小工程骨架：

- React 应用外壳和连接、设置、会话三类视图结构；
- 按领域组织的前端状态、类型和 IPC 访问层；
- Rust 侧稳定错误结构、Tauri Commands 和进程内会话注册表；
- 基于 xterm.js 的终端渲染、输入和 resize 技术验证；
- 浏览器预览适配器，用于不启动 Tauri 时验证界面和终端交互；
- 前端错误边界、简体中文资源和基础自动化测试。

本阶段的模拟会话不访问网络，不代表真实 SSH 功能已经完成。

## 2. 模块边界

```text
React UI
├─ components          通用组件、图标、错误边界
├─ domain              领域类型，不依赖 Tauri 或具体视图
├─ features/sessions   会话列表与活动会话状态
├─ features/terminal   xterm.js 生命周期与终端适配
└─ lib
   ├─ ipc              Tauri Command/Event 唯一访问入口
   └─ i18n             简体中文资源入口

Rust Core
├─ error               可序列化稳定错误契约
├─ models              IPC 响应和事件模型
├─ session             进程内会话注册表与取消句柄
└─ lib                 Tauri 命令、事件发送和应用退出清理
```

前端组件不直接调用任意 Tauri 命令，统一通过 `src/lib/ipc.ts` 访问。Rust 命令不保存前端对象或底层裸句柄，只向前端暴露 UUID 会话 ID。

## 3. IPC v1 契约

### 3.1 Commands

| 命令 | 用途 | 返回值 |
| --- | --- | --- |
| `health_check` | 验证前后端请求响应 | 服务状态、协议版本、应用版本 |
| `create_mock_session` | 创建无网络模拟会话 | `SessionState` |
| `write_mock_session` | 验证二进制安全输入链路 | 空 |
| `resize_mock_session` | 同步终端行列数 | 空 |
| `close_mock_session` | 取消任务并移除会话 | 空 |

### 3.2 Events

| 事件 | 负载 | 说明 |
| --- | --- | --- |
| `session-output` | `{ sessionId, data: number[] }` | 终端数据按字节传递，不假设事件块是完整 UTF-8 |
| `session-status` | `{ sessionId, status, message? }` | 会话状态变化 |

后续阶段扩展 IPC 时应保持现有字段语义，并在发生不兼容调整时递增协议版本。

## 4. 稳定错误结构

Rust 命令错误统一序列化为：

```ts
interface AppCommandError {
  code: string
  category: string
  message: string
  technicalDetails?: string
  retryable: boolean
}
```

- `code` 用于稳定测试和前端文案映射；
- `message` 当前提供简体中文安全提示；
- `technicalDetails` 仅用于诊断，不得包含凭据和终端正文；
- `retryable` 告知界面是否适合提供重试操作。

## 5. 会话生命周期

```text
create_mock_session
  → 生成 UUID
  → 注册取消发送端
  → 启动独立异步任务
  → 发送状态和批量终端字节

close_mock_session / 应用退出
  → 从注册表移除
  → 发送取消信号
  → 异步任务结束
  → 释放终端实例和事件监听
```

`SessionRegistry` 使用互斥保护的映射保存运行期任务取消句柄和最新终端尺寸。活动会话不持久化，应用退出时通过 `close_all` 有界地发出取消信号。

## 6. 终端技术决策

- 使用 `@xterm/xterm` 负责 ANSI/VT、Unicode、选择和滚动缓冲；
- 使用 `@xterm/addon-fit` 根据容器计算行列数；
- 终端输出通过 `Uint8Array` 写入，保留跨事件 UTF-8 解码能力；
- 终端组件卸载时释放输入订阅、ResizeObserver、Tauri Event 监听和 xterm 实例；
- 真实 SSH 输入输出仍由阶段 1 的 Rust SSH 服务接入。

## 7. 安全基线

- Tauri capability 当前保持 `core:default`，未开放文件系统或 shell 权限；
- 模拟会话 ID 使用 UUID v4，不暴露裸指针或文件句柄；
- 日志不记录终端输入输出；
- 外部字符串以 React 文本节点或 xterm 字节流展示，不注入 HTML；
- 浏览器预览适配器只在不存在 Tauri runtime 时启用，不访问网络；
- 应用退出时清空模拟会话注册表。

## 8. 已验证项目

- 前端 Lint、单元测试和生产构建；
- Rust 格式检查、注册表单元测试和 Tauri 编译；
- 连接空状态、设置页和导航切换；
- 模拟会话创建、ANSI/UTF-8 输出、终端输入和关闭；
- 800×600 最小窗口无页面溢出；
- 浏览器预览控制台无错误。

## 9. 已知边界

- 仓库指令引用的 `design/FRONTEND_DESIGN_PROMPT.md`、`docs/rust-backend-development-guidelines.md` 和 `.agents/skills/rust-backend-development/SKILL.md` 在阶段 0 开发时不存在；前端以 `docs/terminalt-prototype-v2-clasht-style.png` 为视觉基准，Rust 以总功能文档的技术与安全边界为准。
- 终端依赖使首个前端包超过 Vite 默认 500 kB 提示线；这是非阻断警告，真实功能增加前应评估按会话工作区拆分代码块。
- 本阶段只验证模拟数据链路，不提供真实 SSH、连接保存或 SFTP。
