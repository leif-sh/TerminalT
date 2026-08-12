# TerminalT

TerminalT 是一个本地优先的 Windows 桌面 SSH 客户端，基于 Tauri 2、React 19、TypeScript 和 Rust 开发。

当前开发阶段为“阶段 0：工程基础与架构骨架”。工程已经具备应用外壳、前后端 IPC 契约、模拟会话生命周期和终端渲染验证，尚未连接真实 SSH 服务器。

## 本地开发

```powershell
npm install
npm run dev
```

启动 Tauri 桌面应用：

```powershell
npm run tauri dev
```

## 验证命令

```powershell
npm run lint
npm test
npm run build
cargo fmt --manifest-path src-tauri/Cargo.toml -- --check
cargo test --manifest-path src-tauri/Cargo.toml
```

## 目录说明

- `src/components`：通用界面组件和错误边界；
- `src/domain`：前端领域模型；
- `src/features`：会话、终端等功能模块；
- `src/lib`：国际化资源和 Tauri IPC 封装；
- `src-tauri/src`：Rust 命令、错误模型和运行期会话注册表；
- `docs/development-stages`：各阶段详细开发文档；
- `docs/architecture`：已落地的架构决策和接口说明。

## 产品与开发文档

- [基础版功能开发文档](./docs/SSH_CLIENT_BASIC_VERSION.md)
- [阶段开发文档总览](./docs/development-stages/README.md)
- [阶段 0 架构说明](./docs/architecture/STAGE_0_FOUNDATION.md)
