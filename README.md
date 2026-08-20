# TerminalT

TerminalT 是一个本地优先的 Windows 桌面 SSH 客户端，基于 Tauri 2、React 19、TypeScript 和 Rust 开发。

当前已完成阶段 0～6 的基础版功能与发布工程。应用支持安全 SSH 连接、多标签终端、SFTP 文件传输、连接与凭据管理、统一设置、版本化导入导出和脱敏诊断日志。

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
npm run release:audit
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

- [总体开发文档](./docs/TERMINALT_OVERALL_DEVELOPMENT_PLAN.md)
- [基础版功能开发文档](./docs/SSH_CLIENT_BASIC_VERSION.md)
- [阶段开发文档总览](./docs/development-stages/README.md)
- [阶段 0 架构说明](./docs/architecture/STAGE_0_FOUNDATION.md)
- [阶段 1 架构说明](./docs/architecture/STAGE_1_SSH_MVP.md)
- [阶段 2 架构说明](./docs/architecture/STAGE_2_CONNECTIONS_AND_CREDENTIALS.md)
- [阶段 3 架构说明](./docs/architecture/STAGE_3_TERMINAL_EXPERIENCE.md)
- [阶段 3 自动化验收记录](./docs/testing/STAGE_3_ACCEPTANCE.md)
- [基础版发布说明](./docs/release/RELEASE_NOTES_1.0.md)
- [阶段 6 发布验收记录](./docs/testing/STAGE_6_RELEASE_ACCEPTANCE.md)
