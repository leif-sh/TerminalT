# 阶段 2 连接资产与安全凭据架构说明

## 1. 阶段成果

阶段 2 将临时 SSH 表单扩展为本地连接资产管理：

- 连接新建、编辑、复制和删除；
- 单层分组的新建、重命名、删除与非空分组迁移；
- 对名称、主机、用户名和备注的即时搜索；
- `user@host`、`user@host:port` 和方括号 IPv6 快速连接；
- Windows Credential Manager 中的密码和私钥口令保存；
- 连接数据 schema、迁移入口、原子替换和中断恢复；
- 主机密钥查询、删除以及快速连接历史清理的后端接口。

## 2. 数据与秘密边界

`connections.json` 位于 Tauri 应用数据目录，保存 schema 版本、分组、连接、凭据引用和脱敏快速连接历史。该文件不得包含密码、私钥口令或私钥内容。

用户勾选“记住凭据”后，秘密写入当前 Windows 用户的 Credential Manager，目标名采用：

```text
TerminalT/connection/{connection-id}/password
TerminalT/connection/{connection-id}/passphrase
```

普通数据只保存目标名引用。凭据库写入、读取或删除失败时返回稳定错误并安全失败，不回退为明文存储。编辑认证方式或关闭记忆选项时清理旧凭据；删除连接时先删除凭据，配置写入失败则尽力恢复原凭据。

Windows 官方 `CredWriteW` 语义允许同一目标名创建或替换当前用户凭据；读取返回的系统缓冲区使用 `CredFree` 释放。

## 3. 持久化策略

当前 schema 版本为 `1`，默认分组内部 ID 固定为 `default`。写入步骤为：

1. 将完整新文档序列化到同目录的 `connections.json.new`；
2. 首次写入使用同卷 rename；
3. 已存在主文件时使用 Windows `ReplaceFileW` 原子替换；
4. 启动读取发现主文件损坏且 `.new` 有效时，恢复待提交文档；
5. schema `0` 通过迁移入口升级为 `1`，并补齐默认分组和失效分组引用。

`known_hosts.json` 同样复用原子写入，避免主机信任记录部分写入。

## 4. IPC 扩展

| 命令 | 用途 |
| --- | --- |
| `list_connection_assets` | 获取分组、连接和脱敏历史快照 |
| `save_connection_profile` | 新建或编辑连接及授权凭据 |
| `copy_connection_profile` | 复制非敏感配置并生成新 ID |
| `delete_connection_profile` | 删除配置及独占凭据 |
| `save_connection_group` | 新建或重命名分组 |
| `delete_connection_group` | 删除分组并迁移连接 |
| `record_recent_target` / `clear_recent_targets` | 管理脱敏快速连接历史 |
| `connect_saved_connection` / `test_saved_connection` | 从凭据库解析秘密后连接或测试 |
| `list_host_keys` / `delete_host_key` | 为阶段 5 指纹管理界面提供接口 |

## 5. 已验证项目

- 连接重启恢复、更新、复制、删除及凭据生命周期；
- 数据文件不含测试密码，凭据库不可用时不创建明文文件；
- Windows Credential Manager 写入、读取和删除真实往返；
- 非空分组迁移、重名校验、搜索字段和快速连接 IPv6 规则；
- schema 迁移、待提交原子文件恢复、主机密钥原子写入；
- 浏览器预览中的保存、搜索、复制、分组、编辑及快速连接错误提示。

## 6. 当前边界

- 多标签会话属于阶段 3，因此当前仍只允许一个活动会话；编辑或删除连接不会修改已建立会话。
- 连接列表以连接名称关联运行状态；阶段 3 引入多会话后应改为显式 profile ID 关联。
- 浏览器预览用 localStorage 模拟非敏感资产，只用于 UI 验收；生产桌面端使用 Rust 原子文件和 Windows Credential Manager。
- Windows 凭据往返测试需要交互式用户 token；受限测试沙箱会返回 Win32 1312，因此完整 CI 中标记忽略，并在交互式用户会话单独执行通过。
- 仓库仍未提供 `design/FRONTEND_DESIGN_PROMPT.md`、Rust 开发规范及项目级 CI/Rust skill 文件；本阶段沿用原型视觉和既有架构安全边界。
