# 阶段 9 架构：SFTP 工作流

## 所有权

```text
React SFTP Panel
  → 有界 SessionCommand
    → 单会话 SFTP Worker（浏览/删除/chmod）
    → 3 槽 Transfer Scheduler（目录任务）
      → 单任务扫描计划
      → 独立 SFTP channel + 原子文件写入
  → TransferRegistry（运行态 + 最近 100 条持久化元数据）
```

- React 只持有路径、任务 ID 和序列化状态，不持有目录树执行计划或协议句柄。
- 会话拥有取消发送端和 `JoinSet`；完成任务即时回收，关闭会话取消任务并有界等待。
- TransferRegistry 是任务状态的单一可查询来源，持久化通过单个有界 `watch` 写入流串行完成。

## 安全遍历

- 本地使用 `symlink_metadata`，远端使用 SFTP `lstat`，不跟随目录符号链接。
- 每个子路径必须保持在所选远端根路径前缀内。
- 深度、总条目和待处理队列分别限制为 64、100000 和 10000。
- 递归删除按深度倒序执行；符号链接作为叶节点删除，不访问其目标。
- 未知文件类型不作为普通文件传输或修改。

## 原子写入

- 上传先写入 `<目标>.terminalt-<任务 ID>.part`，再以 rename 替换目标。
- 下载先写入目标同目录隐藏临时文件，关闭后以本地 rename 替换。
- 覆盖时先将既有目标改名为任务专属 backup；替换失败会恢复 backup。
- 任务只删除由自身 ID 命名的 part/backup，不扫描或清理其他文件。

## 恢复边界

- 运行期内支持取消、失败重试和任务历史查询。
- 应用重启后，queued/scanning/running 状态改为 failed，要求重新连接后显式重试。
- 不声称恢复远端文件句柄或任意服务器的分块断点状态。
