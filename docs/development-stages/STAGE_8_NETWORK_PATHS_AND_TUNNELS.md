# 阶段 8：网络路径与 SSH 隧道

## 1. 阶段目标

补齐企业网络环境所需的 HTTP/SOCKS5 代理、Jump Host 和多跳连接，并实现 SSH 本地、远程、动态端口转发。阶段结束时，终端、SFTP 和隧道可以复用受控 SSH 连接，同时保持独立生命周期和逐跳安全校验。

## 2. 前置条件

- 阶段 7 认证状态机稳定，可在每一跳处理密码、私钥、交互认证和 Agent。
- 完成 `russh` direct-tcpip、forwarded-tcpip、远程监听和 channel 生命周期技术验证。
- 准备 HTTP CONNECT、SOCKS5、单跳和三跳 loopback 测试拓扑。
- 明确连接复用的所有权、引用计数和关闭策略。
- TunnelProfile、跳板链和代理配置 schema 评审完成。

## 3. 范围与非范围

本阶段包含：

- HTTP CONNECT 和 SOCKS5 出站代理，可选代理认证；
- 单跳 Jump Host 和可排序多跳链；
- 每一跳独立主机密钥与认证；
- 本地转发 `-L`、远程转发 `-R`、动态转发 `-D`；
- 隧道规则保存、启停、状态、错误、统计和连接复用；
- 应用退出、断网和端口占用恢复。

本阶段不包含：

- UDP 转发、VPN、系统全局代理配置；
- SSH over WebSocket、自定义代理插件；
- 自动暴露公网监听地址；
- 负载均衡、流量审计和企业集中策略。

## 4. 数据模型

### 4.1 代理和跳板链

```ts
interface ProxyConfig {
  type: 'http' | 'socks5'
  host: string
  port: number
  username?: string
  credentialRef?: string
}

interface JumpHostReference {
  connectionId: string
}
```

- 跳板节点引用已有 ConnectionProfile，不复制连接和凭据。
- 禁止直接或间接循环引用。
- 删除被引用连接时阻止删除或要求先解除引用，不静默破坏链路。
- 每一跳按主机和端口维护独立 known-host 记录。

### 4.2 隧道规则

```ts
interface TunnelProfile {
  id: string
  name: string
  connectionId: string
  kind: 'local' | 'remote' | 'dynamic'
  bindHost: string
  bindPort: number
  targetHost?: string
  targetPort?: number
  startPolicy: 'manual' | 'withConnection'
}
```

- 动态转发不填写固定目标。
- 本地和动态转发默认 `127.0.0.1`。
- `0.0.0.0`、`::` 和远程转发必须标记为高风险配置。
- 运行状态不写入 TunnelProfile，由 TunnelRegistry 管理。

## 5. 后端架构

### 5.1 SshConnector 链路

```text
本机 → 可选 HTTP/SOCKS5 代理 → Jump A → Jump B → 目标服务器
```

- 每一步使用统一超时、取消和错误上下文。
- 每一跳完成主机密钥验证后才能进入下一跳。
- 下一跳 TCP 流量通过前一跳 direct-tcpip channel 建立。
- 错误指出失败跳序号和脱敏目标，不输出代理密码。
- 任一跳断开时关闭下游 channel，并更新所有依赖会话状态。

### 5.2 ConnectionPool

- 以连接配置、认证上下文、跳板链和代理配置共同生成复用键。
- 临时凭据或未完成交互认证的连接不得被其他请求抢占。
- 终端、SFTP 和隧道持有独立租约。
- 释放最后一个租约后按策略关闭底层 SSH 连接。
- 关闭终端不关闭仍有租约的隧道；停止隧道不影响终端。
- 主机密钥或配置变化后不得继续复用旧连接。

### 5.3 TunnelRegistry

- 每条运行中规则拥有不可猜测 runtime ID、取消令牌和状态。
- 管理监听器、SSH channel、活跃连接数、累计字节和最近错误。
- 状态至少包含 starting、running、stopping、stopped、failed。
- 启停操作幂等；重复启动返回已有状态或明确冲突。
- 应用退出有界停止所有监听器和 channel。

## 6. 详细开发功能

### 6.1 HTTP CONNECT 代理

- 支持无认证和 Basic 认证代理。
- 限制响应头大小和等待时间。
- 分别映射 DNS、TCP、代理认证、代理拒绝和协议错误。
- 代理秘密只从 CredentialVault 临时读取。

### 6.2 SOCKS5 代理

- 支持无认证和用户名密码认证。
- 支持域名、IPv4 和 IPv6 目标地址。
- 严格校验协商版本、方法和响应长度。
- 用户名密码不得记录到调试输出。

### 6.3 Jump Host 与多跳

- 连接编辑页可添加、删除和排序跳板节点。
- 保存前检测循环、重复节点和失效引用。
- 连接进度展示当前跳数，例如“正在连接第 2/3 跳”。
- 每一跳可触发独立指纹确认和交互认证。
- 取消任一提示或连接步骤时清理整条未完成链路。

### 6.4 本地转发 `-L`

- 本机监听地址和端口可配置，端口 0 可选用于临时自动分配。
- 每个入站 TCP 连接创建 direct-tcpip channel 到固定目标。
- 端口占用、目标拒绝和 SSH 断开分别展示。
- 默认仅允许 loopback；非 loopback 监听二次确认。

### 6.5 远程转发 `-R`

- 请求服务器监听指定地址和端口。
- 接受 forwarded-tcpip channel 并转发到本地目标。
- 停止规则时撤销远端监听；撤销失败记录可诊断状态。
- 明确提示 GatewayPorts 和防火墙可能影响公网可达性。

### 6.6 动态转发 `-D`

- 在本地实现 SOCKS5 服务端协商，只支持 TCP CONNECT。
- 域名解析按 SOCKS5 请求通过 SSH 目标侧处理。
- 限制握手超时、单连接缓存和最大并发数。
- 不实现 UDP ASSOCIATE，并返回标准不支持响应。

### 6.7 隧道管理界面

- 提供规则列表、新建、编辑、复制、删除、启动和停止。
- 展示类型、监听地址、目标、连接、状态、连接数和最近错误。
- 高风险监听地址使用持续可见标记。
- 删除运行中规则前先确认并停止。
- 隧道页不显示代理密码或认证响应。

### 6.8 错误码

至少覆盖：

```text
PROXY-CONNECT-FAILED
PROXY-AUTH-FAILED
PROXY-PROTOCOL-FAILED
JUMP-HOST-CYCLE
JUMP-HOST-FAILED
TUNNEL-BIND-FAILED
TUNNEL-REMOTE-LISTEN-FAILED
TUNNEL-TARGET-FAILED
TUNNEL-STOP-FAILED
```

## 7. 测试与验证

- HTTP/SOCKS5 无认证、正确认证、错误认证和协议畸形响应。
- 单跳、三跳、循环配置、第二跳失败和逐跳指纹变化。
- `-L/-R/-D` 使用 TCP echo、HTTP 和数据库握手流量验证。
- IPv4、IPv6、域名和非默认端口。
- 100 个并发短连接和至少 1 个长连接。
- 同一 SSH 连接上终端、SFTP 和多个隧道并存。
- 关闭终端、停止隧道、断网、服务器关闭和应用退出。
- 同一规则重复启停 100 次，检查端口、句柄、任务和内存。
- 非 loopback 监听风险确认和配置持久化。

## 8. 任务拆分

1. 协议技术验证与连接所有权设计。
2. ProxyConfig、JumpHost 和 TunnelProfile schema 迁移。
3. HTTP/SOCKS5 客户端代理。
4. 单跳和多跳 SshConnector。
5. ConnectionPool 与租约测试。
6. TunnelRegistry 和 `-L`。
7. `-R`、`-D` 与限流。
8. 隧道管理页、状态事件和风险交互。
9. 拓扑集成、压力、安全和退出测试。

## 9. 阶段交付物

- 代理、多跳和连接复用架构说明。
- 代理、跳板和隧道数据迁移。
- 三类端口转发及管理界面。
- loopback 拓扑、压力和安全验收记录。
- 用户配置说明和故障排查文档。

## 10. 退出条件

- HTTP/SOCKS5、单跳和三跳均能稳定建立终端与 SFTP。
- `-L/-R/-D` 通过功能、并发、断网和重复启停测试。
- 每一跳主机密钥变化均阻断连接。
- 非 loopback 监听默认不发生且风险提示有效。
- 连接复用不造成跨会话秘密或生命周期串扰。
- 应用退出后无监听端口、SSH channel 或后台任务残留。
