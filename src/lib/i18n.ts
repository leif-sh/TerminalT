const zhCN = {
  appName: 'TerminalT',
  connections: '连接',
  settings: '设置',
  connectionCenter: '连接中心',
  searchConnections: '搜索连接',
  newConnection: '新建连接',
  defaultGroup: '默认分组',
  noConnections: '还没有保存的连接',
  noConnectionsHint: '新建连接后，可在这里快速访问你的服务器。',
  stageZeroLabel: '阶段 2 · 连接资产与安全凭据',
  workspaceTitle: '会话工作区',
  workspaceDescription: '新建临时连接，安全确认服务器身份后进入远程 Shell。',
  startMockSession: '启动模拟终端',
  mockSessionTitle: '架构验证会话',
  mockSessionHint: '用于验证 IPC、终端渲染与会话释放，不会访问网络。',
  closeSession: '关闭会话',
  terminalReady: '终端就绪',
  healthChecking: '正在检查后端服务…',
  healthReady: '前后端通信正常',
  healthUnavailable: '浏览器预览模式',
  technicalDetails: '技术详情',
  retry: '重试',
  generalSettings: '通用设置',
  terminalSettings: '终端设置',
  settingsTitle: '应用设置',
  settingsDescription: '阶段 0 已建立设置结构，具体设置项将在后续阶段接入。',
  theme: '界面主题',
  language: '语言',
  darkTheme: '深色',
  simplifiedChinese: '简体中文',
  comingLater: '后续阶段开放',
  connecting: '连接中',
  connected: '已连接',
  disconnected: '已断开',
  failed: '失败',
  close: '关闭',
} as const

export type MessageKey = keyof typeof zhCN

export function t(key: MessageKey): string {
  return zhCN[key]
}
