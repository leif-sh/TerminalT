export type TunnelKind = 'local' | 'remote' | 'dynamic'
export type TunnelStartPolicy = 'manual' | 'withConnection'
export type TunnelStatus = 'starting' | 'running' | 'stopping' | 'stopped' | 'failed'

export interface TunnelProfile {
  id: string
  name: string
  connectionId: string
  kind: TunnelKind
  bindHost: string
  bindPort: number
  targetHost?: string
  targetPort?: number
  startPolicy: TunnelStartPolicy
  createdAt: string
  updatedAt: string
}

export interface SaveTunnelRequest {
  id?: string
  name: string
  connectionId: string
  kind: TunnelKind
  bindHost: string
  bindPort: number
  targetHost?: string
  targetPort?: number
  startPolicy: TunnelStartPolicy
  allowNonLoopback: boolean
}

export interface TunnelRuntimeState {
  runtimeId: string
  profileId: string
  sessionId: string
  status: TunnelStatus
  boundPort: number
  activeConnections: number
  bytesUp: number
  bytesDown: number
  lastError?: string
}

export interface TunnelStatusPayload { tunnel: TunnelRuntimeState }
