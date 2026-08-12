export type RemoteEntryKind = 'directory' | 'file' | 'symlink' | 'other'

export interface RemoteDirectoryEntry {
  name: string
  path: string
  kind: RemoteEntryKind
  size: number
  modifiedAt?: string
  permissions: string
}

export interface RemoteDirectoryListing {
  path: string
  parentPath?: string
  entries: RemoteDirectoryEntry[]
  truncated: boolean
}

export type TransferDirection = 'upload' | 'download'
export type TransferStatus = 'queued' | 'running' | 'succeeded' | 'failed' | 'cancelled'

export interface TransferTask {
  id: string
  sessionId: string
  fileName: string
  direction: TransferDirection
  source: string
  target: string
  transferredBytes: number
  totalBytes?: number
  bytesPerSecond: number
  status: TransferStatus
  error?: string
}

export interface TransferProgressPayload { task: TransferTask }
