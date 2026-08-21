export type RemoteEntryKind = 'directory' | 'file' | 'symlink' | 'other'

export interface RemoteDirectoryEntry {
  name: string
  path: string
  kind: RemoteEntryKind
  size: number
  modifiedAt?: string
  permissions: string
  permissionMode?: number
  uid?: number
  gid?: number
  symlinkTarget?: string
}

export interface RemoteDirectoryListing {
  path: string
  parentPath?: string
  entries: RemoteDirectoryEntry[]
  truncated: boolean
  nextCursor?: string
}

export type TransferDirection = 'upload' | 'download'
export type TransferConflictPolicy = 'ask' | 'overwrite' | 'skip' | 'rename'
export type TransferStatus = 'queued' | 'scanning' | 'running' | 'completed' | 'failed' | 'cancelled'

export interface TransferTask {
  id: string
  createdAt: string
  sessionId: string
  fileName: string
  direction: TransferDirection
  source: string
  target: string
  sources: string[]
  targetDirectory: string
  conflictPolicy: TransferConflictPolicy
  transferredBytes: number
  totalBytes?: number
  totalFiles: number
  totalDirectories: number
  completedFiles: number
  completedDirectories: number
  skippedFiles: number
  bytesPerSecond: number
  currentPath?: string
  elapsedSeconds: number
  status: TransferStatus
  error?: string
  errors: string[]
}

export interface TransferProgressPayload { task: TransferTask }
