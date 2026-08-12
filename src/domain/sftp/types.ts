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
