import { readFile } from 'node:fs/promises'

const versionPattern = /^\d+\.\d+\.\d+-\d+$/

const packageJson = JSON.parse(await readFile('package.json', 'utf8'))
const packageLock = JSON.parse(await readFile('package-lock.json', 'utf8'))
const tauriConfig = JSON.parse(await readFile('src-tauri/tauri.conf.json', 'utf8'))
const cargoToml = await readFile('src-tauri/Cargo.toml', 'utf8')
const cargoLock = await readFile('src-tauri/Cargo.lock', 'utf8')

const cargoManifestVersion = cargoToml.match(
  /^name = "terminalt"\r?\nversion = "([^"]+)"/m,
)?.[1]
const cargoLockVersion = cargoLock.match(
  /^name = "terminalt"\r?\nversion = "([^"]+)"/m,
)?.[1]

const declaredVersions = new Map([
  ['package.json', packageJson.version],
  ['package-lock.json', packageLock.version],
  ['package-lock root package', packageLock.packages?.['']?.version],
  ['src-tauri/Cargo.toml', cargoManifestVersion],
  ['src-tauri/Cargo.lock', cargoLockVersion],
  ['src-tauri/tauri.conf.json', tauriConfig.version],
])

const expectedVersion = packageJson.version
const invalidEntries = [...declaredVersions].filter(
  ([, version]) => version !== expectedVersion,
)

if (!versionPattern.test(expectedVersion)) {
  throw new Error(`Version ${expectedVersion} must match MAJOR.MINOR.PATCH-N`)
}

if (invalidEntries.length > 0) {
  const details = invalidEntries
    .map(([file, version]) => `${file}: ${String(version)}`)
    .join('\n')
  throw new Error(`Application versions are inconsistent:\n${details}`)
}

console.log(`Application version ${expectedVersion} is consistent.`)
