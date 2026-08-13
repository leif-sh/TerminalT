import { readFile, readdir, stat } from 'node:fs/promises'
import { join, relative } from 'node:path'

const root = new URL('../../', import.meta.url).pathname.slice(1)
const roots = ['src', 'src-tauri/src', 'src-tauri/capabilities', 'docs'].map((path) => join(root, path))
const forbidden = [
  /-----BEGIN (?:OPENSSH|RSA|EC|DSA) PRIVATE KEY-----/,
  /(?:password|passphrase|privateKeyPassphrase|secret)\s*:\s*["'][^"']{4,}["']/i,
]
const allowedFixtures = new Set(['src-tauri/src/credentials.rs', 'src-tauri/src/assets.rs', 'src-tauri/src/diagnostics.rs'])
let files = 0
for (const base of roots) await walk(base)
console.log(`Security audit passed: ${files} source and documentation files scanned.`)

async function walk(path) {
  const info = await stat(path)
  if (info.isDirectory()) {
    for (const name of await readdir(path)) await walk(join(path, name))
    return
  }
  files += 1
  const name = relative(root, path).replaceAll('\\', '/')
  const content = await readFile(path, 'utf8').catch(() => '')
  for (const pattern of forbidden) {
    const syntheticFixture = name.endsWith('.test.ts') || allowedFixtures.has(name)
    const matches = [...content.matchAll(new RegExp(pattern.source, `${pattern.flags.replace('g', '')}g`))]
      .filter((match) => !/^[^:]+:\s*['"]{2}$/.test(match[0]))
    if (matches.length && !syntheticFixture) throw new Error(`Potential secret found in ${name}: ${matches[0][0]}`)
  }
}
