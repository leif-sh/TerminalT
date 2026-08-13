import { createHash } from 'node:crypto'
import { readFile, readdir, stat, writeFile } from 'node:fs/promises'
import { basename, join } from 'node:path'

const bundle = new URL('../../src-tauri/target/release/bundle/', import.meta.url).pathname.slice(1)
const output = new URL('../../release-checksums.sha256', import.meta.url).pathname.slice(1)
const manifest = JSON.parse(await readFile(new URL('../../package.json', import.meta.url), 'utf8'))
const files = []
await walk(bundle)
const installers = files.filter((path) => basename(path).includes(`_${manifest.version}_`) && /\.(msi|exe)$/.test(path))
if (!installers.length) throw new Error(`No Windows installer artifacts found for ${manifest.version}.`)
const lines = []
for (const path of installers.sort()) {
  const hash = createHash('sha256').update(await readFile(path)).digest('hex')
  lines.push(`${hash}  ${basename(path)}`)
}
await writeFile(output, `${lines.join('\n')}\n`)
console.log(`Recorded ${installers.length} installer checksum(s) in release-checksums.sha256.`)
async function walk(path) {
  for (const name of await readdir(path)) {
    const child = join(path, name)
    if ((await stat(child)).isDirectory()) await walk(child)
    else files.push(child)
  }
}
