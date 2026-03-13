import fs from 'node:fs/promises'
import path from 'node:path'

if (process.platform === 'win32') process.exit(0)

const binDir = path.join(process.cwd(), 'node_modules', '.bin')

try {
  const entries = await fs.readdir(binDir)
  await Promise.all(
    entries.map(async (entry) => {
      if (entry.endsWith('.cmd') || entry.endsWith('.ps1') || entry.endsWith('.exe')) return

      const fullPath = path.join(binDir, entry)
      let stat
      try {
        stat = await fs.lstat(fullPath)
      } catch {
        return
      }

      if (!stat.isFile()) return

      // If the executable bit was stripped (common when node_modules is copied/zipped),
      // restore a sane default.
      if ((stat.mode & 0o111) === 0) {
        await fs.chmod(fullPath, 0o755)
      }
    }),
  )
} catch {
  // Best-effort: if node_modules isn't present yet, do nothing.
}

