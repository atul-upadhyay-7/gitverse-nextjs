import { exec } from 'child_process'
import { promisify } from 'util'
import * as path from 'path'
import * as fs from 'fs/promises'

const execPromise = promisify(exec)

export interface CommitData {
  hash: string
  shortHash: string
  message: string
  description?: string
  authorName: string
  authorEmail: string
  committedAt: Date
  branch: string
  additions: number
  deletions: number
  filesChanged: number
  fileChanges: FileChangeData[]
}

export interface FileChangeData {
  path: string
  additions: number
  deletions: number
  changeType: 'added' | 'modified' | 'deleted'
}

export interface BranchData {
  name: string
  isDefault: boolean
  isProtected: boolean
  commitCount: number
  lastCommitAt: Date
}

export interface ContributorData {
  name: string
  email: string
  commits: number
  additions: number
  deletions: number
  firstCommit: Date
  lastCommit: Date
}

export interface LanguageData {
  name: string
  percentage: number
  bytes: number
  lines: number
}

export class GitService {
  private repoPath: string

  constructor(repoPath: string) {
    this.repoPath = repoPath
  }

  /**
   * Clone a repository to a temporary directory
   */
  static async cloneRepository(url: string, destination: string): Promise<GitService> {
    try {
      await fs.mkdir(destination, { recursive: true })
      await execPromise(`git clone --depth 1000 "${url}" "${destination}"`)
      return new GitService(destination)
    } catch (error: any) {
      throw new Error(`Failed to clone repository: ${error.message}`)
    }
  }

  /**
   * Get all branches in the repository
   */
  async getBranches(): Promise<BranchData[]> {
    try {
      const { stdout: defaultBranch } = await execPromise(
        `cd "${this.repoPath}" && git symbolic-ref refs/remotes/origin/HEAD | sed 's@^refs/remotes/origin/@@'`
      )
      const defaultBranchName = defaultBranch.trim()

      const { stdout } = await execPromise(
        `cd "${this.repoPath}" && git for-each-ref --format='%(refname:short)|%(committerdate:iso)|%(objectname)' refs/heads/`
      )

      const branches: BranchData[] = []
      const lines = stdout.trim().split('\n').filter(Boolean)

      for (const line of lines) {
        const [name, date] = line.split('|')

        const { stdout: commitCount } = await execPromise(
          `cd "${this.repoPath}" && git rev-list --count "${name}"`
        )

        branches.push({
          name,
          isDefault: name === defaultBranchName,
          isProtected: ['main', 'master', 'develop', 'production'].includes(name),
          commitCount: parseInt(commitCount.trim()),
          lastCommitAt: new Date(date),
        })
      }

      return branches
    } catch (error: any) {
      throw new Error(`Failed to get branches: ${error.message}`)
    }
  }

  /**
   * Get all commits for a specific branch
   */
  async getCommits(branch: string = 'HEAD', limit: number = 1000): Promise<CommitData[]> {
    try {
      const format = '%H|%h|%an|%ae|%aI|%s|%b'
      const { stdout } = await execPromise(
        `cd "${this.repoPath}" && git log --format="${format}" --shortstat -n ${limit} "${branch}"`
      )

      const commits: CommitData[] = []

      // Split by commit hash at the beginning of lines
      const commitRegex = /^([a-f0-9]{40}\|)/gm
      const matches = [...stdout.matchAll(commitRegex)]

      if (matches.length === 0) {
        console.warn('No commits found in git log output')
        return []
      }

      for (let i = 0; i < matches.length; i++) {
        const startIndex = matches[i].index!
        const endIndex = i < matches.length - 1 ? matches[i + 1].index! : stdout.length
        const block = stdout.substring(startIndex, endIndex).trim()

        const lines = block.split('\n').filter(Boolean)
        if (lines.length === 0) continue

        const firstLine = lines[0]
        const parts = firstLine.split('|')

        if (parts.length < 6) {
          console.warn('Skipping commit with insufficient fields')
          continue
        }

        const [hash, shortHash, authorName, authorEmail, date, message, ...descParts] = parts

        // Skip if essential fields are missing
        if (!hash || !authorName || !authorEmail || !date || !message) {
          console.warn('Skipping commit with missing fields')
          continue
        }

        const description = descParts.join('|').trim() || undefined
        const statsLine = lines.find((l) => l.includes('changed') || l.includes('file'))

        let additions = 0
        let deletions = 0
        let filesChanged = 0

        if (statsLine) {
          const match = statsLine.match(
            /(\d+) files? changed(?:, (\d+) insertions?\(\+\))?(?:, (\d+) deletions?\(-\))?/
          )
          if (match) {
            filesChanged = parseInt(match[1])
            additions = match[2] ? parseInt(match[2]) : 0
            deletions = match[3] ? parseInt(match[3]) : 0
          }
        }

        // Get file changes for this commit
        const fileChanges = await this.getFileChanges(hash)

        commits.push({
          hash: hash.trim(),
          shortHash: shortHash?.trim() || hash.substring(0, 7),
          message: message.trim(),
          description,
          authorName: authorName.trim(),
          authorEmail: authorEmail.trim(),
          committedAt: new Date(date.trim()),
          branch,
          additions,
          deletions,
          filesChanged,
          fileChanges,
        })
      }

      return commits
    } catch (error: any) {
      throw new Error(`Failed to get commits: ${error.message}`)
    }
  }

  /**
   * Get file changes for a specific commit
   */
  private async getFileChanges(commitHash: string): Promise<FileChangeData[]> {
    try {
      const { stdout } = await execPromise(
        `cd "${this.repoPath}" && git show --numstat --format="" "${commitHash}"`
      )

      const changes: FileChangeData[] = []
      const lines = stdout.trim().split('\n').filter(Boolean)

      for (const line of lines) {
        const [addStr, delStr, filePath] = line.split('\t')

        // Handle binary files or moved files
        const additions = addStr === '-' ? 0 : parseInt(addStr)
        const deletions = delStr === '-' ? 0 : parseInt(delStr)

        let changeType: 'added' | 'modified' | 'deleted' = 'modified'
        if (additions > 0 && deletions === 0) changeType = 'added'
        else if (additions === 0 && deletions > 0) changeType = 'deleted'

        changes.push({
          path: filePath,
          additions,
          deletions,
          changeType,
        })
      }

      return changes
    } catch (error: any) {
      return [] // Return empty array if commit doesn't exist or has no changes
    }
  }

  /**
   * Get all contributors with their statistics
   */
  async getContributors(): Promise<ContributorData[]> {
    try {
      const { stdout } = await execPromise(
        `cd "${this.repoPath}" && git log --format="%an|%ae|%aI" --numstat`
      )

      const contributorMap = new Map<string, ContributorData>()
      const lines = stdout.trim().split('\n')
      let currentAuthor: { name: string; email: string; date: Date } | null = null

      for (const line of lines) {
        if (!line) continue

        if (line.includes('|') && !line.includes('\t')) {
          // Author line
          const [name, email, date] = line.split('|')
          currentAuthor = { name, email, date: new Date(date) }
        } else if (currentAuthor && line.includes('\t')) {
          // Stats line
          const [addStr, delStr] = line.split('\t')
          const additions = addStr === '-' ? 0 : parseInt(addStr) || 0
          const deletions = delStr === '-' ? 0 : parseInt(delStr) || 0

          const key = currentAuthor.email
          const existing = contributorMap.get(key)

          if (existing) {
            existing.commits++
            existing.additions += additions
            existing.deletions += deletions
            existing.lastCommit =
              currentAuthor.date > existing.lastCommit ? currentAuthor.date : existing.lastCommit
            existing.firstCommit =
              currentAuthor.date < existing.firstCommit ? currentAuthor.date : existing.firstCommit
          } else {
            contributorMap.set(key, {
              name: currentAuthor.name,
              email: currentAuthor.email,
              commits: 1,
              additions,
              deletions,
              firstCommit: currentAuthor.date,
              lastCommit: currentAuthor.date,
            })
          }
        }
      }

      return Array.from(contributorMap.values())
    } catch (error: any) {
      throw new Error(`Failed to get contributors: ${error.message}`)
    }
  }

  /**
   * Check if file should be ignored
   */
  private shouldIgnoreFile(filePath: string): boolean {
    const ignoredPatterns = [
      /node_modules\//,
      /\.git\//,
      /dist\//,
      /build\//,
      /out\//,
      /\.next\//,
      /coverage\//,
      /\.cache\//,
      /\.temp\//,
      /\.tmp\//,
      /package-lock\.json$/,
      /yarn\.lock$/,
      /pnpm-lock\.yaml$/,
      /\.lock$/,
      /\.log$/,
      /\.min\.js$/,
      /\.min\.css$/,
      /\.map$/,
      /\.bundle\.js$/,
    ]

    return ignoredPatterns.some((pattern) => pattern.test(filePath))
  }

  /**
   * Get file tree structure
   */
  /**
   * Detect language from file extension
   */
  private detectLanguageFromExtension(extension: string | null): string | null {
    if (!extension) return null

    const ext = extension.toLowerCase().replace('.', '')
    const languageMap: Record<string, string> = {
      // JavaScript/TypeScript
      js: 'JavaScript',
      jsx: 'JavaScript',
      mjs: 'JavaScript',
      cjs: 'JavaScript',
      ts: 'TypeScript',
      tsx: 'TypeScript',
      // Python
      py: 'Python',
      pyw: 'Python',
      pyx: 'Python',
      // Java
      java: 'Java',
      // C/C++
      c: 'C',
      h: 'C',
      cpp: 'C++',
      cc: 'C++',
      cxx: 'C++',
      hpp: 'C++',
      hxx: 'C++',
      // C#
      cs: 'C#',
      // Go
      go: 'Go',
      // Rust
      rs: 'Rust',
      // Ruby
      rb: 'Ruby',
      // PHP
      php: 'PHP',
      // Swift
      swift: 'Swift',
      // Kotlin
      kt: 'Kotlin',
      kts: 'Kotlin',
      // Scala
      scala: 'Scala',
      sc: 'Scala',
      // R
      r: 'R',
      // Shell
      sh: 'Shell',
      bash: 'Shell',
      zsh: 'Shell',
      // Web
      html: 'HTML',
      htm: 'HTML',
      css: 'CSS',
      scss: 'SCSS',
      sass: 'Sass',
      less: 'Less',
      // Data/Config
      json: 'JSON',
      xml: 'XML',
      yaml: 'YAML',
      yml: 'YAML',
      toml: 'TOML',
      ini: 'INI',
      // Markup
      md: 'Markdown',
      markdown: 'Markdown',
      rst: 'reStructuredText',
      // SQL
      sql: 'SQL',
      // Other
      vue: 'Vue',
      svelte: 'Svelte',
    }

    return languageMap[ext] || null
  }

  async getFileTree(): Promise<
    {
      path: string
      name: string
      size: number
      extension: string | null
      lines: number
      language: string | null
    }[]
  > {
    try {
      const { stdout } = await execPromise(`cd "${this.repoPath}" && git ls-files`)

      const files: {
        path: string
        name: string
        size: number
        extension: string | null
        lines: number
        language: string | null
      }[] = []
      const filePaths = stdout.trim().split('\n').filter(Boolean)

      for (const filePath of filePaths) {
        // Skip ignored files
        if (this.shouldIgnoreFile(filePath)) {
          continue
        }

        try {
          const fullPath = path.join(this.repoPath, filePath)
          const stats = await fs.stat(fullPath)
          const name = path.basename(filePath)
          const extension = path.extname(filePath) || null

          // Count lines in the file
          let lineCount = 0
          try {
            const content = await fs.readFile(fullPath, 'utf-8')
            lineCount = content.split('\n').length
          } catch {
            // If can't read as text, estimate from bytes (avg 80 chars per line)
            lineCount = Math.ceil(stats.size / 80)
          }

          // Detect language from extension
          const language = this.detectLanguageFromExtension(extension)

          files.push({
            path: filePath,
            name,
            size: stats.size,
            extension,
            lines: lineCount,
            language,
          })
        } catch {
          // Skip files that can't be accessed
          continue
        }
      }

      return files
    } catch (error: any) {
      throw new Error(`Failed to get file tree: ${error.message}`)
    }
  }

  /**
   * Detect programming languages in the repository
   */
  async detectLanguages(): Promise<LanguageData[]> {
    try {
      const files = await this.getFileTree()

      const languageStats = new Map<string, { bytes: number; lines: number }>()
      let totalBytes = 0

      const extensionToLanguage: Record<string, string> = {
        '.ts': 'TypeScript',
        '.tsx': 'TypeScript',
        '.js': 'JavaScript',
        '.jsx': 'JavaScript',
        '.py': 'Python',
        '.java': 'Java',
        '.go': 'Go',
        '.rs': 'Rust',
        '.cpp': 'C++',
        '.c': 'C',
        '.cs': 'C#',
        '.rb': 'Ruby',
        '.php': 'PHP',
        '.swift': 'Swift',
        '.kt': 'Kotlin',
        '.css': 'CSS',
        '.scss': 'SCSS',
        '.html': 'HTML',
        '.json': 'JSON',
        '.md': 'Markdown',
        '.yml': 'YAML',
        '.yaml': 'YAML',
      }

      for (const file of files) {
        if (file.extension) {
          const language = extensionToLanguage[file.extension]
          if (language) {
            const stats = languageStats.get(language) || { bytes: 0, lines: 0 }
            stats.bytes += file.size

            // Count lines in the file
            try {
              const fullPath = path.join(this.repoPath, file.path)
              const content = await fs.readFile(fullPath, 'utf-8')
              const lineCount = content.split('\n').length
              stats.lines += lineCount
            } catch {
              // If can't read file, estimate lines from bytes (avg 80 chars per line)
              stats.lines += Math.ceil(file.size / 80)
            }

            languageStats.set(language, stats)
            totalBytes += file.size
          }
        }
      }

      const languages: LanguageData[] = []
      for (const [name, stats] of languageStats.entries()) {
        languages.push({
          name,
          bytes: stats.bytes,
          lines: stats.lines,
          percentage: (stats.bytes / totalBytes) * 100,
        })
      }

      return languages.sort((a, b) => b.percentage - a.percentage)
    } catch (error: any) {
      throw new Error(`Failed to detect languages: ${error.message}`)
    }
  }

  /**
   * Get repository size in bytes
   */
  async getRepositorySize(): Promise<number> {
    try {
      const { stdout } = await execPromise(`cd "${this.repoPath}" && du -sb . | cut -f1`)
      return parseInt(stdout.trim())
    } catch (error: any) {
      return 0
    }
  }

  /**
   * Clean up the cloned repository
   */
  async cleanup(): Promise<void> {
    try {
      await fs.rm(this.repoPath, { recursive: true, force: true })
    } catch (error: any) {
      console.error(`Failed to cleanup repository: ${error.message}`)
    }
  }
}
