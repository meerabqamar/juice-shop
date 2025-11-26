import os from 'node:os'
import fs from 'node:fs'
import path from 'node:path'
import crypto from 'node:crypto'
import unzipper from 'unzipper'
import { type NextFunction, type Request, type Response } from 'express'

// Allowed extracted file extensions
const ALLOWED_EXTENSIONS = new Set(['.txt', '.md', '.json'])

const SAFE_UPLOAD_DIR = path.resolve('uploads/complaints')

// Ensure folder exists
if (!fs.existsSync(SAFE_UPLOAD_DIR)) {
  fs.mkdirSync(SAFE_UPLOAD_DIR, { recursive: true })
}

// Security helper: ensure no path traversal
function safeJoin(base: string, target: string) {
  const targetPath = path.resolve(base, target)
  if (!targetPath.startsWith(base)) {
    throw new Error('Blocked path traversal attempt')
  }
  return targetPath
}

// Security helper: ensure file type is allowed
function isAllowedExtension(filename: string) {
  const ext = path.extname(filename).toLowerCase()
  return ALLOWED_EXTENSIONS.has(ext)
}

// Ensures file was uploaded
export function ensureFileIsPassed(req: Request, res: Response, next: NextFunction) {
  if (req.file) return next()
  res.status(400).json({ error: 'File not provided' })
}

// Secure ZIP handler
export async function handleZipFileUpload(req: Request, res: Response, next: NextFunction) {
  try {
    const file = req.file
    if (!file) return next()

    // Validate extension
    if (!file.originalname.toLowerCase().endsWith('.zip')) {
      return res.status(400).json({ error: 'Only ZIP files allowed' })
    }

    const tempZip = path.join(os.tmpdir(), crypto.randomUUID() + '.zip')
    fs.writeFileSync(tempZip, file.buffer)

    const zipStream = fs.createReadStream(tempZip).pipe(unzipper.Parse())

    zipStream.on('entry', (entry: any) => {
      const originalPath = entry.path
      const ext = path.extname(originalPath)

      if (!isAllowedExtension(originalPath)) {
        entry.autodrain() // skip dangerous files
        return
      }

      try {
        // Prevent path traversal
        const safeOutputPath = safeJoin(
          SAFE_UPLOAD_DIR,
          crypto.randomUUID() + ext // random filename
        )

        entry.pipe(fs.createWriteStream(safeOutputPath))
      } catch (err) {
        entry.autodrain()
      }
    })

    zipStream.on('close', () => {
      res.status(200).json({ message: 'ZIP processed safely' })
    })

    zipStream.on('error', (err: unknown) => {
      next(err)
    })

  } catch (err) {
    next(err)
  }
}

