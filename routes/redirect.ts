import { type Request, type Response, type NextFunction } from 'express'
import { URL } from 'url'

export function performRedirect () {
  return (req: Request, res: Response, next: NextFunction) => {
    const toUrl = (req.query.to as string) || ''

    try {
      // Normalize and parse URL safely
      const parsed = new URL(toUrl, process.env.APP_URL || 'http://localhost:3000')

      // Only allow same-origin redirects
      const allowedHostname = new URL(process.env.APP_URL || 'http://localhost:3000').hostname

      if (parsed.hostname !== allowedHostname) {
        return res.status(400).json({ error: 'External redirects are not allowed.' })
      }

      // Prevent redirecting to dangerous paths
      if (!parsed.pathname.startsWith('/')) {
        return res.status(400).json({ error: 'Invalid redirect path.' })
      }

      return res.redirect(parsed.pathname + parsed.search)
    } catch {
      return res.status(400).json({ error: 'Invalid redirect URL.' })
    }
  }
}

