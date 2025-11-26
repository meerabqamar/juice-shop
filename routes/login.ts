export function login () {
  async function afterLogin (user: { data: User, bid: number }, res: Response, next: NextFunction) {
    try {
      verifyPostLoginChallenges(user)
      const [basket] = await BasketModel.findOrCreate({ where: { UserId: user.data.id } })
      const token = security.authorize(user)
      user.bid = basket.id // keep track of original basket
      security.authenticatedUsers.put(token, user)
      res.json({ authentication: { token, bid: basket.id, umail: user.data.email } })
    } catch (error) {
      next(error)
    }
  }

  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      verifyPreLoginChallenges(req)

      const email = (req.body.email || '').toString().trim()
      const password = (req.body.password || '').toString()

      // Basic input sanity check
      if (!email || !password) {
        // avoid leaking whether email exists
        return res.status(401).send(res.__('Invalid email or password.'))
      }

      // Find user by email only (parameterized by Sequelize)
      const userRecord = await UserModel.findOne({
        where: {
          email,
          deletedAt: null
        },
        raw: true
      })

      // If no user found, still perform a fake hash and compare to mitigate timing attacks
      const suppliedHash = security.hash(password)

      if (!userRecord) {
        // constant-time comparison with a dummy buffer to mitigate timing differences
        // create dummy hash buffer (same length as suppliedHash) to compare
        // Node's crypto.timingSafeEqual requires two Buffers of same length
        try {
          const dummy = Buffer.alloc(Buffer.from(suppliedHash).length, 0)
          const supplied = Buffer.from(suppliedHash)
          // If lengths differ this will throw — catch below and return generic 401
          if (dummy.length === supplied.length) {
            crypto.timingSafeEqual(dummy, supplied)
          }
        } catch {
          // ignore — we just want to burn comparable time
        }
        return res.status(401).send(res.__('Invalid email or password.'))
      }

      // Compare hashed password in constant-time
      const storedHash = (userRecord as any).password || ''
      const bufA = Buffer.from(storedHash)
      const bufB = Buffer.from(suppliedHash)

      // Ensure buffers same length; if not, create padded copies so timingSafeEqual won't throw
      let equal = false
      if (bufA.length === bufB.length) {
        try {
          equal = crypto.timingSafeEqual(bufA, bufB)
        } catch {
          equal = false
        }
      } else {
        // pad the shorter one with zeros so lengths match, then compare
        const maxLen = Math.max(bufA.length, bufB.length)
        const a = Buffer.alloc(maxLen, 0)
        const b = Buffer.alloc(maxLen, 0)
        bufA.copy(a, 0)
        bufB.copy(b, 0)
        try {
          equal = crypto.timingSafeEqual(a, b)
        } catch {
          equal = false
        }
      }

      if (!equal) {
        return res.status(401).send(res.__('Invalid email or password.'))
      }

      // At this point we have a valid user and password
      const user = utils.queryResultToJson(userRecord)
      if (user.data?.id && user.data.totpSecret !== '') {
        res.status(401).json({
          status: 'totp_token_required',
          data: {
            tmpToken: security.authorize({
              userId: user.data.id,
              type: 'password_valid_needs_second_factor_token'
            })
          }
        })
      } else if (user.data?.id) {
        // @ts-expect-error some properties missing in user object
        await afterLogin(user, res, next)
      } else {
        return res.status(401).send(res.__('Invalid email or password.'))
      }
    } catch (error) {
      // Don't propagate raw DB errors to client — keep generic message
      next(error)
    }
  }
}

