const { SynchronizerPattern, HMACBasedPattern } = require('./lib/token');

class CSRFGuard {
  constructor(options = {}) {
    this.secret = options.secret;
    this.synchronizer =
      typeof options.synchronizer === 'boolean' ? options.synchronizer : true;
    this.expiryTime = options.expiryTime || null;

    if (!this.secret) {
      throw new Error('Secret key must be included.');
    }

    return this.middleware.bind(this);
  }

  async middleware(req, res, next) {
    const getToken = async (forced = false) => {
      if (!req.session) {
        throw new Error('Session object is not available.');
      }

      /**
       * Using Synchronizer Token Pattern
       */
      if (this.synchronizer) {
        if (!forced) {
          const token = req.session.csrf_token;

          if (token) {
            const signedToken = SynchronizerPattern.signToken(
              token,
              this.secret
            );

            return signedToken;
          }
        }

        const { serverToken, clientToken } = await SynchronizerPattern.getToken(
          this.secret
        );

        req.session.csrf_token = serverToken;

        return clientToken;
      }

      /**
       * HMAC Based Token Pattern
       */
      const sid = req.session.id;
      const token = HMACBasedPattern.generateToken(sid, this.secret);

      return token;
    };

    const isTokenValid = () => {
      if (!req.session) {
        throw new Error('Session object is not available.');
      }

      const clientToken =
        (req.body && req.body.csrf_token) ||
        (req.query && req.query.csrf_token) ||
        req.get('csrf-token') ||
        req.get('xsrf-token') ||
        req.get('x-csrf-token') ||
        req.get('x-xsrf-token');

      if (!clientToken) return false;

      /**
       * Synchronizer Token Pattern
       */
      if (this.synchronizer) {
        if (!req.session.csrf_token) return false;

        const serverToken = req.session.csrf_token;
        const isValid = SynchronizerPattern.verifyToken(
          serverToken,
          clientToken,
          this.secret
        );

        return isValid;
      }

      /**
       * HMAC Based Token Pattern
       */
      const sid = req.session.id;
      const isValid = HMACBasedPattern.verifyToken(
        clientToken,
        sid,
        this.secret,
        this.expiryTime
      );

      return isValid;
    };

    req.getToken = getToken;
    req.isTokenValid = isTokenValid;

    return next();
  }
}

module.exports = CSRFGuard;
