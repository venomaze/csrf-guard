const { SynchronizerPattern, HMACBasedPattern } = require('./lib/token');

class CSRFGuard {
  /**
   * Set up the main middleware
   * @constructor
   * @param {Object} [options] - Custom options (optional)
   * @returns {Function} - CSRF Guard middleware
   */
  constructor(options = {}) {
    this.secret = options.secret;
    this.expiryTime = options.expiryTime || null;
    this.synchronizer =
      typeof options.synchronizer === 'boolean' ? options.synchronizer : true;

    if (!this.secret) {
      throw new Error('Secret key must be included.');
    }

    return this.middleware.bind(this);
  }

  /**
   * @property {Function} middleware - The main Anti-CSRF middleware
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   * @returns {void} - Call the next middleware
   */
  async middleware(req, res, next) {
    /**
     * Generate and set the token
     * @param {Boolean} [forced] - Force to generate a new token (optional)
     * @returns {String} - Generated token for the client
     */
    const getToken = async (forced = false) => {
      /**
       * Forced option can be used only with Synchronizer pattern.
       * With HMAC Based pattern, a new token is generated anyway.
       */

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
       * Using HMAC Based Token Pattern
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
       * Using Synchronizer Token Pattern
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
       * Using HMAC Based Token Pattern
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
