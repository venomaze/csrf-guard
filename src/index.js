const { SynchronizerPattern, HMACBasedPattern } = require('./lib/token');

class CSRFGuard {
  constructor(options = {}) {
    this.secret = options.secret;
    this.synchronizer = options.synchronizer || true;
    this.expiryTime = options.expiryTime || null;

    if (!this.secret) throw new Error('Secret key must be included.');

    return this.middleware.bind(this);
  }

  async middleware(req, res, next) {}
}

module.exports = CSRFGuard;
