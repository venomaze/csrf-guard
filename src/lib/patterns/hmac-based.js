const crypto = require('crypto');

/**
 * HMAC Based Token Pattern
 */
class HMACBasedPattern {
  /**
   * @property {Function} generateToken - Generate a token based on session id and timestamp
   * @param {String} sid - Session ID
   * @param {String} secret - Secret key which is going to be used for HMAC
   * @returns {String} - The generated token -> timestamp:hash
   */
  static generateToken(sid, secret) {
    const timestamp = Date.now().toString(16);
    const hash = crypto
      .createHmac('sha256', secret)
      .update(timestamp + sid)
      .digest('hex');
    const token = `${timestamp}:${hash}`;

    return token;
  }

  /**
   * @property {Function} verifyToken - Check if the given token is valid
   * @param {String} token - The token to be verified
   * @param {String} sid - Session ID
   * @param {String} secret - Secret key which is used for HMAC
   * @param {(null|Number)} expiryTime - Expiry time (in milliseconds)
   * @returns {Boolean} - True if the token is valid
   */
  static verifyToken(token, sid, secret, expiryTime = null) {
    const timestamp = parseInt(token.split(':')[0], 16);
    const hash = token.split(':')[1];

    if (!(timestamp && hash) || typeof timestamp !== 'number') return false;

    const expected = crypto
      .createHmac('sha256', secret)
      .update(timestamp.toString(16) + sid)
      .digest('hex');

    const isHashValid = expected === hash;
    const isTimestampValid = expiryTime
      ? Date.now() - timestamp < expiryTime
      : true;

    return isHashValid && isTimestampValid;
  }
}

module.exports = HMACBasedPattern;
