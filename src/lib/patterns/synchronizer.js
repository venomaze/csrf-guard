const crypto = require('crypto');
const util = require('util');

class SynchronizerPattern {
  /**
   * @property {Function} generateToken - Generate a random token with the given length
   * @access private
   * @param {Number} [length] - The length of the token bytes (optional)
   * @returns {String} - The generated token
   */
  static async generateToken(length = 16) {
    const randomBytes = util.promisify(crypto.randomBytes);
    const bytes = await randomBytes(length);
    const token = bytes.toString('hex');

    return token;
  }

  /**
   * @property {Function} signToken - Sign the token with the given secret key
   * @access private
   * @param {String} token - The token which is going to be signed
   * @param {String} secret - The secret which is used for signing
   * @returns {String} - The signed key
   */
  static signToken(token, secret) {
    const hash = crypto.createHmac('sha256', secret).update(token);
    const signedToken = hash.digest('hex');

    return signedToken;
  }

  /**
   * @property {Function} verifyToken - Verify if the token is valid or not
   * @param {String} token - The token to be verified (Server token)
   * @param {String} signedToken - The signed token to compare with (Client token)
   * @param {String} secret - The secret which is used for signed token
   * @returns {Boolean} - True if the given token is valid
   */
  static verifyToken(token, signedToken, secret) {
    const expected = this.signToken(token, secret);
    const isValid = expected === signedToken;

    return isValid;
  }

  /**
   * @property {Function} getToken - Generate and sign a new token
   * @param {String} secret - The secret key which is used for signing tokens
   * @param {Number} [tokenLength] - The length of the token bytes (optional)
   * @returns {Object} - An object containing both generated (For server) and signed (For client) tokens
   */
  static async getToken(secret, tokenLength = 16) {
    const token = await this.generateToken(tokenLength);
    const signedToken = this.signToken(token, secret);

    return {
      serverToken: token,
      clientToken: signedToken,
    };
  }
}

module.exports = SynchronizerPattern;
