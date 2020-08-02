const crypto = require('crypto');
const util = require('util');

/**
 * Generate a random token with the given length
 * @access private
 * @param {Number} [length] - The length of the token bytes (optional)
 * @returns {String} - The generated token
 */
const generateToken = async (length = 16) => {
  const randomBytes = util.promisify(crypto.randomBytes);
  const bytes = await randomBytes(length);
  const token = bytes.toString('hex');

  return token;
};

/**
 * Sign the token with the given secret key
 * @access private
 * @param {String} token - The token which is going to be signed
 * @param {String} secret - The secret which is used for signing
 * @returns {String} - The signed key
 */
const signToken = (token, secret) => {
  const hash = crypto.createHmac('sha1', secret).update(token);
  const signedToken = hash.digest('hex');

  return signedToken;
};

/**
 * Verify if the token is valid or not
 * @param {String} token - The token to be verified
 * @param {String} signedToken - The signed token to compare with
 * @param {String} secret - The secret which is used for signed token
 * @returns {Boolean} - True if the given token is valid
 */
const verifyToken = (token, signedToken, secret) => {
  const expected = signToken(token, secret);
  const isValid = expected === signedToken;

  return isValid;
};

/**
 * Generate and sign a new token
 * @param {String} secret - The secret key which is used for signing tokens
 * @param {Number} [tokenLength] - The length of the token bytes (optional)
 * @returns {Object} - An object containing both generated and signed tokens
 */
const getToken = async (secret, tokenLength = 16) => {
  const token = await generateToken(tokenLength);
  const signedToken = signToken(token, secret);

  return {
    token,
    signedToken,
  };
};

module.exports = {
  getToken,
  signToken,
  verifyToken,
  generateToken,
};
