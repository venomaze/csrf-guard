const crypto = require('crypto');
const util = require('util');

const generateToken = async (length = 16) => {
  const randomBytes = util.promisify(crypto.randomBytes);
  const bytes = await randomBytes(length);
  const token = bytes.toString('hex');

  return token;
};

const signToken = (token, secret) => {
  const hash = crypto.createHmac('sha1', secret).update(token);
  const signedToken = hash.digest('hex');

  return signedToken;
};

const verifyToken = (token, signedToken, secret) => {
  const expected = signToken(token, secret);
  const isValid = expected === signedToken;

  return isValid;
};

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
