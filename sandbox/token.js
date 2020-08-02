const tokenHelper = require('../src/lib/token');

(async () => {
  const tokenLength = 32;
  const secret = 'secret_key';
  const token = await tokenHelper.generateToken(tokenLength);
  const signedToken = tokenHelper.signToken(token, secret);
  const isValid = tokenHelper.verifyToken(token, signedToken, secret);

  console.log(token, signedToken, isValid);
})();

(async () => {
  const tokenLength = 32;
  const secret = 'secret_key';
  const { token, signedToken } = await tokenHelper.getToken(
    secret,
    tokenLength
  );
  const isValid = tokenHelper.verifyToken(token, signedToken, secret);

  console.log(token, signedToken, isValid);
})();
