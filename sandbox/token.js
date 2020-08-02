const { SynchronizerPattern, HMACBasedPattern } = require('../src/lib/token');

/**
 * Synchronizer Token Pattern: using generator method directly
 */
(async () => {
  const secret = 'secret_key';
  const token = await SynchronizerPattern.generateToken();
  const signedToken = SynchronizerPattern.signToken(token, secret);
  const isValid = SynchronizerPattern.verifyToken(token, signedToken, secret);

  console.log(
    'Synchronizer Token Pattern (direct):',
    token,
    signedToken,
    isValid
  );
})();

/**
 * Synchronizer Token Pattern: using getToken method
 */
(async () => {
  const secret = 'secret_key';
  const {
    serverToken: token,
    clientToken: signedToken,
  } = await SynchronizerPattern.getToken(secret);
  const isValid = SynchronizerPattern.verifyToken(token, signedToken, secret);

  console.log(
    'Synchronizer Token Pattern (get method):',
    token,
    signedToken,
    isValid
  );
})();

/**
 * HMAC Based Token Pattern
 */
(() => {
  const secret = 'secret_key';
  const sid = 'random_session_id';
  const token = HMACBasedPattern.generateToken(sid, secret);
  const isValid = HMACBasedPattern.verifyToken(token, sid, secret);

  console.log('HMAC Based Token Pattern:', token, isValid);
})();
