const { HMACBasedPattern } = require('../src/lib/token');

test('Generate a token from session id', () => {
  const secret = 'secret_key';
  const sid = 'session_id';
  const token = HMACBasedPattern.generateToken(sid, secret);

  expect(token.split(':')[1].length).toBe(32 * 2); // 256 bits
  expect(parseInt(token.split(':')[0], 16)).toBeLessThanOrEqual(Date.now());
});

describe('Verify token', () => {
  test('Should be valid', () => {
    const secret = 'secret_key';
    const sid = 'session_id';
    const token = HMACBasedPattern.generateToken(sid, secret);
    const isValid = HMACBasedPattern.verifyToken(token, sid, secret);

    expect(isValid).toBeTruthy();
  });

  test("Shouldn't be valid (wrong session id)", () => {
    const secret = 'secret_key';
    const sid = 'session_id';
    const wrongSID = 'wrong_session_id';
    const token = HMACBasedPattern.generateToken(sid, secret);
    const isValid = HMACBasedPattern.verifyToken(token, wrongSID, secret);

    expect(isValid).toBeFalsy();
  });

  const pause = amount =>
    new Promise(resolve => {
      setTimeout(resolve, amount);
    });

  test("Shouldn't be valid (expired token)", async () => {
    const secret = 'secret_key';
    const sid = 'session_id';
    const token = HMACBasedPattern.generateToken(sid, secret);

    await pause(2000);

    const expiryTime = 1000;
    const isValid = HMACBasedPattern.verifyToken(
      token,
      sid,
      secret,
      expiryTime
    );

    expect(isValid).toBeFalsy();
  });

  test('Should be valid (with expiry time)', async () => {
    const secret = 'secret_key';
    const sid = 'session_id';
    const token = HMACBasedPattern.generateToken(sid, secret);

    await pause(2000);

    const expiryTime = 5000;
    const isValid = HMACBasedPattern.verifyToken(
      token,
      sid,
      secret,
      expiryTime
    );

    expect(isValid).toBeTruthy();
  });
});
