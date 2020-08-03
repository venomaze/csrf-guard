const { SynchronizerPattern } = require('../src/lib/token');

describe('Generate random token', () => {
  test('Generate 16 bytes token', async () => {
    const token = await SynchronizerPattern.generateToken();

    expect(token.length).toBe(16 * 2); // 16 bytes
  });

  test('Generate 32 bytes token', async () => {
    const token = await SynchronizerPattern.generateToken(32);

    expect(token.length).toBe(32 * 2); // 32 bytes
  });
});

test('Sign a token', async () => {
  const secret = 'secret_key';
  const token = await SynchronizerPattern.generateToken();
  const signedToken = SynchronizerPattern.signToken(token, secret);

  expect(signedToken.length).toBe(32 * 2); // 256 bits
});

test('Generate and sign token', async () => {
  const secret = 'secret_key';
  const {
    serverToken: token,
    clientToken: signedToken,
  } = await SynchronizerPattern.getToken(secret, 8);

  expect(token.length).toBe(8 * 2); // 8 bytes
  expect(signedToken.length).toBe(32 * 2); // 256 bits
});

describe('Verify token', () => {
  test('Should be valid', async () => {
    const secret = 'secret_key';
    const {
      serverToken: token,
      clientToken: signedToken,
    } = await SynchronizerPattern.getToken(secret, 8);
    const isValid = SynchronizerPattern.verifyToken(token, signedToken, secret);

    expect(isValid).toBeTruthy();
  });

  test("Shouldn't be valid (wrong secret)", async () => {
    const secret = 'secret_key';
    const invalidSecret = 'wrong_secret';
    const {
      serverToken: token,
      clientToken: signedToken,
    } = await SynchronizerPattern.getToken(secret, 8);
    const isValid = SynchronizerPattern.verifyToken(
      token,
      signedToken,
      invalidSecret
    );

    expect(isValid).toBeFalsy();
  });

  test("Shouldn't be valid (wrong signed token)", async () => {
    const secret = 'secret_key';
    const token = await SynchronizerPattern.generateToken();
    const invalidSignedToken = 'wrong_token';
    const isValid = SynchronizerPattern.verifyToken(
      token,
      invalidSignedToken,
      secret
    );

    expect(isValid).toBeFalsy();
  });
});
