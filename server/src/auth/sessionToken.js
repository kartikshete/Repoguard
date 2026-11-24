import jwt from 'jsonwebtoken';

const MINIMUM_SECRET_BYTES = 32;
const SESSION_ISSUER = 'repoguard-api';
const SESSION_AUDIENCE = 'repoguard-client';
const SESSION_DURATION = '1h';

function getSigningSecret(secret = process.env.JWT_SECRET) {
  if (
    typeof secret !== 'string' ||
    Buffer.byteLength(secret, 'utf8') < MINIMUM_SECRET_BYTES
  ) {
    throw new Error('JWT_SECRET must contain at least 32 bytes.');
  }

  return secret;
}

export function createSessionToken(userId, secret) {
  if (typeof userId !== 'string' || userId.trim() === '') {
    throw new Error('A user ID is required to create a session token.');
  }

  return jwt.sign({}, getSigningSecret(secret), {
    algorithm: 'HS256',
    audience: SESSION_AUDIENCE,
    expiresIn: SESSION_DURATION,
    issuer: SESSION_ISSUER,
    subject: userId.trim(),
  });
}

export function verifySessionToken(token, secret) {
  if (typeof token !== 'string' || token.trim() === '') {
    throw new Error('A session token is required.');
  }

  const signingSecret = getSigningSecret(secret);

  try {
    const payload = jwt.verify(token, signingSecret, {
      algorithms: ['HS256'],
      audience: SESSION_AUDIENCE,
      issuer: SESSION_ISSUER,
    });

    if (typeof payload === 'string' || typeof payload.sub !== 'string') {
      throw new Error('Session token subject is invalid.');
    }

    return Object.freeze({ userId: payload.sub });
  } catch {
    throw new Error('Invalid or expired session token.');
  }
}
