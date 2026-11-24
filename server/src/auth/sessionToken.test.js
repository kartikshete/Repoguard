import { randomBytes } from 'node:crypto';
import { describe, expect, it } from '@jest/globals';
import jwt from 'jsonwebtoken';
import {
  createSessionToken,
  verifySessionToken,
} from './sessionToken.js';

const testSecret = randomBytes(32).toString('base64url');

describe('session token helpers', () => {
  it('creates and verifies a token for a user ID', () => {
    const token = createSessionToken('user-123', testSecret);

    expect(verifySessionToken(token, testSecret)).toEqual({
      userId: 'user-123',
    });
  });

  it('rejects blank user IDs and secrets shorter than 32 bytes', () => {
    expect(() => createSessionToken(' ', testSecret)).toThrow(
      'A user ID is required to create a session token.',
    );
    expect(() => createSessionToken('user-123', 'short-secret')).toThrow(
      'JWT_SECRET must contain at least 32 bytes.',
    );
  });

  it('rejects missing, malformed, or wrongly signed tokens safely', () => {
    expect(() => verifySessionToken('', testSecret)).toThrow(
      'A session token is required.',
    );
    expect(() => verifySessionToken('not.a.jwt', testSecret)).toThrow(
      'Invalid or expired session token.',
    );

    const token = createSessionToken('user-123', testSecret);
    const otherSecret = randomBytes(32).toString('base64url');

    expect(() => verifySessionToken(token, otherSecret)).toThrow(
      'Invalid or expired session token.',
    );
  });

  it('rejects expired tokens', () => {
    const expiredToken = jwt.sign({}, testSecret, {
      algorithm: 'HS256',
      audience: 'repoguard-client',
      expiresIn: -1,
      issuer: 'repoguard-api',
      subject: 'user-123',
    });

    expect(() => verifySessionToken(expiredToken, testSecret)).toThrow(
      'Invalid or expired session token.',
    );
  });
});
