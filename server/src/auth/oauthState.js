import { randomBytes, timingSafeEqual } from 'node:crypto';

const STATE_BYTES = 32;
const STATE_PATTERN = /^[A-Za-z0-9_-]{43}$/;

export function createOAuthState() {
  return randomBytes(STATE_BYTES).toString('base64url');
}

export function isValidOAuthState(candidate, expected) {
  if (
    typeof candidate !== 'string' ||
    typeof expected !== 'string' ||
    !STATE_PATTERN.test(candidate) ||
    !STATE_PATTERN.test(expected)
  ) {
    return false;
  }

  const candidateBytes = Buffer.from(candidate, 'base64url');
  const expectedBytes = Buffer.from(expected, 'base64url');

  if (
    candidateBytes.length !== STATE_BYTES ||
    expectedBytes.length !== STATE_BYTES ||
    candidateBytes.toString('base64url') !== candidate ||
    expectedBytes.toString('base64url') !== expected
  ) {
    return false;
  }

  return timingSafeEqual(candidateBytes, expectedBytes);
}
