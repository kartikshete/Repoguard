import { describe, expect, it } from '@jest/globals';
import { createOAuthState, isValidOAuthState } from './oauthState.js';

describe('OAuth state helpers', () => {
  it('creates a 32-byte URL-safe state value', () => {
    const state = createOAuthState();

    expect(Buffer.from(state, 'base64url')).toHaveLength(32);
    expect(state).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it('accepts a matching state and rejects a mismatch', () => {
    const expected = createOAuthState();
    const candidate = createOAuthState();

    expect(isValidOAuthState(expected, expected)).toBe(true);
    expect(isValidOAuthState(candidate, expected)).toBe(false);
  });

  it('rejects malformed and non-canonical state values', () => {
    const expected = createOAuthState();
    const nonCanonicalState = `${'A'.repeat(42)}B`;

    expect(isValidOAuthState(null, expected)).toBe(false);
    expect(isValidOAuthState('short', expected)).toBe(false);
    expect(isValidOAuthState(nonCanonicalState, expected)).toBe(false);
    expect(isValidOAuthState(expected, 'invalid')).toBe(false);
  });
});
