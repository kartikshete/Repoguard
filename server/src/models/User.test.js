import { describe, expect, it } from '@jest/globals';
import User from './User.js';

function createValidUser(overrides = {}) {
  return new User({
    githubId: '123456789',
    username: 'Repo-Guard',
    displayName: 'Repo Guard',
    avatarUrl: 'https://avatars.githubusercontent.com/u/123456789?v=4',
    ...overrides,
  });
}

describe('User model', () => {
  it('normalizes a valid GitHub username', async () => {
    const user = createValidUser();

    await expect(user.validate()).resolves.toBeUndefined();
    expect(user.username).toBe('repo-guard');
  });

  it.each(['-leading', 'trailing-', 'double--hyphen', 'has spaces'])(
    'rejects invalid GitHub username %s',
    async (username) => {
      const user = createValidUser({ username });

      await expect(user.validate()).rejects.toThrow();
    },
  );

  it('rejects avatar URLs that do not use HTTPS', async () => {
    const user = createValidUser({
      avatarUrl: 'http://avatars.example/profile.png',
    });

    await expect(user.validate()).rejects.toThrow('Avatar URL must use HTTPS.');
  });

  it('rejects undeclared access-token fields', () => {
    expect(() =>
      createValidUser({ githubAccessToken: 'placeholder-token-value' }),
    ).toThrow();
  });
});
