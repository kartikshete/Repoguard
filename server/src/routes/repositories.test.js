import {
  afterAll,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  jest,
} from '@jest/globals';
import { randomBytes } from 'node:crypto';
import express from 'express';
import request from 'supertest';
import { createSessionToken } from '../auth/sessionToken.js';

const findByIdMock = jest.fn();
jest.unstable_mockModule('../models/User.js', () => ({
  default: { findById: findByIdMock },
}));

const testSecret = randomBytes(32).toString('base64url');
const originalJwtSecret = process.env.JWT_SECRET;
const originalFetch = globalThis.fetch;
const githubUsername = 'repoguard-user';
const sessionToken = createSessionToken('user-123', testSecret);

let app;

function configureUser(username = githubUsername) {
  const query = {
    select: jest.fn().mockReturnThis(),
    lean: jest.fn().mockResolvedValue(username ? { username } : null),
  };

  findByIdMock.mockReturnValue(query);
  return query;
}

function authenticatedRequest() {
  return request(app)
    .get('/api/repositories')
    .set('Cookie', `repoguard_session=${sessionToken}`);
}

beforeAll(async () => {
  process.env.JWT_SECRET = testSecret;

  const { default: repositoriesRouter } = await import('./repositories.js');
  app = express();
  app.use('/api/repositories', repositoriesRouter);
});

afterAll(() => {
  if (originalJwtSecret === undefined) {
    delete process.env.JWT_SECRET;
  } else {
    process.env.JWT_SECRET = originalJwtSecret;
  }

  globalThis.fetch = originalFetch;
});

beforeEach(() => {
  findByIdMock.mockReset();
  globalThis.fetch = jest.fn();
});

describe('repository listing route', () => {
  it('requires an authenticated session before loading user data', async () => {
    const response = await request(app).get('/api/repositories').expect(401);

    expect(response.body).toEqual({ error: 'Authentication required.' });
    expect(findByIdMock).not.toHaveBeenCalled();
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it('returns a safe public repository summary and pagination state', async () => {
    const userQuery = configureUser();
    const publicRepository = {
      id: 42,
      private: false,
      name: 'repoguard',
      full_name: `${githubUsername}/repoguard`,
      description: 'Code review and security analysis',
      language: 'JavaScript',
      default_branch: 'main',
      updated_at: '2026-11-26T12:00:00Z',
      archived: false,
      fork: false,
    };

    globalThis.fetch.mockResolvedValue({
      ok: true,
      json: async () => [
        publicRepository,
        {
          ...publicRepository,
          id: 43,
          name: 'private',
          full_name: `${githubUsername}/private`,
          private: true,
        },
        {
          ...publicRepository,
          id: 44,
          full_name: `${githubUsername}/invalid/extra`,
        },
      ],
      headers: {
        get: jest
          .fn()
          .mockReturnValue('<https://api.github.com/next>; rel="next"'),
      },
    });

    const response = await authenticatedRequest().expect(200);

    expect(findByIdMock).toHaveBeenCalledWith('user-123');
    expect(userQuery.select).toHaveBeenCalledWith('username');
    expect(response.headers['cache-control']).toBe('private, no-store');
    expect(response.body).toEqual({
      repositories: [
        {
          id: 42,
          name: 'repoguard',
          fullName: `${githubUsername}/repoguard`,
          description: 'Code review and security analysis',
          language: 'JavaScript',
          defaultBranch: 'main',
          updatedAt: '2026-11-26T12:00:00Z',
          archived: false,
          fork: false,
          htmlUrl: `https://github.com/${githubUsername}/repoguard`,
        },
      ],
      hasMore: true,
    });

    const [requestedUrl, options] = globalThis.fetch.mock.calls[0];
    const parsedUrl = new URL(requestedUrl);

    expect(parsedUrl.origin).toBe('https://api.github.com');
    expect(parsedUrl.pathname).toBe(`/users/${githubUsername}/repos`);
    expect(parsedUrl.searchParams.get('type')).toBe('owner');
    expect(parsedUrl.searchParams.get('per_page')).toBe('100');
    expect(options.headers).toMatchObject({
      Accept: 'application/vnd.github+json',
      'User-Agent': 'RepoGuard',
      'X-GitHub-Api-Version': '2026-03-10',
    });
  });

  it('returns an expired-session response when the account was removed', async () => {
    configureUser(null);

    const response = await authenticatedRequest().expect(401);

    expect(response.body).toEqual({ error: 'Session is no longer valid.' });
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it('hides upstream GitHub errors from the client', async () => {
    configureUser();
    globalThis.fetch.mockResolvedValue({ ok: false, status: 403 });

    const response = await authenticatedRequest().expect(502);

    expect(response.body).toEqual({
      error: 'GitHub repositories could not be loaded.',
    });
    expect(JSON.stringify(response.body)).not.toContain('403');
  });

  it('returns a safe error when GitHub cannot be reached', async () => {
    configureUser();
    globalThis.fetch.mockRejectedValue(new Error('upstream network details'));

    const response = await authenticatedRequest().expect(502);

    expect(response.body).toEqual({
      error: 'GitHub repositories could not be loaded.',
    });
    expect(JSON.stringify(response.body)).not.toContain(
      'upstream network details',
    );
  });
});
