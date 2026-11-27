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
const createRepositoryScanMock = jest.fn();

class MockRepositoryScanServiceError extends Error {
  constructor(message, status, scanId = null) {
    super(message);
    this.name = 'RepositoryScanServiceError';
    this.status = status;
    this.scanId = scanId;
  }
}

jest.unstable_mockModule('../models/User.js', () => ({
  default: { findById: findByIdMock },
}));
jest.unstable_mockModule('../services/repositoryScanService.js', () => ({
  createRepositoryScan: createRepositoryScanMock,
  RepositoryScanServiceError: MockRepositoryScanServiceError,
}));

const testSecret = randomBytes(32).toString('base64url');
const originalJwtSecret = process.env.JWT_SECRET;
const originalClientOrigin = process.env.CLIENT_ORIGIN;
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

function authenticatedScanRequest(repositoryName = 'repoguard', body = { repositoryId: 42 }) {
  return request(app)
    .post(`/api/repositories/${repositoryName}/scans`)
    .set('Cookie', `repoguard_session=${sessionToken}`)
    .set('Origin', 'http://localhost:5173')
    .send(body);
}

beforeAll(async () => {
  process.env.JWT_SECRET = testSecret;
  process.env.CLIENT_ORIGIN = 'http://localhost:5173';

  const { default: repositoriesRouter } = await import('./repositories.js');
  app = express();
  app.use(express.json());
  app.use('/api/repositories', repositoriesRouter);
});

afterAll(() => {
  if (originalJwtSecret === undefined) {
    delete process.env.JWT_SECRET;
  } else {
    process.env.JWT_SECRET = originalJwtSecret;
  }

  if (originalClientOrigin === undefined) {
    delete process.env.CLIENT_ORIGIN;
  } else {
    process.env.CLIENT_ORIGIN = originalClientOrigin;
  }

  globalThis.fetch = originalFetch;
});

beforeEach(() => {
  findByIdMock.mockReset();
  createRepositoryScanMock.mockReset();
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

  it('requires an authenticated session before accepting a scan request', async () => {
    const response = await request(app)
      .post('/api/repositories/repoguard/scans')
      .send({ repositoryId: 42 })
      .expect(401);

    expect(response.body).toEqual({ error: 'Authentication required.' });
    expect(findByIdMock).not.toHaveBeenCalled();
    expect(createRepositoryScanMock).not.toHaveBeenCalled();
  });

  it('rejects invalid repository names and identifiers before loading the user', async () => {
    await authenticatedScanRequest('bad!name', { repositoryId: 42 }).expect(400);
    await authenticatedScanRequest('repoguard', { repositoryId: '42' }).expect(400);

    expect(findByIdMock).not.toHaveBeenCalled();
    expect(createRepositoryScanMock).not.toHaveBeenCalled();
  });

  it('starts a scan for the authenticated user and returns only safe scan fields', async () => {
    const userQuery = configureUser();
    const scan = {
      _id: { toString: () => 'scan-123' },
      userId: 'user-123',
      repositoryFullName: `${githubUsername}/repoguard`,
      defaultBranch: 'main',
      commitSha: 'a'.repeat(40),
      status: 'completed',
      findings: [
        {
          tool: 'semgrep',
          ruleId: 'repoguard.javascript.dynamic-code-execution',
          severity: 'high',
          title: 'Dynamic Code Execution',
          message: 'Avoid evaluating strings as code.',
          filePath: 'src/index.js',
          startLine: 3,
          endLine: 3,
          referenceUrl: null,
        },
      ],
      createdAt: new Date('2026-11-28T10:00:00.000Z'),
      completedAt: new Date('2026-11-28T10:00:05.000Z'),
    };
    createRepositoryScanMock.mockResolvedValue(scan);

    const response = await authenticatedScanRequest().expect(201);

    expect(userQuery.select).toHaveBeenCalledWith('username');
    expect(createRepositoryScanMock).toHaveBeenCalledWith({
      userId: 'user-123',
      githubUsername,
      repositoryName: 'repoguard',
      githubRepositoryId: 42,
    });
    expect(response.headers['cache-control']).toBe('private, no-store');
    expect(response.body).toEqual({
      scan: {
        id: 'scan-123',
        repositoryFullName: `${githubUsername}/repoguard`,
        defaultBranch: 'main',
        commitSha: 'a'.repeat(40),
        status: 'completed',
        findings: [
          {
            tool: 'semgrep',
            ruleId: 'repoguard.javascript.dynamic-code-execution',
            severity: 'high',
            title: 'Dynamic Code Execution',
            message: 'Avoid evaluating strings as code.',
            filePath: 'src/index.js',
            startLine: 3,
            endLine: 3,
            referenceUrl: null,
          },
        ],
        createdAt: '2026-11-28T10:00:00.000Z',
        completedAt: '2026-11-28T10:00:05.000Z',
      },
    });
    expect(response.body.scan).not.toHaveProperty('userId');
  });

  it('returns safe scan-service errors and their scan IDs', async () => {
    configureUser();
    createRepositoryScanMock.mockRejectedValue(
      new MockRepositoryScanServiceError(
        'Repository scan timed out.',
        504,
        'scan-123',
      ),
    );

    const response = await authenticatedScanRequest().expect(504);

    expect(response.body).toEqual({
      error: 'Repository scan timed out.',
      scanId: 'scan-123',
    });
  });

  it('returns an expired-session response when the account was removed before scanning', async () => {
    configureUser(null);

    const response = await authenticatedScanRequest().expect(401);

    expect(response.body).toEqual({ error: 'Session is no longer valid.' });
    expect(createRepositoryScanMock).not.toHaveBeenCalled();
  });
});
