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

const findMock = jest.fn();
const findOneMock = jest.fn();
jest.unstable_mockModule('../models/Scan.js', () => ({
  default: { find: findMock, findOne: findOneMock },
}));

const testSecret = randomBytes(32).toString('base64url');
const originalJwtSecret = process.env.JWT_SECRET;
const sessionToken = createSessionToken('user-123', testSecret);
let app;

function createQuery(result) {
  const query = {
    select: jest.fn().mockReturnThis(),
    sort: jest.fn().mockReturnThis(),
    limit: jest.fn().mockReturnThis(),
    lean: jest.fn().mockResolvedValue(result),
  };

  return query;
}

function createScan(id, overrides = {}) {
  return {
    _id: id,
    repositoryFullName: 'repo-user/project',
    defaultBranch: 'main',
    commitSha: 'a'.repeat(40),
    status: 'completed',
    findings: [],
    createdAt: new Date('2026-11-28T10:00:00.000Z'),
    completedAt: new Date('2026-11-28T10:00:05.000Z'),
    ...overrides,
  };
}

function authenticatedRequest(path) {
  return request(app)
    .get(`/api/scans${path}`)
    .set('Cookie', `repoguard_session=${sessionToken}`);
}

beforeAll(async () => {
  process.env.JWT_SECRET = testSecret;

  const { default: scansRouter } = await import('./scans.js');
  app = express();
  app.use('/api/scans', scansRouter);
});

afterAll(() => {
  if (originalJwtSecret === undefined) {
    delete process.env.JWT_SECRET;
  } else {
    process.env.JWT_SECRET = originalJwtSecret;
  }
});

beforeEach(() => {
  findMock.mockReset();
  findOneMock.mockReset();
});

describe('scan history and detail routes', () => {
  it('requires authentication before querying scan history', async () => {
    const response = await request(app).get('/api/scans').expect(401);

    expect(response.body).toEqual({ error: 'Authentication required.' });
    expect(findMock).not.toHaveBeenCalled();
    expect(findOneMock).not.toHaveBeenCalled();
  });

  it('returns a paginated summary scoped to the signed-in user', async () => {
    const firstScanId = 'a'.repeat(24);
    const secondScanId = 'b'.repeat(24);
    const query = createQuery([
      createScan(firstScanId),
      createScan(secondScanId, { repositoryFullName: 'repo-user/another' }),
    ]);
    findMock.mockReturnValue(query);

    const response = await authenticatedRequest('/?limit=1').expect(200);

    expect(findMock).toHaveBeenCalledWith({ userId: 'user-123' });
    expect(query.select).toHaveBeenCalledWith(
      '_id repositoryFullName defaultBranch commitSha status createdAt completedAt',
    );
    expect(query.sort).toHaveBeenCalledWith({ createdAt: -1, _id: -1 });
    expect(query.limit).toHaveBeenCalledWith(2);
    expect(response.headers['cache-control']).toBe('private, no-store');
    expect(response.body).toEqual({
      scans: [
        {
          id: firstScanId,
          repositoryFullName: 'repo-user/project',
          defaultBranch: 'main',
          commitSha: 'a'.repeat(40),
          status: 'completed',
          createdAt: '2026-11-28T10:00:00.000Z',
          completedAt: '2026-11-28T10:00:05.000Z',
        },
      ],
      nextCursor: firstScanId,
    });
  });

  it('uses an owned scan cursor to fetch the next history page', async () => {
    const cursorId = 'c'.repeat(24);
    const cursorDate = new Date('2026-11-28T10:00:00.000Z');
    const cursorQuery = createQuery({ _id: cursorId, createdAt: cursorDate });
    const historyQuery = createQuery([]);
    findOneMock.mockReturnValue(cursorQuery);
    findMock.mockReturnValue(historyQuery);

    const response = await authenticatedRequest(
      `/?limit=2&cursor=${cursorId}`,
    ).expect(200);

    expect(findOneMock).toHaveBeenCalledWith({
      _id: cursorId,
      userId: 'user-123',
    });
    expect(findMock).toHaveBeenCalledWith({
      userId: 'user-123',
      $or: [
        { createdAt: { $lt: cursorDate } },
        { createdAt: cursorDate, _id: { $lt: cursorId } },
      ],
    });
    expect(historyQuery.limit).toHaveBeenCalledWith(3);
    expect(response.body).toEqual({ scans: [], nextCursor: null });
  });

  it('rejects malformed scan IDs and history cursors before querying MongoDB', async () => {
    await authenticatedRequest('/not-a-scan-id').expect(400);
    await authenticatedRequest('/?limit=51').expect(400);
    await authenticatedRequest('/?cursor=not-a-scan-id').expect(400);

    expect(findMock).not.toHaveBeenCalled();
    expect(findOneMock).not.toHaveBeenCalled();
  });

  it('returns findings only when the scan belongs to the signed-in user', async () => {
    const scanId = 'd'.repeat(24);
    const query = createQuery(
      createScan(scanId, {
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
        userId: 'private-user-id',
      }),
    );
    findOneMock.mockReturnValue(query);

    const response = await authenticatedRequest(`/${scanId}`).expect(200);

    expect(findOneMock).toHaveBeenCalledWith({
      _id: scanId,
      userId: 'user-123',
    });
    expect(response.body.scan).toMatchObject({
      id: scanId,
      repositoryFullName: 'repo-user/project',
      findings: [
        {
          tool: 'semgrep',
          ruleId: 'repoguard.javascript.dynamic-code-execution',
          severity: 'high',
          filePath: 'src/index.js',
          startLine: 3,
          endLine: 3,
        },
      ],
    });
    expect(response.body.scan).not.toHaveProperty('userId');
    expect(response.headers['cache-control']).toBe('private, no-store');
  });

  it('returns the same not-found response for scans owned by another user', async () => {
    findOneMock.mockReturnValue(createQuery(null));

    const response = await authenticatedRequest(`/${'e'.repeat(24)}`).expect(404);

    expect(response.body).toEqual({ error: 'Scan was not found.' });
    expect(findOneMock).toHaveBeenCalledWith({
      _id: 'e'.repeat(24),
      userId: 'user-123',
    });
  });

  it('rejects a history cursor that does not identify the user’s scan', async () => {
    const cursorId = 'f'.repeat(24);
    findOneMock.mockReturnValue(createQuery(null));

    const response = await authenticatedRequest(`/?cursor=${cursorId}`).expect(400);

    expect(response.body).toEqual({ error: 'Scan history cursor is invalid.' });
    expect(findMock).not.toHaveBeenCalled();
  });
});
