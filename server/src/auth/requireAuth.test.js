import { randomBytes } from 'node:crypto';
import {
  afterAll,
  beforeEach,
  describe,
  expect,
  it,
  jest,
} from '@jest/globals';
import { createSessionToken } from './sessionToken.js';
import { requireAuth } from './requireAuth.js';

const testSecret = randomBytes(32).toString('base64url');
const originalJwtSecret = process.env.JWT_SECRET;
const originalClientOrigin = process.env.CLIENT_ORIGIN;

function createResponse() {
  const response = {};
  response.set = jest.fn(() => response);
  response.status = jest.fn(() => response);
  response.json = jest.fn(() => response);
  return response;
}

function createRequest(authorizationHeader, options = {}) {
  const headers = {
    authorization: authorizationHeader,
    cookie: options.cookie,
    origin: options.origin,
  };

  return {
    method: options.method ?? 'GET',
    get: jest.fn((name) => headers[name]),
  };
}

describe('requireAuth middleware', () => {
  beforeEach(() => {
    process.env.JWT_SECRET = testSecret;
    process.env.CLIENT_ORIGIN = 'http://localhost:5173';
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
  });

  it('rejects a request without a bearer token', () => {
    const request = createRequest(undefined);
    const response = createResponse();
    const next = jest.fn();

    requireAuth(request, response, next);

    expect(response.set).toHaveBeenCalledWith(
      'WWW-Authenticate',
      'Bearer realm="RepoGuard API"',
    );
    expect(response.status).toHaveBeenCalledWith(401);
    expect(response.json).toHaveBeenCalledWith({
      error: 'Authentication required.',
    });
    expect(next).not.toHaveBeenCalled();
  });

  it('rejects an invalid token without exposing its value', () => {
    const token = 'not-a-valid-token';
    const request = createRequest(`Bearer ${token}`);
    const response = createResponse();
    const next = jest.fn();

    requireAuth(request, response, next);

    expect(response.status).toHaveBeenCalledWith(401);
    expect(response.json).toHaveBeenCalledWith({
      error: 'Invalid or expired session.',
    });
    expect(next).not.toHaveBeenCalled();
  });

  it('attaches verified user identity and continues', () => {
    const token = createSessionToken('user-123', testSecret);
    const request = createRequest(`bearer ${token}`);
    const response = createResponse();
    const next = jest.fn();

    requireAuth(request, response, next);

    expect(request.auth).toEqual({ userId: 'user-123' });
    expect(next).toHaveBeenCalledTimes(1);
    expect(response.status).not.toHaveBeenCalled();
  });

  it('authenticates a valid HttpOnly session cookie', () => {
    const token = createSessionToken('user-456', testSecret);
    const request = createRequest(undefined, {
      cookie: `repoguard_session=${token}`,
    });
    const response = createResponse();
    const next = jest.fn();

    requireAuth(request, response, next);

    expect(request.auth).toEqual({ userId: 'user-456' });
    expect(next).toHaveBeenCalledTimes(1);
  });

  it('rejects cross-origin cookie-authenticated POST requests', () => {
    const token = createSessionToken('user-456', testSecret);
    const request = createRequest(undefined, {
      cookie: `repoguard_session=${token}`,
      method: 'POST',
      origin: 'https://untrusted.example',
    });
    const response = createResponse();
    const next = jest.fn();

    requireAuth(request, response, next);

    expect(response.status).toHaveBeenCalledWith(403);
    expect(response.json).toHaveBeenCalledWith({
      error: 'Cross-origin request blocked.',
    });
    expect(next).not.toHaveBeenCalled();
  });

  it('allows same-origin cookie-authenticated POST requests', () => {
    const token = createSessionToken('user-456', testSecret);
    const request = createRequest(undefined, {
      cookie: `repoguard_session=${token}`,
      method: 'POST',
      origin: 'http://localhost:5173',
    });
    const response = createResponse();
    const next = jest.fn();

    requireAuth(request, response, next);

    expect(request.auth).toEqual({ userId: 'user-456' });
    expect(next).toHaveBeenCalledTimes(1);
  });

  it('forwards JWT configuration errors to Express', () => {
    const token = createSessionToken('user-123', testSecret);
    const request = createRequest(`Bearer ${token}`);
    const response = createResponse();
    const next = jest.fn();

    delete process.env.JWT_SECRET;
    requireAuth(request, response, next);

    expect(next).toHaveBeenCalledWith(expect.any(Error));
    expect(response.status).not.toHaveBeenCalled();
  });
});
