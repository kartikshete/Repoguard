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

function createResponse() {
  const response = {};
  response.set = jest.fn(() => response);
  response.status = jest.fn(() => response);
  response.json = jest.fn(() => response);
  return response;
}

function createRequest(authorizationHeader) {
  return {
    get: jest.fn(() => authorizationHeader),
  };
}

describe('requireAuth middleware', () => {
  beforeEach(() => {
    process.env.JWT_SECRET = testSecret;
  });

  afterAll(() => {
    if (originalJwtSecret === undefined) {
      delete process.env.JWT_SECRET;
    } else {
      process.env.JWT_SECRET = originalJwtSecret;
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
