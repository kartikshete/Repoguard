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
import request from 'supertest';
import { createOAuthState } from '../auth/oauthState.js';
import { createSessionToken } from '../auth/sessionToken.js';

const findByIdMock = jest.fn();
jest.unstable_mockModule('../models/User.js', () => ({
  default: {
    findById: findByIdMock,
    findOneAndUpdate: jest.fn(),
  },
}));

const environmentKeys = [
  'CLIENT_ORIGIN',
  'GITHUB_CALLBACK_URL',
  'GITHUB_CLIENT_ID',
  'JWT_SECRET',
  'PORT',
];
const originalEnvironment = Object.fromEntries(
  environmentKeys.map((key) => [key, process.env[key]]),
);
const testSecret = randomBytes(32).toString('base64url');

let app;

beforeAll(async () => {
  process.env.CLIENT_ORIGIN = 'http://localhost:5173';
  process.env.GITHUB_CALLBACK_URL =
    'http://localhost:5000/api/auth/github/callback';
  process.env.GITHUB_CLIENT_ID = 'repoguard-test-client';
  process.env.JWT_SECRET = testSecret;
  process.env.PORT = '5000';

  ({ app } = await import('../server.js'));
});

afterAll(() => {
  for (const [key, value] of Object.entries(originalEnvironment)) {
    if (value === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = value;
    }
  }
});

beforeEach(() => {
  findByIdMock.mockReset();
});

describe('GitHub OAuth routes', () => {
  it('redirects with a minimal scope and an HttpOnly state cookie', async () => {
    const response = await request(app).get('/api/auth/github').expect(302);
    const authorizationUrl = new URL(response.headers.location);
    const setCookies = response.headers['set-cookie'];
    const stateCookie = setCookies.find((cookie) =>
      cookie.startsWith('repoguard_oauth_state='),
    );
    const cookieState = stateCookie?.match(
      /^repoguard_oauth_state=([^;]+)/,
    )?.[1];

    expect(authorizationUrl.origin).toBe('https://github.com');
    expect(authorizationUrl.pathname).toBe('/login/oauth/authorize');
    expect(authorizationUrl.searchParams.get('client_id')).toBe(
      'repoguard-test-client',
    );
    expect(authorizationUrl.searchParams.get('redirect_uri')).toBe(
      'http://localhost:5000/api/auth/github/callback',
    );
    expect(authorizationUrl.searchParams.get('scope')).toBe('read:user');
    expect(authorizationUrl.searchParams.get('state')).toBe(cookieState);
    expect(stateCookie).toMatch(/HttpOnly/i);
    expect(stateCookie).toMatch(/SameSite=Lax/i);
    expect(stateCookie).toMatch(/Path=\/api\/auth\/github/i);
    expect(response.headers['cache-control']).toBe('no-store');
  });

  it('rejects a callback with mismatched state before token exchange', async () => {
    const cookieState = createOAuthState();
    const queryState = createOAuthState();
    const response = await request(app)
      .get('/api/auth/github/callback')
      .set('Cookie', `repoguard_oauth_state=${cookieState}`)
      .query({ code: 'temporary-code', state: queryState })
      .expect(400);

    expect(response.body).toEqual({ error: 'OAuth state validation failed.' });
    expect(response.headers['set-cookie'].some((cookie) =>
      /Max-Age=0/i.test(cookie),
    )).toBe(true);
  });

  it('handles authorization denial without exchanging a code', async () => {
    const state = createOAuthState();
    const response = await request(app)
      .get('/api/auth/github/callback')
      .set('Cookie', `repoguard_oauth_state=${state}`)
      .query({ error: 'access_denied', state })
      .expect(400);

    expect(response.body).toEqual({
      error: 'GitHub authorization was not completed.',
    });
    expect(response.headers['set-cookie'].some((cookie) =>
      /Max-Age=0/i.test(cookie),
    )).toBe(true);
  });

  it('requires authentication before loading the current user', async () => {
    const response = await request(app).get('/api/auth/me').expect(401);

    expect(response.body).toEqual({ error: 'Authentication required.' });
    expect(findByIdMock).not.toHaveBeenCalled();
  });

  it('returns only the authenticated user profile fields', async () => {
    const user = {
      _id: 'user-123',
      username: 'repoguard-user',
      displayName: 'Repo Guard User',
      avatarUrl: 'https://avatars.example/user.png',
    };
    const leanQuery = {
      lean: jest.fn().mockResolvedValue(user),
    };
    const selectQuery = {
      select: jest.fn().mockReturnValue(leanQuery),
    };
    findByIdMock.mockReturnValue(selectQuery);
    const sessionToken = createSessionToken('user-123', testSecret);
    const response = await request(app)
      .get('/api/auth/me')
      .set('Cookie', `repoguard_session=${sessionToken}`)
      .expect(200);

    expect(findByIdMock).toHaveBeenCalledWith('user-123');
    expect(selectQuery.select).toHaveBeenCalledWith(
      '_id username displayName avatarUrl',
    );
    expect(response.body).toEqual({
      user: {
        id: 'user-123',
        username: 'repoguard-user',
        displayName: 'Repo Guard User',
        avatarUrl: 'https://avatars.example/user.png',
      },
    });
  });

  it('clears the session cookie for a same-origin logout', async () => {
    const response = await request(app)
      .post('/api/auth/logout')
      .set('Origin', 'http://localhost:5173')
      .set('Cookie', 'repoguard_session=expired-session')
      .expect(204);
    const clearedSessionCookie = response.headers['set-cookie'].find((cookie) =>
      cookie.startsWith('repoguard_session='),
    );

    expect(clearedSessionCookie).toMatch(/Max-Age=0/i);
    expect(clearedSessionCookie).toMatch(/HttpOnly/i);
    expect(clearedSessionCookie).toMatch(/Path=\/api/i);
    expect(response.headers['cache-control']).toBe('no-store');
  });

  it('rejects logout requests from an untrusted Origin', async () => {
    const response = await request(app)
      .post('/api/auth/logout')
      .set('Origin', 'https://untrusted.example')
      .set('Cookie', 'repoguard_session=expired-session')
      .expect(403);

    expect(response.body).toEqual({ error: 'Cross-origin request blocked.' });
    expect(response.headers['set-cookie']).toBeUndefined();
  });
});
