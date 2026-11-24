import {
  afterAll,
  beforeAll,
  describe,
  expect,
  it,
} from '@jest/globals';
import request from 'supertest';
import { createOAuthState } from '../auth/oauthState.js';

const environmentKeys = [
  'CLIENT_ORIGIN',
  'GITHUB_CALLBACK_URL',
  'GITHUB_CLIENT_ID',
  'PORT',
];
const originalEnvironment = Object.fromEntries(
  environmentKeys.map((key) => [key, process.env[key]]),
);

let app;

beforeAll(async () => {
  process.env.CLIENT_ORIGIN = 'http://localhost:5173';
  process.env.GITHUB_CALLBACK_URL =
    'http://localhost:5000/api/auth/github/callback';
  process.env.GITHUB_CLIENT_ID = 'repoguard-test-client';
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
});
