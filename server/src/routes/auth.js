import { Octokit } from '@octokit/rest';
import { Router } from 'express';
import User from '../models/User.js';
import { createOAuthState, isValidOAuthState } from '../auth/oauthState.js';
import { createSessionToken } from '../auth/sessionToken.js';
import { loadServerEnvironment } from '../config/environment.js';

const router = Router();
const OAUTH_STATE_COOKIE = 'repoguard_oauth_state';
const SESSION_COOKIE = 'repoguard_session';
const OAUTH_STATE_TTL_MS = 10 * 60 * 1000;
const SESSION_TTL_MS = 60 * 60 * 1000;
const OAUTH_STATE_COOKIE_PATH = '/api/auth/github';

function requiredEnvironmentValue(name) {
  const value = process.env[name]?.trim();

  if (!value) {
    throw new Error(`${name} is required for GitHub authentication.`);
  }

  return value;
}

function getOAuthConfiguration(includeSecret = false) {
  const { clientOrigin, nodeEnv } = loadServerEnvironment();
  const callbackUrl = requiredEnvironmentValue('GITHUB_CALLBACK_URL');
  let parsedCallbackUrl;

  try {
    parsedCallbackUrl = new URL(callbackUrl);
  } catch {
    throw new Error('GITHUB_CALLBACK_URL must be a valid HTTP(S) URL.');
  }

  if (
    !['http:', 'https:'].includes(parsedCallbackUrl.protocol) ||
    parsedCallbackUrl.username ||
    parsedCallbackUrl.password ||
    parsedCallbackUrl.search ||
    parsedCallbackUrl.hash ||
    (nodeEnv === 'production' && parsedCallbackUrl.protocol !== 'https:')
  ) {
    throw new Error('GITHUB_CALLBACK_URL must be a secure callback URL.');
  }

  const configuration = {
    clientId: requiredEnvironmentValue('GITHUB_CLIENT_ID'),
    callbackUrl: parsedCallbackUrl.toString(),
    clientOrigin,
    secureCookies: nodeEnv === 'production',
  };

  if (includeSecret) {
    configuration.clientSecret = requiredEnvironmentValue(
      'GITHUB_CLIENT_SECRET',
    );
  }

  return configuration;
}

function readCookie(request, name) {
  const cookieHeader = request.get('cookie');

  if (typeof cookieHeader !== 'string') {
    return null;
  }

  for (const cookie of cookieHeader.split(';')) {
    const separator = cookie.indexOf('=');

    if (separator < 0 || cookie.slice(0, separator).trim() !== name) {
      continue;
    }

    return cookie.slice(separator + 1).trim();
  }

  return null;
}

function clearOAuthStateCookie(response, secure) {
  response.clearCookie(OAUTH_STATE_COOKIE, {
    httpOnly: true,
    path: OAUTH_STATE_COOKIE_PATH,
    sameSite: 'lax',
    secure,
  });
}

function getHttpsAvatarUrl(value) {
  if (typeof value !== 'string') {
    return '';
  }

  try {
    return new URL(value).protocol === 'https:' ? value : '';
  } catch {
    return '';
  }
}

router.get('/github', (request, response, next) => {
  try {
    const { callbackUrl, clientId, secureCookies } = getOAuthConfiguration();
    const state = createOAuthState();
    const authorizationUrl = new URL(
      'https://github.com/login/oauth/authorize',
    );

    authorizationUrl.searchParams.set('client_id', clientId);
    authorizationUrl.searchParams.set('redirect_uri', callbackUrl);
    authorizationUrl.searchParams.set('scope', 'read:user');
    authorizationUrl.searchParams.set('state', state);

    response.set('Cache-Control', 'no-store');
    response.cookie(OAUTH_STATE_COOKIE, state, {
      httpOnly: true,
      maxAge: OAUTH_STATE_TTL_MS,
      path: OAUTH_STATE_COOKIE_PATH,
      sameSite: 'lax',
      secure: secureCookies,
    });

    return response.redirect(302, authorizationUrl.toString());
  } catch (error) {
    return next(error);
  }
});

router.get('/github/callback', async (request, response, next) => {
  response.set('Cache-Control', 'no-store');
  const stateCookie = readCookie(request, OAUTH_STATE_COOKIE);
  const stateQuery = request.query.state;
  const { secureCookies } = loadServerEnvironment();

  clearOAuthStateCookie(response, secureCookies);

  if (!isValidOAuthState(stateQuery, stateCookie)) {
    return response.status(400).json({ error: 'OAuth state validation failed.' });
  }

  if (
    request.query.error ||
    typeof request.query.code !== 'string' ||
    request.query.code.trim() === ''
  ) {
    return response.status(400).json({ error: 'GitHub authorization was not completed.' });
  }

  try {
    const {
      callbackUrl,
      clientId,
      clientOrigin,
      clientSecret,
      secureCookies: useSecureCookies,
    } = getOAuthConfiguration(true);
    const tokenResponse = await fetch(
      'https://github.com/login/oauth/access_token',
      {
        method: 'POST',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          client_id: clientId,
          client_secret: clientSecret,
          code: request.query.code,
          redirect_uri: callbackUrl,
        }),
        signal: AbortSignal.timeout(10_000),
      },
    );

    if (!tokenResponse.ok) {
      throw new Error('GitHub token exchange failed.');
    }

    const tokenData = await tokenResponse.json();

    if (typeof tokenData.access_token !== 'string' || tokenData.error) {
      throw new Error('GitHub token exchange failed.');
    }

    const grantedScopes =
      typeof tokenData.scope === 'string'
        ? tokenData.scope.split(',').map((scope) => scope.trim())
        : [];

    if (!grantedScopes.includes('read:user') && !grantedScopes.includes('user')) {
      return response.status(403).json({
        error: 'GitHub profile access was not granted.',
      });
    }

    const octokit = new Octokit({ auth: tokenData.access_token });
    const { data: profile } = await octokit.users.getAuthenticated();

    if (
      !Number.isSafeInteger(profile.id) ||
      profile.id < 1 ||
      typeof profile.login !== 'string'
    ) {
      throw new Error('GitHub returned an invalid user profile.');
    }

    const user = await User.findOneAndUpdate(
      { githubId: String(profile.id) },
      {
        $set: {
          username: profile.login,
          displayName: typeof profile.name === 'string' ? profile.name : '',
          avatarUrl: getHttpsAvatarUrl(profile.avatar_url),
        },
      },
      {
        new: true,
        runValidators: true,
        setDefaultsOnInsert: true,
        upsert: true,
      },
    );

    if (!user) {
      throw new Error('GitHub account could not be saved.');
    }

    const sessionToken = createSessionToken(user._id.toString());

    response.cookie(SESSION_COOKIE, sessionToken, {
      httpOnly: true,
      maxAge: SESSION_TTL_MS,
      path: '/api',
      sameSite: 'lax',
      secure: useSecureCookies,
    });

    return response.redirect(
      303,
      new URL('/?auth=connected', clientOrigin).toString(),
    );
  } catch (error) {
    return next(error);
  }
});

export default router;
