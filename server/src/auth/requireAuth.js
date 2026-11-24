import { verifySessionToken } from './sessionToken.js';
import { loadServerEnvironment } from '../config/environment.js';

const AUTHENTICATION_CHALLENGE = 'Bearer realm="RepoGuard API"';
const JWT_CONFIGURATION_ERROR = 'JWT_SECRET must contain at least 32 bytes.';
const SESSION_COOKIE = 'repoguard_session';
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

function sendUnauthorized(response, message) {
  return response
    .set('WWW-Authenticate', AUTHENTICATION_CHALLENGE)
    .status(401)
    .json({ error: message });
}

function sendForbidden(response) {
  return response.status(403).json({ error: 'Cross-origin request blocked.' });
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

export function requireAuth(request, response, next) {
  const authorizationHeader = request.get('authorization');
  const bearerMatch =
    typeof authorizationHeader === 'string'
      ? /^Bearer\s+([^\s]+)$/i.exec(authorizationHeader)
      : null;
  const usesBearerToken = Boolean(bearerMatch);
  const sessionToken = usesBearerToken
    ? bearerMatch[1]
    : typeof authorizationHeader === 'string' && authorizationHeader.length > 0
      ? null
      : readCookie(request, SESSION_COOKIE);

  if (!sessionToken) {
    return sendUnauthorized(response, 'Authentication required.');
  }

  if (
    !usesBearerToken &&
    !SAFE_METHODS.has(request.method.toUpperCase()) &&
    request.get('origin') !== loadServerEnvironment().clientOrigin
  ) {
    return sendForbidden(response);
  }

  try {
    request.auth = verifySessionToken(sessionToken);
  } catch (error) {
    if (error.message === JWT_CONFIGURATION_ERROR) {
      return next(error);
    }

    return sendUnauthorized(response, 'Invalid or expired session.');
  }

  return next();
}
