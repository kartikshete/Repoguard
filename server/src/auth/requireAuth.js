import { verifySessionToken } from './sessionToken.js';

const AUTHENTICATION_CHALLENGE = 'Bearer realm="RepoGuard API"';
const JWT_CONFIGURATION_ERROR = 'JWT_SECRET must contain at least 32 bytes.';

function sendUnauthorized(response, message) {
  return response
    .set('WWW-Authenticate', AUTHENTICATION_CHALLENGE)
    .status(401)
    .json({ error: message });
}

export function requireAuth(request, response, next) {
  const authorizationHeader = request.get('authorization');
  const bearerMatch =
    typeof authorizationHeader === 'string'
      ? /^Bearer\s+([^\s]+)$/i.exec(authorizationHeader)
      : null;

  if (!bearerMatch) {
    return sendUnauthorized(response, 'Authentication required.');
  }

  try {
    request.auth = verifySessionToken(bearerMatch[1]);
  } catch (error) {
    if (error.message === JWT_CONFIGURATION_ERROR) {
      return next(error);
    }

    return sendUnauthorized(response, 'Invalid or expired session.');
  }

  return next();
}
