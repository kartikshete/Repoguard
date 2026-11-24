const DEFAULT_PORT = 5000;
const DEFAULT_CLIENT_ORIGIN = 'http://localhost:5173';

function parsePort(value) {
  const port = Number(value);

  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error('PORT must be an integer between 1 and 65535.');
  }

  return port;
}

function parseClientOrigin(value) {
  let parsedOrigin;

  try {
    parsedOrigin = new URL(value);
  } catch {
    throw new Error('CLIENT_ORIGIN must be a valid HTTP(S) origin.');
  }

  if (
    !['http:', 'https:'].includes(parsedOrigin.protocol) ||
    parsedOrigin.origin !== value
  ) {
    throw new Error('CLIENT_ORIGIN must be an HTTP(S) origin without a path.');
  }

  return parsedOrigin.origin;
}

export function loadServerEnvironment(environment = process.env) {
  return Object.freeze({
    nodeEnv: environment.NODE_ENV ?? 'development',
    port: parsePort(environment.PORT ?? DEFAULT_PORT),
    clientOrigin: parseClientOrigin(
      environment.CLIENT_ORIGIN ?? DEFAULT_CLIENT_ORIGIN,
    ),
  });
}
