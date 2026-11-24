import { describe, expect, it } from '@jest/globals';
import { loadServerEnvironment } from './environment.js';

describe('loadServerEnvironment', () => {
  it('applies safe local defaults', () => {
    expect(loadServerEnvironment({})).toEqual({
      nodeEnv: 'development',
      port: 5000,
      clientOrigin: 'http://localhost:5173',
    });
  });

  it('accepts valid runtime overrides without returning secrets', () => {
    const config = loadServerEnvironment({
      NODE_ENV: 'test',
      PORT: '8080',
      CLIENT_ORIGIN: 'https://app.example',
      JWT_SECRET: 'never-copy-secrets-into-shared-config',
    });

    expect(config).toEqual({
      nodeEnv: 'test',
      port: 8080,
      clientOrigin: 'https://app.example',
    });
    expect(Object.keys(config)).toEqual(['nodeEnv', 'port', 'clientOrigin']);
    expect(Object.isFrozen(config)).toBe(true);
  });

  it.each(['0', '65536', 'not-a-port'])('rejects invalid port %s', (port) => {
    expect(() => loadServerEnvironment({ PORT: port })).toThrow(
      'PORT must be an integer between 1 and 65535.',
    );
  });

  it.each([
    'not-a-url',
    'ftp://app.example',
    'https://app.example/path',
  ])('rejects invalid client origin %s', (clientOrigin) => {
    expect(() => loadServerEnvironment({ CLIENT_ORIGIN: clientOrigin })).toThrow(
      'CLIENT_ORIGIN',
    );
  });
});
