import { describe, expect, it } from '@jest/globals';
import request from 'supertest';
import { app } from './server.js';

const clientOrigin = process.env.CLIENT_ORIGIN ?? 'http://localhost:5173';

describe('API foundation', () => {
  it('reports API health', async () => {
    const response = await request(app)
      .get('/api/health')
      .expect('Content-Type', /json/)
      .expect(200);

    expect(response.body).toEqual({ status: 'ok' });
  });

  it('sets security headers', async () => {
    const response = await request(app).get('/api/health').expect(200);

    expect(response.headers['x-content-type-options']).toBe('nosniff');
    expect(response.headers['x-powered-by']).toBeUndefined();
  });

  it('allows the configured frontend origin', async () => {
    const response = await request(app)
      .get('/api/health')
      .set('Origin', clientOrigin)
      .expect(200);

    expect(response.headers['access-control-allow-origin']).toBe(clientOrigin);
    expect(response.headers['access-control-allow-credentials']).toBe('true');
  });

  it('does not grant CORS access to an unconfigured origin', async () => {
    const response = await request(app)
      .get('/api/health')
      .set('Origin', 'https://untrusted.example')
      .expect(200);

    expect(response.headers['access-control-allow-origin']).toBeUndefined();
  });

  it('returns a generic 404 response for unknown routes', async () => {
    const response = await request(app).get('/api/unknown').expect(404);

    expect(response.body).toEqual({ error: 'Not found' });
  });

  it('does not expose parser details for malformed JSON', async () => {
    const response = await request(app)
      .post('/api/health')
      .set('Content-Type', 'application/json')
      .send('{invalid')
      .expect(400);

    expect(response.body).toEqual({ error: 'Invalid request' });
  });
});
