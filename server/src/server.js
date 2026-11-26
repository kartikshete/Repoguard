import 'dotenv/config';

import cors from 'cors';
import express from 'express';
import { rateLimit } from 'express-rate-limit';
import helmet from 'helmet';
import { createServer } from 'node:http';
import { pathToFileURL } from 'node:url';
import { connectToDatabase } from './config/database.js';
import { loadServerEnvironment } from './config/environment.js';
import authRouter from './routes/auth.js';
import repositoriesRouter from './routes/repositories.js';

const { port, clientOrigin } = loadServerEnvironment();

const app = express();

app.disable('x-powered-by');
app.use(helmet());
app.use(
  cors({
    origin: clientOrigin,
    credentials: true,
  }),
);
app.use(
  '/api',
  rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 100,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
  }),
);
app.use(express.json({ limit: '100kb' }));
app.use('/api/auth', authRouter);
app.use('/api/repositories', repositoriesRouter);

app.get('/api/health', (request, response) => {
  response.status(200).json({ status: 'ok' });
});

app.use((request, response) => {
  response.status(404).json({ error: 'Not found' });
});

app.use((error, request, response, next) => {
  if (response.headersSent) {
    return next(error);
  }

  const statusCode =
    Number.isInteger(error.status) && error.status >= 400 && error.status < 500
      ? error.status
      : 500;

  response.status(statusCode).json({
    error: statusCode === 500 ? 'Internal server error' : 'Invalid request',
  });
});

const server = createServer(app);
const isMainModule =
  process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;

if (isMainModule) {
  try {
    await connectToDatabase();
    server.listen(port, () => {
      console.log(`RepoGuard API listening on port ${port}.`);
    });
  } catch (error) {
    console.error(`RepoGuard API startup failed: ${error.message}`);
    process.exitCode = 1;
  }
}

export { app, server };
