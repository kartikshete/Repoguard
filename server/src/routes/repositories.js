import { rateLimit } from 'express-rate-limit';
import { Router } from 'express';
import { requireAuth } from '../auth/requireAuth.js';
import User from '../models/User.js';
import {
  createRepositoryScan,
  RepositoryScanServiceError,
} from '../services/repositoryScanService.js';

const router = Router();
const GITHUB_API_VERSION = '2026-03-10';
const GITHUB_REPOSITORY_LIMIT = 100;
const GITHUB_NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_.-]*$/;
const SCAN_REPOSITORY_NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$/;

const repositoryListRateLimit = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 50,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Repository list rate limit exceeded.' },
});

const repositoryScanRateLimit = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 5,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Repository scan rate limit exceeded.' },
});

function toRepositorySummary(repository) {
  if (
    !repository ||
    typeof repository !== 'object' ||
    repository.private !== false ||
    !Number.isSafeInteger(repository.id) ||
    repository.id < 1 ||
    typeof repository.name !== 'string' ||
    typeof repository.full_name !== 'string'
  ) {
    return null;
  }

  const [owner, name, ...extraSegments] = repository.full_name.split('/');

  if (
    extraSegments.length > 0 ||
    name !== repository.name ||
    !GITHUB_NAME_PATTERN.test(owner) ||
    !GITHUB_NAME_PATTERN.test(name)
  ) {
    return null;
  }

  return {
    id: repository.id,
    name,
    fullName: `${owner}/${name}`,
    description:
      typeof repository.description === 'string' ? repository.description : null,
    language:
      typeof repository.language === 'string' ? repository.language : null,
    defaultBranch:
      typeof repository.default_branch === 'string'
        ? repository.default_branch
        : null,
    updatedAt:
      typeof repository.updated_at === 'string' ? repository.updated_at : null,
    archived: repository.archived === true,
    fork: repository.fork === true,
    htmlUrl: `https://github.com/${owner}/${name}`,
  };
}

router.get(
  '/',
  requireAuth,
  repositoryListRateLimit,
  async (request, response, next) => {
    response.set('Cache-Control', 'private, no-store');

    try {
      const user = await User.findById(request.auth.userId)
        .select('username')
        .lean();

      if (!user) {
        return response
          .status(401)
          .json({ error: 'Session is no longer valid.' });
      }

      const repositoriesUrl = new URL(
        `https://api.github.com/users/${encodeURIComponent(user.username)}/repos`,
      );
      repositoriesUrl.searchParams.set('type', 'owner');
      repositoriesUrl.searchParams.set('sort', 'updated');
      repositoriesUrl.searchParams.set('direction', 'desc');
      repositoriesUrl.searchParams.set(
        'per_page',
        String(GITHUB_REPOSITORY_LIMIT),
      );

      let githubResponse;

      try {
        githubResponse = await fetch(repositoriesUrl, {
          headers: {
            Accept: 'application/vnd.github+json',
            'User-Agent': 'RepoGuard',
            'X-GitHub-Api-Version': GITHUB_API_VERSION,
          },
          signal: AbortSignal.timeout(10_000),
        });
      } catch {
        return response
          .status(502)
          .json({ error: 'GitHub repositories could not be loaded.' });
      }

      if (!githubResponse.ok) {
        return response
          .status(502)
          .json({ error: 'GitHub repositories could not be loaded.' });
      }

      let githubRepositories;

      try {
        githubRepositories = await githubResponse.json();
      } catch {
        return response
          .status(502)
          .json({ error: 'GitHub repositories could not be loaded.' });
      }

      if (!Array.isArray(githubRepositories)) {
        return response
          .status(502)
          .json({ error: 'GitHub repositories could not be loaded.' });
      }

      const repositories = githubRepositories
        .map(toRepositorySummary)
        .filter(Boolean);
      const hasMore = /\brel="next"/.test(
        githubResponse.headers.get('link') ?? '',
      );

      return response.status(200).json({ repositories, hasMore });
    } catch (error) {
      return next(error);
    }
  },
);

function toScanResponse(scan) {
  return {
    id: scan._id.toString(),
    repositoryFullName: scan.repositoryFullName,
    defaultBranch: scan.defaultBranch,
    commitSha: scan.commitSha,
    status: scan.status,
    findings: scan.findings.map((finding) => ({
      tool: finding.tool,
      ruleId: finding.ruleId,
      severity: finding.severity,
      title: finding.title,
      message: finding.message,
      filePath: finding.filePath,
      startLine: finding.startLine,
      endLine: finding.endLine,
      referenceUrl: finding.referenceUrl,
    })),
    createdAt: scan.createdAt,
    completedAt: scan.completedAt,
  };
}

router.post(
  '/:repositoryName/scans',
  requireAuth,
  repositoryScanRateLimit,
  async (request, response, next) => {
    response.set('Cache-Control', 'private, no-store');
    const body = request.body;

    if (
      typeof request.params.repositoryName !== 'string' ||
      !SCAN_REPOSITORY_NAME_PATTERN.test(request.params.repositoryName) ||
      !body ||
      typeof body !== 'object' ||
      Array.isArray(body) ||
      Object.keys(body).length !== 1 ||
      !Number.isSafeInteger(body.repositoryId) ||
      body.repositoryId < 1
    ) {
      return response.status(400).json({ error: 'Repository scan request is invalid.' });
    }

    try {
      const user = await User.findById(request.auth.userId)
        .select('username')
        .lean();

      if (!user) {
        return response
          .status(401)
          .json({ error: 'Session is no longer valid.' });
      }

      const scan = await createRepositoryScan({
        userId: request.auth.userId,
        githubUsername: user.username,
        repositoryName: request.params.repositoryName,
        githubRepositoryId: body.repositoryId,
      });

      return response.status(201).json({ scan: toScanResponse(scan) });
    } catch (error) {
      if (error instanceof RepositoryScanServiceError) {
        return response.status(error.status).json({
          error: error.message,
          ...(error.scanId ? { scanId: error.scanId } : {}),
        });
      }

      return next(error);
    }
  },
);

export default router;
