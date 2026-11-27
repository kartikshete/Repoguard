import Scan from '../models/Scan.js';
import { fetchPublicRepositorySnapshot } from './publicRepositorySnapshot.js';
import { runSemgrepScan } from './semgrepRunner.js';

const GITHUB_API_VERSION = '2026-03-10';
const GITHUB_API_ROOT = new URL('https://api.github.com/');
const GITHUB_USERNAME_PATTERN = /^[A-Za-z0-9](?:-?[A-Za-z0-9])*$/;
const REPOSITORY_NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$/;
const REPOSITORY_FULL_NAME_PATTERN =
  /^[A-Za-z0-9][A-Za-z0-9_.-]{0,38}\/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$/;
const COMMIT_SHA_PATTERN = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/i;
const MAX_FINDINGS_PER_SCAN = 1000;
const SEMGREP_SEVERITY = new Map([
  ['ERROR', 'high'],
  ['WARNING', 'medium'],
  ['INFO', 'info'],
]);

export class RepositoryScanServiceError extends Error {
  constructor(message, status = 502, scanId = null) {
    super(message);
    this.name = 'RepositoryScanServiceError';
    this.status = status;
    this.scanId = scanId;
  }
}

function validateRequest({
  userId,
  githubUsername,
  repositoryName,
  githubRepositoryId,
}) {
  if (
    typeof userId !== 'string' ||
    userId.length === 0 ||
    userId.length > 128 ||
    typeof githubUsername !== 'string' ||
    !GITHUB_USERNAME_PATTERN.test(githubUsername) ||
    typeof repositoryName !== 'string' ||
    !REPOSITORY_NAME_PATTERN.test(repositoryName) ||
    !Number.isSafeInteger(githubRepositoryId) ||
    githubRepositoryId < 1
  ) {
    throw new RepositoryScanServiceError('Repository scan request is invalid.', 400);
  }

  return { userId, githubUsername, repositoryName };
}

async function cancelResponseBody(response) {
  try {
    await response.body?.cancel();
  } catch {
    // Keep the safe GitHub API error that caused the response body to be discarded.
  }
}

async function fetchGithubJson(url, messages) {
  let response;

  try {
    response = await fetch(url, {
      headers: {
        Accept: 'application/vnd.github+json',
        'User-Agent': 'RepoGuard',
        'X-GitHub-Api-Version': GITHUB_API_VERSION,
      },
      signal: AbortSignal.timeout(10_000),
    });
  } catch (error) {
    const timedOut = error?.name === 'TimeoutError';
    throw new RepositoryScanServiceError(
      timedOut ? 'GitHub request timed out.' : messages.unavailable,
      timedOut ? 504 : 502,
    );
  }

  let responseUrl;

  try {
    responseUrl = new URL(response.url || url);
  } catch {
    await cancelResponseBody(response);
    throw new RepositoryScanServiceError(messages.unavailable, 502);
  }

  if (responseUrl.origin !== GITHUB_API_ROOT.origin) {
    await cancelResponseBody(response);
    throw new RepositoryScanServiceError(messages.unavailable, 502);
  }

  if (!response.ok) {
    await cancelResponseBody(response);
    const rateLimited = response.status === 403 || response.status === 429;
    const notFound = response.status === 404;

    throw new RepositoryScanServiceError(
      rateLimited
        ? 'GitHub API rate limit was reached.'
        : notFound
          ? messages.notFound
          : messages.unavailable,
      rateLimited ? 503 : notFound ? 404 : 502,
    );
  }

  try {
    return await response.json();
  } catch {
    throw new RepositoryScanServiceError(messages.unavailable, 502);
  }
}

async function getPublicRepository({ githubUsername, repositoryName, githubRepositoryId }) {
  const repositoryUrl = new URL(
    `repos/${encodeURIComponent(githubUsername)}/${encodeURIComponent(repositoryName)}`,
    GITHUB_API_ROOT,
  );
  const repository = await fetchGithubJson(repositoryUrl, {
    unavailable: 'GitHub repository details could not be loaded.',
    notFound: 'Public repository was not found.',
  });

  if (
    !repository ||
    repository.private !== false ||
    repository.id !== githubRepositoryId ||
    typeof repository.name !== 'string' ||
    repository.name.toLowerCase() !== repositoryName.toLowerCase() ||
    typeof repository.owner?.login !== 'string' ||
    repository.owner.login.toLowerCase() !== githubUsername.toLowerCase() ||
    typeof repository.full_name !== 'string' ||
    !REPOSITORY_FULL_NAME_PATTERN.test(repository.full_name) ||
    repository.full_name.split('/')[0].toLowerCase() !==
      githubUsername.toLowerCase() ||
    repository.full_name.split('/')[1].toLowerCase() !==
      repositoryName.toLowerCase() ||
    typeof repository.default_branch !== 'string' ||
    repository.default_branch.length === 0 ||
    repository.default_branch.length > 255 ||
    repository.default_branch.trim() !== repository.default_branch ||
    /[\u0000-\u001f\u007f]/.test(repository.default_branch)
  ) {
    throw new RepositoryScanServiceError('Public repository was not found.', 404);
  }

  return repository;
}

async function getDefaultBranchCommit(repository) {
  const [owner, name] = repository.full_name.split('/');
  const commitUrl = new URL(
    `repos/${encodeURIComponent(owner)}/${encodeURIComponent(name)}/commits/${encodeURIComponent(repository.default_branch)}`,
    GITHUB_API_ROOT,
  );
  const commit = await fetchGithubJson(commitUrl, {
    unavailable: 'Default-branch commit could not be loaded.',
    notFound: 'Repository has no commit on its default branch.',
  });

  if (typeof commit?.sha !== 'string' || !COMMIT_SHA_PATTERN.test(commit.sha)) {
    throw new RepositoryScanServiceError(
      'GitHub returned an invalid default-branch commit.',
      502,
    );
  }

  return commit.sha.toLowerCase();
}

function toScanFinding(finding) {
  const ruleId = finding?.ruleId;
  const title =
    typeof ruleId === 'string'
      ? ruleId
          .split('.')
          .at(-1)
          .replace(/[-_]+/g, ' ')
          .replace(/\b[a-z]/g, (letter) => letter.toUpperCase())
          .slice(0, 200)
      : '';

  if (
    typeof ruleId !== 'string' ||
    ruleId.length === 0 ||
    ruleId.length > 200 ||
    typeof finding.message !== 'string' ||
    finding.message.length === 0 ||
    finding.message.length > 5000 ||
    !SEMGREP_SEVERITY.has(finding.severity) ||
    typeof finding.location?.path !== 'string' ||
    finding.location.path.length > 1024
  ) {
    throw new RepositoryScanServiceError('Semgrep returned an invalid finding.', 502);
  }

  return {
    tool: 'semgrep',
    ruleId,
    severity: SEMGREP_SEVERITY.get(finding.severity),
    title: title || 'Security finding',
    message: finding.message,
    filePath: finding.location.path,
    startLine: finding.location.start?.line ?? null,
    endLine: finding.location.end?.line ?? null,
  };
}

function toSafeScanError(error, scanId) {
  if (error instanceof RepositoryScanServiceError) {
    error.scanId = scanId;
    return error;
  }

  if (error?.status === 413) {
    return new RepositoryScanServiceError(
      'Repository snapshot exceeds the supported scan limits.',
      413,
      scanId,
    );
  }

  if (error?.status === 503) {
    return new RepositoryScanServiceError(
      'Semgrep scanner is unavailable.',
      503,
      scanId,
    );
  }

  if (error?.status === 504) {
    return new RepositoryScanServiceError('Repository scan timed out.', 504, scanId);
  }

  return new RepositoryScanServiceError('Repository scan failed.', 502, scanId);
}

export async function createRepositoryScan(input) {
  const request = validateRequest(input ?? {});
  const repository = await getPublicRepository({
    ...request,
    githubRepositoryId: input.githubRepositoryId,
  });
  const commitSha = await getDefaultBranchCommit(repository);
  const scan = await Scan.create({
    userId: request.userId,
    githubRepositoryId: repository.id,
    repositoryFullName: repository.full_name,
    defaultBranch: repository.default_branch,
    commitSha,
    status: 'queued',
  });

  try {
    scan.status = 'running';
    await scan.save();

    const snapshot = await fetchPublicRepositorySnapshot({
      repositoryFullName: repository.full_name,
      commitSha,
    });
    const semgrepResult = await runSemgrepScan(snapshot);

    if (!semgrepResult.complete) {
      throw new RepositoryScanServiceError(
        'Scan could not analyze the complete repository snapshot.',
        502,
      );
    }

    if (semgrepResult.findings.length > MAX_FINDINGS_PER_SCAN) {
      throw new RepositoryScanServiceError(
        'Scan produced more findings than the storage limit.',
        502,
      );
    }

    scan.findings = semgrepResult.findings.map(toScanFinding);
    scan.status = 'completed';
    scan.completedAt = new Date();
    await scan.save();
    return scan;
  } catch (error) {
    scan.findings = [];
    scan.status = 'failed';
    scan.completedAt = new Date();

    try {
      await scan.save();
    } catch {
      throw new RepositoryScanServiceError(
        'Repository scan state could not be saved.',
        500,
        scan._id.toString(),
      );
    }

    throw toSafeScanError(error, scan._id.toString());
  }
}
