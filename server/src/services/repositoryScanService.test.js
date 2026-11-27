import {
  afterAll,
  beforeEach,
  describe,
  expect,
  it,
  jest,
} from '@jest/globals';

const scanCreateMock = jest.fn();
const fetchSnapshotMock = jest.fn();
const runSemgrepScanMock = jest.fn();
const originalFetch = globalThis.fetch;

jest.unstable_mockModule('../models/Scan.js', () => ({
  default: { create: scanCreateMock },
}));
jest.unstable_mockModule('./publicRepositorySnapshot.js', () => ({
  fetchPublicRepositorySnapshot: fetchSnapshotMock,
}));
jest.unstable_mockModule('./semgrepRunner.js', () => ({
  runSemgrepScan: runSemgrepScanMock,
}));

const { createRepositoryScan, RepositoryScanServiceError } = await import(
  './repositoryScanService.js'
);

const requestInput = {
  userId: 'user-123',
  githubUsername: 'repo-user',
  repositoryName: 'project',
  githubRepositoryId: 42,
};
const commitSha = 'a'.repeat(40);

function githubRepository(overrides = {}) {
  return {
    id: 42,
    private: false,
    name: 'project',
    full_name: 'repo-user/project',
    default_branch: 'main',
    owner: { login: 'repo-user' },
    ...overrides,
  };
}

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function configureGitHubResponses(repository = githubRepository()) {
  globalThis.fetch
    .mockResolvedValueOnce(jsonResponse(repository))
    .mockResolvedValueOnce(jsonResponse({ sha: commitSha }));
}

function configureScanDocument() {
  const scan = {
    _id: { toString: () => 'scan-123' },
    status: 'queued',
    statusHistory: [],
    findings: [],
    completedAt: null,
    save: jest.fn().mockImplementation(async () => {
      scan.statusHistory.push(scan.status);
    }),
  };

  scanCreateMock.mockResolvedValue(scan);
  return scan;
}

beforeEach(() => {
  scanCreateMock.mockReset();
  fetchSnapshotMock.mockReset();
  runSemgrepScanMock.mockReset();
  globalThis.fetch = jest.fn();
});

afterAll(() => {
  globalThis.fetch = originalFetch;
});

describe('repository scan service', () => {
  it('verifies the public repository, scans its default-branch commit, and stores findings', async () => {
    const scan = configureScanDocument();
    configureGitHubResponses();
    fetchSnapshotMock.mockResolvedValue({
      repositoryFullName: 'repo-user/project',
      commitSha,
      files: [],
      truncated: false,
    });
    runSemgrepScanMock.mockResolvedValue({
      complete: true,
      findings: [
        {
          ruleId: 'repoguard.javascript.dynamic-code-execution',
          message: 'Avoid evaluating strings as code.',
          severity: 'ERROR',
          location: {
            path: 'src/index.js',
            start: { line: 4, column: 2 },
            end: { line: 4, column: 14 },
          },
        },
        {
          ruleId: 'repoguard.javascript.document-write',
          message: 'Review untrusted document.write content.',
          severity: 'WARNING',
          location: { path: 'src/page.js', start: { line: 8 }, end: { line: 8 } },
        },
        {
          ruleId: 'repoguard.generic.hardcoded-credential',
          message: 'Potential hardcoded credential.',
          severity: 'INFO',
          location: { path: '.env.example', start: {}, end: {} },
        },
      ],
    });

    const result = await createRepositoryScan(requestInput);

    expect(result).toBe(scan);
    expect(scan.statusHistory).toEqual(['running', 'completed']);
    expect(scan.status).toBe('completed');
    expect(scan.completedAt).toBeInstanceOf(Date);
    expect(scan.findings).toEqual([
      {
        tool: 'semgrep',
        ruleId: 'repoguard.javascript.dynamic-code-execution',
        severity: 'high',
        title: 'Dynamic Code Execution',
        message: 'Avoid evaluating strings as code.',
        filePath: 'src/index.js',
        startLine: 4,
        endLine: 4,
      },
      {
        tool: 'semgrep',
        ruleId: 'repoguard.javascript.document-write',
        severity: 'medium',
        title: 'Document Write',
        message: 'Review untrusted document.write content.',
        filePath: 'src/page.js',
        startLine: 8,
        endLine: 8,
      },
      {
        tool: 'semgrep',
        ruleId: 'repoguard.generic.hardcoded-credential',
        severity: 'info',
        title: 'Hardcoded Credential',
        message: 'Potential hardcoded credential.',
        filePath: '.env.example',
        startLine: null,
        endLine: null,
      },
    ]);
    expect(scanCreateMock).toHaveBeenCalledWith({
      userId: 'user-123',
      githubRepositoryId: 42,
      repositoryFullName: 'repo-user/project',
      defaultBranch: 'main',
      commitSha,
      status: 'queued',
    });
    expect(fetchSnapshotMock).toHaveBeenCalledWith({
      repositoryFullName: 'repo-user/project',
      commitSha,
    });
    expect(runSemgrepScanMock).toHaveBeenCalledWith(
      await fetchSnapshotMock.mock.results[0].value,
    );
    expect(
      globalThis.fetch.mock.calls.map(([url]) => url.toString()),
    ).toEqual([
      'https://api.github.com/repos/repo-user/project',
      'https://api.github.com/repos/repo-user/project/commits/main',
    ]);
    expect(globalThis.fetch.mock.calls[0][1].headers).toMatchObject({
      Accept: 'application/vnd.github+json',
      'User-Agent': 'RepoGuard',
      'X-GitHub-Api-Version': '2026-03-10',
    });
  });

  it('rejects a private or mismatched repository before creating a scan', async () => {
    configureGitHubResponses(githubRepository({ id: 43 }));

    await expect(createRepositoryScan(requestInput)).rejects.toMatchObject({
      name: 'RepositoryScanServiceError',
      status: 404,
      message: 'Public repository was not found.',
    });
    expect(scanCreateMock).not.toHaveBeenCalled();
    expect(fetchSnapshotMock).not.toHaveBeenCalled();
    expect(runSemgrepScanMock).not.toHaveBeenCalled();
  });

  it('records a failed scan when the analysis is incomplete', async () => {
    const scan = configureScanDocument();
    configureGitHubResponses();
    fetchSnapshotMock.mockResolvedValue({
      repositoryFullName: 'repo-user/project',
      commitSha,
      files: [],
      truncated: true,
    });
    runSemgrepScanMock.mockResolvedValue({ complete: false, findings: [] });

    await expect(createRepositoryScan(requestInput)).rejects.toMatchObject({
      name: 'RepositoryScanServiceError',
      status: 502,
      scanId: 'scan-123',
      message: 'Scan could not analyze the complete repository snapshot.',
    });
    expect(scan.statusHistory).toEqual(['running', 'failed']);
    expect(scan.status).toBe('failed');
    expect(scan.findings).toEqual([]);
    expect(scan.completedAt).toBeInstanceOf(Date);
  });

  it('rejects invalid input before contacting GitHub', async () => {
    await expect(
      createRepositoryScan({ ...requestInput, repositoryName: '../project' }),
    ).rejects.toMatchObject({
      name: 'RepositoryScanServiceError',
      status: 400,
    });

    expect(globalThis.fetch).not.toHaveBeenCalled();
    expect(scanCreateMock).not.toHaveBeenCalled();
  });

  it('exposes the service error type for route handling', () => {
    const error = new RepositoryScanServiceError('Scanner unavailable.', 503);

    expect(error).toMatchObject({
      name: 'RepositoryScanServiceError',
      status: 503,
      scanId: null,
    });
  });
});
