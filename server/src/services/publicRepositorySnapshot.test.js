import {
  afterAll,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  jest,
} from '@jest/globals';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import * as tar from 'tar';
import {
  fetchPublicRepositorySnapshot,
} from './publicRepositorySnapshot.js';

const repositoryFullName = 'kartik/repoguard';
const commitSha = 'a'.repeat(40);
const originalFetch = globalThis.fetch;
let testDirectory;

async function createArchive(files) {
  const fixtureDirectory = await mkdtemp(
    path.join(testDirectory, 'repository-fixture-'),
  );
  const repositoryDirectory = path.join(fixtureDirectory, 'repo-fixture');
  await mkdir(repositoryDirectory);

  for (const file of files) {
    const filePath = path.join(repositoryDirectory, ...file.path.split('/'));
    await mkdir(path.dirname(filePath), { recursive: true });
    await writeFile(filePath, file.content);
  }

  const archivePath = path.join(fixtureDirectory, 'repository.tar.gz');
  await tar.c(
    { cwd: fixtureDirectory, file: archivePath, gzip: true },
    ['repo-fixture'],
  );

  return readFile(archivePath);
}

function mockArchiveResponse(archive, overrides = {}) {
  const responseBody = new Response(archive).body;
  const headers = new Headers({
    'content-length': String(archive.byteLength),
    ...overrides.headers,
  });

  globalThis.fetch.mockResolvedValue({
    ok: overrides.ok ?? true,
    url:
      overrides.url ??
      `https://codeload.github.com/kartik/repoguard/legacy.tar.gz/${commitSha}`,
    headers,
    body: responseBody,
  });
}

beforeAll(async () => {
  testDirectory = await mkdtemp(path.join(tmpdir(), 'repoguard-snapshot-test-'));
});

afterAll(async () => {
  globalThis.fetch = originalFetch;
  await rm(testDirectory, { recursive: true, force: true });
});

beforeEach(() => {
  globalThis.fetch = jest.fn();
});

describe('public repository snapshot service', () => {
  it('returns bounded source files from the requested public commit', async () => {
    const archive = await createArchive([
      { path: 'src/index.js', content: 'export const answer = 42;\n' },
      { path: 'package.json', content: '{"name":"repoguard"}\n' },
      { path: '.env.production', content: 'API_KEY=example\n' },
      { path: 'node_modules/package/index.js', content: 'ignored dependency' },
      { path: 'assets/logo.png', content: Buffer.from([0, 1, 2, 3]) },
    ]);
    mockArchiveResponse(archive);

    const snapshot = await fetchPublicRepositorySnapshot({
      repositoryFullName,
      commitSha,
    });

    expect(snapshot.repositoryFullName).toBe(repositoryFullName);
    expect(snapshot.commitSha).toBe(commitSha);
    expect(snapshot.truncated).toBe(false);
    expect(snapshot.files.map((file) => file.path).sort()).toEqual([
      '.env.production',
      'package.json',
      'src/index.js',
    ]);
    expect(
      snapshot.files.find((file) => file.path === 'src/index.js').content,
    ).toBe('export const answer = 42;\n');

    const [requestedUrl, options] = globalThis.fetch.mock.calls[0];
    expect(requestedUrl.toString()).toBe(
      `https://api.github.com/repos/kartik/repoguard/tarball/${commitSha}`,
    );
    expect(options.headers).toEqual({
      Accept: 'application/vnd.github+json',
      'User-Agent': 'RepoGuard',
      'X-GitHub-Api-Version': '2026-03-10',
    });
  });

  it('marks a snapshot truncated when a source file exceeds the per-file limit', async () => {
    const archive = await createArchive([
      { path: 'src/large.js', content: 'x'.repeat(1024 * 1024 + 1) },
      { path: 'src/small.js', content: 'export const safe = true;\n' },
    ]);
    mockArchiveResponse(archive);

    const snapshot = await fetchPublicRepositorySnapshot({
      repositoryFullName,
      commitSha,
    });

    expect(snapshot.truncated).toBe(true);
    expect(snapshot.files.map((file) => file.path)).toEqual(['src/small.js']);
  });

  it('rejects invalid repository and commit identifiers before making a request', async () => {
    await expect(
      fetchPublicRepositorySnapshot({
        repositoryFullName: '../private/repo',
        commitSha,
      }),
    ).rejects.toMatchObject({ name: 'RepositorySnapshotError', status: 400 });

    await expect(
      fetchPublicRepositorySnapshot({
        repositoryFullName,
        commitSha: 'not-a-commit',
      }),
    ).rejects.toMatchObject({ name: 'RepositorySnapshotError', status: 400 });

    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it('rejects a redirect outside GitHub archive hosting', async () => {
    const archive = Buffer.from('unused');
    mockArchiveResponse(archive, {
      url: 'https://attacker.example/repository.tar.gz',
    });

    await expect(
      fetchPublicRepositorySnapshot({ repositoryFullName, commitSha }),
    ).rejects.toMatchObject({ name: 'RepositorySnapshotError', status: 502 });
  });

  it('rejects an archive over the compressed download limit', async () => {
    mockArchiveResponse(Buffer.from('unused'), {
      headers: { 'content-length': String(21 * 1024 * 1024) },
    });

    await expect(
      fetchPublicRepositorySnapshot({ repositoryFullName, commitSha }),
    ).rejects.toMatchObject({ name: 'RepositorySnapshotError', status: 413 });
  });

  it('returns a safe error when GitHub cannot provide the archive', async () => {
    mockArchiveResponse(Buffer.from('not found'), { ok: false });

    await expect(
      fetchPublicRepositorySnapshot({ repositoryFullName, commitSha }),
    ).rejects.toMatchObject({ name: 'RepositorySnapshotError', status: 502 });
  });

  it('rejects an invalid gzip archive without returning parser details', async () => {
    mockArchiveResponse(Buffer.from('not a gzip archive'));

    await expect(
      fetchPublicRepositorySnapshot({ repositoryFullName, commitSha }),
    ).rejects.toMatchObject({
      name: 'RepositorySnapshotError',
      message: 'Repository snapshot archive could not be processed.',
      status: 502,
    });
  });
});
