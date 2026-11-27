import { createWriteStream } from 'node:fs';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { Readable, Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { createGunzip } from 'node:zlib';
import { TextDecoder } from 'node:util';
import * as tar from 'tar';

const GITHUB_API_VERSION = '2026-03-10';
const MAX_COMPRESSED_ARCHIVE_BYTES = 20 * 1024 * 1024;
const MAX_EXPANDED_ARCHIVE_BYTES = 96 * 1024 * 1024;
const MAX_SOURCE_FILES = 250;
const MAX_SOURCE_FILE_BYTES = 1024 * 1024;
const MAX_TOTAL_SOURCE_BYTES = 8 * 1024 * 1024;
const MAX_TAR_METADATA_BYTES = 64 * 1024;
const REPOSITORY_NAME_PATTERN =
  /^[A-Za-z0-9][A-Za-z0-9_.-]{0,38}\/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$/;
const COMMIT_SHA_PATTERN = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/i;
const SOURCE_EXTENSIONS = new Set([
  '.bash',
  '.c',
  '.cc',
  '.cpp',
  '.cs',
  '.css',
  '.go',
  '.h',
  '.html',
  '.htm',
  '.java',
  '.js',
  '.json',
  '.jsonc',
  '.jsx',
  '.kt',
  '.kts',
  '.less',
  '.md',
  '.mjs',
  '.php',
  '.py',
  '.rb',
  '.rs',
  '.sass',
  '.scss',
  '.sh',
  '.sql',
  '.svelte',
  '.swift',
  '.toml',
  '.ts',
  '.tsx',
  '.tf',
  '.tfvars',
  '.vue',
  '.xml',
  '.yaml',
  '.yml',
]);
const SOURCE_FILE_NAMES = new Set([
  '.dockerignore',
  '.env',
  '.env.example',
  '.env.sample',
  '.gitignore',
  'dockerfile',
  'go.mod',
  'go.sum',
  'jenkinsfile',
  'makefile',
  'npm-shrinkwrap.json',
  'package-lock.json',
  'package.json',
  'pnpm-lock.yaml',
  'pyproject.toml',
  'requirements.txt',
  'yarn.lock',
]);
const IGNORED_DIRECTORY_NAMES = new Set(['.git', 'node_modules']);

export class RepositorySnapshotError extends Error {
  constructor(message, status = 502) {
    super(message);
    this.name = 'RepositorySnapshotError';
    this.status = status;
  }
}

function createByteLimit(maximumBytes, message) {
  return new Transform({
    transform(chunk, encoding, callback) {
      this.bytesRead = (this.bytesRead ?? 0) + chunk.length;

      if (this.bytesRead > maximumBytes) {
        callback(new RepositorySnapshotError(message, 413));
        return;
      }

      callback(null, chunk);
    },
  });
}

function getRepositoryRelativePath(archivePath, archiveRoot) {
  if (
    typeof archivePath !== 'string' ||
    archivePath.startsWith('/') ||
    archivePath.includes('\\') ||
    path.posix.isAbsolute(archivePath)
  ) {
    return null;
  }

  const segments = archivePath.split('/');
  const root = segments.shift();

  if (
    !root ||
    root === '.' ||
    root === '..' ||
    root.includes(':') ||
    root !== archiveRoot ||
    segments.length === 0 ||
    segments.some(
      (segment) =>
        segment === '' || segment === '.' || segment === '..' || segment.includes(':'),
    )
  ) {
    return null;
  }

  return segments.join('/');
}

function isSupportedSourceFile(relativePath) {
  const pathSegments = relativePath.split('/');

  if (
    pathSegments.some((segment) =>
      IGNORED_DIRECTORY_NAMES.has(segment.toLowerCase()),
    )
  ) {
    return false;
  }

  const fileName = pathSegments.at(-1).toLowerCase();

  if (
    SOURCE_FILE_NAMES.has(fileName) ||
    /^\.env(?:\.[a-z0-9_-]+)?$/i.test(fileName)
  ) {
    return true;
  }

  return SOURCE_EXTENSIONS.has(path.posix.extname(fileName));
}

function validateSnapshotArguments(repositoryFullName, commitSha) {
  if (
    typeof repositoryFullName !== 'string' ||
    !REPOSITORY_NAME_PATTERN.test(repositoryFullName)
  ) {
    throw new RepositorySnapshotError('Repository name is invalid.', 400);
  }

  if (typeof commitSha !== 'string' || !COMMIT_SHA_PATTERN.test(commitSha)) {
    throw new RepositorySnapshotError('Commit SHA is invalid.', 400);
  }
}

async function fetchArchive(repositoryFullName, commitSha) {
  const [owner, repository] = repositoryFullName.split('/');
  const archiveUrl = new URL(
    `https://api.github.com/repos/${owner}/${repository}/tarball/${commitSha}`,
  );
  let response;

  try {
    response = await fetch(archiveUrl, {
      headers: {
        Accept: 'application/vnd.github+json',
        'User-Agent': 'RepoGuard',
        'X-GitHub-Api-Version': GITHUB_API_VERSION,
      },
      signal: AbortSignal.timeout(30_000),
    });
  } catch (error) {
    const timedOut = error.name === 'TimeoutError';
    throw new RepositorySnapshotError(
      timedOut
        ? 'Repository snapshot download timed out.'
        : 'Public repository snapshot could not be downloaded.',
      timedOut ? 504 : 502,
    );
  }

  if (!response.ok) {
    await cancelResponseBody(response);
    throw new RepositorySnapshotError(
      'Public repository snapshot could not be downloaded.',
      502,
    );
  }

  let responseUrl;

  try {
    responseUrl = new URL(response.url);
  } catch {
    await cancelResponseBody(response);
    throw new RepositorySnapshotError(
      'GitHub returned an invalid repository archive URL.',
      502,
    );
  }

  if (
    responseUrl.protocol !== 'https:' ||
    responseUrl.hostname !== 'codeload.github.com' ||
    !response.body
  ) {
    await cancelResponseBody(response);
    throw new RepositorySnapshotError(
      'GitHub returned an invalid repository archive.',
      502,
    );
  }

  const contentLength = response.headers.get('content-length');

  if (
    contentLength !== null &&
    Number.isFinite(Number(contentLength)) &&
    Number(contentLength) > MAX_COMPRESSED_ARCHIVE_BYTES
  ) {
    await cancelResponseBody(response);
    throw new RepositorySnapshotError(
      'Repository archive exceeds the supported size limit.',
      413,
    );
  }

  return response;
}

async function cancelResponseBody(response) {
  try {
    await response.body?.cancel();
  } catch {
    // Preserve the safe error that caused the response body to be discarded.
  }
}

export async function fetchPublicRepositorySnapshot({
  repositoryFullName,
  commitSha,
}) {
  validateSnapshotArguments(repositoryFullName, commitSha);

  const response = await fetchArchive(repositoryFullName, commitSha);
  const temporaryDirectory = await mkdtemp(
    path.join(tmpdir(), 'repoguard-snapshot-'),
  );
  const archivePath = path.join(temporaryDirectory, 'repository.tar');
  const compressedByteLimit = createByteLimit(
    MAX_COMPRESSED_ARCHIVE_BYTES,
    'Repository archive exceeds the supported size limit.',
  );
  const expandedByteLimit = createByteLimit(
    MAX_EXPANDED_ARCHIVE_BYTES,
    'Expanded repository archive exceeds the supported size limit.',
  );

  try {
    await pipeline(
      Readable.fromWeb(response.body),
      compressedByteLimit,
      createGunzip(),
      expandedByteLimit,
      createWriteStream(archivePath, { flags: 'wx', mode: 0o600 }),
    );

    const selectedFiles = [];
    const selectedPaths = new Set();
    let archiveRoot = null;
    let sourceBytes = 0;
    let truncated = false;

    await tar.x({
      file: archivePath,
      cwd: temporaryDirectory,
      strip: 1,
      strict: true,
      preservePaths: false,
      preserveOwner: false,
      noMtime: true,
      umask: 0o077,
      fmode: 0o600,
      dmode: 0o700,
      maxMetaEntrySize: MAX_TAR_METADATA_BYTES,
      filter(archivePathname, entry) {
        if (entry.type !== 'File') {
          return false;
        }

        const segments = archivePathname.split('/');

        if (archiveRoot === null) {
          archiveRoot = segments[0];
        }

        const relativePath = getRepositoryRelativePath(
          archivePathname,
          archiveRoot,
        );

        if (
          !relativePath ||
          !isSupportedSourceFile(relativePath) ||
          selectedPaths.has(relativePath)
        ) {
          return false;
        }

        if (
          !Number.isSafeInteger(entry.size) ||
          entry.size < 0 ||
          entry.size > MAX_SOURCE_FILE_BYTES ||
          selectedFiles.length >= MAX_SOURCE_FILES ||
          sourceBytes + entry.size > MAX_TOTAL_SOURCE_BYTES
        ) {
          truncated = true;
          return false;
        }

        selectedPaths.add(relativePath);
        selectedFiles.push({ path: relativePath, size: entry.size });
        sourceBytes += entry.size;
        return true;
      },
    });

    const decoder = new TextDecoder('utf-8', { fatal: true });
    const files = [];

    for (const selectedFile of selectedFiles) {
      const diskPath = path.join(
        temporaryDirectory,
        ...selectedFile.path.split('/'),
      );
      const contentBuffer = await readFile(diskPath);

      if (
        contentBuffer.length !== selectedFile.size ||
        contentBuffer.includes(0)
      ) {
        truncated = true;
        continue;
      }

      try {
        files.push({
          path: selectedFile.path,
          content: decoder.decode(contentBuffer),
          size: contentBuffer.length,
        });
      } catch {
        truncated = true;
      }
    }

    return {
      repositoryFullName,
      commitSha: commitSha.toLowerCase(),
      files,
      truncated,
    };
  } catch (error) {
    if (error instanceof RepositorySnapshotError) {
      throw error;
    }

    throw new RepositorySnapshotError(
      'Repository snapshot archive could not be processed.',
      502,
    );
  } finally {
    await rm(temporaryDirectory, { recursive: true, force: true });
  }
}
