import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  jest,
} from '@jest/globals';
import { EventEmitter } from 'node:events';
import { access, chmod, readFile, rm, stat } from 'node:fs/promises';
import path from 'node:path';

const mockSpawn = jest.fn();
let dockerArguments;
let workspaceDirectory;
let workspaceInspection;
let workspaceInspectionError;

jest.unstable_mockModule('node:child_process', () => ({ spawn: mockSpawn }));

const { runSemgrepScan, SemgrepRunnerError } = await import('./semgrepRunner.js');

function createSnapshot(overrides = {}) {
  return {
    repositoryFullName: 'kartik/repoguard',
    commitSha: 'a'.repeat(40),
    truncated: false,
    files: [
      {
        path: 'src/index.js',
        content: 'const payload = eval(input);\n',
        size: Buffer.byteLength('const payload = eval(input);\n'),
      },
    ],
    ...overrides,
  };
}

function createReport(overrides = {}) {
  return {
    version: '1.187.0',
    results: [
      {
        check_id: 'repoguard.javascript.dynamic-code-execution',
        path: 'src/index.js',
        start: { line: 1, col: 19 },
        end: { line: 1, col: 31 },
        extra: {
          message: 'Avoid evaluating strings as code.',
          severity: 'ERROR',
          metadata: { category: 'security', cwe: 'CWE-95' },
        },
      },
    ],
    errors: [],
    paths: {
      scanned: ['src/index.js'],
      skipped: { cli: [], gitignore: [], secrets: [], always: [] },
    },
    ...overrides,
  };
}

function configureDocker(report, exitCode = 0) {
  const child = new EventEmitter();
  child.stdout = new EventEmitter();
  child.kill = jest.fn();

  mockSpawn.mockImplementation((command, args, options) => {
    dockerArguments = args;
    const mount = args[args.indexOf('--mount') + 1];
    const match = mount.match(
      /^type=bind,source=(.+),target=\/workspace,readonly$/,
    );
    workspaceDirectory = match?.[1];

    setImmediate(async () => {
      try {
        const repositoryDirectory = path.join(workspaceDirectory, 'repository');
        const sourcePath = path.join(repositoryDirectory, 'src/index.js');
        const rulesPath = path.join(workspaceDirectory, 'semgrep-rules.yml');
        const [source, rules, rootStats, repositoryStats, fileStats] =
          await Promise.all([
            readFile(sourcePath, 'utf8'),
            readFile(rulesPath, 'utf8'),
            stat(workspaceDirectory),
            stat(repositoryDirectory),
            stat(sourcePath),
          ]);

        workspaceInspection = {
          source,
          rules,
          workspaceMode: rootStats.mode & 0o777,
          repositoryMode: repositoryStats.mode & 0o777,
          sourceMode: fileStats.mode & 0o777,
        };
      } catch (error) {
        workspaceInspectionError = error;
      }

      child.stdout.emit('data', Buffer.from(JSON.stringify(report)));
      child.emit('close', exitCode, null);
    });

    expect(command).toBe('docker');
    expect(options).toEqual({ stdio: ['ignore', 'pipe', 'ignore'] });
    return child;
  });

  return child;
}

beforeEach(() => {
  mockSpawn.mockReset();
  dockerArguments = null;
  workspaceDirectory = null;
  workspaceInspection = null;
  workspaceInspectionError = null;
});

afterEach(async () => {
  if (workspaceDirectory) {
    await chmod(workspaceDirectory, 0o700).catch(() => {});
    await rm(workspaceDirectory, { recursive: true, force: true }).catch(() => {});
  }
});

describe('Semgrep runner', () => {
  it('runs in a restricted container and normalizes findings from the report', async () => {
    configureDocker(createReport(), 1);

    const result = await runSemgrepScan(createSnapshot());

    expect(result).toMatchObject({
      scanner: 'semgrep',
      scannerVersion: '1.187.0',
      repositoryFullName: 'kartik/repoguard',
      commitSha: 'a'.repeat(40),
      complete: true,
      filesScanned: 1,
      filesSkipped: 0,
      errors: [],
      findings: [
        {
          ruleId: 'repoguard.javascript.dynamic-code-execution',
          message: 'Avoid evaluating strings as code.',
          severity: 'ERROR',
          category: 'security',
          cwe: ['CWE-95'],
          location: {
            path: 'src/index.js',
            start: { line: 1, column: 19 },
            end: { line: 1, column: 31 },
          },
        },
      ],
    });
    expect(workspaceInspectionError).toBeNull();
    expect(workspaceInspection).toMatchObject({
      source: 'const payload = eval(input);\n',
      workspaceMode: 0o555,
      repositoryMode: 0o555,
      sourceMode: 0o444,
    });
    expect(workspaceInspection.rules).toContain(
      'repoguard.javascript.dynamic-code-execution',
    );
    expect(dockerArguments).toEqual(
      expect.arrayContaining([
        '--pull=never',
        '--network',
        'none',
        '--read-only',
        '--cap-drop=ALL',
        '--security-opt=no-new-privileges',
        '--memory=1g',
        '--cpus=2',
        '--pids-limit=128',
        '--user',
        '65532:65532',
        'semgrep/semgrep:1.187.0',
        '--metrics=off',
      ]),
    );
    expect(mockSpawn).toHaveBeenCalledTimes(1);
    await expect(access(workspaceDirectory)).rejects.toMatchObject({
      code: 'ENOENT',
    });
  });

  it('rejects traversal and duplicate paths before starting Docker', async () => {
    const traversalSnapshot = createSnapshot({
      files: [{ path: '../outside.js', content: 'unsafe' }],
    });
    const duplicatePathSnapshot = createSnapshot({
      files: [
        { path: 'src/index.js', content: 'first' },
        { path: 'src/index.js', content: 'second' },
      ],
    });

    await expect(runSemgrepScan(traversalSnapshot)).rejects.toMatchObject({
      name: 'SemgrepRunnerError',
      status: 400,
    });
    await expect(runSemgrepScan(duplicatePathSnapshot)).rejects.toMatchObject({
      name: 'SemgrepRunnerError',
      status: 400,
    });
    expect(mockSpawn).not.toHaveBeenCalled();
  });

  it('rejects a findings exit code when the report contains no findings', async () => {
    configureDocker(createReport({ results: [] }), 1);

    await expect(runSemgrepScan(createSnapshot())).rejects.toMatchObject({
      name: 'SemgrepRunnerError',
      status: 502,
      message: 'Semgrep scan could not be completed.',
    });
    await expect(access(workspaceDirectory)).rejects.toMatchObject({
      code: 'ENOENT',
    });
  });

  it('marks results incomplete when the source snapshot was truncated', async () => {
    configureDocker(createReport());

    const result = await runSemgrepScan(
      createSnapshot({ truncated: true }),
    );

    expect(result.complete).toBe(false);
  });

  it('exposes the runner error type for API error handling', () => {
    const error = new SemgrepRunnerError('Scan failed.', 503);

    expect(error).toMatchObject({
      name: 'SemgrepRunnerError',
      message: 'Scan failed.',
      status: 503,
    });
  });
});
